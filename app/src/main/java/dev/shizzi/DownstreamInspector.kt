package dev.shizzi

import android.content.Context
import android.net.MacAddress
import android.net.wifi.WifiManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor

data class DiscoveredHost(
    val mac: String,
    val ip: String = "",
    val allIps: List<String> = emptyList(),
    val interfaceName: String = "wlan0",
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val seenPackets: Long = 0L,
    val matchedPackets: Long = 0L,
    val droppedPackets: Long = 0L,
    val blockedDropPackets: Long = 0L,
    val shapingDropPackets: Long = 0L,
    val policyVersionBlockedDrops: Long = 0L,
    val shapedBytes: Long = 0L,
    val policyInstalled: Boolean = false,
    val unattributedPostNatObserved: Boolean = false,
    val mappingSource: String = "softap_dump+downstream_neigh",
    val directAttributedPackets: Long = 0L,
    val bpfAttributedPackets: Long = 0L,
    val policyVersion: Long = 1L,
)

data class CallbackObservation(
    val softApCallbackStatus: String = "NOT_REGISTERED",
    val softApCallbackMacs: Set<String> = emptySet(),
    val tetheringCallbackStatus: String = "NOT_REGISTERED",
    val tetheringCallbackClientIps: Map<String, List<String>> = emptyMap(),
)

data class DownstreamSnapshot(
    val count: Int,
    val clients: List<DiscoveredHost>,
    val apInterfaces: Set<String> = emptySet(),
    val mappingSourceSummary: String = "softap_dump+downstream_neigh",
    val callbackObservation: CallbackObservation = CallbackObservation(),
)

class DownstreamInspector(
    private val inspector: UpstreamInspector = UpstreamInspector(),
    private val context: Context? = null,
) {

    private var cachedSnapshot = DownstreamSnapshot(count = 0, clients = emptyList())
    private var lastReadAt = 0L
    private var loggedCount = -1

    @Volatile
    private var callbacksInitialized = false

    @Volatile
    private var softApCallbackStatus: String = "NOT_INITIALIZED"

    @Volatile
    private var tetheringCallbackStatus: String = "NOT_INITIALIZED"

    private val callbackConnectedMacs = ConcurrentHashMap.newKeySet<String>()
    private val callbackClientIpsByMac = ConcurrentHashMap<String, List<String>>()

    @Synchronized
    fun ensureOfficialCallbacksProbed(targetContext: Context? = context): CallbackObservation {
        if (!callbacksInitialized && targetContext != null) {
            callbacksInitialized = true
            val directExecutor = Executor { runnable -> runnable.run() }
            probeSoftApCallback(targetContext, directExecutor)
            probeTetheringEventCallback(targetContext, directExecutor)
        } else if (targetContext == null && !callbacksInitialized) {
            softApCallbackStatus = "NO_CONTEXT"
            tetheringCallbackStatus = "NO_CONTEXT"
        }
        return CallbackObservation(
            softApCallbackStatus = softApCallbackStatus,
            softApCallbackMacs = callbackConnectedMacs.toSet(),
            tetheringCallbackStatus = tetheringCallbackStatus,
            tetheringCallbackClientIps = HashMap(callbackClientIpsByMac),
        )
    }

    private fun probeSoftApCallback(ctx: Context, executor: Executor) {
        runCatching {
            val wifiManager = ctx.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (wifiManager == null) {
                softApCallbackStatus = "WIFI_MANAGER_NULL"
                return
            }
            val callbackClass = Class.forName("android.net.wifi.WifiManager\$SoftApCallback")
            val registerMethod = wifiManager.javaClass.methods.firstOrNull {
                it.name == "registerSoftApCallback" && it.parameterTypes.size == 2
            }
            if (registerMethod == null) {
                softApCallbackStatus = "METHOD_NOT_FOUND"
                return
            }
            val proxy = java.lang.reflect.Proxy.newProxyInstance(
                callbackClass.classLoader,
                arrayOf(callbackClass),
            ) { _, method, args ->
                if (method.name == "onConnectedClientsChanged") {
                    val clientsList = args?.firstOrNull { it is List<*> } as? List<*>
                    if (clientsList != null) {
                        val extracted = mutableSetOf<String>()
                        for (clientObj in clientsList) {
                            if (clientObj == null) continue
                            val macObj = runCatching {
                                clientObj.javaClass.getMethod("getMacAddress").invoke(clientObj)
                            }.getOrNull()
                            val macStr = (macObj as? MacAddress)?.toString()?.uppercase()
                                ?: macObj?.toString()?.uppercase()
                            if (macStr != null && isValidClientMac(macStr)) {
                                extracted.add(macStr)
                            }
                        }
                        callbackConnectedMacs.clear()
                        callbackConnectedMacs.addAll(extracted)
                        softApCallbackStatus = "ACTIVE_CLIENTS_${extracted.size}"
                    }
                }
                null
            }
            registerMethod.invoke(wifiManager, executor, proxy)
            if (softApCallbackStatus == "NOT_INITIALIZED") {
                softApCallbackStatus = "REGISTERED"
            }
        }.onFailure { err ->
            val cause = (err as? java.lang.reflect.InvocationTargetException)?.targetException ?: err
            softApCallbackStatus = "FAILED:${cause.javaClass.simpleName}:${cause.message?.take(80)}"
        }
    }

    private fun probeTetheringEventCallback(ctx: Context, executor: Executor) {
        runCatching {
            val tetheringManager = ctx.getSystemService("tethering")
            if (tetheringManager == null) {
                tetheringCallbackStatus = "TETHERING_MANAGER_NULL"
                return
            }
            val callbackClass = Class.forName("android.net.TetheringManager\$TetheringEventCallback")
            val registerMethod = tetheringManager.javaClass.methods.firstOrNull {
                it.name == "registerTetheringEventCallback" && it.parameterTypes.size == 2
            }
            if (registerMethod == null) {
                tetheringCallbackStatus = "METHOD_NOT_FOUND"
                return
            }
            val proxy = java.lang.reflect.Proxy.newProxyInstance(
                callbackClass.classLoader,
                arrayOf(callbackClass),
            ) { _, method, args ->
                if (method.name == "onClientsChanged") {
                    val clientsCol = args?.firstOrNull { it is Collection<*> } as? Collection<*>
                    if (clientsCol != null) {
                        val map = HashMap<String, List<String>>()
                        for (tetheredClient in clientsCol) {
                            if (tetheredClient == null) continue
                            val macObj = runCatching {
                                tetheredClient.javaClass.getMethod("getMacAddress").invoke(tetheredClient)
                            }.getOrNull()
                            val macStr = (macObj as? MacAddress)?.toString()?.uppercase()
                                ?: macObj?.toString()?.uppercase()
                                ?: continue
                            val addressesCol = runCatching {
                                tetheredClient.javaClass.getMethod("getAddresses").invoke(tetheredClient) as? Collection<*>
                            }.getOrNull().orEmpty()
                            val ips = mutableListOf<String>()
                            for (linkAddrObj in addressesCol) {
                                if (linkAddrObj == null) continue
                                val addrObj = runCatching {
                                    linkAddrObj.javaClass.getMethod("getAddress").invoke(linkAddrObj) as? java.net.InetAddress
                                }.getOrNull()
                                val hostAddr = addrObj?.hostAddress?.substringBefore('%')
                                if (!hostAddr.isNullOrBlank()) {
                                    ips.add(hostAddr)
                                }
                            }
                            if (isValidClientMac(macStr)) {
                                map[macStr] = ips.distinct()
                            }
                        }
                        callbackClientIpsByMac.clear()
                        callbackClientIpsByMac.putAll(map)
                        tetheringCallbackStatus = "ACTIVE_CLIENTS_${map.size}"
                    }
                }
                null
            }
            registerMethod.invoke(tetheringManager, executor, proxy)
            if (tetheringCallbackStatus == "NOT_INITIALIZED") {
                tetheringCallbackStatus = "REGISTERED"
            }
        }.onFailure { err ->
            val cause = (err as? java.lang.reflect.InvocationTargetException)?.targetException ?: err
            tetheringCallbackStatus = "FAILED:${cause.javaClass.simpleName}:${cause.message?.take(80)}"
        }
    }

    fun findTetheredDownstream(): String? {
        val observation = inspector.observe()
        if (observation.didTimeout) return "dumpsys tethering timed out; downstream state unknown"

        val tethered = parseTetheredInterfaces(observation.rawOutput)

        return when {
            tethered.isEmpty() -> null
            else -> "downstream still tethered: $tethered"
        }
    }

    @Synchronized
    fun inspectSnapshot(forceRefresh: Boolean = false): DownstreamSnapshot {
        val now = System.currentTimeMillis()
        if (!forceRefresh && lastReadAt > 0L && now - lastReadAt < REFRESH_INTERVAL_MS) {
            return cachedSnapshot
        }

        val cbObs = ensureOfficialCallbacksProbed()

        val tetheredIfaces = runCatching {
            val obs = inspector.observe()
            if (obs.didTimeout) emptySet() else parseTetheredInterfaces(obs.rawOutput).toSet()
        }.getOrDefault(emptySet())

        val wifiObservation = inspector.observeWifi()
        val wifiParsed = if (!wifiObservation.didTimeout) {
            parseWifiSoftApDump(wifiObservation.rawOutput)
        } else {
            null
        }

        val apIfaces = LinkedHashSet<String>().apply {
            addAll(tetheredIfaces)
            wifiParsed?.apInterfaces?.let { addAll(it) }
        }

        val rawNeighbors = ArrayList<NeighborRecord>().apply {
            addAll(runCatching { parseIpNeighFromShell() }.getOrDefault(emptyList()))
            addAll(runCatching { parseIp6NeighFromShell() }.getOrDefault(emptyList()))
            addAll(runCatching { parseArpFromShell() }.getOrDefault(emptyList()))
        }

        val resolvedClients = buildVerifiedConnectedClients(
            wifiDump = wifiParsed,
            tetheredInterfaces = apIfaces,
            neighbors = rawNeighbors,
            callbackObservation = cbObs,
        )

        val enrichedClients = resolvedClients.map { host ->
            val counters = TunTrafficEngine.getCounterSnapshot(host.mac)
            host.copy(
                rxBytes = counters.rxBytes,
                txBytes = counters.txBytes,
                seenPackets = counters.seenPackets,
                matchedPackets = counters.matchedPackets,
                droppedPackets = counters.droppedPackets,
                blockedDropPackets = counters.blockedDropPackets,
                shapingDropPackets = counters.shapingDropPackets,
                policyVersionBlockedDrops = counters.policyVersionBlockedDrops,
                shapedBytes = counters.shapedBytes,
                policyInstalled = counters.policyInstalled,
                unattributedPostNatObserved = counters.unattributedPostNatObserved,
                directAttributedPackets = counters.directAttributedPackets,
                bpfAttributedPackets = counters.bpfAttributedPackets,
                policyVersion = counters.policyVersion,
            )
        }

        val finalCount = enrichedClients.size
        val sourceSummary = enrichedClients.map { it.mappingSource }.distinct().joinToString(",")
            .ifBlank { "softap_dump+downstream_neigh" }
        lastReadAt = now
        cachedSnapshot = DownstreamSnapshot(
            count = finalCount,
            clients = enrichedClients,
            apInterfaces = apIfaces,
            mappingSourceSummary = sourceSummary,
            callbackObservation = cbObs,
        )

        logCountChange(finalCount, enrichedClients)
        return cachedSnapshot
    }

    fun countDevices(): Int = inspectSnapshot(forceRefresh = false).count

    fun listDiscoveredClients(forceRefresh: Boolean = false): List<DiscoveredHost> =
        inspectSnapshot(forceRefresh = forceRefresh).clients

    private fun logCountChange(count: Int, clients: List<DiscoveredHost>) {
        if (loggedCount == -1) {
            loggedCount = count
            if (count > 0) {
                val summary = clients.joinToString(", ") { "${it.mac} (${it.ip.ifBlank { "pending IP" }})" }
                SessionLog.info("client connected: $count now on the hotspot [$summary]")
            }
            return
        }
        if (count == loggedCount) return

        val direction = if (count > loggedCount) "connected" else "disconnected"
        loggedCount = count
        if (clients.isEmpty()) {
            SessionLog.info("client $direction: 0 now on the hotspot")
        } else {
            val summary = clients.joinToString(", ") { "${it.mac} (${it.ip.ifBlank { "pending IP" }})" }
            SessionLog.info("client $direction: $count now on the hotspot [$summary]")
        }
    }

    internal data class WifiSoftApDump(
        val reportedCount: Int,
        val connectedMacs: List<String>,
        val apInterfaces: Set<String>,
        val hasAuthoritativeCount: Boolean,
    )

    internal data class NeighborRecord(
        val mac: String,
        val ip: String,
        val interfaceName: String,
        val state: String,
    )

    private fun parseIpNeighFromShell(): List<NeighborRecord> {
        val res = HostFirewall.executeCommand("ip", "-4", "neigh", "show", timeoutMs = 1_500L)
        if (!res.isSuccess && res.stdout.isBlank()) {
            val fallback = HostFirewall.executeCommand("ip", "neigh", "show", timeoutMs = 1_500L)
            return parseIpNeighOutput(fallback.stdout)
        }
        return parseIpNeighOutput(res.stdout)
    }

    private fun parseIp6NeighFromShell(): List<NeighborRecord> {
        val res = HostFirewall.executeCommand("ip", "-6", "neigh", "show", timeoutMs = 1_500L)
        return parseIpNeighOutput(res.stdout)
    }

    private fun parseArpFromShell(): List<NeighborRecord> {
        val file = File("/proc/net/arp")
        if (!file.exists() || !file.canRead()) return emptyList()
        return runCatching {
            parseArpOutput(file.readText())
        }.getOrDefault(emptyList())
    }

    companion object {

        private val TETHERED_STATE_PATTERN =
            Regex("""^\s*([\w.-]+)\s+-\s+TetheredState\s+-""")

        private val AP_INTERFACE_PATTERN =
            Regex("""^\s*mApInterfaceName:\s*(\S+)""")

        private val CONNECTED_CLIENTS_LINE_PATTERN =
            Regex("""^\s*getConnectedClientList\(\)\.size\(\):\s*(\d+)\s*$""")

        private val WIFI_CLIENT_MAC_PATTERN =
            Regex("""(?:WifiClient\{[^}]*mMacAddress=|mMacAddress[=:]\s*|MacAddress[=:]\s*)([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b""")

        private val IP_NEIGH_PATTERN =
            Regex("""^(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)""")

        private const val REFRESH_INTERVAL_MS = 1_500L

        internal fun parseTetheredInterfaces(tetheringDump: String): List<String> =
            tetheringDump.lineSequence()
                .mapNotNull { line -> TETHERED_STATE_PATTERN.find(line)?.groupValues?.get(1) }
                .distinct()
                .toList()

        internal fun parseIpNeighOutput(text: String): List<NeighborRecord> {
            val results = mutableListOf<NeighborRecord>()
            for (line in text.lines()) {
                val match = IP_NEIGH_PATTERN.find(line.trim()) ?: continue
                val ip = match.groupValues[1].trim().substringBefore('%')
                val iface = match.groupValues[2].trim()
                val mac = match.groupValues[3].uppercase()
                val state = match.groupValues[4].uppercase()
                if (state != "FAILED" && state != "INCOMPLETE" && isValidClientMac(mac)) {
                    results.add(NeighborRecord(mac = mac, ip = ip, interfaceName = iface, state = state))
                }
            }
            return results
        }

        internal fun parseArpOutput(text: String): List<NeighborRecord> {
            val results = mutableListOf<NeighborRecord>()
            val lines = text.lines()
            for (line in lines.drop(1)) {
                val tokens = line.trim().split(Regex("\\s+"))
                if (tokens.size >= 6) {
                    val ip = tokens[0].trim()
                    val flags = tokens[2].trim()
                    val mac = tokens[3].uppercase()
                    val device = tokens[5].trim()
                    if (flags != "0x0" && isValidClientMac(mac)) {
                        results.add(NeighborRecord(mac = mac, ip = ip, interfaceName = device, state = "ARP_VALID"))
                    }
                }
            }
            return results
        }

        internal fun parseWifiSoftApDump(output: String): WifiSoftApDump {
            val lines = output.lines()
            val apInterfaces = LinkedHashSet<String>()
            val connectedMacs = LinkedHashSet<String>()
            var totalReportedCount = 0
            var foundAuthoritativeBlock = false

            var i = 0
            while (i < lines.size) {
                val line = lines[i]

                AP_INTERFACE_PATTERN.find(line)?.let { match ->
                    val iface = match.groupValues[1].trim()
                    if (iface.isNotEmpty() && iface != "null") {
                        apInterfaces.add(iface)
                    }
                }

                val countMatch = CONNECTED_CLIENTS_LINE_PATTERN.find(line)
                if (countMatch != null) {
                    foundAuthoritativeBlock = true
                    val blockCount = countMatch.groupValues[1].toIntOrNull() ?: 0
                    totalReportedCount += blockCount

                    if (blockCount > 0) {
                        var extractedInBlock = 0
                        val maxLookahead = minOf(lines.size - 1, i + (blockCount * 5) + 6)
                        var j = i + 1
                        while (j <= maxLookahead && extractedInBlock < blockCount) {
                            val nextLine = lines[j]
                            if (CONNECTED_CLIENTS_LINE_PATTERN.containsMatchIn(nextLine) ||
                                nextLine.trimStart().startsWith("Dump of ") ||
                                nextLine.trimStart().startsWith("WifiScoreReport") ||
                                nextLine.trimStart().startsWith("WifiConfigManager")
                            ) {
                                break
                            }
                            val macMatch = WIFI_CLIENT_MAC_PATTERN.find(nextLine)
                            if (macMatch != null) {
                                val mac = macMatch.groupValues[1].uppercase()
                                if (isValidClientMac(mac)) {
                                    connectedMacs.add(mac)
                                    extractedInBlock++
                                }
                            }
                            j++
                        }
                    }
                }
                i++
            }

            return WifiSoftApDump(
                reportedCount = totalReportedCount,
                connectedMacs = connectedMacs.toList(),
                apInterfaces = apInterfaces,
                hasAuthoritativeCount = foundAuthoritativeBlock,
            )
        }

        internal fun buildVerifiedConnectedClients(
            wifiDump: WifiSoftApDump?,
            tetheredInterfaces: Set<String>,
            neighbors: List<NeighborRecord>,
            callbackObservation: CallbackObservation = CallbackObservation(),
        ): List<DiscoveredHost> {
            val apIfaces = LinkedHashSet<String>().apply {
                addAll(tetheredInterfaces)
                wifiDump?.apInterfaces?.let { addAll(it) }
            }

            // Strictly scope neighbor entries to downstream AP interfaces so upstream neighbors or
            // scan results are never mistaken for connected clients.
            val filteredNeighbors = neighbors.filter { record ->
                when {
                    apIfaces.isNotEmpty() -> record.interfaceName in apIfaces
                    else -> isLikelyDownstreamInterface(record.interfaceName)
                }
            }

            val apNeighborsByMac = filteredNeighbors.groupBy { it.mac.uppercase() }

            fun buildHostForMac(mac: String, defaultIface: String, hasSoftApDump: Boolean): DiscoveredHost {
                val records = apNeighborsByMac[mac].orEmpty()
                val cbIps = callbackObservation.tetheringCallbackClientIps[mac].orEmpty()
                val neighIps = records.map { it.ip }.filter { it.isNotBlank() }
                val allIps = (cbIps + neighIps).distinct()
                val primaryIpv4 = allIps.firstOrNull { !it.contains(':') }
                val primaryIp = primaryIpv4 ?: allIps.firstOrNull().orEmpty()
                val iface = records.firstOrNull()?.interfaceName
                    ?: apIfaces.firstOrNull()
                    ?: defaultIface

                val sources = mutableListOf<String>()
                if (mac in callbackObservation.softApCallbackMacs) sources.add("softap_callback")
                if (cbIps.isNotEmpty()) sources.add("tethering_callback")
                if (hasSoftApDump) sources.add("softap_dump")
                if (neighIps.isNotEmpty()) sources.add("downstream_neigh")
                val sourceLabel = sources.joinToString("+").ifBlank { "softap_dump" }

                return DiscoveredHost(
                    mac = mac,
                    ip = primaryIp,
                    allIps = allIps,
                    interfaceName = iface,
                    mappingSource = sourceLabel,
                )
            }

            val defaultApIface = apIfaces.firstOrNull() ?: "wlan1"

            // If official SoftApCallback reported active MACs, combine with WifiSoftApDump
            if (wifiDump != null && wifiDump.hasAuthoritativeCount) {
                val nonWifiTetheredIfaces = apIfaces.filter {
                    !it.startsWith("wlan") && !it.startsWith("ap") && !it.startsWith("swlan") && !it.startsWith("softap")
                }

                if (wifiDump.reportedCount == 0 &&
                    callbackObservation.softApCallbackMacs.isEmpty() &&
                    nonWifiTetheredIfaces.isEmpty()
                ) {
                    return emptyList()
                }

                val verified = LinkedHashMap<String, DiscoveredHost>()

                for (mac in callbackObservation.softApCallbackMacs) {
                    verified[mac] = buildHostForMac(mac, defaultApIface, hasSoftApDump = true)
                }

                for (mac in wifiDump.connectedMacs) {
                    verified[mac] = buildHostForMac(mac, defaultApIface, hasSoftApDump = true)
                }

                if (verified.size < wifiDump.reportedCount) {
                    val needed = wifiDump.reportedCount - verified.size
                    val candidates = apNeighborsByMac.entries
                        .filter { (mac, _) -> !verified.containsKey(mac) }
                        .sortedBy { (_, recs) -> neighborStatePriority(recs) }
                        .take(needed)

                    for ((mac, _) in candidates) {
                        verified[mac] = buildHostForMac(mac, defaultApIface, hasSoftApDump = true)
                    }
                }

                for (nonWifiIface in nonWifiTetheredIfaces) {
                    for ((mac, recs) in apNeighborsByMac) {
                        if (recs.any { it.interfaceName == nonWifiIface && it.state == "REACHABLE" }) {
                            verified.putIfAbsent(mac, buildHostForMac(mac, nonWifiIface, hasSoftApDump = false))
                        }
                    }
                }

                return verified.values.toList()
            }

            if (callbackObservation.softApCallbackMacs.isNotEmpty()) {
                return callbackObservation.softApCallbackMacs.map { mac ->
                    buildHostForMac(mac, defaultApIface, hasSoftApDump = false)
                }
            }

            if (apIfaces.isEmpty()) {
                return emptyList()
            }

            return apNeighborsByMac.keys
                .map { mac -> buildHostForMac(mac, defaultApIface, hasSoftApDump = false) }
        }

        private fun neighborStatePriority(records: List<NeighborRecord>): Int {
            val states = records.map { it.state }.toSet()
            return when {
                "REACHABLE" in states -> 0
                "DELAY" in states || "PROBE" in states -> 1
                "ARP_VALID" in states -> 2
                else -> 3
            }
        }

        private fun isLikelyDownstreamInterface(iface: String): Boolean {
            val lower = iface.lowercase()
            if (lower.startsWith("rmnet") || lower.startsWith("ccmni") || lower.startsWith("tun") || lower.startsWith("testtun") || lower.startsWith("lo") || lower.startsWith("dummy")) {
                return false
            }
            return lower.startsWith("ap") ||
                lower.startsWith("wlan1") ||
                lower.startsWith("wlan2") ||
                lower.startsWith("swlan") ||
                lower.startsWith("softap") ||
                lower.startsWith("rndis") ||
                lower.startsWith("ncm")
        }

        private fun isValidClientMac(mac: String): Boolean {
            if (mac.length != 17) return false
            if (mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") return false
            return true
        }
    }
}
