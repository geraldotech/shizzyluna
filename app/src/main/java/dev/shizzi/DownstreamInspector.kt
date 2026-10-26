package dev.shizzi

import java.io.File
import java.util.concurrent.TimeUnit

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
    val shapedBytes: Long = 0L,
    val policyInstalled: Boolean = false,
)

data class DownstreamSnapshot(
    val count: Int,
    val clients: List<DiscoveredHost>,
    val apInterfaces: Set<String> = emptySet(),
)

class DownstreamInspector(private val inspector: UpstreamInspector = UpstreamInspector()) {

    private var cachedSnapshot = DownstreamSnapshot(count = 0, clients = emptyList())
    private var lastReadAt = 0L
    private var loggedCount = -1

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
            addAll(runCatching { parseArpFromShell() }.getOrDefault(emptyList()))
        }

        val resolvedClients = buildVerifiedConnectedClients(
            wifiDump = wifiParsed,
            tetheredInterfaces = apIfaces,
            neighbors = rawNeighbors,
        )

        val enrichedClients = resolvedClients.map { host ->
            val counters = TunTrafficEngine.getCounterSnapshot(host.mac)
            host.copy(
                rxBytes = counters.rxBytes,
                txBytes = counters.txBytes,
                seenPackets = counters.seenPackets,
                matchedPackets = counters.matchedPackets,
                droppedPackets = counters.droppedPackets,
                shapedBytes = counters.shapedBytes,
                policyInstalled = counters.policyInstalled,
            )
        }

        val finalCount = enrichedClients.size
        lastReadAt = now
        cachedSnapshot = DownstreamSnapshot(
            count = finalCount,
            clients = enrichedClients,
            apInterfaces = apIfaces,
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
        return runCatching {
            val process = ProcessBuilder("ip", "neigh").start()
            val text = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(2, TimeUnit.SECONDS)
            parseIpNeighOutput(text)
        }.getOrDefault(emptyList())
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
                val ip = match.groupValues[1].trim()
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

        /**
         * Parses `dumpsys wifi` strictly from the active `SoftApManager` state dump.
         * Never scans general `dumpsys wifi` lines for arbitrary MAC addresses (which would
         * match hundreds of Wi-Fi scan BSSIDs, saved networks, and historical logs).
         */
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
        ): List<DiscoveredHost> {
            val apIfaces = LinkedHashSet<String>().apply {
                addAll(tetheredInterfaces)
                wifiDump?.apInterfaces?.let { addAll(it) }
            }

            // Group neighbor records by MAC, keeping only neighbors on downstream AP interfaces
            // (or if apIfaces isn't reported yet, neighbors that are NOT on upstream cellular/tun)
            val filteredNeighbors = neighbors.filter { record ->
                when {
                    apIfaces.isNotEmpty() -> record.interfaceName in apIfaces
                    else -> isLikelyDownstreamInterface(record.interfaceName)
                }
            }

            // Also keep an unfiltered neighbor lookup by MAC so if a MAC is already verified by
            // SoftApManager, we can still resolve its IPv4/IPv6 regardless of interface naming
            val allNeighborsByMac = neighbors.groupBy { it.mac.uppercase() }
            val apNeighborsByMac = filteredNeighbors.groupBy { it.mac.uppercase() }

            fun buildHostForMac(mac: String, defaultIface: String): DiscoveredHost {
                val records = apNeighborsByMac[mac] ?: allNeighborsByMac[mac].orEmpty()
                val allIps = records.map { it.ip }.filter { it.isNotBlank() }.distinct()
                val primaryIpv4 = allIps.firstOrNull { !it.contains(':') }
                val primaryIp = primaryIpv4 ?: allIps.firstOrNull().orEmpty()
                val iface = records.firstOrNull()?.interfaceName
                    ?: apIfaces.firstOrNull()
                    ?: defaultIface

                return DiscoveredHost(
                    mac = mac,
                    ip = primaryIp,
                    allIps = allIps,
                    interfaceName = iface,
                )
            }

            val defaultApIface = apIfaces.firstOrNull() ?: "wlan1"

            // Case 1: We have an authoritative SoftApManager client count from `dumpsys wifi`
            if (wifiDump != null && wifiDump.hasAuthoritativeCount) {
                val nonWifiTetheredIfaces = apIfaces.filter { !it.startsWith("wlan") && !it.startsWith("ap") && !it.startsWith("swlan") && !it.startsWith("softap") }

                if (wifiDump.reportedCount == 0 && nonWifiTetheredIfaces.isEmpty()) {
                    // 0 Wi-Fi clients are connected to the hotspot -> return empty list!
                    return emptyList()
                }

                val verified = LinkedHashMap<String, DiscoveredHost>()

                // 1a. Add the exact WifiClient MACs reported by SoftApManager
                for (mac in wifiDump.connectedMacs) {
                    verified[mac] = buildHostForMac(mac, defaultApIface)
                }

                // 1b. If SoftApManager reported N > verified.size (e.g. OEM redacted WifiClient line),
                // fill the remaining slots strictly from active neighbors on the downstream AP interface
                if (verified.size < wifiDump.reportedCount) {
                    val needed = wifiDump.reportedCount - verified.size
                    val candidates = apNeighborsByMac.entries
                        .filter { (mac, _) -> !verified.containsKey(mac) }
                        .sortedBy { (_, recs) -> neighborStatePriority(recs) }
                        .take(needed)

                    for ((mac, _) in candidates) {
                        verified[mac] = buildHostForMac(mac, defaultApIface)
                    }
                }

                // 1c. Also include active USB/Ethernet tethered clients if any non-Wi-Fi downstream is active
                for (nonWifiIface in nonWifiTetheredIfaces) {
                    for ((mac, recs) in apNeighborsByMac) {
                        if (recs.any { it.interfaceName == nonWifiIface && it.state == "REACHABLE" }) {
                            verified.putIfAbsent(mac, buildHostForMac(mac, nonWifiIface))
                        }
                    }
                }

                return verified.values.toList()
            }

            // Case 2: Fallback if `dumpsys wifi` timed out — only trust active neighbors on known tethered AP interfaces
            if (apIfaces.isEmpty()) {
                return emptyList()
            }

            return apNeighborsByMac.keys
                .map { mac -> buildHostForMac(mac, defaultApIface) }
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
