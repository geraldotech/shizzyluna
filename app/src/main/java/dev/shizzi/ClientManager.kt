package dev.shizzi

import org.json.JSONArray
import org.json.JSONObject
import java.util.Calendar

data class ClientRule(
    val mac: String,
    val alias: String = "",
    val isBlocked: Boolean = false,
    val bandwidthLimitKbps: Int = 0, // 0 = unlimited
    val connectionTimeLimitMinutes: Int = 0, // 0 = unlimited
    val scheduleEnabled: Boolean = false,
    val scheduleStartHour: Int = 8,
    val scheduleEndHour: Int = 22,
) {
    val cleanMac: String get() = mac.uppercase()

    val displayName: String
        get() = alias.ifBlank {
            val suffix = cleanMac.takeLast(5).replace(":", "")
            "Host-$suffix"
        }

    fun formattedBandwidthLimit(): String = when {
        bandwidthLimitKbps <= 0 -> "Unlimited"
        bandwidthLimitKbps >= 1000 && bandwidthLimitKbps % 1000 == 0 -> "${bandwidthLimitKbps / 1000} Mbps"
        bandwidthLimitKbps >= 1000 -> String.format("%.1f Mbps", bandwidthLimitKbps / 1000.0)
        else -> "$bandwidthLimitKbps Kbps"
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("mac", mac.uppercase())
        put("alias", alias)
        put("isBlocked", isBlocked)
        put("bandwidthLimitKbps", bandwidthLimitKbps)
        put("connectionTimeLimitMinutes", connectionTimeLimitMinutes)
        put("scheduleEnabled", scheduleEnabled)
        put("scheduleStartHour", scheduleStartHour)
        put("scheduleEndHour", scheduleEndHour)
    }

    companion object {
        fun fromJson(json: JSONObject): ClientRule = ClientRule(
            mac = json.optString("mac").uppercase(),
            alias = json.optString("alias"),
            isBlocked = json.optBoolean("isBlocked", false),
            bandwidthLimitKbps = json.optInt("bandwidthLimitKbps", 0),
            connectionTimeLimitMinutes = json.optInt("connectionTimeLimitMinutes", 0),
            scheduleEnabled = json.optBoolean("scheduleEnabled", false),
            scheduleStartHour = json.optInt("scheduleStartHour", 8),
            scheduleEndHour = json.optInt("scheduleEndHour", 22),
        )

        fun serializeList(rules: List<ClientRule>): String {
            val array = JSONArray()
            rules.forEach { array.put(it.toJson()) }
            return array.toString()
        }

        fun parseList(raw: String?): List<ClientRule> {
            if (raw.isNullOrBlank()) return emptyList()
            return runCatching {
                val array = JSONArray(raw)
                val list = mutableListOf<ClientRule>()
                for (i in 0 until array.length()) {
                    list.add(fromJson(array.getJSONObject(i)))
                }
                list
            }.getOrDefault(emptyList())
        }
    }
}

data class ConnectedClient(
    val mac: String,
    val ip: String,
    val allIps: List<String> = emptyList(),
    val alias: String = "",
    val interfaceName: String = "",
    val firstSeenAt: Long = System.currentTimeMillis(),
    val lastSeenAt: Long = System.currentTimeMillis(),
    val isBlocked: Boolean = false,
    val bandwidthLimitKbps: Int = 0, // 0 = unlimited
    val connectionTimeLimitMinutes: Int = 0, // 0 = unlimited
    val scheduleEnabled: Boolean = false,
    val scheduleStartHour: Int = 8,
    val scheduleEndHour: Int = 22,
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val seenPackets: Long = 0,
    val matchedPackets: Long = 0,
    val droppedPackets: Long = 0,
    val shapedBytes: Long = 0,
    val policyInstalled: Boolean = false,
    val datapathMode: DatapathMode = DatapathMode.INACTIVE,
    val firewallBackend: FirewallBackend = FirewallBackend.NONE,
    val kernelNetfilterAvailable: Boolean = false,
) {
    val cleanMac: String get() = mac.uppercase()

    val displayName: String
        get() = alias.ifBlank {
            val suffix = cleanMac.takeLast(5).replace(":", "")
            "Host-$suffix"
        }

    fun isRestricted(): Pair<Boolean, String?> {
        if (isBlocked) {
            return true to "Blocked by administrator"
        }
        if (connectionTimeLimitMinutes > 0) {
            val elapsedMinutes = (System.currentTimeMillis() - firstSeenAt) / 60_000
            if (elapsedMinutes >= connectionTimeLimitMinutes) {
                return true to "Time limit reached ($connectionTimeLimitMinutes min)"
            }
        }
        if (scheduleEnabled) {
            val currentHour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
            val allowed = if (scheduleStartHour <= scheduleEndHour) {
                currentHour in scheduleStartHour until scheduleEndHour
            } else {
                currentHour >= scheduleStartHour || currentHour < scheduleEndHour
            }
            if (!allowed) {
                return true to "Restricted by schedule ($scheduleStartHour:00 - $scheduleEndHour:00)"
            }
        }
        return false to null
    }

    val enforcementState: EnforcementState
        get() {
            val (restricted, _) = isRestricted()
            val snapshot = TunTrafficEngine.CounterSnapshot(
                mac = cleanMac,
                seenPackets = seenPackets,
                matchedPackets = matchedPackets,
                forwardedPackets = (seenPackets - droppedPackets).coerceAtLeast(0L),
                droppedPackets = droppedPackets,
                shapedPackets = if (shapedBytes > 0L) 1L else 0L,
                rxBytes = rxBytes,
                txBytes = txBytes,
                droppedBytes = 0L,
                shapedBytes = shapedBytes,
                policyInstalled = policyInstalled,
            )
            return HostFirewall.computeClientEnforcementState(
                isRestricted = restricted,
                bandwidthLimitKbps = bandwidthLimitKbps,
                counters = snapshot,
                datapathMode = datapathMode,
                kernelAvailable = kernelNetfilterAvailable,
            )
        }

    fun formattedBlockStatusLabel(): String {
        val (restricted, reason) = isRestricted()
        if (!restricted) return "Connected (${formattedUptime()})"
        return when (enforcementState) {
            EnforcementState.PACKETS_DROPPED ->
                "Blocked (verified • $droppedPackets pkts dropped)"
            EnforcementState.PACKETS_MATCHED,
            EnforcementState.POLICY_INSTALLED,
            -> "Block policy active (${reason ?: "Blocked"} • awaiting packets)"
            EnforcementState.DEGRADED_MULTI_CLIENT ->
                "Block degraded — multi-client isolation requires conntrack or root"
            EnforcementState.ENFORCEMENT_UNAVAILABLE ->
                "Block configured — not enforced (direct-TUN fallback)"
            else ->
                "Block configured — syncing policy"
        }
    }

    fun formattedBandwidthBadgeLabel(isCurrentlyConnected: Boolean): String {
        val cap = formattedBandwidthLimit()
        if (!isCurrentlyConnected) return "Cap: $cap (saved)"
        return when (enforcementState) {
            EnforcementState.THROTTLING_OBSERVED ->
                "Cap: $cap (verified • ${Traffic.format(shapedBytes)} shaped)"
            EnforcementState.PACKETS_MATCHED ->
                "Cap: $cap (verified • $matchedPackets pkts matched)"
            EnforcementState.POLICY_INSTALLED,
            EnforcementState.DATAPATH_ACTIVE,
            -> "Cap: $cap (policy active)"
            EnforcementState.DEGRADED_MULTI_CLIENT ->
                "Cap: $cap — degraded (multi-client)"
            EnforcementState.ENFORCEMENT_UNAVAILABLE ->
                "Cap: $cap — not enforced"
            else -> "Cap: $cap (configured)"
        }
    }

    fun formattedBandwidthLimit(): String = when {
        bandwidthLimitKbps <= 0 -> "Unlimited"
        bandwidthLimitKbps >= 1000 && bandwidthLimitKbps % 1000 == 0 -> "${bandwidthLimitKbps / 1000} Mbps"
        bandwidthLimitKbps >= 1000 -> String.format("%.1f Mbps", bandwidthLimitKbps / 1000.0)
        else -> "$bandwidthLimitKbps Kbps"
    }

    fun formattedUptime(): String {
        val elapsed = (System.currentTimeMillis() - firstSeenAt).coerceAtLeast(0)
        val mins = (elapsed / 60_000) % 60
        val hrs = elapsed / 3_600_000
        return when {
            hrs > 0 -> "${hrs}h ${mins}m"
            mins > 0 -> "${mins}m"
            else -> "< 1m"
        }
    }
}

object ClientDiscovery {

    private val seenTimes = mutableMapOf<String, Long>()

    /**
     * Synchronizes the UI ConnectedClient list strictly with the verified [discoveredHosts]
     * from the authoritative hotspot state. Never mixes in unverified ARP cache entries,
     * scan BSSIDs, or offline saved rules.
     */
    @Synchronized
    fun discoverClients(
        savedRules: List<ClientRule>,
        discoveredHosts: List<DiscoveredHost> = emptyList(),
        activeClientCount: Int = 0,
        includeSimulatedIfEmpty: Boolean = false,
        datapathMode: DatapathMode = DatapathMode.USERSPACE_PROXY,
        firewallBackend: FirewallBackend = FirewallBackend.USERSPACE,
        kernelNetfilterAvailable: Boolean = false,
    ): List<ConnectedClient> {
        if (discoveredHosts.isEmpty() && activeClientCount <= 0) {
            seenTimes.clear()
            return emptyList()
        }

        val rulesByMac = savedRules.associateBy { it.mac.uppercase().trim() }
        val foundClients = mutableListOf<ConnectedClient>()
        val seenMacs = mutableSetOf<String>()
        val now = System.currentTimeMillis()

        for (host in discoveredHosts) {
            val mac = host.mac.uppercase().trim()
            if (mac.length != 17 || mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") continue
            if (!seenMacs.add(mac)) continue

            val rule = rulesByMac[mac]
            val firstSeen = seenTimes.getOrPut(mac) { now }

            foundClients.add(
                ConnectedClient(
                    mac = mac,
                    ip = host.ip.ifBlank { "Assigning IP..." },
                    allIps = host.allIps,
                    alias = rule?.alias.orEmpty(),
                    interfaceName = host.interfaceName.ifBlank { "wlan1" },
                    firstSeenAt = firstSeen,
                    lastSeenAt = now,
                    isBlocked = rule?.isBlocked ?: false,
                    bandwidthLimitKbps = rule?.bandwidthLimitKbps ?: 0,
                    connectionTimeLimitMinutes = rule?.connectionTimeLimitMinutes ?: 0,
                    scheduleEnabled = rule?.scheduleEnabled ?: false,
                    scheduleStartHour = rule?.scheduleStartHour ?: 8,
                    scheduleEndHour = rule?.scheduleEndHour ?: 22,
                    rxBytes = host.rxBytes,
                    txBytes = host.txBytes,
                    seenPackets = host.seenPackets,
                    matchedPackets = host.matchedPackets,
                    droppedPackets = host.droppedPackets,
                    shapedBytes = host.shapedBytes,
                    policyInstalled = host.policyInstalled,
                    datapathMode = datapathMode,
                    firewallBackend = firewallBackend,
                    kernelNetfilterAvailable = kernelNetfilterAvailable,
                ),
            )
        }

        // Remove stale firstSeenAt timestamps for clients that have disconnected
        seenTimes.keys.retainAll(seenMacs)

        return foundClients
    }
}
