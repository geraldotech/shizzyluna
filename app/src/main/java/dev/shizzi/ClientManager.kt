package dev.shizzi

import java.time.ZoneId
import java.util.Calendar
import org.json.JSONArray
import org.json.JSONObject

data class ClientRule(
    val mac: String,
    val alias: String = "",
    val isBlocked: Boolean = false,
    val bandwidthLimitKbps: Int = 0, // 0 = unlimited
    val connectionTimeLimitMinutes: Int = 0, // 0 = unlimited
    val scheduleEnabled: Boolean = false,
    val scheduleStartHour: Int = 8,
    val scheduleEndHour: Int = 22,
    val dataLimitBytes: Long = 0L, // 0 = unlimited (canonical unit: bytes; 1 MB = 1,048,576 bytes)
    val quotaResetPeriod: QuotaResetPeriod = QuotaResetPeriod.MANUAL,
    val quotaUsedRxBytes: Long = 0L,
    val quotaUsedTxBytes: Long = 0L,
    val quotaWindowId: String = "",
    val quotaWindowStartEpochMs: Long = 0L,
    val quotaLastUpdatedEpochMs: Long = 0L,
    val quotaResetGeneration: Long = 0L,
) {
    val cleanMac: String get() = mac.uppercase().trim()

    val quotaUsedTotalBytes: Long
        get() = DataQuota.safeAddBytes(quotaUsedRxBytes.coerceAtLeast(0L), quotaUsedTxBytes.coerceAtLeast(0L))

    val isQuotaExceeded: Boolean
        get() = dataLimitBytes > 0L && quotaUsedTotalBytes >= dataLimitBytes

    val displayName: String
        get() = alias.ifBlank {
            val suffix = cleanMac.takeLast(5).replace(":", "")
            "Host-$suffix"
        }

    fun toQuotaRecord(): ClientQuotaRecord = ClientQuotaRecord(
        mac = cleanMac,
        dataLimitBytes = dataLimitBytes.coerceAtLeast(0L),
        resetPeriod = quotaResetPeriod,
        usedRxBytes = quotaUsedRxBytes.coerceAtLeast(0L),
        usedTxBytes = quotaUsedTxBytes.coerceAtLeast(0L),
        windowId = quotaWindowId,
        windowStartEpochMs = quotaWindowStartEpochMs.coerceAtLeast(0L),
        lastUpdatedEpochMs = quotaLastUpdatedEpochMs.coerceAtLeast(0L),
        resetGeneration = quotaResetGeneration.coerceAtLeast(0L),
    )

    fun evaluateQuotaRecord(
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): ClientQuotaRecord = DataQuota.evaluateWindowRollover(
        record = toQuotaRecord(),
        nowEpochMs = nowEpochMs,
        zoneId = zoneId,
    )

    fun withEvaluatedQuotaWindow(
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): ClientRule {
        val evaluated = evaluateQuotaRecord(nowEpochMs, zoneId)
        return copy(
            dataLimitBytes = evaluated.sanitizedLimitBytes,
            quotaUsedRxBytes = evaluated.sanitizedRxBytes,
            quotaUsedTxBytes = evaluated.sanitizedTxBytes,
            quotaWindowId = evaluated.windowId,
            quotaWindowStartEpochMs = evaluated.windowStartEpochMs,
            quotaLastUpdatedEpochMs = evaluated.lastUpdatedEpochMs,
            quotaResetGeneration = evaluated.resetGeneration,
        )
    }

    fun withResetQuotaUsage(
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): ClientRule {
        val window = DataQuota.computeWindow(quotaResetPeriod, nowEpochMs, zoneId)
        return copy(
            quotaUsedRxBytes = 0L,
            quotaUsedTxBytes = 0L,
            quotaWindowId = window.windowId,
            quotaWindowStartEpochMs = window.windowStartEpochMs.takeIf { it > 0L } ?: nowEpochMs,
            quotaLastUpdatedEpochMs = nowEpochMs,
            quotaResetGeneration = quotaResetGeneration.coerceAtLeast(0L) + 1L,
        )
    }

    fun formattedBandwidthLimit(): String = when {
        bandwidthLimitKbps <= 0 -> "Unlimited"
        bandwidthLimitKbps >= 1000 && bandwidthLimitKbps % 1000 == 0 -> "${bandwidthLimitKbps / 1000} Mbps"
        bandwidthLimitKbps >= 1000 -> String.format("%.1f Mbps", bandwidthLimitKbps / 1000.0)
        else -> "$bandwidthLimitKbps Kbps"
    }

    fun formattedDataLimit(): String =
        if (dataLimitBytes <= 0L) "Unlimited" else DataQuota.formatBytes(dataLimitBytes)

    fun toJson(): JSONObject = JSONObject().apply {
        put("mac", cleanMac)
        put("alias", alias)
        put("isBlocked", isBlocked)
        put("bandwidthLimitKbps", bandwidthLimitKbps.coerceAtLeast(0))
        put("connectionTimeLimitMinutes", connectionTimeLimitMinutes.coerceAtLeast(0))
        put("scheduleEnabled", scheduleEnabled)
        put("scheduleStartHour", scheduleStartHour.coerceIn(0, 23))
        put("scheduleEndHour", scheduleEndHour.coerceIn(0, 23))
        put("dataLimitBytes", dataLimitBytes.coerceAtLeast(0L))
        put("quotaResetPeriod", quotaResetPeriod.name)
        put("quotaUsedRxBytes", quotaUsedRxBytes.coerceAtLeast(0L))
        put("quotaUsedTxBytes", quotaUsedTxBytes.coerceAtLeast(0L))
        put("quotaWindowId", quotaWindowId)
        put("quotaWindowStartEpochMs", quotaWindowStartEpochMs.coerceAtLeast(0L))
        put("quotaLastUpdatedEpochMs", quotaLastUpdatedEpochMs.coerceAtLeast(0L))
        put("quotaResetGeneration", quotaResetGeneration.coerceAtLeast(0L))
    }

    companion object {
        fun fromJson(json: JSONObject): ClientRule = ClientRule(
            mac = json.optString("mac").uppercase().trim(),
            alias = json.optString("alias"),
            isBlocked = json.optBoolean("isBlocked", false),
            bandwidthLimitKbps = json.optInt("bandwidthLimitKbps", 0).coerceAtLeast(0),
            connectionTimeLimitMinutes = json.optInt("connectionTimeLimitMinutes", 0).coerceAtLeast(0),
            scheduleEnabled = json.optBoolean("scheduleEnabled", false),
            scheduleStartHour = json.optInt("scheduleStartHour", 8).coerceIn(0, 23),
            scheduleEndHour = json.optInt("scheduleEndHour", 22).coerceIn(0, 23),
            dataLimitBytes = json.optLong("dataLimitBytes", 0L).coerceAtLeast(0L),
            quotaResetPeriod = QuotaResetPeriod.fromName(
                if (json.has("quotaResetPeriod")) json.optString("quotaResetPeriod") else null,
            ),
            quotaUsedRxBytes = json.optLong("quotaUsedRxBytes", 0L).coerceAtLeast(0L),
            quotaUsedTxBytes = json.optLong("quotaUsedTxBytes", 0L).coerceAtLeast(0L),
            quotaWindowId = json.optString("quotaWindowId", ""),
            quotaWindowStartEpochMs = json.optLong("quotaWindowStartEpochMs", 0L).coerceAtLeast(0L),
            quotaLastUpdatedEpochMs = json.optLong("quotaLastUpdatedEpochMs", 0L).coerceAtLeast(0L),
            quotaResetGeneration = json.optLong("quotaResetGeneration", 0L).coerceAtLeast(0L),
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
    val dataLimitBytes: Long = 0L, // 0 = unlimited
    val quotaResetPeriod: QuotaResetPeriod = QuotaResetPeriod.MANUAL,
    val quotaUsedRxBytes: Long = 0L,
    val quotaUsedTxBytes: Long = 0L,
    val quotaWindowId: String = "",
    val quotaWindowStartEpochMs: Long = 0L,
    val quotaLastUpdatedEpochMs: Long = 0L,
    val quotaResetGeneration: Long = 0L,
    val quotaDropPackets: Long = 0L,
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val seenPackets: Long = 0,
    val matchedPackets: Long = 0,
    val droppedPackets: Long = 0,
    val blockedDropPackets: Long = 0,
    val shapingDropPackets: Long = 0,
    val policyVersionBlockedDrops: Long = -1L,
    val shapedBytes: Long = 0,
    val policyInstalled: Boolean = false,
    val unattributedPostNatObserved: Boolean = false,
    val mappingSource: String = "softap_dump+downstream_neigh",
    val directAttributedPackets: Long = 0,
    val bpfAttributedPackets: Long = 0,
    val policyVersion: Long = 1L,
    val datapathMode: DatapathMode = DatapathMode.INACTIVE,
    val firewallBackend: FirewallBackend = FirewallBackend.NONE,
    val kernelNetfilterAvailable: Boolean = false,
) {
    val cleanMac: String get() = mac.uppercase().trim()

    val displayName: String
        get() = alias.ifBlank {
            val suffix = cleanMac.takeLast(5).replace(":", "")
            "Host-$suffix"
        }

    fun effectiveQuotaRecord(
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): ClientQuotaRecord = DataQuota.evaluateWindowRollover(
        record = ClientQuotaRecord(
            mac = cleanMac,
            dataLimitBytes = dataLimitBytes.coerceAtLeast(0L),
            resetPeriod = quotaResetPeriod,
            usedRxBytes = quotaUsedRxBytes.coerceAtLeast(0L),
            usedTxBytes = quotaUsedTxBytes.coerceAtLeast(0L),
            windowId = quotaWindowId,
            windowStartEpochMs = quotaWindowStartEpochMs.coerceAtLeast(0L),
            lastUpdatedEpochMs = quotaLastUpdatedEpochMs.coerceAtLeast(0L),
            resetGeneration = quotaResetGeneration.coerceAtLeast(0L),
        ),
        nowEpochMs = nowEpochMs,
        zoneId = zoneId,
    )

    val quotaUsedTotalBytes: Long
        get() = effectiveQuotaRecord().usedTotalBytes

    val isQuotaExceeded: Boolean
        get() = effectiveQuotaRecord().isQuotaExceeded

    fun isRestricted(
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): Pair<Boolean, String?> {
        if (isBlocked) {
            return true to "Blocked by admin"
        }
        val quota = effectiveQuotaRecord(nowEpochMs, zoneId)
        if (quota.isQuotaExceeded) {
            return true to "Data limit reached"
        }
        if (connectionTimeLimitMinutes > 0) {
            val elapsedMinutes = (nowEpochMs - firstSeenAt) / 60_000
            if (elapsedMinutes >= connectionTimeLimitMinutes) {
                return true to "Time limit reached ($connectionTimeLimitMinutes min)"
            }
        }
        if (scheduleEnabled) {
            val cal = Calendar.getInstance( java.util.TimeZone.getTimeZone(zoneId)).apply {
                timeInMillis = nowEpochMs
            }
            val currentHour = cal.get(Calendar.HOUR_OF_DAY)
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

    val effectivePolicyVersionDrops: Long
        get() = if (policyVersionBlockedDrops >= 0L) {
            policyVersionBlockedDrops
        } else if (blockedDropPackets > 0L || shapingDropPackets > 0L) {
            blockedDropPackets
        } else {
            droppedPackets
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
                blockedDropPackets = if (blockedDropPackets > 0L) blockedDropPackets else effectivePolicyVersionDrops,
                shapingDropPackets = shapingDropPackets,
                shapedPackets = if (shapedBytes > 0L) 1L else 0L,
                rxBytes = rxBytes,
                txBytes = txBytes,
                droppedBytes = 0L,
                shapedBytes = shapedBytes,
                policyInstalled = policyInstalled,
                policyVersion = policyVersion,
                policyVersionBlockedDrops = effectivePolicyVersionDrops,
                unattributedPostNatObserved = unattributedPostNatObserved,
                directAttributedPackets = directAttributedPackets,
                bpfAttributedPackets = bpfAttributedPackets,
                quotaDropPackets = quotaDropPackets,
                quotaUsedRxBytes = quotaUsedRxBytes,
                quotaUsedTxBytes = quotaUsedTxBytes,
                quotaWindowId = quotaWindowId,
                quotaWindowStartEpochMs = quotaWindowStartEpochMs,
                quotaLastUpdatedEpochMs = quotaLastUpdatedEpochMs,
            )
            return HostFirewall.computeClientEnforcementState(
                isRestricted = restricted,
                bandwidthLimitKbps = bandwidthLimitKbps,
                counters = snapshot,
                datapathMode = datapathMode,
                kernelAvailable = kernelNetfilterAvailable,
                isDegradedMultiClient = unattributedPostNatObserved,
            )
        }

    fun formattedBlockStatusLabel(): String {
        val (restricted, reason) = isRestricted()
        if (!restricted) return "Connected (${formattedUptime()})"
        val reasonPrefix = reason ?: "Blocked"
        return when (enforcementState) {
            EnforcementState.PACKETS_DROPPED ->
                "$reasonPrefix (verified • $effectivePolicyVersionDrops pkts dropped in policy v$policyVersion)"
            EnforcementState.PARTIAL_BPF_ENFORCEMENT ->
                "$reasonPrefix • Partial enforcement ($effectivePolicyVersionDrops BPF-mapped pkts dropped; initial/unknown flows possible)"
            EnforcementState.PACKETS_MATCHED,
            EnforcementState.POLICY_INSTALLED,
            -> "$reasonPrefix (policy active • awaiting mapped traffic)"
            EnforcementState.DEGRADED_MULTI_CLIENT ->
                "$reasonPrefix — degraded (post-NAT traffic unattributed; enable Experimental BPF or run Diagnostic)"
            EnforcementState.ENFORCEMENT_UNAVAILABLE ->
                "$reasonPrefix — not enforced (direct-TUN fallback)"
            else ->
                "$reasonPrefix — syncing policy"
        }
    }

    fun formattedBandwidthBadgeLabel(isCurrentlyConnected: Boolean): String {
        val cap = formattedBandwidthLimit()
        if (!isCurrentlyConnected) return "Cap: $cap (saved)"
        return when (enforcementState) {
            EnforcementState.THROTTLING_OBSERVED ->
                "Cap: $cap (shaped • ${Traffic.format(shapedBytes)})"
            EnforcementState.PARTIAL_BPF_ENFORCEMENT ->
                "Cap: $cap (partial BPF • ${Traffic.format(shapedBytes)} shaped)"
            EnforcementState.PACKETS_MATCHED ->
                "Cap: $cap (matched • $matchedPackets pkts)"
            EnforcementState.POLICY_INSTALLED,
            EnforcementState.DATAPATH_ACTIVE,
            -> "Cap: $cap (requested • policy active)"
            EnforcementState.DEGRADED_MULTI_CLIENT ->
                "Cap: $cap — degraded (post-NAT unattributed)"
            EnforcementState.ENFORCEMENT_UNAVAILABLE ->
                "Cap: $cap — not enforced"
            else -> "Cap: $cap (configured)"
        }
    }

    fun formattedQuotaBadgeLabel(isCurrentlyConnected: Boolean): String {
        val quota = effectiveQuotaRecord()
        if (!quota.isQuotaEnabled) return "Data: Unlimited"
        val usageRatio = DataQuota.formatUsageSummary(quota.usedTotalBytes, quota.sanitizedLimitBytes)
        val pct = "${quota.usagePercent}%"
        val remaining = "${DataQuota.formatBytes(quota.remainingBytes)} left"
        val statusSuffix = when {
            !isCurrentlyConnected -> if (quota.isQuotaExceeded) "Data limit reached • saved" else "$remaining • saved"
            quota.isQuotaExceeded -> when (enforcementState) {
                EnforcementState.PACKETS_DROPPED,
                EnforcementState.PARTIAL_BPF_ENFORCEMENT,
                -> "Data limit reached • enforced"
                EnforcementState.DEGRADED_MULTI_CLIENT,
                EnforcementState.ENFORCEMENT_UNAVAILABLE,
                -> "Data limit reached — Usage may be incomplete"
                else -> "Data limit reached • policy active"
            }
            enforcementState == EnforcementState.DEGRADED_MULTI_CLIENT ||
                enforcementState == EnforcementState.ENFORCEMENT_UNAVAILABLE ||
                datapathMode != DatapathMode.USERSPACE_PROXY ->
                "$remaining • configured (Usage may be incomplete)"
            policyInstalled -> "$remaining • enforced (${quota.resetPeriod.displayName})"
            else -> "$remaining • configured (${quota.resetPeriod.displayName})"
        }
        return "Quota: $usageRatio ($pct • $statusSuffix)"
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

            val rawRule = rulesByMac[mac]
            val rule = rawRule?.withEvaluatedQuotaWindow(now)
            val firstSeen = seenTimes.getOrPut(mac) { now }

            val ruleWindowId = rule?.quotaWindowId.orEmpty()
            val hostWindowId = host.quotaWindowId
            val sameWindow = hostWindowId.isEmpty() || ruleWindowId.isEmpty() || hostWindowId == ruleWindowId
            val mergedQuotaRx = if (sameWindow) {
                maxOf(rule?.quotaUsedRxBytes ?: 0L, host.quotaUsedRxBytes)
            } else {
                host.quotaUsedRxBytes
            }
            val mergedQuotaTx = if (sameWindow) {
                maxOf(rule?.quotaUsedTxBytes ?: 0L, host.quotaUsedTxBytes)
            } else {
                host.quotaUsedTxBytes
            }
            val effectiveWindowId = hostWindowId.ifBlank { ruleWindowId }
            val effectiveWindowStart = maxOf(rule?.quotaWindowStartEpochMs ?: 0L, host.quotaWindowStartEpochMs)
            val effectiveLastUpdated = maxOf(rule?.quotaLastUpdatedEpochMs ?: 0L, host.quotaLastUpdatedEpochMs)

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
                    dataLimitBytes = rule?.dataLimitBytes ?: 0L,
                    quotaResetPeriod = rule?.quotaResetPeriod ?: QuotaResetPeriod.MANUAL,
                    quotaUsedRxBytes = mergedQuotaRx,
                    quotaUsedTxBytes = mergedQuotaTx,
                    quotaWindowId = effectiveWindowId,
                    quotaWindowStartEpochMs = effectiveWindowStart,
                    quotaLastUpdatedEpochMs = effectiveLastUpdated,
                    quotaResetGeneration = rule?.quotaResetGeneration ?: 0L,
                    quotaDropPackets = host.quotaDropPackets,
                    rxBytes = maxOf(host.rxBytes, mergedQuotaRx),
                    txBytes = maxOf(host.txBytes, mergedQuotaTx),
                    seenPackets = host.seenPackets,
                    matchedPackets = host.matchedPackets,
                    droppedPackets = host.droppedPackets,
                    blockedDropPackets = host.blockedDropPackets,
                    shapingDropPackets = host.shapingDropPackets,
                    policyVersionBlockedDrops = host.policyVersionBlockedDrops,
                    shapedBytes = host.shapedBytes,
                    policyInstalled = host.policyInstalled,
                    unattributedPostNatObserved = host.unattributedPostNatObserved,
                    mappingSource = host.mappingSource,
                    directAttributedPackets = host.directAttributedPackets,
                    bpfAttributedPackets = host.bpfAttributedPackets,
                    policyVersion = host.policyVersion,
                    datapathMode = datapathMode,
                    firewallBackend = firewallBackend,
                    kernelNetfilterAvailable = kernelNetfilterAvailable,
                ),
            )
        }

        seenTimes.keys.retainAll(seenMacs)

        return foundClients
    }
}
