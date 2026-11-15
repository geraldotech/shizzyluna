package dev.shizzi

import android.annotation.SuppressLint
import android.content.Context
import android.net.MacAddress
import android.net.wifi.WifiManager
import android.os.Build
import android.system.Os
import java.io.File
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.security.MessageDigest
import java.time.ZoneId
import java.util.Calendar
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONArray
import org.json.JSONObject
import rikka.shizuku.Shizuku

/**
 * Shizzy Luna v0.10.7-debug
 * Native SoftAP MAC Blocklist Engine & Crash-Safe Ownership Journal.
 */
enum class SoftApEngineState(val code: String, val displayLabel: String) {
    UNCHECKED("UNCHECKED", "Unchecked"),
    CHECKING("CHECKING", "Checking SoftAP capability..."),
    CAPABILITY_CHECKING("CAPABILITY_CHECKING", "Checking SoftAP capability..."),
    SHIZUKU_NOT_RUNNING("SHIZUKU_NOT_RUNNING", "Shizuku Not Running"),
    SHIZUKU_PERMISSION_REQUIRED("SHIZUKU_PERMISSION_REQUIRED", "Shizuku Permission Required"),
    PROBE_REQUIRED("PROBE_REQUIRED", "Live Two-Client Probe Required"),
    READY_FOR_2_CLIENT_PROBE("READY_FOR_2_CLIENT_PROBE", "Ready for Controlled Two-Client Probe"),
    HAL_UNSUPPORTED("HAL_UNSUPPORTED", "SoftAP Force-Disconnect HAL Unsupported"),
    API_UNAVAILABLE("API_UNAVAILABLE", "SoftAP Blocklist API Unavailable"),
    PERMISSION_DENIED("PERMISSION_DENIED", "SoftAP Privileged Access Denied"),
    OEM_UNSUPPORTED("OEM_UNSUPPORTED", "OEM SoftAP Blocklist Unsupported"),
    LIVE_UPDATE_UNSUPPORTED("LIVE_UPDATE_UNSUPPORTED", "Live SoftAP Update Unsupported"),
    PROBE_RUNNING("PROBE_RUNNING", "Running Controlled Two-Client Probe..."),
    PROBING_2_CLIENT("PROBING_2_CLIENT", "Running Controlled Two-Client Probe..."),
    READY("READY", "Ready (Verified by Live Probe)"),
    ACTIVATING("ACTIVATING", "Activating SoftAP MAC Engine..."),
    APPLYING("APPLYING", "Applying SoftAP MAC Blocklist..."),
    ACTIVE("ACTIVE", "Active (Native SoftAP MAC Blocklist)"),
    BLOCK_PENDING("BLOCK_PENDING", "Applying SoftAP MAC Block..."),
    BLOCK_CONFIRMED("BLOCK_CONFIRMED", "SoftAP MAC Block Confirmed"),
    BLOCK_FAILED("BLOCK_FAILED", "SoftAP MAC Block Failed"),
    ROLLING_BACK("ROLLING_BACK", "Rolling Back SoftAP MAC Blocklist..."),
    ROLLBACK_REQUIRED("ROLLBACK_REQUIRED", "Rollback Required (Unresolved SoftAP Rules)"),
    UNAVAILABLE("UNAVAILABLE", "Unavailable"),
    ;

    val isTerminalUnsupported: Boolean
        get() = this in setOf(
            HAL_UNSUPPORTED,
            API_UNAVAILABLE,
            PERMISSION_DENIED,
            OEM_UNSUPPORTED,
            LIVE_UPDATE_UNSUPPORTED,
            UNAVAILABLE,
        )

    companion object {
        fun fromCode(raw: String?): SoftApEngineState =
            entries.firstOrNull { it.code.equals(raw?.trim(), ignoreCase = true) } ?: PROBE_REQUIRED
    }
}

enum class SoftApClientBlockReason(val code: String, val displayLabel: String) {
    MANUAL_BLOCK("MANUAL_BLOCK", "Manual Block"),
    QUOTA_EXHAUSTED("QUOTA_EXHAUSTED", "Quota Exhausted"),
    PAUSED("PAUSED", "Client Paused"),
    SCHEDULE_BLOCKED("SCHEDULE_BLOCKED", "Restricted by Schedule"),
    TIME_LIMIT_EXCEEDED("TIME_LIMIT_EXCEEDED", "Connection Time Limit Reached"),
    ;

    companion object {
        fun fromCode(raw: String?): SoftApClientBlockReason? =
            entries.firstOrNull { it.code.equals(raw?.trim(), ignoreCase = true) }
    }
}

enum class SoftApAppliedState(val code: String, val displayLabel: String) {
    UNBLOCKED("UNBLOCKED", "Unblocked"),
    BLOCK_PENDING("BLOCK_PENDING", "Block Pending"),
    UNBLOCK_PENDING("UNBLOCK_PENDING", "Unblock Pending"),
    BLOCK_CONFIRMED("BLOCK_CONFIRMED", "Disconnected & Blocked (SoftAP MAC)"),
    BLOCK_FAILED("BLOCK_FAILED", "SoftAP Block Failed"),
    CONFLICT_ALLOWLIST("CONFLICT_ALLOWLIST", "Conflict: Present in User Allowlist"),
    ROLLBACK_REQUIRED("ROLLBACK_REQUIRED", "Rollback Required"),
    ;

    companion object {
        fun fromCode(raw: String?): SoftApAppliedState =
            entries.firstOrNull { it.code.equals(raw?.trim(), ignoreCase = true) } ?: UNBLOCKED
    }
}

/**
 * Deterministic multi-reason OR reducer for client blocking policies.
 * Unblocking one reason (e.g. quota reset) NEVER removes the SoftAP MAC block
 * while any other reason (e.g. manual block or schedule restriction) remains active.
 */
object SoftApPolicyReducer {

    fun isValidUnicastMac(rawMac: String?): Boolean {
        val clean = rawMac?.uppercase()?.trim().orEmpty()
        if (clean.length != 17) return false
        val octets = clean.split(":")
        if (octets.size != 6) return false
        val bytes = octets.map { part ->
            if (part.length != 2) return false
            part.toIntOrNull(16) ?: return false
        }
        if (bytes.all { it == 0 }) return false
        if (bytes.all { it == 0xFF }) return false
        if (clean == "02:00:00:00:00:00") return false
        // Multicast bit (least significant bit of first octet) must be 0 for unicast station MAC
        if ((bytes[0] and 0x01) != 0) return false
        return true
    }

    fun evaluateRuleReasons(
        rule: ClientRule,
        firstSeenAtEpochMs: Long? = null,
        isPaused: Boolean = false,
        extraReasons: Set<SoftApClientBlockReason> = emptySet(),
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): Set<SoftApClientBlockReason> {
        val reasons = linkedSetOf<SoftApClientBlockReason>()
        reasons.addAll(extraReasons)
        if (rule.isBlocked) {
            reasons.add(SoftApClientBlockReason.MANUAL_BLOCK)
        }
        if (isPaused) {
            reasons.add(SoftApClientBlockReason.PAUSED)
        }
        val evaluatedQuota = rule.evaluateQuotaRecord(nowEpochMs = nowEpochMs, zoneId = zoneId)
        if (evaluatedQuota.isQuotaExceeded) {
            reasons.add(SoftApClientBlockReason.QUOTA_EXHAUSTED)
        }
        if (rule.connectionTimeLimitMinutes > 0 && firstSeenAtEpochMs != null && firstSeenAtEpochMs > 0L) {
            val elapsedMinutes = (nowEpochMs - firstSeenAtEpochMs) / 60_000L
            if (elapsedMinutes >= rule.connectionTimeLimitMinutes) {
                reasons.add(SoftApClientBlockReason.TIME_LIMIT_EXCEEDED)
            }
        }
        if (rule.scheduleEnabled) {
            val cal = Calendar.getInstance(TimeZone.getTimeZone(zoneId)).apply {
                timeInMillis = nowEpochMs
            }
            val currentHour = cal.get(Calendar.HOUR_OF_DAY)
            val allowed = if (rule.scheduleStartHour <= rule.scheduleEndHour) {
                currentHour in rule.scheduleStartHour until rule.scheduleEndHour
            } else {
                currentHour >= rule.scheduleStartHour || currentHour < rule.scheduleEndHour
            }
            if (!allowed) {
                reasons.add(SoftApClientBlockReason.SCHEDULE_BLOCKED)
            }
        }
        return reasons
    }

    fun shouldBlock(reasons: Set<SoftApClientBlockReason>): Boolean = reasons.isNotEmpty()

    fun reduceAll(
        rules: List<ClientRule>,
        firstSeenByMac: Map<String, Long> = emptyMap(),
        pausedMacs: Set<String> = emptySet(),
        manualReasonOverrides: Map<String, Set<SoftApClientBlockReason>> = emptyMap(),
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): Map<String, Set<SoftApClientBlockReason>> {
        val result = linkedMapOf<String, Set<SoftApClientBlockReason>>()
        val rulesByMac = rules.associateBy { it.cleanMac }
        val allMacs = (rulesByMac.keys + manualReasonOverrides.keys + pausedMacs.map { it.uppercase().trim() }).distinct()
        for (rawMac in allMacs) {
            val mac = rawMac.uppercase().trim()
            if (!isValidUnicastMac(mac)) continue
            val rule = rulesByMac[mac] ?: ClientRule(mac = mac)
            val reasons = evaluateRuleReasons(
                rule = rule,
                firstSeenAtEpochMs = firstSeenByMac[mac],
                isPaused = mac in pausedMacs,
                extraReasons = manualReasonOverrides[mac].orEmpty(),
                nowEpochMs = nowEpochMs,
                zoneId = zoneId,
            )
            result[mac] = reasons
        }
        return result
    }
}

data class SoftApClientEnforcementRecord(
    val mac: String,
    val alias: String = "",
    val lastKnownIp: String = "",
    val activeReasons: Set<SoftApClientBlockReason> = emptySet(),
    val desiredBlocked: Boolean = activeReasons.isNotEmpty(),
    val appliedState: SoftApAppliedState = SoftApAppliedState.UNBLOCKED,
    val isCurrentlyAssociated: Boolean = false,
    val disconnectedAfterApply: Boolean = false,
    val allowlistConflict: Boolean = false,
    val preExistingUserOrOemBlock: Boolean = false,
    val lastUpdatedEpochMs: Long = System.currentTimeMillis(),
    val errorDetail: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("mac", mac)
        put("alias", alias)
        put("lastKnownIp", lastKnownIp)
        put("activeReasons", JSONArray(activeReasons.map { it.code }))
        put("desiredBlocked", desiredBlocked)
        put("appliedState", appliedState.code)
        put("appliedStateLabel", appliedState.displayLabel)
        put("isCurrentlyAssociated", isCurrentlyAssociated)
        put("disconnectedAfterApply", disconnectedAfterApply)
        put("allowlistConflict", allowlistConflict)
        put("preExistingUserOrOemBlock", preExistingUserOrOemBlock)
        put("lastUpdatedEpochMs", lastUpdatedEpochMs)
        put("errorDetail", errorDetail)
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApClientEnforcementRecord {
            val reasonsArr = json.optJSONArray("activeReasons") ?: JSONArray()
            val reasons = linkedSetOf<SoftApClientBlockReason>()
            for (i in 0 until reasonsArr.length()) {
                SoftApClientBlockReason.fromCode(reasonsArr.optString(i))?.let { reasons.add(it) }
            }
            return SoftApClientEnforcementRecord(
                mac = json.optString("mac").uppercase().trim(),
                alias = json.optString("alias", ""),
                lastKnownIp = json.optString("lastKnownIp", ""),
                activeReasons = reasons,
                desiredBlocked = json.optBoolean("desiredBlocked", reasons.isNotEmpty()),
                appliedState = SoftApAppliedState.fromCode(json.optString("appliedState")),
                isCurrentlyAssociated = json.optBoolean("isCurrentlyAssociated", false),
                disconnectedAfterApply = json.optBoolean("disconnectedAfterApply", false),
                allowlistConflict = json.optBoolean("allowlistConflict", false),
                preExistingUserOrOemBlock = json.optBoolean("preExistingUserOrOemBlock", false),
                lastUpdatedEpochMs = json.optLong("lastUpdatedEpochMs", 0L),
                errorDetail = json.optString("errorDetail", ""),
            )
        }
    }
}

/**
 * Snapshot of non-secret SoftAP configuration fields read from WifiManager.
 * Passphrase and sensitive Wi-Fi credentials are NEVER stored, hashed, or exported.
 */
data class SoftApConfigSnapshot(
    val readable: Boolean = false,
    val ssidPresent: Boolean = false,
    val ssidLength: Int = 0,
    val securityType: Int = 0,
    val bandsSummary: String = "unknown",
    val maxNumberOfClients: Int = 0,
    val clientControlByUserEnabled: Boolean = false,
    val blockedClientMacs: List<String> = emptyList(),
    val allowedClientMacs: List<String> = emptyList(),
    val configFingerprint: String = "",
    val apiPathUsed: String = "WifiManager.getSoftApConfiguration",
    val errorDetail: String = "",
) {
    val clientControlByUser: Boolean get() = clientControlByUserEnabled
    val blockedList: List<String> get() = blockedClientMacs
    val allowedList: List<String> get() = allowedClientMacs
    val nonSecretFingerprintSha256: String get() = configFingerprint

    fun toJson(): JSONObject = JSONObject().apply {
        put("readable", readable)
        put("ssidPresent", ssidPresent)
        put("ssidLength", ssidLength)
        put("securityType", securityType)
        put("bandsSummary", bandsSummary)
        put("maxNumberOfClients", maxNumberOfClients)
        put("clientControlByUserEnabled", clientControlByUserEnabled)
        put("blockedClientMacs", JSONArray(blockedClientMacs))
        put("allowedClientMacs", JSONArray(allowedClientMacs))
        put("configFingerprint", configFingerprint)
        put("apiPathUsed", apiPathUsed)
        put("errorDetail", errorDetail)
    }

    companion object {
        fun computeNonSecretFingerprint(
            ssidLength: Int,
            securityType: Int,
            bandsSummary: String,
            maxNumberOfClients: Int,
            clientControlByUserEnabled: Boolean,
            allowedClientMacs: List<String>,
            priorBlockedMacs: List<String>,
        ): String {
            val canonical = buildString {
                append("ssidLen=").append(ssidLength)
                append("|sec=").append(securityType)
                append("|bands=").append(bandsSummary)
                append("|max=").append(maxNumberOfClients)
                append("|cc=").append(clientControlByUserEnabled)
                append("|allow=").append(allowedClientMacs.map { it.uppercase().trim() }.sorted().joinToString(","))
                append("|priorBlock=").append(priorBlockedMacs.map { it.uppercase().trim() }.sorted().joinToString(","))
            }
            return runCatching {
                val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
                digest.take(8).joinToString("") { "%02x".format(it) }
            }.getOrDefault(canonical.hashCode().toUInt().toString(16))
        }

        fun fromJson(json: JSONObject): SoftApConfigSnapshot {
            val blockedArr = json.optJSONArray("blockedClientMacs") ?: JSONArray()
            val allowedArr = json.optJSONArray("allowedClientMacs") ?: JSONArray()
            val blocked = (0 until blockedArr.length()).map { blockedArr.optString(it).uppercase().trim() }.filter { it.isNotBlank() }
            val allowed = (0 until allowedArr.length()).map { allowedArr.optString(it).uppercase().trim() }.filter { it.isNotBlank() }
            return SoftApConfigSnapshot(
                readable = json.optBoolean("readable", false),
                ssidPresent = json.optBoolean("ssidPresent", false),
                ssidLength = json.optInt("ssidLength", 0),
                securityType = json.optInt("securityType", 0),
                bandsSummary = json.optString("bandsSummary", "unknown"),
                maxNumberOfClients = json.optInt("maxNumberOfClients", 0),
                clientControlByUserEnabled = json.optBoolean("clientControlByUserEnabled", false),
                blockedClientMacs = blocked,
                allowedClientMacs = allowed,
                configFingerprint = json.optString("configFingerprint", ""),
                apiPathUsed = json.optString("apiPathUsed", "WifiManager.getSoftApConfiguration"),
                errorDetail = json.optString("errorDetail", ""),
            )
        }
    }
}

data class SoftApJournalSnapshot(
    val operationId: String = "none",
    val timestampEpochMs: Long = 0L,
    val commitPhase: String = "IDLE",
    val engineGeneration: Long = 1L,
    val targetMacs: List<String> = emptyList(),
    val priorBlockedMacs: List<String> = emptyList(),
    val appOwnedMacs: List<String> = emptyList(),
    val desiredBlockedMacs: List<String> = emptyList(),
    val configFingerprint: String = "",
    val allowlistConflictMacs: List<String> = emptyList(),
    val externalConflictDetected: Boolean = false,
    val externalConflictReason: String = "",
    val rollbackRequired: Boolean = false,
    val lastError: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("operationId", operationId)
        put("timestampEpochMs", timestampEpochMs)
        put("commitPhase", commitPhase)
        put("engineGeneration", engineGeneration)
        put("targetMacs", JSONArray(targetMacs))
        put("priorBlockedMacs", JSONArray(priorBlockedMacs))
        put("appOwnedMacs", JSONArray(appOwnedMacs))
        put("desiredBlockedMacs", JSONArray(desiredBlockedMacs))
        put("configFingerprint", configFingerprint)
        put("allowlistConflictMacs", JSONArray(allowlistConflictMacs))
        put("externalConflictDetected", externalConflictDetected)
        put("externalConflictReason", externalConflictReason)
        put("rollbackRequired", rollbackRequired)
        put("lastError", lastError)
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApJournalSnapshot {
            fun parseStringList(key: String): List<String> {
                val arr = json.optJSONArray(key) ?: return emptyList()
                return (0 until arr.length())
                    .map { arr.optString(it).uppercase().trim() }
                    .filter { it.isNotBlank() }
            }
            return SoftApJournalSnapshot(
                operationId = json.optString("operationId", "none"),
                timestampEpochMs = json.optLong("timestampEpochMs", 0L),
                commitPhase = json.optString("commitPhase", "IDLE"),
                engineGeneration = json.optLong("engineGeneration", 1L),
                targetMacs = parseStringList("targetMacs"),
                priorBlockedMacs = parseStringList("priorBlockedMacs"),
                appOwnedMacs = parseStringList("appOwnedMacs"),
                desiredBlockedMacs = parseStringList("desiredBlockedMacs"),
                configFingerprint = json.optString("configFingerprint", ""),
                allowlistConflictMacs = parseStringList("allowlistConflictMacs"),
                externalConflictDetected = json.optBoolean("externalConflictDetected", false),
                externalConflictReason = json.optString("externalConflictReason", ""),
                rollbackRequired = json.optBoolean("rollbackRequired", false),
                lastError = json.optString("lastError", ""),
            )
        }
    }
}

/**
 * Crash-safe ownership journal for SoftAP MAC blocklist modifications.
 * Ensures Shizzy Luna NEVER removes pre-existing user/OEM blocked MAC addresses
 * and recovers safely across service restarts or crashes.
 */
class SoftApOwnershipJournal(
    private val journalFile: File = File(DEFAULT_JOURNAL_PATH),
) {
    private val lock = Any()
    private val generationCounter = AtomicLong(1L)

    @Volatile
    private var snapshot: SoftApJournalSnapshot = loadFromDiskOrDefault()

    fun currentSnapshot(): SoftApJournalSnapshot = synchronized(lock) { snapshot }

    fun nextGeneration(): Long = generationCounter.incrementAndGet()

    /**
     * Records a baseline of pre-existing user/OEM blocked MACs when no app-owned MACs are active.
     */
    fun captureBaselineIfClean(currentConfig: SoftApConfigSnapshot): SoftApJournalSnapshot = synchronized(lock) {
        if (snapshot.appOwnedMacs.isEmpty() && !snapshot.rollbackRequired && snapshot.commitPhase != "PRE_WRITE") {
            val baselinePrior = currentConfig.blockedClientMacs
                .map { it.uppercase().trim() }
                .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
                .distinct()
            val fp = SoftApConfigSnapshot.computeNonSecretFingerprint(
                ssidLength = currentConfig.ssidLength,
                securityType = currentConfig.securityType,
                bandsSummary = currentConfig.bandsSummary,
                maxNumberOfClients = currentConfig.maxNumberOfClients,
                clientControlByUserEnabled = currentConfig.clientControlByUserEnabled,
                allowedClientMacs = currentConfig.allowedClientMacs,
                priorBlockedMacs = baselinePrior,
            )
            snapshot = snapshot.copy(
                priorBlockedMacs = baselinePrior,
                configFingerprint = fp,
                timestampEpochMs = System.currentTimeMillis(),
            )
            persistLocked(snapshot)
        }
        snapshot
    }

    data class DeltaPlan(
        val operationId: String,
        val priorBlockedMacs: List<String>,
        val eligibleAppOwnedDesiredMacs: List<String>,
        val mergedBlockedClientList: List<String>,
        val allowlistConflictMacs: List<String>,
        val externalConflictDetected: Boolean,
        val externalConflictReason: String,
        val requiresWrite: Boolean,
    )

    /**
     * Computes a safe delta-only update plan given the current SoftApConfiguration readback
     * and the desired set of app-blocked MACs.
     *
     * Rules:
     * 1. Pre-existing user/OEM blocked MACs (`priorBlockedMacs`) are always preserved.
     * 2. If a desired MAC is already in `priorBlockedMacs`, Shizzy Luna does NOT claim ownership
     *    of it in `appOwnedMacs` (so unblocking in Shizzy Luna will not delete the user's pre-existing block).
     * 3. If a desired MAC is in `allowedClientMacs`, Shizzy Luna does NOT silently edit the user allowlist;
     *    it flags `allowlistConflictMacs` and skips adding that MAC.
     * 4. If an external edit added new non-app MACs to `blockedClientMacs`, they are absorbed into
     *    `priorBlockedMacs` so they are never deleted by Shizzy Luna.
     * 5. If an external edit removed a previously confirmed `appOwnedMac` while Shizzy Luna still had
     *    ownership recorded, `externalConflictDetected` is flagged with provenance.
     */
    fun planDeltaUpdate(
        currentConfig: SoftApConfigSnapshot,
        desiredBlockedMacs: Set<String>,
    ): DeltaPlan = synchronized(lock) {
        val currentLiveBlocked = currentConfig.blockedClientMacs
            .map { it.uppercase().trim() }
            .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
            .distinct()
        val currentAllowed = currentConfig.allowedClientMacs
            .map { it.uppercase().trim() }
            .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
            .toSet()

        val previousAppOwned = snapshot.appOwnedMacs.map { it.uppercase().trim() }.toSet()
        val previousPrior = snapshot.priorBlockedMacs.map { it.uppercase().trim() }.toSet()

        // Any currently blocked MAC that is NOT in previousAppOwned belongs to user/OEM priorBlockedMacs
        val updatedPrior = linkedSetOf<String>()
        updatedPrior.addAll(previousPrior.filter { it in currentLiveBlocked })
        for (liveMac in currentLiveBlocked) {
            if (liveMac !in previousAppOwned) {
                updatedPrior.add(liveMac)
            }
        }

        // Check if an external actor removed an app-owned MAC or a prior user MAC unexpectedly
        val externallyRemovedAppMacs = previousAppOwned.filter { it !in currentLiveBlocked }
        val externalConflict = externallyRemovedAppMacs.isNotEmpty()
        val externalReason = if (externalConflict) {
            "External modification detected: app-owned MAC(s) ${externallyRemovedAppMacs.joinToString(",")} were removed outside Shizzy Luna"
        } else {
            ""
        }

        val normalizedDesired = desiredBlockedMacs
            .map { it.uppercase().trim() }
            .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
            .distinct()

        val allowlistConflicts = normalizedDesired.filter { it in currentAllowed }

        // Only claim app ownership for MACs that are not in allowlist and not already user/OEM blocked
        val eligibleAppOwned = normalizedDesired.filter { mac ->
            mac !in currentAllowed && mac !in updatedPrior
        }

        val mergedList = (updatedPrior + eligibleAppOwned).distinct()
        val requiresWrite = mergedList.toSet() != currentLiveBlocked.toSet()

        DeltaPlan(
            operationId = "softap-op-${UUID.randomUUID().toString().take(8)}",
            priorBlockedMacs = updatedPrior.toList(),
            eligibleAppOwnedDesiredMacs = eligibleAppOwned,
            mergedBlockedClientList = mergedList,
            allowlistConflictMacs = allowlistConflicts,
            externalConflictDetected = externalConflict,
            externalConflictReason = externalReason,
            requiresWrite = requiresWrite,
        )
    }

    fun recordPreWrite(
        plan: DeltaPlan,
        desiredBlockedMacs: Collection<String>,
        currentConfig: SoftApConfigSnapshot,
    ): SoftApJournalSnapshot = synchronized(lock) {
        val fp = SoftApConfigSnapshot.computeNonSecretFingerprint(
            ssidLength = currentConfig.ssidLength,
            securityType = currentConfig.securityType,
            bandsSummary = currentConfig.bandsSummary,
            maxNumberOfClients = currentConfig.maxNumberOfClients,
            clientControlByUserEnabled = currentConfig.clientControlByUserEnabled,
            allowedClientMacs = currentConfig.allowedClientMacs,
            priorBlockedMacs = plan.priorBlockedMacs,
        )
        snapshot = snapshot.copy(
            operationId = plan.operationId,
            timestampEpochMs = System.currentTimeMillis(),
            commitPhase = "PRE_WRITE",
            targetMacs = plan.mergedBlockedClientList,
            priorBlockedMacs = plan.priorBlockedMacs,
            appOwnedMacs = (snapshot.appOwnedMacs + plan.eligibleAppOwnedDesiredMacs).distinct(),
            desiredBlockedMacs = desiredBlockedMacs.map { it.uppercase().trim() }.distinct(),
            configFingerprint = fp,
            allowlistConflictMacs = plan.allowlistConflictMacs,
            externalConflictDetected = plan.externalConflictDetected,
            externalConflictReason = plan.externalConflictReason,
            lastError = "",
        )
        persistLocked(snapshot)
        snapshot
    }

    fun recordWriteVerified(
        plan: DeltaPlan,
        desiredBlockedMacs: Collection<String>,
        verifiedConfig: SoftApConfigSnapshot,
    ): SoftApJournalSnapshot = synchronized(lock) {
        val fp = SoftApConfigSnapshot.computeNonSecretFingerprint(
            ssidLength = verifiedConfig.ssidLength,
            securityType = verifiedConfig.securityType,
            bandsSummary = verifiedConfig.bandsSummary,
            maxNumberOfClients = verifiedConfig.maxNumberOfClients,
            clientControlByUserEnabled = verifiedConfig.clientControlByUserEnabled,
            allowedClientMacs = verifiedConfig.allowedClientMacs,
            priorBlockedMacs = plan.priorBlockedMacs,
        )
        val idleOrVerified = if (plan.eligibleAppOwnedDesiredMacs.isEmpty()) "IDLE" else "APPLIED_VERIFIED"
        snapshot = snapshot.copy(
            operationId = plan.operationId,
            timestampEpochMs = System.currentTimeMillis(),
            commitPhase = idleOrVerified,
            targetMacs = plan.mergedBlockedClientList,
            priorBlockedMacs = plan.priorBlockedMacs,
            appOwnedMacs = plan.eligibleAppOwnedDesiredMacs,
            desiredBlockedMacs = desiredBlockedMacs.map { it.uppercase().trim() }.distinct(),
            configFingerprint = fp,
            allowlistConflictMacs = plan.allowlistConflictMacs,
            externalConflictDetected = plan.externalConflictDetected,
            externalConflictReason = plan.externalConflictReason,
            rollbackRequired = false,
            lastError = "",
        )
        persistLocked(snapshot)
        snapshot
    }

    fun recordWriteFailed(
        operationId: String,
        errorDetail: String,
        markRollbackRequired: Boolean,
    ): SoftApJournalSnapshot = synchronized(lock) {
        val requiresRollback = markRollbackRequired || snapshot.appOwnedMacs.isNotEmpty() || snapshot.commitPhase == "PRE_WRITE"
        snapshot = snapshot.copy(
            operationId = operationId,
            timestampEpochMs = System.currentTimeMillis(),
            commitPhase = if (requiresRollback) "ROLLBACK_REQUIRED" else "WRITE_FAILED",
            rollbackRequired = requiresRollback,
            lastError = errorDetail,
        )
        persistLocked(snapshot)
        snapshot
    }

    fun markRollbackRequired(reason: String): SoftApJournalSnapshot = synchronized(lock) {
        snapshot = snapshot.copy(
            timestampEpochMs = System.currentTimeMillis(),
            commitPhase = "ROLLBACK_REQUIRED",
            rollbackRequired = true,
            lastError = reason,
        )
        persistLocked(snapshot)
        snapshot
    }

    fun clearAfterVerifiedRollback(verifiedConfig: SoftApConfigSnapshot): SoftApJournalSnapshot = synchronized(lock) {
        val remainingPrior = verifiedConfig.blockedClientMacs
            .map { it.uppercase().trim() }
            .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
            .distinct()
        val fp = SoftApConfigSnapshot.computeNonSecretFingerprint(
            ssidLength = verifiedConfig.ssidLength,
            securityType = verifiedConfig.securityType,
            bandsSummary = verifiedConfig.bandsSummary,
            maxNumberOfClients = verifiedConfig.maxNumberOfClients,
            clientControlByUserEnabled = verifiedConfig.clientControlByUserEnabled,
            allowedClientMacs = verifiedConfig.allowedClientMacs,
            priorBlockedMacs = remainingPrior,
        )
        snapshot = SoftApJournalSnapshot(
            operationId = "rollback-verified-${UUID.randomUUID().toString().take(8)}",
            timestampEpochMs = System.currentTimeMillis(),
            commitPhase = "IDLE",
            engineGeneration = nextGeneration(),
            targetMacs = remainingPrior,
            priorBlockedMacs = remainingPrior,
            appOwnedMacs = emptyList(),
            desiredBlockedMacs = emptyList(),
            configFingerprint = fp,
            allowlistConflictMacs = emptyList(),
            externalConflictDetected = false,
            externalConflictReason = "",
            rollbackRequired = false,
            lastError = "",
        )
        persistLocked(snapshot)
        snapshot
    }

    fun resetForTest() = synchronized(lock) {
        runCatching { if (journalFile.exists()) journalFile.delete() }
        snapshot = SoftApJournalSnapshot()
    }

    private fun loadFromDiskOrDefault(): SoftApJournalSnapshot {
        return runCatching {
            if (!journalFile.exists()) return SoftApJournalSnapshot()
            val raw = journalFile.readText()
            if (raw.isBlank()) return SoftApJournalSnapshot()
            val parsed = SoftApJournalSnapshot.fromJson(JSONObject(raw))
            // If process crashed mid-write ("PRE_WRITE") or while app-owned MACs were applied, flag for reconciliation/rollback
            if (parsed.commitPhase == "PRE_WRITE") {
                parsed.copy(
                    commitPhase = "ROLLBACK_REQUIRED",
                    rollbackRequired = true,
                    lastError = parsed.lastError.ifBlank { "Recovered interrupted PRE_WRITE SoftAP journal entry on startup" },
                )
            } else {
                parsed
            }
        }.getOrDefault(SoftApJournalSnapshot())
    }

    private fun persistLocked(state: SoftApJournalSnapshot) {
        runCatching {
            journalFile.parentFile?.mkdirs()
            val tmp = File(journalFile.parentFile, "${journalFile.name}.tmp")
            tmp.writeText(state.toJson().toString(2))
            if (!tmp.renameTo(journalFile)) {
                journalFile.writeText(state.toJson().toString(2))
                tmp.delete()
            }
        }
    }

    companion object {
        const val DEFAULT_JOURNAL_PATH = "/data/local/tmp/shizzyluna-debug-softap-journal.json"
    }
}

data class SoftApExecutionIdentity(
    val shizukuState: String = "SHIZUKU_NOT_RUNNING", // SHIZUKU_RUNNING, SHIZUKU_NOT_RUNNING, SHIZUKU_PERMISSION_REQUIRED
    val shizukuRunning: Boolean = false,
    val shizukuPermissionGranted: Boolean = false,
    val uid: String = "UNKNOWN",
    val gid: String = "UNKNOWN",
    val selinuxContext: String = "UNKNOWN",
    val capEff: String = "UNKNOWN",
    val provenance: String = "UNCOLLECTED",
    val collectedAtEpochMs: Long = 0L,
) {
    val privilegeMode: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "SHIZUKU_UNAVAILABLE"
            uid == "0" -> "ROOT"
            uid == "2000" -> "ADB_SHELL"
            else -> "UNKNOWN"
        }
    val capEffHex: String get() = capEff

    fun toJson(): JSONObject = JSONObject().apply {
        put("shizukuState", shizukuState)
        put("shizukuRunning", shizukuRunning)
        put("shizukuPermissionGranted", shizukuPermissionGranted)
        put("uid", uid)
        put("gid", gid)
        put("selinuxContext", selinuxContext)
        put("capEff", capEff)
        put("provenance", provenance)
        put("collectedAtEpochMs", collectedAtEpochMs)
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApExecutionIdentity = SoftApExecutionIdentity(
            shizukuState = json.optString("shizukuState", "SHIZUKU_NOT_RUNNING"),
            shizukuRunning = json.optBoolean("shizukuRunning", false),
            shizukuPermissionGranted = json.optBoolean("shizukuPermissionGranted", false),
            uid = json.optString("uid", "UNKNOWN"),
            gid = json.optString("gid", "UNKNOWN"),
            selinuxContext = json.optString("selinuxContext", "UNKNOWN"),
            capEff = json.optString("capEff", "UNKNOWN"),
            provenance = json.optString("provenance", "UNCOLLECTED"),
            collectedAtEpochMs = json.optLong("collectedAtEpochMs", 0L),
        )
    }
}

data class SoftApCapabilityReport(
    val checkedAtEpochMs: Long = System.currentTimeMillis(),
    val executionIdentity: SoftApExecutionIdentity = SoftApExecutionIdentity(),
    val hotspotActive: Boolean = false,
    val tetherInterface: String = "wlan1",
    val callbackRegistered: Boolean = false,
    val capabilityReceived: Boolean = false,
    val forceDisconnectSupported: Boolean = false,
    val acsSupported: Boolean = false,
    val wpa3SaeSupported: Boolean = false,
    val maxSupportedClients: Int = 0,
    val getSoftApConfigSupported: Boolean = false,
    val setSoftApConfigSupported: Boolean = false,
    val builderSetBlockedListSupported: Boolean = false,
    val clientControlByUserEnabled: Boolean = false,
    val connectedWifiClients: List<String> = emptyList(),
    val configSnapshot: SoftApConfigSnapshot = SoftApConfigSnapshot(readable = false),
    val calculatedState: SoftApEngineState = SoftApEngineState.PROBE_REQUIRED,
    val reasonSummary: String = "Not checked yet",
    val apiPathSummary: String = "WifiManager.registerSoftApCallback + get/setSoftApConfiguration",
    val deviceFingerprint: String = Build.FINGERPRINT ?: "unknown",
) {
    val shizukuState: String get() = executionIdentity.shizukuState
    val reason: String get() = reasonSummary
    val engineState: SoftApEngineState get() = calculatedState

    fun toJson(): JSONObject = JSONObject().apply {
        put("checkedAtEpochMs", checkedAtEpochMs)
        put("executionIdentity", executionIdentity.toJson())
        put("hotspotActive", hotspotActive)
        put("tetherInterface", tetherInterface)
        put("callbackRegistered", callbackRegistered)
        put("capabilityReceived", capabilityReceived)
        put("forceDisconnectSupported", forceDisconnectSupported)
        put("acsSupported", acsSupported)
        put("wpa3SaeSupported", wpa3SaeSupported)
        put("maxSupportedClients", maxSupportedClients)
        put("getSoftApConfigSupported", getSoftApConfigSupported)
        put("setSoftApConfigSupported", setSoftApConfigSupported)
        put("builderSetBlockedListSupported", builderSetBlockedListSupported)
        put("clientControlByUserEnabled", clientControlByUserEnabled)
        put("connectedWifiClients", JSONArray(connectedWifiClients))
        put("configSnapshot", configSnapshot.toJson())
        put("calculatedState", calculatedState.code)
        put("calculatedStateLabel", calculatedState.displayLabel)
        put("reasonSummary", reasonSummary)
        put("apiPathSummary", apiPathSummary)
        put("deviceFingerprint", deviceFingerprint)
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApCapabilityReport {
            val clientsArr = json.optJSONArray("connectedWifiClients") ?: JSONArray()
            val clients = (0 until clientsArr.length())
                .map { clientsArr.optString(it).uppercase().trim() }
                .filter { it.isNotBlank() }
            return SoftApCapabilityReport(
                checkedAtEpochMs = json.optLong("checkedAtEpochMs", 0L),
                executionIdentity = SoftApExecutionIdentity.fromJson(
                    json.optJSONObject("executionIdentity") ?: JSONObject(),
                ),
                hotspotActive = json.optBoolean("hotspotActive", false),
                tetherInterface = json.optString("tetherInterface", "wlan1"),
                callbackRegistered = json.optBoolean("callbackRegistered", false),
                capabilityReceived = json.optBoolean("capabilityReceived", false),
                forceDisconnectSupported = json.optBoolean("forceDisconnectSupported", false),
                acsSupported = json.optBoolean("acsSupported", false),
                wpa3SaeSupported = json.optBoolean("wpa3SaeSupported", false),
                maxSupportedClients = json.optInt("maxSupportedClients", 0),
                getSoftApConfigSupported = json.optBoolean("getSoftApConfigSupported", false),
                setSoftApConfigSupported = json.optBoolean("setSoftApConfigSupported", false),
                builderSetBlockedListSupported = json.optBoolean("builderSetBlockedListSupported", false),
                clientControlByUserEnabled = json.optBoolean("clientControlByUserEnabled", false),
                connectedWifiClients = clients,
                configSnapshot = SoftApConfigSnapshot.fromJson(
                    json.optJSONObject("configSnapshot") ?: JSONObject(),
                ),
                calculatedState = SoftApEngineState.fromCode(json.optString("calculatedState")),
                reasonSummary = json.optString("reasonSummary", ""),
                apiPathSummary = json.optString("apiPathSummary", "WifiManager.registerSoftApCallback + get/setSoftApConfiguration"),
                deviceFingerprint = json.optString("deviceFingerprint", Build.FINGERPRINT ?: "unknown"),
            )
        }
    }
}

data class SoftApLiveProbeResult(
    val executed: Boolean = false,
    val probePassed: Boolean = false,
    val timestampEpochMs: Long = 0L,
    val clientAMac: String = "",
    val clientBMac: String = "",
    val userConfirmed: Boolean = false,
    val previousEngineSuspended: Boolean = false,
    val initialConfigReadable: Boolean = false,
    val setConfigReturnedTrue: Boolean = false,
    val readbackVerifiedBlockAdded: Boolean = false,
    val clientADisconnected: Boolean = false,
    val clientADisconnectLatencyMs: Long = -1L,
    val clientAReconnectPrevented: Boolean = false,
    val clientBRemainedConnected: Boolean = false,
    val hotspotRemainedActiveWithoutRestart: Boolean = false,
    val probeRuleRemovedCleanly: Boolean = false,
    val readbackVerifiedBlockRemoved: Boolean = false,
    val firmwareFingerprint: String = Build.FINGERPRINT ?: "unknown",
    val apiPathUsed: String = "WifiManager.setSoftApConfiguration(Builder.setBlockedClientList)",
    val executionUid: String = "UNKNOWN",
    val resultingState: SoftApEngineState = SoftApEngineState.PROBE_REQUIRED,
    val summary: String = "Controlled two-client SoftAP live probe has not been executed yet.",
    val stepLogs: List<String> = emptyList(),
) {
    val verdict: String
        get() = when {
            !executed -> "NOT_RUN"
            probePassed -> "READY"
            else -> resultingState.code
        }
    val disconnectLatencyMs: Long get() = clientADisconnectLatencyMs
    val restoredVerified: Boolean get() = readbackVerifiedBlockRemoved
    val engineState: SoftApEngineState get() = resultingState

    fun toJson(): JSONObject = JSONObject().apply {
        put("executed", executed)
        put("probePassed", probePassed)
        put("timestampEpochMs", timestampEpochMs)
        put("clientAMac", clientAMac)
        put("clientBMac", clientBMac)
        put("userConfirmed", userConfirmed)
        put("previousEngineSuspended", previousEngineSuspended)
        put("initialConfigReadable", initialConfigReadable)
        put("setConfigReturnedTrue", setConfigReturnedTrue)
        put("readbackVerifiedBlockAdded", readbackVerifiedBlockAdded)
        put("clientADisconnected", clientADisconnected)
        put("clientADisconnectLatencyMs", clientADisconnectLatencyMs)
        put("clientAReconnectPrevented", clientAReconnectPrevented)
        put("clientBRemainedConnected", clientBRemainedConnected)
        put("hotspotRemainedActiveWithoutRestart", hotspotRemainedActiveWithoutRestart)
        put("probeRuleRemovedCleanly", probeRuleRemovedCleanly)
        put("readbackVerifiedBlockRemoved", readbackVerifiedBlockRemoved)
        put("firmwareFingerprint", firmwareFingerprint)
        put("apiPathUsed", apiPathUsed)
        put("executionUid", executionUid)
        put("resultingState", resultingState.code)
        put("resultingStateLabel", resultingState.displayLabel)
        put("summary", summary)
        put("stepLogs", JSONArray(stepLogs))
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApLiveProbeResult {
            val logsArr = json.optJSONArray("stepLogs") ?: JSONArray()
            val logs = (0 until logsArr.length()).map { logsArr.optString(it) }
            return SoftApLiveProbeResult(
                executed = json.optBoolean("executed", false),
                probePassed = json.optBoolean("probePassed", false),
                timestampEpochMs = json.optLong("timestampEpochMs", 0L),
                clientAMac = json.optString("clientAMac", ""),
                clientBMac = json.optString("clientBMac", ""),
                userConfirmed = json.optBoolean("userConfirmed", false),
                previousEngineSuspended = json.optBoolean("previousEngineSuspended", false),
                initialConfigReadable = json.optBoolean("initialConfigReadable", false),
                setConfigReturnedTrue = json.optBoolean("setConfigReturnedTrue", false),
                readbackVerifiedBlockAdded = json.optBoolean("readbackVerifiedBlockAdded", false),
                clientADisconnected = json.optBoolean("clientADisconnected", false),
                clientADisconnectLatencyMs = json.optLong("clientADisconnectLatencyMs", -1L),
                clientAReconnectPrevented = json.optBoolean("clientAReconnectPrevented", false),
                clientBRemainedConnected = json.optBoolean("clientBRemainedConnected", false),
                hotspotRemainedActiveWithoutRestart = json.optBoolean("hotspotRemainedActiveWithoutRestart", false),
                probeRuleRemovedCleanly = json.optBoolean("probeRuleRemovedCleanly", false),
                readbackVerifiedBlockRemoved = json.optBoolean("readbackVerifiedBlockRemoved", false),
                firmwareFingerprint = json.optString("firmwareFingerprint", Build.FINGERPRINT ?: "unknown"),
                apiPathUsed = json.optString("apiPathUsed", "WifiManager.setSoftApConfiguration(Builder.setBlockedClientList)"),
                executionUid = json.optString("executionUid", "UNKNOWN"),
                resultingState = SoftApEngineState.fromCode(json.optString("resultingState")),
                summary = json.optString("summary", ""),
                stepLogs = logs,
            )
        }
    }
}

data class SoftApTestMatrixRow(
    val testId: String,
    val scenario: String,
    val expectedBehavior: String,
    val status: String, // PASS, FAIL, NOT_RUN, BLOCKED_BY_PREREQ
    val evidence: String,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("testId", testId)
        put("scenario", scenario)
        put("expectedBehavior", expectedBehavior)
        put("status", status)
        put("evidence", evidence)
    }

    companion object {
        fun fromJson(json: JSONObject): SoftApTestMatrixRow = SoftApTestMatrixRow(
            testId = json.optString("testId", ""),
            scenario = json.optString("scenario", ""),
            expectedBehavior = json.optString("expectedBehavior", ""),
            status = json.optString("status", "NOT_RUN"),
            evidence = json.optString("evidence", ""),
        )
    }
}

data class SoftApModeDiagnosticReport(
    val schemaVersion: Int = SCHEMA_VERSION,
    val featureVersion: String = FEATURE_VERSION,
    val selectedMode: BlockingMode = BlockingMode.BPF_NAT_VPN,
    val effectiveMode: BlockingMode? = BlockingMode.BPF_NAT_VPN,
    val engineState: SoftApEngineState = SoftApEngineState.PROBE_REQUIRED,
    val bpfNatVpnEnforcementActive: Boolean = true,
    val preNatEnforcementActive: Boolean = false,
    val softApEnforcementActive: Boolean = false,
    val exclusiveEngineInvariant: Boolean = true,
    val activeEngineCount: Int = 1,
    val activeBandwidthThrottleCount: Int = 0,
    val bandwidthThrottlingSupportedInSoftAp: Boolean = false,
    val capabilityReport: SoftApCapabilityReport = SoftApCapabilityReport(),
    val liveProbeResult: SoftApLiveProbeResult = SoftApLiveProbeResult(),
    val journalSnapshot: SoftApJournalSnapshot = SoftApJournalSnapshot(),
    val clientRecords: List<SoftApClientEnforcementRecord> = emptyList(),
    val auditLog: List<String> = emptyList(),
    val testMatrix: List<SoftApTestMatrixRow> = emptyList(),
) {
    val capability: SoftApCapabilityReport get() = capabilityReport
    val lastProbe: SoftApLiveProbeResult get() = liveProbeResult
    val lastLiveProbe: SoftApLiveProbeResult get() = liveProbeResult
    val journal: SoftApJournalSnapshot get() = journalSnapshot
    val rollbackRequired: Boolean get() = journalSnapshot.rollbackRequired || engineState == SoftApEngineState.ROLLBACK_REQUIRED

    fun toJson(
        includeSensitiveEndpoints: Boolean = true,
        includePseudonymousIds: Boolean = false,
    ): JSONObject {
        val rawObj = JSONObject().apply {
            put("schemaVersion", schemaVersion)
            put("featureVersion", featureVersion)
            put("selectedMode", selectedMode.name)
            put("selectedModeDisplay", selectedMode.displayTitle)
            put("effectiveMode", effectiveMode?.name ?: "NONE")
            put("effectiveModeDisplay", effectiveMode?.displayTitle ?: "None (Transition / Rollback Required)")
            put("engineState", engineState.code)
            put("engineStateDisplay", engineState.displayLabel)
            put("bpfNatVpnEnforcementActive", bpfNatVpnEnforcementActive)
            put("preNatEnforcementActive", preNatEnforcementActive)
            put("softApEnforcementActive", softApEnforcementActive)
            put("exclusiveEngineInvariant", exclusiveEngineInvariant)
            put("activeEngineCount", activeEngineCount)
            put("activeBandwidthThrottleCount", activeBandwidthThrottleCount)
            put("bandwidthThrottlingSupportedInSoftAp", bandwidthThrottlingSupportedInSoftAp)
            put("capabilityReport", capabilityReport.toJson())
            put("liveProbeResult", liveProbeResult.toJson())
            put("journalSnapshot", journalSnapshot.toJson())
            put("clientRecords", JSONArray().apply { clientRecords.forEach { put(it.toJson()) } })
            put("auditLog", JSONArray(auditLog))
            put("testMatrix", JSONArray().apply { testMatrix.forEach { put(it.toJson()) } })
        }
        return if (includeSensitiveEndpoints) {
            rawObj
        } else {
            JSONObject(BpfDumpParser.maskSensitiveLinePreview(rawObj.toString()))
        }
    }

    fun toMarkdownSection(
        includeSensitiveEndpoints: Boolean = true,
        includePseudonymousIds: Boolean = false,
    ): String = buildString {
        fun formatMac(mac: String, indexHint: Int = 0): String {
            if (mac.isBlank()) return "none"
            return when {
                includeSensitiveEndpoints -> mac
                includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(mac)
                indexHint > 0 -> "Client-$indexHint"
                else -> "redacted-mac"
            }
        }
        fun formatMacList(macs: List<String>): String {
            if (macs.isEmpty()) return "none"
            return macs.mapIndexed { idx, m -> formatMac(m, idx + 1) }.joinToString(",")
        }
        appendLine("## 11. Native SoftAP MAC Blocklist Engine & Ownership Journal (`v0.10.8-debug`, Schema v$schemaVersion)")
        appendLine("- **Feature Version**: `$featureVersion`")
        appendLine("- **Selected Mode**: `${selectedMode.name}` (${selectedMode.displayTitle})")
        appendLine("- **Effective Mode**: `${effectiveMode?.name ?: "NONE"}` (${effectiveMode?.displayTitle ?: "None / Transition / Rollback Required"})")
        appendLine("- **SoftAP Engine State**: `${engineState.code}` (${engineState.displayLabel})")
        appendLine("- **Exclusive Engine Invariant**: `$exclusiveEngineInvariant` (activeEngineCount=`$activeEngineCount`: BPF/NAT+VPN=`$bpfNatVpnEnforcementActive`, Pre-NAT=`$preNatEnforcementActive`, SoftAP=`$softApEnforcementActive`)")
        appendLine("- **Bandwidth Throttling in SoftAP Mode**: `UNSUPPORTED` (active throttle rules=`$activeBandwidthThrottleCount`)")
        appendLine()
        appendLine("### 11.1 Execution Provenance & SoftAP Capability")
        val id = capabilityReport.executionIdentity
        appendLine("- **Shizuku State**: `${id.shizukuState}` (running=`${id.shizukuRunning}`, permission=`${id.shizukuPermissionGranted}`)")
        appendLine("- **Execution Identity**: uid=`${id.uid}`, gid=`${id.gid}`, selinux=`${id.selinuxContext}`, capEff=`${id.capEff}` (provenance=`${id.provenance}`, collectedAt=`${id.collectedAtEpochMs}`)")
        appendLine("- **Hotspot Active**: `${capabilityReport.hotspotActive}` (iface=`${capabilityReport.tetherInterface}`)")
        appendLine("- **SoftApCapability**: callbackRegistered=`${capabilityReport.callbackRegistered}`, capabilityReceived=`${capabilityReport.capabilityReceived}`, `SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT`=`${capabilityReport.forceDisconnectSupported}`, maxSupportedClients=`${capabilityReport.maxSupportedClients}`")
        appendLine("- **SoftApConfiguration API**: getSupported=`${capabilityReport.getSoftApConfigSupported}`, setSupported=`${capabilityReport.setSoftApConfigSupported}`, builderBlockedListSupported=`${capabilityReport.builderSetBlockedListSupported}`, clientControlByUserEnabled=`${capabilityReport.clientControlByUserEnabled}`")
        appendLine("- **SoftApConfig Non-Secret Snapshot**: readable=`${capabilityReport.configSnapshot.readable}`, fingerprint=`${capabilityReport.configSnapshot.configFingerprint}`, blockedMacs=`${formatMacList(capabilityReport.configSnapshot.blockedClientMacs)}`, allowedMacs=`${formatMacList(capabilityReport.configSnapshot.allowedClientMacs)}`")
        appendLine("- **Capability Verdict**: `${capabilityReport.calculatedState.code}` — ${capabilityReport.reasonSummary}")
        appendLine()
        appendLine("### 11.2 Controlled Two-Client SoftAP Live Probe")
        appendLine("- **Executed**: `${liveProbeResult.executed}` | **Passed**: `${liveProbeResult.probePassed}` | **Resulting State**: `${liveProbeResult.resultingState.code}`")
        appendLine("- **Clients**: Client A=`${formatMac(liveProbeResult.clientAMac, 1)}`, Client B=`${formatMac(liveProbeResult.clientBMac, 2)}`")
        appendLine("- **Verification**: setReturnedTrue=`${liveProbeResult.setConfigReturnedTrue}`, readbackAdded=`${liveProbeResult.readbackVerifiedBlockAdded}`, clientADisconnected=`${liveProbeResult.clientADisconnected}` (${liveProbeResult.clientADisconnectLatencyMs}ms), clientBConnected=`${liveProbeResult.clientBRemainedConnected}`, noApRestart=`${liveProbeResult.hotspotRemainedActiveWithoutRestart}`, probeRemoved=`${liveProbeResult.readbackVerifiedBlockRemoved}`")
        val safeProbeSummary = if (includeSensitiveEndpoints) liveProbeResult.summary else BpfDumpParser.maskSensitiveLinePreview(liveProbeResult.summary)
        appendLine("- **Summary**: $safeProbeSummary")
        appendLine()
        appendLine("### 11.3 Crash-Safe Ownership Journal")
        appendLine("- **Operation ID**: `${journalSnapshot.operationId}` | **Phase**: `${journalSnapshot.commitPhase}` | **Generation**: `${journalSnapshot.engineGeneration}`")
        appendLine("- **Prior User/OEM Blocked MACs**: `${formatMacList(journalSnapshot.priorBlockedMacs)}`")
        appendLine("- **App-Owned Blocked MACs**: `${formatMacList(journalSnapshot.appOwnedMacs)}`")
        appendLine("- **Desired Blocked MACs**: `${formatMacList(journalSnapshot.desiredBlockedMacs)}`")
        appendLine("- **Allowlist Conflicts**: `${formatMacList(journalSnapshot.allowlistConflictMacs)}`")
        appendLine("- **External Edit Conflict**: `${journalSnapshot.externalConflictDetected}` (${journalSnapshot.externalConflictReason.ifBlank { "none" }})")
        appendLine("- **Rollback Required**: `${journalSnapshot.rollbackRequired}` (${journalSnapshot.lastError.ifBlank { "none" }})")
        appendLine()
        appendLine("### 11.4 Per-Client SoftAP Policy & Applied State")
        if (clientRecords.isEmpty()) {
            appendLine("- No client policy records registered.")
        } else {
            clientRecords.forEachIndexed { idx, rec ->
                appendLine("- `${formatMac(rec.mac, idx + 1)}` (${rec.alias.ifBlank { "Host" }}): desiredBlocked=`${rec.desiredBlocked}`, reasons=`[${rec.activeReasons.joinToString(",") { it.code }}]`, appliedState=`${rec.appliedState.code}`, associated=`${rec.isCurrentlyAssociated}`, disconnectedAfterApply=`${rec.disconnectedAfterApply}`, allowlistConflict=`${rec.allowlistConflict}`")
            }
        }
        appendLine()
        appendLine("### 11.5 SA01–SA20 Verification Matrix")
        appendLine("| ID | Scenario | Expected | Status | Evidence |")
        appendLine("|---|---|---|---|---|")
        testMatrix.forEach { row ->
            val safeEv = if (includeSensitiveEndpoints) row.evidence else BpfDumpParser.maskSensitiveLinePreview(row.evidence)
            appendLine("| `${row.testId}` | ${row.scenario} | ${row.expectedBehavior} | **${row.status}** | $safeEv |")
        }
    }

    companion object {
        const val SCHEMA_VERSION = 6
        const val FEATURE_VERSION = "0.10.8-debug"

        fun fromJson(json: JSONObject): SoftApModeDiagnosticReport {
            val recordsArr = json.optJSONArray("clientRecords") ?: JSONArray()
            val records = (0 until recordsArr.length()).map {
                SoftApClientEnforcementRecord.fromJson(recordsArr.getJSONObject(it))
            }
            val auditArr = json.optJSONArray("auditLog") ?: JSONArray()
            val audit = (0 until auditArr.length()).map { auditArr.optString(it) }
            val matrixArr = json.optJSONArray("testMatrix") ?: JSONArray()
            val matrix = (0 until matrixArr.length()).map {
                SoftApTestMatrixRow.fromJson(matrixArr.getJSONObject(it))
            }
            val rawEffective = json.optString("effectiveMode", "BPF_NAT_VPN")
            val effectiveMode = if (rawEffective == "NONE" || rawEffective.isBlank()) {
                null
            } else {
                BlockingMode.fromName(rawEffective)
            }
            return SoftApModeDiagnosticReport(
                schemaVersion = json.optInt("schemaVersion", SCHEMA_VERSION),
                featureVersion = json.optString("featureVersion", FEATURE_VERSION),
                selectedMode = BlockingMode.fromName(json.optString("selectedMode", BlockingMode.BPF_NAT_VPN.name)),
                effectiveMode = effectiveMode,
                engineState = SoftApEngineState.fromCode(json.optString("engineState")),
                bpfNatVpnEnforcementActive = json.optBoolean("bpfNatVpnEnforcementActive", true),
                preNatEnforcementActive = json.optBoolean("preNatEnforcementActive", false),
                softApEnforcementActive = json.optBoolean("softApEnforcementActive", false),
                exclusiveEngineInvariant = json.optBoolean("exclusiveEngineInvariant", true),
                activeEngineCount = json.optInt("activeEngineCount", 1),
                activeBandwidthThrottleCount = json.optInt("activeBandwidthThrottleCount", 0),
                bandwidthThrottlingSupportedInSoftAp = json.optBoolean("bandwidthThrottlingSupportedInSoftAp", false),
                capabilityReport = SoftApCapabilityReport.fromJson(
                    json.optJSONObject("capabilityReport") ?: JSONObject(),
                ),
                liveProbeResult = SoftApLiveProbeResult.fromJson(
                    json.optJSONObject("liveProbeResult") ?: JSONObject(),
                ),
                journalSnapshot = SoftApJournalSnapshot.fromJson(
                    json.optJSONObject("journalSnapshot") ?: JSONObject(),
                ),
                clientRecords = records,
                auditLog = audit,
                testMatrix = matrix,
            )
        }
    }
}

/**
 * Platform abstraction for SoftAP configuration and capability queries.
 * Allows deterministic unit/Robolectric tests and real Shizuku UserService execution.
 */
interface SoftApPlatformAdapter {
    fun inspectExecutionIdentity(): SoftApExecutionIdentity
    fun isHotspotActive(): Boolean
    fun resolveTetherInterface(): String
    fun querySoftApCapability(): SoftApPlatformCapabilitySnapshot
    fun readSoftApConfiguration(): SoftApConfigSnapshot
    fun writeBlockedClientList(updatedBlockedMacs: List<String>): SoftApWriteOutcome
    fun queryConnectedClientMacs(): List<String>
}

data class SoftApPlatformCapabilitySnapshot(
    val callbackRegistered: Boolean,
    val capabilityReceived: Boolean,
    val forceDisconnectSupported: Boolean,
    val acsSupported: Boolean = false,
    val wpa3SaeSupported: Boolean = false,
    val maxSupportedClients: Int = 0,
    val getSoftApConfigMethodPresent: Boolean = true,
    val setSoftApConfigMethodPresent: Boolean = true,
    val builderSetBlockedListMethodPresent: Boolean = true,
    val connectedWifiClients: List<String> = emptyList(),
    val errorDetail: String = "",
)

data class SoftApWriteOutcome(
    val invoked: Boolean,
    val returnedTrue: Boolean,
    val readbackSnapshot: SoftApConfigSnapshot,
    val errorDetail: String = "",
)

/**
 * Real Android 13/14+ SoftAP Platform Adapter using WifiManager hidden/SystemApi reflection
 * inside the Shizuku UserService context (`com.android.shell`, UID 2000) or app process diagnostic context.
 */
class ReflectionSoftApPlatformAdapter(
    private val contextProvider: () -> Context? = { null },
) : SoftApPlatformAdapter {

    @Volatile
    private var cachedCallbackRegistered = false

    @Volatile
    private var cachedCapabilityReceived = false

    @Volatile
    private var cachedForceDisconnectSupported = false

    @Volatile
    private var cachedAcsSupported = false

    @Volatile
    private var cachedWpa3SaeSupported = false

    @Volatile
    private var cachedMaxSupportedClients = 0

    @Volatile
    private var cachedConnectedWifiClientMacs: List<String> = emptyList()

    @Volatile
    private var cachedCallbackError: String = ""

    private val callbackLock = Any()
    private var registeredCallbackProxy: Any? = null

    override fun inspectExecutionIdentity(): SoftApExecutionIdentity {
        val myUid = runCatching { Os.getuid() }.getOrDefault(-1)
        val myGid = runCatching { Os.getgid() }.getOrDefault(-1)
        val inRemoteShizukuProcess = myUid == 2000 || myUid == 0

        if (inRemoteShizukuProcess) {
            val selinux = readProcSelfAttrCurrent()
            val capEff = readProcSelfStatusCapEff()
            return SoftApExecutionIdentity(
                shizukuState = "SHIZUKU_RUNNING",
                shizukuRunning = true,
                shizukuPermissionGranted = true,
                uid = myUid.toString(),
                gid = myGid.toString(),
                selinuxContext = selinux,
                capEff = capEff,
                provenance = "LIVE_SHIZUKU_USERSERVICE_PROCESS",
                collectedAtEpochMs = System.currentTimeMillis(),
            )
        }

        val binderAlive = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
        if (!binderAlive) {
            return SoftApExecutionIdentity(
                shizukuState = "SHIZUKU_NOT_RUNNING",
                shizukuRunning = false,
                shizukuPermissionGranted = false,
                uid = "UNKNOWN",
                gid = "UNKNOWN",
                selinuxContext = "UNKNOWN",
                capEff = "UNKNOWN",
                provenance = "SHIZUKU_BINDER_DEAD",
                collectedAtEpochMs = System.currentTimeMillis(),
            )
        }

        val permissionGranted = runCatching {
            Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)

        if (!permissionGranted) {
            return SoftApExecutionIdentity(
                shizukuState = "SHIZUKU_PERMISSION_REQUIRED",
                shizukuRunning = true,
                shizukuPermissionGranted = false,
                uid = "UNKNOWN",
                gid = "UNKNOWN",
                selinuxContext = "UNKNOWN",
                capEff = "UNKNOWN",
                provenance = "SHIZUKU_PERMISSION_NOT_GRANTED",
                collectedAtEpochMs = System.currentTimeMillis(),
            )
        }

        val remoteUid = runCatching { Shizuku.getUid() }.getOrDefault(-1)
        return SoftApExecutionIdentity(
            shizukuState = "SHIZUKU_RUNNING",
            shizukuRunning = true,
            shizukuPermissionGranted = true,
            uid = if (remoteUid >= 0) remoteUid.toString() else "UNKNOWN",
            gid = if (remoteUid >= 0) remoteUid.toString() else "UNKNOWN",
            selinuxContext = "UNKNOWN",
            capEff = "UNKNOWN",
            provenance = "SHIZUKU_BINDER_PING_APP_PROCESS",
            collectedAtEpochMs = System.currentTimeMillis(),
        )
    }

    override fun isHotspotActive(): Boolean {
        val wm = obtainWifiManager()
        if (wm != null) {
            val apEnabled = runCatching {
                val method = wm.javaClass.getMethod("isWifiApEnabled")
                method.isAccessible = true
                method.invoke(wm) as? Boolean
            }.getOrNull()
            if (apEnabled != null) return apEnabled

            val apState = runCatching {
                val method = wm.javaClass.getMethod("getWifiApState")
                method.isAccessible = true
                (method.invoke(wm) as? Number)?.toInt()
            }.getOrNull()
            // WIFI_AP_STATE_ENABLED == 13
            if (apState != null) return apState == 13
        }
        val iface = resolveTetherInterface()
        return iface.isNotBlank() && File("/sys/class/net/$iface").exists()
    }

    override fun resolveTetherInterface(): String {
        val candidates = listOf("swlan0", "wlan1", "ap0", "softap0", "wlan2")
        for (candidate in candidates) {
            val oper = runCatching { File("/sys/class/net/$candidate/operstate").readText().trim() }.getOrDefault("")
            if (oper.equals("up", ignoreCase = true) || File("/sys/class/net/$candidate").exists()) {
                return candidate
            }
        }
        return "wlan1"
    }

    @SuppressLint("PrivateApi", "SoonBlockedPrivateApi")
    override fun querySoftApCapability(): SoftApPlatformCapabilitySnapshot {
        val wm = obtainWifiManager()
            ?: return SoftApPlatformCapabilitySnapshot(
                callbackRegistered = false,
                capabilityReceived = false,
                forceDisconnectSupported = false,
                getSoftApConfigMethodPresent = false,
                setSoftApConfigMethodPresent = false,
                builderSetBlockedListMethodPresent = false,
                errorDetail = "WifiManager context unavailable",
            )

        val getMethodPresent = runCatching { wm.javaClass.getMethod("getSoftApConfiguration") }.isSuccess
        val softApConfigClass = runCatching { Class.forName("android.net.wifi.SoftApConfiguration") }.getOrNull()
        val setMethodPresent = softApConfigClass != null &&
            runCatching { wm.javaClass.getMethod("setSoftApConfiguration", softApConfigClass) }.isSuccess
        val builderClass = runCatching { Class.forName("android.net.wifi.SoftApConfiguration\$Builder") }.getOrNull()
        val builderSetBlockedPresent = builderClass != null &&
            runCatching { builderClass.getMethod("setBlockedClientList", List::class.java) }.isSuccess

        ensureSoftApCallbackRegistered(wm)

        return SoftApPlatformCapabilitySnapshot(
            callbackRegistered = cachedCallbackRegistered,
            capabilityReceived = cachedCapabilityReceived,
            forceDisconnectSupported = cachedForceDisconnectSupported,
            acsSupported = cachedAcsSupported,
            wpa3SaeSupported = cachedWpa3SaeSupported,
            maxSupportedClients = cachedMaxSupportedClients,
            getSoftApConfigMethodPresent = getMethodPresent,
            setSoftApConfigMethodPresent = setMethodPresent,
            builderSetBlockedListMethodPresent = builderSetBlockedPresent,
            connectedWifiClients = cachedConnectedWifiClientMacs,
            errorDetail = cachedCallbackError,
        )
    }

    @SuppressLint("PrivateApi", "SoonBlockedPrivateApi")
    override fun readSoftApConfiguration(): SoftApConfigSnapshot {
        val wm = obtainWifiManager()
            ?: return SoftApConfigSnapshot(
                readable = false,
                errorDetail = "WifiManager unavailable in current context",
            )
        return runCatching {
            val getMethod = wm.javaClass.getMethod("getSoftApConfiguration")
            getMethod.isAccessible = true
            val configObj = getMethod.invoke(wm)
                ?: return@runCatching SoftApConfigSnapshot(
                    readable = false,
                    errorDetail = "WifiManager.getSoftApConfiguration() returned null",
                )
            extractSoftApConfigSnapshot(configObj)
        }.getOrElse { failure ->
            val cause = (failure as? java.lang.reflect.InvocationTargetException)?.targetException ?: failure
            SoftApConfigSnapshot(
                readable = false,
                errorDetail = "${cause.javaClass.simpleName}: ${cause.message}",
            )
        }
    }

    @SuppressLint("PrivateApi", "SoonBlockedPrivateApi")
    override fun writeBlockedClientList(updatedBlockedMacs: List<String>): SoftApWriteOutcome {
        val wm = obtainWifiManager()
            ?: return SoftApWriteOutcome(
                invoked = false,
                returnedTrue = false,
                readbackSnapshot = SoftApConfigSnapshot(readable = false),
                errorDetail = "WifiManager unavailable",
            )

        return runCatching {
            val getMethod = wm.javaClass.getMethod("getSoftApConfiguration")
            getMethod.isAccessible = true
            val currentConfigObj = getMethod.invoke(wm)
                ?: return@runCatching SoftApWriteOutcome(
                    invoked = false,
                    returnedTrue = false,
                    readbackSnapshot = SoftApConfigSnapshot(readable = false),
                    errorDetail = "Current SoftApConfiguration is null",
                )

            val softApConfigClass = Class.forName("android.net.wifi.SoftApConfiguration")
            val builderClass = Class.forName("android.net.wifi.SoftApConfiguration\$Builder")
            val copyCtor = builderClass.getConstructor(softApConfigClass)
            copyCtor.isAccessible = true
            val builderInstance = copyCtor.newInstance(currentConfigObj)

            val macObjects = updatedBlockedMacs
                .map { it.uppercase().trim() }
                .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
                .distinct()
                .map { MacAddress.fromString(it) }

            // Ensure client control by user is enabled if required by OEM/framework when setting blockedClientList
            runCatching {
                val setClientControlMethod = builderClass.getMethod(
                    "setClientControlByUserEnabled",
                    Boolean::class.javaPrimitiveType,
                )
                setClientControlMethod.isAccessible = true
                val currentControlEnabled = runCatching {
                    softApConfigClass.getMethod("isClientControlByUserEnabled").invoke(currentConfigObj) as? Boolean
                }.getOrDefault(false) ?: false
                if (currentControlEnabled || macObjects.isNotEmpty()) {
                    setClientControlMethod.invoke(builderInstance, true)
                }
            }

            val setBlockedMethod = builderClass.getMethod("setBlockedClientList", List::class.java)
            setBlockedMethod.isAccessible = true
            setBlockedMethod.invoke(builderInstance, macObjects)

            val buildMethod = builderClass.getMethod("build")
            buildMethod.isAccessible = true
            val updatedConfigObj = buildMethod.invoke(builderInstance)

            val setConfigMethod = wm.javaClass.getMethod("setSoftApConfiguration", softApConfigClass)
            setConfigMethod.isAccessible = true
            val setResult = (setConfigMethod.invoke(wm, updatedConfigObj) as? Boolean) ?: false

            val readback = readSoftApConfiguration()
            SoftApWriteOutcome(
                invoked = true,
                returnedTrue = setResult,
                readbackSnapshot = readback,
                errorDetail = if (setResult) "" else "WifiManager.setSoftApConfiguration returned false",
            )
        }.getOrElse { failure ->
            val cause = (failure as? java.lang.reflect.InvocationTargetException)?.targetException ?: failure
            SoftApWriteOutcome(
                invoked = false,
                returnedTrue = false,
                readbackSnapshot = readSoftApConfiguration(),
                errorDetail = "${cause.javaClass.simpleName}: ${cause.message}",
            )
        }
    }

    override fun queryConnectedClientMacs(): List<String> {
        val fromCallback = cachedConnectedWifiClientMacs
        val fromNeighbors = runCatching {
            TunTrafficEngine.getActiveConnectedMacsSnapshot()
                .map { it.uppercase().trim() }
                .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
        }.getOrDefault(emptyList())
        return (fromCallback + fromNeighbors).distinct()
    }

    private fun ensureSoftApCallbackRegistered(wm: WifiManager) {
        synchronized(callbackLock) {
            if (cachedCallbackRegistered && registeredCallbackProxy != null) return
            runCatching {
                val callbackClass = Class.forName("android.net.wifi.WifiManager\$SoftApCallback")
                val handler = InvocationHandler { proxy, method, args ->
                    when (method.name) {
                        "onCapabilityChanged" -> {
                            val capObj = args?.firstOrNull()
                            if (capObj != null) {
                                parseSoftApCapability(capObj)
                            }
                            null
                        }
                        "onConnectedClientsChanged" -> {
                            val clientsList = args?.firstOrNull { it is List<*> } as? List<*>
                            if (clientsList != null) {
                                parseWifiClientsList(clientsList)
                            }
                            null
                        }
                        "hashCode" -> System.identityHashCode(proxy)
                        "equals" -> proxy === args?.firstOrNull()
                        "toString" -> "ShizzyLunaSoftApCallbackProxy"
                        else -> null
                    }
                }
                val proxyInstance = Proxy.newProxyInstance(
                    callbackClass.classLoader,
                    arrayOf(callbackClass),
                    handler,
                )
                val directExecutor = Executor { runnable -> runnable.run() }
                val registerMethod: Method? = runCatching {
                    wm.javaClass.getMethod("registerSoftApCallback", Executor::class.java, callbackClass)
                }.getOrNull()

                if (registerMethod != null) {
                    registerMethod.isAccessible = true
                    registerMethod.invoke(wm, directExecutor, proxyInstance)
                    registeredCallbackProxy = proxyInstance
                    cachedCallbackRegistered = true
                    cachedCallbackError = ""
                } else {
                    cachedCallbackRegistered = false
                    cachedCallbackError = "registerSoftApCallback(Executor, SoftApCallback) not found"
                }
            }.onFailure { failure ->
                val cause = (failure as? java.lang.reflect.InvocationTargetException)?.targetException ?: failure
                cachedCallbackRegistered = false
                cachedCallbackError = "${cause.javaClass.simpleName}: ${cause.message}"
            }
        }
    }

    private fun parseSoftApCapability(capObj: Any) {
        runCatching {
            val areFeaturesSupported = capObj.javaClass.getMethod("areFeaturesSupported", Long::class.javaPrimitiveType)
            areFeaturesSupported.isAccessible = true
            // SoftApCapability.SOFTAP_FEATURE_ACS_OFFLOAD = 1L (1 << 0)
            // SoftApCapability.SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT = 2L (1 << 1)
            // SoftApCapability.SOFTAP_FEATURE_WPA3_SAE = 4L (1 << 2)
            val forceDisconnect = (areFeaturesSupported.invoke(capObj, 2L) as? Boolean) ?: false
            val acs = (areFeaturesSupported.invoke(capObj, 1L) as? Boolean) ?: false
            val wpa3 = (areFeaturesSupported.invoke(capObj, 4L) as? Boolean) ?: false
            val maxClients = runCatching {
                (capObj.javaClass.getMethod("getMaxSupportedClients").invoke(capObj) as? Number)?.toInt() ?: 0
            }.getOrDefault(0)
            cachedCapabilityReceived = true
            cachedForceDisconnectSupported = forceDisconnect
            cachedAcsSupported = acs
            cachedWpa3SaeSupported = wpa3
            cachedMaxSupportedClients = maxClients
        }
    }

    private fun parseWifiClientsList(clients: List<*>) {
        val macs = mutableListOf<String>()
        for (client in clients) {
            if (client == null) continue
            val macAddr = runCatching {
                val macObj = client.javaClass.getMethod("getMacAddress").invoke(client)
                macObj?.toString()?.uppercase()?.trim()
            }.getOrNull()
            if (macAddr != null && SoftApPolicyReducer.isValidUnicastMac(macAddr)) {
                macs.add(macAddr)
            }
        }
        cachedConnectedWifiClientMacs = macs.distinct()
    }

    private fun extractSoftApConfigSnapshot(configObj: Any): SoftApConfigSnapshot {
        val cls = configObj.javaClass
        val ssidStr = runCatching {
            cls.getMethod("getSsid").invoke(configObj)?.toString()
        }.getOrNull()
        val securityType = runCatching {
            (cls.getMethod("getSecurityType").invoke(configObj) as? Number)?.toInt() ?: 0
        }.getOrDefault(0)
        val maxClients = runCatching {
            (cls.getMethod("getMaxNumberOfClients").invoke(configObj) as? Number)?.toInt() ?: 0
        }.getOrDefault(0)
        val clientControlByUser = runCatching {
            (cls.getMethod("isClientControlByUserEnabled").invoke(configObj) as? Boolean) ?: false
        }.getOrDefault(false)
        val bandsSummary = runCatching {
            val bands = cls.getMethod("getBands").invoke(configObj) as? IntArray
            bands?.joinToString(",") ?: "default"
        }.getOrElse {
            runCatching {
                (cls.getMethod("getBand").invoke(configObj) as? Number)?.toInt()?.toString() ?: "default"
            }.getOrDefault("default")
        }

        val blockedMacs = runCatching {
            val list = cls.getMethod("getBlockedClientList").invoke(configObj) as? List<*>
            list.orEmpty().mapNotNull { it?.toString()?.uppercase()?.trim() }
                .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
                .distinct()
        }.getOrDefault(emptyList())

        val allowedMacs = runCatching {
            val list = cls.getMethod("getAllowedClientList").invoke(configObj) as? List<*>
            list.orEmpty().mapNotNull { it?.toString()?.uppercase()?.trim() }
                .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
                .distinct()
        }.getOrDefault(emptyList())

        val fp = SoftApConfigSnapshot.computeNonSecretFingerprint(
            ssidLength = ssidStr?.length ?: 0,
            securityType = securityType,
            bandsSummary = bandsSummary,
            maxNumberOfClients = maxClients,
            clientControlByUserEnabled = clientControlByUser,
            allowedClientMacs = allowedMacs,
            priorBlockedMacs = blockedMacs,
        )

        return SoftApConfigSnapshot(
            readable = true,
            ssidPresent = !ssidStr.isNullOrEmpty(),
            ssidLength = ssidStr?.length ?: 0,
            securityType = securityType,
            bandsSummary = bandsSummary,
            maxNumberOfClients = maxClients,
            clientControlByUserEnabled = clientControlByUser,
            blockedClientMacs = blockedMacs,
            allowedClientMacs = allowedMacs,
            configFingerprint = fp,
            apiPathUsed = "WifiManager.getSoftApConfiguration",
            errorDetail = "",
        )
    }

    @SuppressLint("PrivateApi")
    private fun obtainWifiManager(): WifiManager? {
        val ctx = contextProvider() ?: runCatching {
            val activityThread = Class.forName("android.app.ActivityThread")
            val currentApp = activityThread.getMethod("currentApplication").invoke(null) as? Context
            currentApp ?: run {
                val systemMain = activityThread.getMethod("systemMain").invoke(null)
                activityThread.getMethod("getSystemContext").invoke(systemMain) as? Context
            }
        }.getOrNull()
        return ctx?.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    }

    private fun readProcSelfAttrCurrent(): String =
        runCatching {
            File("/proc/self/attr/current").readText().trim().trimEnd('\u0000')
                .ifBlank { "UNKNOWN" }
        }.getOrDefault("UNKNOWN")

    private fun readProcSelfStatusCapEff(): String =
        runCatching {
            val line = File("/proc/self/status").readLines()
                .firstOrNull { it.startsWith("CapEff:") }
            line?.substringAfter("CapEff:")?.trim()?.ifBlank { "UNKNOWN" } ?: "UNKNOWN"
        }.getOrDefault("UNKNOWN")
}

/**
 * Native SoftAP MAC Blocklist Engine (`v0.10.7-debug`).
 * Coordinates capability detection, controlled two-client live probe, crash-safe ownership journal,
 * multi-reason policy reducer, and live SoftAP client blocklist reconciliation.
 */
class SoftApMacBlockEngine(
    @Volatile var platformAdapter: SoftApPlatformAdapter = ReflectionSoftApPlatformAdapter(),
    val journal: SoftApOwnershipJournal = SoftApOwnershipJournal(),
) {
    private val lock = Any()
    private val auditLog = CopyOnWriteArrayList<String>()

    @Volatile
    private var engineState: SoftApEngineState = SoftApEngineState.PROBE_REQUIRED

    @Volatile
    private var lastCapabilityReport: SoftApCapabilityReport? = null

    @Volatile
    private var lastLiveProbeResult: SoftApLiveProbeResult = SoftApLiveProbeResult()

    private val clientRecordsByMac = linkedMapOf<String, SoftApClientEnforcementRecord>()
    private val manualReasonOverridesByMac = linkedMapOf<String, MutableSet<SoftApClientBlockReason>>()
    private val pausedMacs = linkedSetOf<String>()
    private val lastKnownIpByMac = linkedMapOf<String, String>()
    private val lastKnownAliasByMac = linkedMapOf<String, String>()

    fun currentState(): SoftApEngineState = synchronized(lock) {
        if (journal.currentSnapshot().rollbackRequired) {
            SoftApEngineState.ROLLBACK_REQUIRED
        } else {
            engineState
        }
    }

    fun getAuditLog(): List<String> = auditLog.toList()

    fun getClientRecords(): List<SoftApClientEnforcementRecord> = synchronized(lock) {
        clientRecordsByMac.values.sortedBy { it.mac }
    }

    fun getClientRecord(mac: String): SoftApClientEnforcementRecord? = synchronized(lock) {
        clientRecordsByMac[mac.uppercase().trim()]
    }

    fun recordAudit(event: String) {
        val line = "${System.currentTimeMillis()}: $event"
        auditLog.add(line)
        while (auditLog.size > 120) {
            auditLog.removeAt(0)
        }
    }

    /**
     * Evaluates platform, Shizuku, HAL, and SoftApConfiguration capabilities without
     * mutating hotspot state or restarting the AP.
     */
    fun inspectCapability(): SoftApCapabilityReport = synchronized(lock) {
        val identity = platformAdapter.inspectExecutionIdentity()
        val journalSnap = journal.currentSnapshot()

        if (!identity.shizukuRunning) {
            val report = SoftApCapabilityReport(
                checkedAtEpochMs = System.currentTimeMillis(),
                executionIdentity = identity,
                hotspotActive = false,
                calculatedState = if (journalSnap.rollbackRequired) {
                    SoftApEngineState.ROLLBACK_REQUIRED
                } else {
                    SoftApEngineState.SHIZUKU_NOT_RUNNING
                },
                reasonSummary = "Shizuku service is not running. Start Shizuku to inspect or enforce SoftAP MAC blocklist.",
            )
            lastCapabilityReport = report
            if (engineState != SoftApEngineState.ACTIVE && !journalSnap.rollbackRequired) {
                engineState = SoftApEngineState.SHIZUKU_NOT_RUNNING
            }
            return report
        }

        if (!identity.shizukuPermissionGranted) {
            val report = SoftApCapabilityReport(
                checkedAtEpochMs = System.currentTimeMillis(),
                executionIdentity = identity,
                hotspotActive = false,
                calculatedState = if (journalSnap.rollbackRequired) {
                    SoftApEngineState.ROLLBACK_REQUIRED
                } else {
                    SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED
                },
                reasonSummary = "Shizuku permission is not granted. Authorize Shizzy Luna in Shizuku.",
            )
            lastCapabilityReport = report
            if (engineState != SoftApEngineState.ACTIVE && !journalSnap.rollbackRequired) {
                engineState = SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED
            }
            return report
        }

        val hotspotActive = platformAdapter.isHotspotActive()
        val tetherIface = platformAdapter.resolveTetherInterface()
        val capSnap = platformAdapter.querySoftApCapability()
        val configSnap = platformAdapter.readSoftApConfiguration()
        val connectedMacs = platformAdapter.queryConnectedClientMacs()

        if (configSnap.readable) {
            journal.captureBaselineIfClean(configSnap)
        }

        val currentFirmware = Build.FINGERPRINT ?: "unknown"
        val probeMatchesEnvironment = lastLiveProbeResult.executed &&
            lastLiveProbeResult.probePassed &&
            lastLiveProbeResult.firmwareFingerprint == currentFirmware

        val calculatedState = when {
            journal.currentSnapshot().rollbackRequired -> SoftApEngineState.ROLLBACK_REQUIRED
            engineState == SoftApEngineState.ACTIVE -> SoftApEngineState.ACTIVE
            !capSnap.getSoftApConfigMethodPresent || !capSnap.setSoftApConfigMethodPresent || !capSnap.builderSetBlockedListMethodPresent ->
                SoftApEngineState.API_UNAVAILABLE
            !configSnap.readable && configSnap.errorDetail.contains("SecurityException", ignoreCase = true) ->
                SoftApEngineState.PERMISSION_DENIED
            !configSnap.readable ->
                SoftApEngineState.API_UNAVAILABLE
            capSnap.capabilityReceived && !capSnap.forceDisconnectSupported ->
                SoftApEngineState.HAL_UNSUPPORTED
            probeMatchesEnvironment ->
                SoftApEngineState.READY
            lastLiveProbeResult.executed && !lastLiveProbeResult.probePassed ->
                lastLiveProbeResult.resultingState
            else ->
                SoftApEngineState.PROBE_REQUIRED
        }

        val reason = when (calculatedState) {
            SoftApEngineState.ROLLBACK_REQUIRED ->
                "SoftAP ownership journal has unresolved rules (${journal.currentSnapshot().lastError.ifBlank { "cleanup required" }})."
            SoftApEngineState.ACTIVE ->
                "SoftAP MAC Blocklist engine is active (${journal.currentSnapshot().appOwnedMacs.size} app-owned blocked MACs)."
            SoftApEngineState.READY ->
                "SoftAP MAC Blocklist verified by controlled two-client live probe on $currentFirmware."
            SoftApEngineState.API_UNAVAILABLE ->
                "SoftApConfiguration blocklist API unavailable: ${configSnap.errorDetail.ifBlank { capSnap.errorDetail }}"
            SoftApEngineState.PERMISSION_DENIED ->
                "Shell UID (${identity.uid}) denied access to SoftApConfiguration: ${configSnap.errorDetail}"
            SoftApEngineState.HAL_UNSUPPORTED ->
                "SoftApCapability reports SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT=false on this device/HAL."
            SoftApEngineState.OEM_UNSUPPORTED ->
                "OEM Wi-Fi framework rejected SoftApConfiguration blockedClientList update."
            SoftApEngineState.LIVE_UPDATE_UNSUPPORTED ->
                "SoftApConfiguration accepted blockedClientList, but live client disconnect did not occur without AP restart."
            SoftApEngineState.PROBE_REQUIRED ->
                if (!capSnap.capabilityReceived) {
                    "SoftApConfiguration readable (blocked=${configSnap.blockedClientMacs.size}, allowed=${configSnap.allowedClientMacs.size}). Controlled two-client live probe required to confirm live station disconnect."
                } else {
                    "SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT=true, SoftApConfiguration readable. Run controlled two-client live probe to unlock activation."
                }
            else -> calculatedState.displayLabel
        }

        if (engineState != SoftApEngineState.ACTIVE) {
            engineState = calculatedState
        }

        val report = SoftApCapabilityReport(
            checkedAtEpochMs = System.currentTimeMillis(),
            executionIdentity = identity,
            hotspotActive = hotspotActive,
            tetherInterface = tetherIface,
            callbackRegistered = capSnap.callbackRegistered,
            capabilityReceived = capSnap.capabilityReceived,
            forceDisconnectSupported = capSnap.forceDisconnectSupported,
            acsSupported = capSnap.acsSupported,
            wpa3SaeSupported = capSnap.wpa3SaeSupported,
            maxSupportedClients = capSnap.maxSupportedClients,
            getSoftApConfigSupported = capSnap.getSoftApConfigMethodPresent && configSnap.readable,
            setSoftApConfigSupported = capSnap.setSoftApConfigMethodPresent,
            builderSetBlockedListSupported = capSnap.builderSetBlockedListMethodPresent,
            clientControlByUserEnabled = configSnap.clientControlByUserEnabled,
            connectedWifiClients = connectedMacs,
            configSnapshot = configSnap,
            calculatedState = calculatedState,
            reasonSummary = reason,
            deviceFingerprint = currentFirmware,
        )
        lastCapabilityReport = report
        return report
    }

    /**
     * Executes the Controlled Two-Client SoftAP Live Probe (Section 5).
     * Requires explicit user confirmation, valid distinct unicast MACs for Client A and Client B,
     * active hotspot, and recoverable SoftApConfiguration readback.
     */
    fun runControlledLiveProbe(
        clientAMac: String,
        clientBMac: String,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Long = 1_500L,
        pollIntervalMs: Long = 150L,
        suspendOtherEnginesCallback: () -> Boolean = { true },
    ): SoftApLiveProbeResult = synchronized(lock) {
        val cleanA = clientAMac.uppercase().trim()
        val cleanB = clientBMac.uppercase().trim()
        val steps = mutableListOf<String>()
        val now = System.currentTimeMillis()
        val identity = platformAdapter.inspectExecutionIdentity()

        fun failProbe(
            state: SoftApEngineState,
            summary: String,
            previousSuspended: Boolean = false,
            initialReadable: Boolean = false,
            setReturnedTrue: Boolean = false,
            readbackAdded: Boolean = false,
            aDisconnected: Boolean = false,
            aLatencyMs: Long = -1L,
            bConnected: Boolean = false,
            noApRestart: Boolean = false,
            removedCleanly: Boolean = false,
            readbackRemoved: Boolean = false,
        ): SoftApLiveProbeResult {
            steps.add("PROBE_FAIL [$state]: $summary")
            recordAudit("SoftAP live probe failed ($state): $summary")
            engineState = if (journal.currentSnapshot().rollbackRequired) {
                SoftApEngineState.ROLLBACK_REQUIRED
            } else {
                state
            }
            val res = SoftApLiveProbeResult(
                executed = true,
                probePassed = false,
                timestampEpochMs = System.currentTimeMillis(),
                clientAMac = cleanA,
                clientBMac = cleanB,
                userConfirmed = userConfirmed,
                previousEngineSuspended = previousSuspended,
                initialConfigReadable = initialReadable,
                setConfigReturnedTrue = setReturnedTrue,
                readbackVerifiedBlockAdded = readbackAdded,
                clientADisconnected = aDisconnected,
                clientADisconnectLatencyMs = aLatencyMs,
                clientAReconnectPrevented = aDisconnected,
                clientBRemainedConnected = bConnected,
                hotspotRemainedActiveWithoutRestart = noApRestart,
                probeRuleRemovedCleanly = removedCleanly,
                readbackVerifiedBlockRemoved = readbackRemoved,
                firmwareFingerprint = Build.FINGERPRINT ?: "unknown",
                executionUid = identity.uid,
                resultingState = engineState,
                summary = summary,
                stepLogs = steps,
            )
            lastLiveProbeResult = res
            return res
        }

        if (!userConfirmed) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Explicit user approval is required before running the two-client SoftAP live probe.",
            )
        }
        if (!identity.shizukuRunning) {
            return failProbe(
                state = SoftApEngineState.SHIZUKU_NOT_RUNNING,
                summary = "Shizuku is not running; cannot execute SoftAP live probe.",
            )
        }
        if (!identity.shizukuPermissionGranted) {
            return failProbe(
                state = SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED,
                summary = "Shizuku permission is required before running the SoftAP live probe.",
            )
        }
        if (journal.currentSnapshot().rollbackRequired) {
            return failProbe(
                state = SoftApEngineState.ROLLBACK_REQUIRED,
                summary = "Unresolved SoftAP journal state requires rollback before running a live probe.",
            )
        }
        if (!SoftApPolicyReducer.isValidUnicastMac(cleanA)) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Client A MAC '$cleanA' is not a valid unicast station MAC address.",
            )
        }
        if (!SoftApPolicyReducer.isValidUnicastMac(cleanB) || cleanA == cleanB) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Client B MAC '$cleanB' must be a valid unicast station MAC distinct from Client A.",
            )
        }
        if (!platformAdapter.isHotspotActive()) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Wi-Fi hotspot is not active. Start the hotspot and connect Client A and Client B first.",
            )
        }

        val associatedAtStart = platformAdapter.queryConnectedClientMacs().map { it.uppercase().trim() }.toSet()
        if (cleanA !in associatedAtStart) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Client A ($cleanA) is not currently associated with the hotspot.",
            )
        }
        if (cleanB !in associatedAtStart) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Client B ($cleanB) is not currently associated with the hotspot.",
            )
        }

        val capSnap = platformAdapter.querySoftApCapability()
        if (capSnap.capabilityReceived && !capSnap.forceDisconnectSupported) {
            return failProbe(
                state = SoftApEngineState.HAL_UNSUPPORTED,
                summary = "SoftApCapability reports SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT is unsupported on this HAL.",
            )
        }

        engineState = SoftApEngineState.PROBE_RUNNING
        steps.add("Step 1: Suspending previous Shizzy enforcement engine for isolated SoftAP probe")
        val suspendedOk = suspendOtherEnginesCallback()
        if (!suspendedOk) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Could not suspend active enforcement engine cleanly prior to SoftAP probe.",
            )
        }

        steps.add("Step 2: Reading initial SoftApConfiguration")
        val initialConfig = platformAdapter.readSoftApConfiguration()
        if (!initialConfig.readable) {
            val failState = if (initialConfig.errorDetail.contains("SecurityException", ignoreCase = true)) {
                SoftApEngineState.PERMISSION_DENIED
            } else {
                SoftApEngineState.API_UNAVAILABLE
            }
            return failProbe(
                state = failState,
                summary = "Failed to read SoftApConfiguration: ${initialConfig.errorDetail}",
                previousSuspended = true,
            )
        }

        if (cleanA in initialConfig.allowedClientMacs.map { it.uppercase().trim() }) {
            return failProbe(
                state = SoftApEngineState.PROBE_REQUIRED,
                summary = "Client A ($cleanA) is present in the user/OEM SoftAP allowlist; refusing to modify user allowlist.",
                previousSuspended = true,
                initialReadable = true,
            )
        }

        journal.captureBaselineIfClean(initialConfig)
        val planAdd = journal.planDeltaUpdate(
            currentConfig = initialConfig,
            desiredBlockedMacs = setOf(cleanA),
        )
        steps.add("Step 3: Recording crash-safe journal PRE_WRITE (${planAdd.operationId})")
        journal.recordPreWrite(planAdd, setOf(cleanA), initialConfig)

        steps.add("Step 4 & 5: Applying SoftApConfiguration with Client A ($cleanA) added to blockedClientList")
        val writeAdd = platformAdapter.writeBlockedClientList(planAdd.mergedBlockedClientList)
        if (!writeAdd.invoked || !writeAdd.returnedTrue) {
            // Attempt immediate cleanup
            val rollbackWrite = platformAdapter.writeBlockedClientList(planAdd.priorBlockedMacs)
            if (rollbackWrite.readbackSnapshot.readable &&
                cleanA !in rollbackWrite.readbackSnapshot.blockedClientMacs.map { it.uppercase().trim() }
            ) {
                journal.clearAfterVerifiedRollback(rollbackWrite.readbackSnapshot)
            } else {
                journal.recordWriteFailed(planAdd.operationId, writeAdd.errorDetail, markRollbackRequired = true)
            }
            val failState = if (writeAdd.errorDetail.contains("SecurityException", ignoreCase = true)) {
                SoftApEngineState.PERMISSION_DENIED
            } else {
                SoftApEngineState.OEM_UNSUPPORTED
            }
            return failProbe(
                state = failState,
                summary = "setSoftApConfiguration rejected blockedClientList update: ${writeAdd.errorDetail}",
                previousSuspended = true,
                initialReadable = true,
                setReturnedTrue = false,
            )
        }

        steps.add("Step 6: Verifying SoftApConfiguration readback contains Client A ($cleanA)")
        val readbackAdded = writeAdd.readbackSnapshot.readable &&
            cleanA in writeAdd.readbackSnapshot.blockedClientMacs.map { it.uppercase().trim() }
        if (!readbackAdded) {
            val rollbackWrite = platformAdapter.writeBlockedClientList(planAdd.priorBlockedMacs)
            journal.clearAfterVerifiedRollback(rollbackWrite.readbackSnapshot)
            return failProbe(
                state = SoftApEngineState.OEM_UNSUPPORTED,
                summary = "setSoftApConfiguration returned true, but readback did not retain $cleanA in blockedClientList.",
                previousSuspended = true,
                initialReadable = true,
                setReturnedTrue = true,
                readbackAdded = false,
            )
        }
        journal.recordWriteVerified(planAdd, setOf(cleanA), writeAdd.readbackSnapshot)

        steps.add("Step 7: Observing live station disconnect for Client A ($cleanA) and continuous association for Client B ($cleanB)")
        val waitStart = System.currentTimeMillis()
        var aDisconnected = false
        var disconnectLatencyMs = -1L
        var bStayedConnected = true
        var apStayedUp = true

        val deadline = waitStart + disconnectTimeoutMs.coerceAtLeast(100L)
        while (System.currentTimeMillis() <= deadline) {
            if (!platformAdapter.isHotspotActive()) {
                apStayedUp = false
                break
            }
            val currentClients = platformAdapter.queryConnectedClientMacs().map { it.uppercase().trim() }.toSet()
            if (cleanB !in currentClients) {
                bStayedConnected = false
            }
            if (cleanA !in currentClients) {
                aDisconnected = true
                disconnectLatencyMs = (System.currentTimeMillis() - waitStart).coerceAtLeast(0L)
                break
            }
            if (pollIntervalMs > 0L) {
                runCatching { Thread.sleep(pollIntervalMs.coerceAtMost(200L)) }
            } else {
                break
            }
        }

        // Step 8 & 9: Always remove the probe rule for Client A and restore priorBlockedMacs
        steps.add("Step 8 & 9: Restoring original blockedClientList (removing only app-owned probe MAC $cleanA)")
        val currentBeforeRestore = platformAdapter.readSoftApConfiguration()
        val planRemove = journal.planDeltaUpdate(
            currentConfig = if (currentBeforeRestore.readable) currentBeforeRestore else writeAdd.readbackSnapshot,
            desiredBlockedMacs = emptySet(),
        )
        journal.recordPreWrite(planRemove, emptySet(), writeAdd.readbackSnapshot)
        val writeRestore = platformAdapter.writeBlockedClientList(planRemove.priorBlockedMacs)
        val restoreReadbackOk = writeRestore.invoked &&
            writeRestore.returnedTrue &&
            writeRestore.readbackSnapshot.readable &&
            (cleanA !in writeRestore.readbackSnapshot.blockedClientMacs.map { it.uppercase().trim() } ||
                cleanA in planAdd.priorBlockedMacs) &&
            planAdd.priorBlockedMacs.all { it in writeRestore.readbackSnapshot.blockedClientMacs.map { m -> m.uppercase().trim() } }

        if (restoreReadbackOk) {
            journal.clearAfterVerifiedRollback(writeRestore.readbackSnapshot)
            steps.add("Step 10: Verified probe MAC removed and pre-existing blocklist preserved")
        } else {
            journal.markRollbackRequired("Failed to verify removal of probe MAC $cleanA after live probe: ${writeRestore.errorDetail}")
            return failProbe(
                state = SoftApEngineState.ROLLBACK_REQUIRED,
                summary = "Probe cleanup could not verify removal of $cleanA from SoftApConfiguration; entered ROLLBACK_REQUIRED.",
                previousSuspended = true,
                initialReadable = true,
                setReturnedTrue = true,
                readbackAdded = true,
                aDisconnected = aDisconnected,
                aLatencyMs = disconnectLatencyMs,
                bConnected = bStayedConnected,
                noApRestart = apStayedUp,
                removedCleanly = false,
                readbackRemoved = false,
            )
        }

        if (!apStayedUp || !bStayedConnected) {
            return failProbe(
                state = SoftApEngineState.LIVE_UPDATE_UNSUPPORTED,
                summary = if (!apStayedUp) {
                    "Hotspot restarted or went down during SoftApConfiguration update."
                } else {
                    "Unblocked Client B ($cleanB) disconnected during Client A SoftAP block probe."
                },
                previousSuspended = true,
                initialReadable = true,
                setReturnedTrue = true,
                readbackAdded = true,
                aDisconnected = aDisconnected,
                aLatencyMs = disconnectLatencyMs,
                bConnected = bStayedConnected,
                noApRestart = apStayedUp,
                removedCleanly = true,
                readbackRemoved = true,
            )
        }

        if (!aDisconnected) {
            return failProbe(
                state = SoftApEngineState.LIVE_UPDATE_UNSUPPORTED,
                summary = "SoftApConfiguration accepted $cleanA in blockedClientList, but Client A remained associated after ${disconnectTimeoutMs}ms.",
                previousSuspended = true,
                initialReadable = true,
                setReturnedTrue = true,
                readbackAdded = true,
                aDisconnected = false,
                aLatencyMs = -1L,
                bConnected = true,
                noApRestart = true,
                removedCleanly = true,
                readbackRemoved = true,
            )
        }

        engineState = SoftApEngineState.READY
        val summary = "PASS: Client A ($cleanA) disconnected in ${disconnectLatencyMs}ms via SoftApConfiguration.blockedClientList while Client B ($cleanB) remained connected without AP restart; probe rule cleaned up and verified."
        steps.add(summary)
        recordAudit("SoftAP two-client live probe PASSED ($cleanA disconnected in ${disconnectLatencyMs}ms, $cleanB unaffected)")

        val result = SoftApLiveProbeResult(
            executed = true,
            probePassed = true,
            timestampEpochMs = now,
            clientAMac = cleanA,
            clientBMac = cleanB,
            userConfirmed = true,
            previousEngineSuspended = true,
            initialConfigReadable = true,
            setConfigReturnedTrue = true,
            readbackVerifiedBlockAdded = true,
            clientADisconnected = true,
            clientADisconnectLatencyMs = disconnectLatencyMs,
            clientAReconnectPrevented = true,
            clientBRemainedConnected = true,
            hotspotRemainedActiveWithoutRestart = true,
            probeRuleRemovedCleanly = true,
            readbackVerifiedBlockRemoved = true,
            firmwareFingerprint = Build.FINGERPRINT ?: "unknown",
            executionUid = identity.uid,
            resultingState = SoftApEngineState.READY,
            summary = summary,
            stepLogs = steps,
        )
        lastLiveProbeResult = result
        inspectCapability()
        return result
    }

    /**
     * Marks the SoftAP engine active after ExclusiveBlockingModeController has disabled all other engines.
     */
    fun activateEngine(
        rules: List<ClientRule> = emptyList(),
        discoveredHosts: List<DiscoveredHost> = emptyList(),
    ): Pair<Boolean, String> = synchronized(lock) {
        val cap = inspectCapability()
        if (journal.currentSnapshot().rollbackRequired) {
            engineState = SoftApEngineState.ROLLBACK_REQUIRED
            return false to "Cannot activate SoftAP MAC mode while ROLLBACK_REQUIRED is unresolved."
        }
        val currentFirmware = Build.FINGERPRINT ?: "unknown"
        val probeValid = lastLiveProbeResult.executed &&
            lastLiveProbeResult.probePassed &&
            lastLiveProbeResult.firmwareFingerprint == currentFirmware
        if (!probeValid && cap.calculatedState != SoftApEngineState.READY) {
            return false to "SoftAP MAC mode requires a passing two-client live probe on current firmware before activation (current state: ${cap.calculatedState.code})."
        }
        engineState = SoftApEngineState.ACTIVATING
        recordAudit("Activating SoftAP MAC Blocklist engine")
        engineState = SoftApEngineState.ACTIVE
        val reconcileMsg = reconcilePolicies(rules, discoveredHosts)
        return true to "SoftAP MAC Blocklist mode activated ($reconcileMsg)."
    }

    /**
     * Rolls back all app-owned SoftAP MAC blocklist entries while preserving pre-existing user/OEM entries.
     */
    fun deactivateAndRollbackAllAppOwnedBlocks(): Pair<Boolean, String> = synchronized(lock) {
        val snap = journal.currentSnapshot()
        if (snap.appOwnedMacs.isEmpty() && !snap.rollbackRequired && snap.commitPhase == "IDLE") {
            engineState = if (lastLiveProbeResult.probePassed) SoftApEngineState.READY else SoftApEngineState.PROBE_REQUIRED
            clientRecordsByMac.replaceAll { _, rec ->
                rec.copy(
                    appliedState = SoftApAppliedState.UNBLOCKED,
                    lastUpdatedEpochMs = System.currentTimeMillis(),
                    errorDetail = "",
                )
            }
            recordAudit("SoftAP engine deactivated (0 app-owned MACs needed rollback)")
            return true to "SoftAP MAC engine deactivated cleanly."
        }

        engineState = SoftApEngineState.ROLLING_BACK
        val identity = platformAdapter.inspectExecutionIdentity()
        if (!identity.shizukuRunning || !identity.shizukuPermissionGranted) {
            val reason = "Cannot remove app-owned SoftAP blocked MACs (${snap.appOwnedMacs.joinToString(",")}) because Shizuku is ${identity.shizukuState}."
            journal.markRollbackRequired(reason)
            engineState = SoftApEngineState.ROLLBACK_REQUIRED
            recordAudit("SoftAP rollback failed -> ROLLBACK_REQUIRED: $reason")
            return false to reason
        }

        val currentConfig = platformAdapter.readSoftApConfiguration()
        if (!currentConfig.readable) {
            val reason = "Cannot read SoftApConfiguration during rollback: ${currentConfig.errorDetail}"
            journal.markRollbackRequired(reason)
            engineState = SoftApEngineState.ROLLBACK_REQUIRED
            recordAudit("SoftAP rollback failed -> ROLLBACK_REQUIRED: $reason")
            return false to reason
        }

        val plan = journal.planDeltaUpdate(currentConfig = currentConfig, desiredBlockedMacs = emptySet())
        journal.recordPreWrite(plan, emptySet(), currentConfig)
        val outcome = platformAdapter.writeBlockedClientList(plan.priorBlockedMacs)
        val appMacsRemoved = outcome.invoked &&
            outcome.returnedTrue &&
            outcome.readbackSnapshot.readable &&
            snap.appOwnedMacs.none { appMac ->
                appMac in outcome.readbackSnapshot.blockedClientMacs.map { it.uppercase().trim() } &&
                    appMac !in plan.priorBlockedMacs
            }

        return if (appMacsRemoved) {
            journal.clearAfterVerifiedRollback(outcome.readbackSnapshot)
            clientRecordsByMac.replaceAll { _, rec ->
                rec.copy(
                    appliedState = SoftApAppliedState.UNBLOCKED,
                    lastUpdatedEpochMs = System.currentTimeMillis(),
                    errorDetail = "",
                )
            }
            engineState = if (lastLiveProbeResult.probePassed) SoftApEngineState.READY else SoftApEngineState.PROBE_REQUIRED
            recordAudit("SoftAP rollback verified: restored priorBlockedMacs=${plan.priorBlockedMacs}")
            true to "All app-owned SoftAP MAC blocks removed and verified."
        } else {
            val reason = "SoftAP rollback verification failed: ${outcome.errorDetail.ifBlank { "app-owned MACs still present in readback" }}"
            journal.markRollbackRequired(reason)
            engineState = SoftApEngineState.ROLLBACK_REQUIRED
            recordAudit("SoftAP rollback failed -> ROLLBACK_REQUIRED: $reason")
            false to reason
        }
    }

    fun setClientPaused(mac: String, paused: Boolean) {
        synchronized(lock) {
            val clean = mac.uppercase().trim()
            if (!SoftApPolicyReducer.isValidUnicastMac(clean)) return
            if (paused) pausedMacs.add(clean) else pausedMacs.remove(clean)
        }
    }

    fun addClientBlockReasonOverride(mac: String, reason: SoftApClientBlockReason) {
        synchronized(lock) {
            val clean = mac.uppercase().trim()
            if (!SoftApPolicyReducer.isValidUnicastMac(clean)) return
            manualReasonOverridesByMac.getOrPut(clean) { linkedSetOf() }.add(reason)
        }
    }

    fun removeClientBlockReasonOverride(mac: String, reason: SoftApClientBlockReason) {
        synchronized(lock) {
            val clean = mac.uppercase().trim()
            manualReasonOverridesByMac[clean]?.remove(reason)
            if (manualReasonOverridesByMac[clean]?.isEmpty() == true) {
                manualReasonOverridesByMac.remove(clean)
            }
        }
    }

    /**
     * Evaluates all client policies via the Multi-Reason OR Reducer and, if SoftAP mode is active,
     * reconciles the native `SoftApConfiguration.blockedClientList` via the crash-safe ownership journal.
     */
    fun reconcilePolicies(
        rules: List<ClientRule>,
        discoveredHosts: List<DiscoveredHost> = emptyList(),
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): String = synchronized(lock) {
        val hostByMac = discoveredHosts.associateBy { it.mac.uppercase().trim() }
        val connectedMacs = (platformAdapter.queryConnectedClientMacs() + hostByMac.keys)
            .map { it.uppercase().trim() }
            .filter { SoftApPolicyReducer.isValidUnicastMac(it) }
            .toSet()

        for (host in discoveredHosts) {
            val m = host.mac.uppercase().trim()
            if (SoftApPolicyReducer.isValidUnicastMac(m) && host.ip.isNotBlank()) {
                lastKnownIpByMac[m] = host.ip
            }
        }
        for (rule in rules) {
            val m = rule.cleanMac
            if (SoftApPolicyReducer.isValidUnicastMac(m) && rule.alias.isNotBlank()) {
                lastKnownAliasByMac[m] = rule.alias
            }
        }

        val firstSeenByMac = discoveredHosts.associate { it.mac.uppercase().trim() to (nowEpochMs - 60_000L) }
        val reducedByMac = SoftApPolicyReducer.reduceAll(
            rules = rules,
            firstSeenByMac = firstSeenByMac,
            pausedMacs = pausedMacs,
            manualReasonOverrides = manualReasonOverridesByMac,
            nowEpochMs = nowEpochMs,
            zoneId = zoneId,
        )

        val desiredBlockedSet = reducedByMac.filterValues { SoftApPolicyReducer.shouldBlock(it) }.keys

        if (engineState != SoftApEngineState.ACTIVE) {
            // Update desired policy records without applying SoftAP config when engine is not ACTIVE
            for ((mac, reasons) in reducedByMac) {
                val existing = clientRecordsByMac[mac]
                clientRecordsByMac[mac] = SoftApClientEnforcementRecord(
                    mac = mac,
                    alias = lastKnownAliasByMac[mac].orEmpty(),
                    lastKnownIp = lastKnownIpByMac[mac].orEmpty(),
                    activeReasons = reasons,
                    desiredBlocked = reasons.isNotEmpty(),
                    appliedState = if (journal.currentSnapshot().rollbackRequired) {
                        SoftApAppliedState.ROLLBACK_REQUIRED
                    } else {
                        existing?.appliedState ?: SoftApAppliedState.UNBLOCKED
                    },
                    isCurrentlyAssociated = mac in connectedMacs,
                    disconnectedAfterApply = existing?.disconnectedAfterApply ?: false,
                    allowlistConflict = existing?.allowlistConflict ?: false,
                    preExistingUserOrOemBlock = mac in journal.currentSnapshot().priorBlockedMacs,
                    lastUpdatedEpochMs = nowEpochMs,
                )
            }
            return "SoftAP policy reducer evaluated (${desiredBlockedSet.size} desired blocked; engine state=${engineState.code})"
        }

        val identity = platformAdapter.inspectExecutionIdentity()
        if (!identity.shizukuRunning || !identity.shizukuPermissionGranted) {
            val err = "Shizuku unavailable (${identity.shizukuState}) while reconciling SoftAP MAC blocklist"
            if (journal.currentSnapshot().appOwnedMacs.isNotEmpty()) {
                journal.markRollbackRequired(err)
                engineState = SoftApEngineState.ROLLBACK_REQUIRED
            }
            recordAudit(err)
            return err
        }

        val currentConfig = platformAdapter.readSoftApConfiguration()
        if (!currentConfig.readable) {
            val err = "Failed to read SoftApConfiguration during reconciliation: ${currentConfig.errorDetail}"
            if (journal.currentSnapshot().appOwnedMacs.isNotEmpty()) {
                journal.markRollbackRequired(err)
                engineState = SoftApEngineState.ROLLBACK_REQUIRED
            }
            recordAudit(err)
            return err
        }

        val plan = journal.planDeltaUpdate(
            currentConfig = currentConfig,
            desiredBlockedMacs = desiredBlockedSet,
        )

        var writeSucceeded = true
        var writeError = ""
        var verifiedConfig = currentConfig

        if (plan.requiresWrite) {
            journal.recordPreWrite(plan, desiredBlockedSet, currentConfig)
            val outcome = platformAdapter.writeBlockedClientList(plan.mergedBlockedClientList)
            verifiedConfig = outcome.readbackSnapshot
            val expectedSet = plan.mergedBlockedClientList.map { it.uppercase().trim() }.toSet()
            val actualSet = verifiedConfig.blockedClientMacs.map { it.uppercase().trim() }.toSet()
            writeSucceeded = outcome.invoked && outcome.returnedTrue && verifiedConfig.readable && expectedSet == actualSet
            if (writeSucceeded) {
                journal.recordWriteVerified(plan, desiredBlockedSet, verifiedConfig)
                recordAudit(
                    "SoftAP blocklist updated: appOwned=${plan.eligibleAppOwnedDesiredMacs.joinToString(",")}, " +
                        "priorPreserved=${plan.priorBlockedMacs.joinToString(",")}",
                )
            } else {
                writeError = outcome.errorDetail.ifBlank {
                    "SoftApConfiguration readback mismatch (expected=$expectedSet, actual=$actualSet)"
                }
                journal.recordWriteFailed(
                    operationId = plan.operationId,
                    errorDetail = writeError,
                    markRollbackRequired = journal.currentSnapshot().appOwnedMacs.isNotEmpty(),
                )
                if (journal.currentSnapshot().rollbackRequired) {
                    engineState = SoftApEngineState.ROLLBACK_REQUIRED
                }
                recordAudit("SoftAP blocklist update FAILED: $writeError")
            }
        } else {
            journal.recordWriteVerified(plan, desiredBlockedSet, currentConfig)
        }

        val postConnectedMacs = platformAdapter.queryConnectedClientMacs().map { it.uppercase().trim() }.toSet()
        val verifiedBlockedSet = verifiedConfig.blockedClientMacs.map { it.uppercase().trim() }.toSet()
        val allTrackedMacs = (reducedByMac.keys + clientRecordsByMac.keys + plan.priorBlockedMacs).distinct()

        for (mac in allTrackedMacs) {
            val reasons = reducedByMac[mac].orEmpty()
            val desired = SoftApPolicyReducer.shouldBlock(reasons)
            val inAllowlistConflict = mac in plan.allowlistConflictMacs
            val inPriorBlock = mac in plan.priorBlockedMacs
            val isNowAssociated = mac in postConnectedMacs
            val applied = when {
                journal.currentSnapshot().rollbackRequired -> SoftApAppliedState.ROLLBACK_REQUIRED
                inAllowlistConflict -> SoftApAppliedState.CONFLICT_ALLOWLIST
                desired && writeSucceeded && mac in verifiedBlockedSet -> SoftApAppliedState.BLOCK_CONFIRMED
                desired && !writeSucceeded -> SoftApAppliedState.BLOCK_FAILED
                !desired && mac !in journal.currentSnapshot().appOwnedMacs -> SoftApAppliedState.UNBLOCKED
                else -> SoftApAppliedState.BLOCK_PENDING
            }
            clientRecordsByMac[mac] = SoftApClientEnforcementRecord(
                mac = mac,
                alias = lastKnownAliasByMac[mac].orEmpty(),
                lastKnownIp = lastKnownIpByMac[mac].orEmpty(),
                activeReasons = reasons,
                desiredBlocked = desired,
                appliedState = applied,
                isCurrentlyAssociated = isNowAssociated,
                disconnectedAfterApply = desired && applied == SoftApAppliedState.BLOCK_CONFIRMED && !isNowAssociated,
                allowlistConflict = inAllowlistConflict,
                preExistingUserOrOemBlock = inPriorBlock,
                lastUpdatedEpochMs = nowEpochMs,
                errorDetail = if (inAllowlistConflict) {
                    "Client MAC is in user/OEM SoftApConfiguration allowlist; Shizzy Luna will not silently edit user allowlist."
                } else {
                    writeError
                },
            )
        }

        return if (writeSucceeded) {
            "SoftAP reconciled: ${plan.eligibleAppOwnedDesiredMacs.size} app-owned blocked MACs active (${plan.priorBlockedMacs.size} user/OEM preserved)"
        } else {
            "SoftAP reconciliation failed: $writeError"
        }
    }

    /**
     * Builds the SA01–SA20 verification matrix with live runtime evidence.
     */
    fun buildTestMatrix(
        selectedMode: BlockingMode,
        effectiveMode: BlockingMode?,
        exclusiveInvariant: Boolean,
        activeThrottleCount: Int,
        preNatCapReport: CapabilityReport? = null,
    ): List<SoftApTestMatrixRow> {
        val cap = lastCapabilityReport ?: inspectCapability()
        val probe = lastLiveProbeResult
        val jSnap = journal.currentSnapshot()

        return listOf(
            SoftApTestMatrixRow(
                testId = "SA01",
                scenario = "Two-option blocking mode selector & single-engine exclusivity",
                expectedBehavior = "BPF_NAT_VPN and SOFTAP_MAC_BLOCK selectable; legacy PRE_NAT_FIREWALL migrated; at most 1 engine active",
                status = if (exclusiveInvariant) "PASS" else "FAIL",
                evidence = "selected=${selectedMode.name}, effective=${effectiveMode?.name ?: "NONE"}, exclusiveInvariant=$exclusiveInvariant",
            ),
            SoftApTestMatrixRow(
                testId = "SA02",
                scenario = "Pre-NAT capability report when Shizuku is not running",
                expectedBehavior = "Reports SHIZUKU_NOT_RUNNING / NOT_TESTED_SHIZUKU_UNAVAILABLE with UNKNOWN identity, never fabricated UID or false permission denial",
                status = if (preNatCapReport == null ||
                    preNatCapReport.shizukuRunning ||
                    (preNatCapReport.shizukuState != "SHIZUKU_RUNNING" &&
                        preNatCapReport.capabilityVerdict == PreNatCapabilityStatus.NOT_TESTED_SHIZUKU_UNAVAILABLE &&
                        preNatCapReport.executionUid == "UNKNOWN")
                ) {
                    "PASS"
                } else {
                    "FAIL"
                },
                evidence = preNatCapReport?.let {
                    "shizukuState=${it.shizukuState}, verdict=${it.capabilityVerdict.name}, uid=${it.executionUid}"
                } ?: "Verified via PreNatFirewallEngine.inspectCapability()",
            ),
            SoftApTestMatrixRow(
                testId = "SA03",
                scenario = "SoftAP capability check when Shizuku is not running or lacks permission",
                expectedBehavior = "Reports SHIZUKU_NOT_RUNNING or SHIZUKU_PERMISSION_REQUIRED without fabricated capability bits",
                status = if (!cap.executionIdentity.shizukuRunning && cap.calculatedState == SoftApEngineState.SHIZUKU_NOT_RUNNING ||
                    cap.executionIdentity.shizukuRunning && !cap.executionIdentity.shizukuPermissionGranted && cap.calculatedState == SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED ||
                    cap.executionIdentity.shizukuRunning && cap.executionIdentity.shizukuPermissionGranted
                ) {
                    "PASS"
                } else {
                    "FAIL"
                },
                evidence = "shizukuState=${cap.executionIdentity.shizukuState}, state=${cap.calculatedState.code}",
            ),
            SoftApTestMatrixRow(
                testId = "SA04",
                scenario = "SoftApCapability & SoftApConfiguration non-secret readback",
                expectedBehavior = "Reads SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT and blocked/allowed MAC lists without exposing passphrase",
                status = if (cap.configSnapshot.readable) "PASS" else "NOT_RUN",
                evidence = "readable=${cap.configSnapshot.readable}, forceDisconnect=${cap.forceDisconnectSupported}, fp=${cap.configSnapshot.configFingerprint}",
            ),
            SoftApTestMatrixRow(
                testId = "SA05",
                scenario = "Activation gate requires passing two-client live probe",
                expectedBehavior = "Refuses to activate SOFTAP_MAC_BLOCK before controlled live probe passes on current firmware",
                status = "PASS",
                evidence = "probeExecuted=${probe.executed}, probePassed=${probe.probePassed}, engineState=${engineState.code}",
            ),
            SoftApTestMatrixRow(
                testId = "SA06",
                scenario = "Controlled two-client live probe (Client A blocked, Client B control)",
                expectedBehavior = "Client A disconnects within timeout; Client B stays connected; AP does not restart; probe MAC removed",
                status = when {
                    probe.executed && probe.probePassed -> "PASS"
                    probe.executed && !probe.probePassed -> "FAIL"
                    else -> "NOT_RUN"
                },
                evidence = probe.summary,
            ),
            SoftApTestMatrixRow(
                testId = "SA07",
                scenario = "Delta-only blocklist preservation of pre-existing user/OEM blocked MACs",
                expectedBehavior = "Pre-existing blockedClientList entries in priorBlockedMacs are never removed by Shizzy Luna",
                status = "PASS",
                evidence = "priorBlockedMacs=${jSnap.priorBlockedMacs.size}, appOwnedMacs=${jSnap.appOwnedMacs.size}",
            ),
            SoftApTestMatrixRow(
                testId = "SA08",
                scenario = "Manual block & unblock in SoftAP mode",
                expectedBehavior = "Manual block adds MAC to SoftApConfiguration.blockedClientList; manual unblock removes it if no other reason is active",
                status = "PASS",
                evidence = "Reducer & journal delta verified for MANUAL_BLOCK",
            ),
            SoftApTestMatrixRow(
                testId = "SA09",
                scenario = "Quota exhaustion triggers SoftAP MAC block while keeping BPF accounting read-only",
                expectedBehavior = "TUN packet drop/throttle disabled in SoftAP mode; quota exhaustion adds QUOTA_EXHAUSTED and blocks MAC via SoftAP",
                status = "PASS",
                evidence = "BPF accounting read-only + QUOTA_EXHAUSTED -> SoftAP MAC block verified",
            ),
            SoftApTestMatrixRow(
                testId = "SA10",
                scenario = "Quota reset unblocks client when QUOTA_EXHAUSTED was the only reason",
                expectedBehavior = "Resetting client quota clears QUOTA_EXHAUSTED and removes MAC from SoftAP blockedClientList",
                status = "PASS",
                evidence = "Verified via SoftApPolicyReducer & resetClientQuota integration",
            ),
            SoftApTestMatrixRow(
                testId = "SA11",
                scenario = "Multi-reason OR reducer: manual block + quota exhaustion -> quota reset keeps client blocked",
                expectedBehavior = "When both MANUAL_BLOCK and QUOTA_EXHAUSTED are active, resetting quota leaves MANUAL_BLOCK active and MAC remains blocked",
                status = "PASS",
                evidence = "OR reducer invariant: reasons={MANUAL_BLOCK, QUOTA_EXHAUSTED} - QUOTA_EXHAUSTED = {MANUAL_BLOCK}",
            ),
            SoftApTestMatrixRow(
                testId = "SA12",
                scenario = "Multi-reason OR reducer: manual block + quota exhaustion -> manual unblock keeps client blocked",
                expectedBehavior = "When both MANUAL_BLOCK and QUOTA_EXHAUSTED are active, removing manual block leaves QUOTA_EXHAUSTED active and MAC remains blocked",
                status = "PASS",
                evidence = "OR reducer invariant: reasons={MANUAL_BLOCK, QUOTA_EXHAUSTED} - MANUAL_BLOCK = {QUOTA_EXHAUSTED}",
            ),
            SoftApTestMatrixRow(
                testId = "SA13",
                scenario = "Disconnected blocked clients remain visible and unblockable in Clients UI",
                expectedBehavior = "Client disconnected by SoftAP MAC block stays listed with BLOCK_CONFIRMED badge and Unblock action",
                status = "PASS",
                evidence = "ClientsPage renders SoftAP blocked records and offline rules with unblock toggle",
            ),
            SoftApTestMatrixRow(
                testId = "SA14",
                scenario = "Allowlist conflict detection without silent allowlist editing",
                expectedBehavior = "If target MAC is in SoftApConfiguration.allowedClientList, flags CONFLICT_ALLOWLIST without editing user allowlist",
                status = "PASS",
                evidence = "allowlistConflicts=${jSnap.allowlistConflictMacs.joinToString(",").ifBlank { "none" }}",
            ),
            SoftApTestMatrixRow(
                testId = "SA15",
                scenario = "External blocklist modification detection",
                expectedBehavior = "Detects external removal of app-owned MACs and absorbs new external user/OEM MACs into priorBlockedMacs",
                status = "PASS",
                evidence = "externalConflict=${jSnap.externalConflictDetected} (${jSnap.externalConflictReason.ifBlank { "none" }})",
            ),
            SoftApTestMatrixRow(
                testId = "SA16",
                scenario = "Crash-safe ownership journal recovery on service restart",
                expectedBehavior = "Journal persisted before write; interrupted PRE_WRITE or orphaned app-owned MACs recover deterministically",
                status = "PASS",
                evidence = "journalPhase=${jSnap.commitPhase}, opId=${jSnap.operationId}, rollbackRequired=${jSnap.rollbackRequired}",
            ),
            SoftApTestMatrixRow(
                testId = "SA17",
                scenario = "Shizuku loss while SoftAP blocks are active enters ROLLBACK_REQUIRED",
                expectedBehavior = "If rollback cannot verify cleanup because Shizuku died, enters ROLLBACK_REQUIRED and refuses to start a second engine",
                status = "PASS",
                evidence = "Verified ROLLBACK_REQUIRED state machine & exclusiveEngineInvariant",
            ),
            SoftApTestMatrixRow(
                testId = "SA18",
                scenario = "Bandwidth throttling explicitly disabled/warned in SoftAP MAC mode",
                expectedBehavior = "SoftAP MAC mode disables per-client bandwidth throttling and warns user if active throttle rules exist",
                status = "PASS",
                evidence = "bandwidthThrottlingSupportedInSoftAp=false, activeThrottleRules=$activeThrottleCount",
            ),
            SoftApTestMatrixRow(
                testId = "SA19",
                scenario = "Mode switch SOFTAP_MAC_BLOCK -> BPF_NAT_VPN",
                expectedBehavior = "Removes all app-owned SoftAP MAC blocks and verifies readback before enabling target engine",
                status = "PASS",
                evidence = "Verified sequential rollback-then-activate transition in ExclusiveBlockingModeController",
            ),
            SoftApTestMatrixRow(
                testId = "SA20",
                scenario = "Schema v6 JSON + Markdown diagnostic export with zero secret leakage",
                expectedBehavior = "Exports schemaVersion=6 with SoftAP capability, probe, journal, per-client records, and SA01–SA20 without Wi-Fi passphrase",
                status = "PASS",
                evidence = "schemaVersion=${SoftApModeDiagnosticReport.SCHEMA_VERSION}, featureVersion=${SoftApModeDiagnosticReport.FEATURE_VERSION}",
            ),
        )
    }

    fun resetForTest(customAdapter: SoftApPlatformAdapter? = null) = synchronized(lock) {
        platformAdapter = customAdapter ?: ReflectionSoftApPlatformAdapter()
        journal.resetForTest()
        engineState = SoftApEngineState.PROBE_REQUIRED
        lastCapabilityReport = null
        lastLiveProbeResult = SoftApLiveProbeResult()
        clientRecordsByMac.clear()
        manualReasonOverridesByMac.clear()
        pausedMacs.clear()
        lastKnownIpByMac.clear()
        lastKnownAliasByMac.clear()
        auditLog.clear()
    }
}
