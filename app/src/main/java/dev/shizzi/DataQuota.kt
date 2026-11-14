package dev.shizzi

import java.io.File
import java.math.BigDecimal
import java.math.RoundingMode
import java.time.DayOfWeek
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.TemporalAdjusters
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

enum class QuotaResetPeriod(val displayName: String) {
    DAILY("Daily"),
    WEEKLY("Weekly"),
    MONTHLY("Monthly"),
    MANUAL("Manual"),
    ;

    companion object {
        fun fromName(raw: String?): QuotaResetPeriod {
            if (raw.isNullOrBlank()) return MANUAL
            return entries.firstOrNull { it.name.equals(raw.trim(), ignoreCase = true) } ?: MANUAL
        }
    }
}

data class DataLimitParseResult(
    val bytes: Long?,
    val mb: Long?,
    val errorMessage: String? = null,
) {
    val isValid: Boolean get() = bytes != null && errorMessage == null
}

data class QuotaWindowSpec(
    val period: QuotaResetPeriod,
    val windowId: String,
    val windowStartEpochMs: Long,
    val nextResetEpochMs: Long?,
    val nextResetFormatted: String,
)

data class ClientQuotaRecord(
    val mac: String,
    val dataLimitBytes: Long = 0L,
    val resetPeriod: QuotaResetPeriod = QuotaResetPeriod.MANUAL,
    val usedRxBytes: Long = 0L,
    val usedTxBytes: Long = 0L,
    val windowId: String = "",
    val windowStartEpochMs: Long = 0L,
    val lastUpdatedEpochMs: Long = 0L,
    val resetGeneration: Long = 0L,
) {
    val cleanMac: String get() = mac.uppercase().trim()
    val sanitizedRxBytes: Long get() = usedRxBytes.coerceAtLeast(0L)
    val sanitizedTxBytes: Long get() = usedTxBytes.coerceAtLeast(0L)
    val usedTotalBytes: Long
        get() = DataQuota.safeAddBytes(sanitizedRxBytes, sanitizedTxBytes)
    val sanitizedLimitBytes: Long get() = dataLimitBytes.coerceAtLeast(0L)

    val isQuotaEnabled: Boolean get() = sanitizedLimitBytes > 0L
    val isQuotaExceeded: Boolean
        get() = isQuotaEnabled && usedTotalBytes >= sanitizedLimitBytes

    val remainingBytes: Long
        get() = if (!isQuotaEnabled) Long.MAX_VALUE else (sanitizedLimitBytes - usedTotalBytes).coerceAtLeast(0L)

    val usagePercent: Int
        get() {
            if (!isQuotaEnabled) return 0
            val pct = (BigDecimal.valueOf(usedTotalBytes)
                .multiply(BigDecimal.valueOf(100L))
                .divide(BigDecimal.valueOf(sanitizedLimitBytes), 0, RoundingMode.FLOOR))
                .toLong()
            return pct.coerceIn(0L, 999L).toInt()
        }

    fun toJson(): JSONObject = JSONObject().apply {
        put("mac", cleanMac)
        put("dataLimitBytes", sanitizedLimitBytes)
        put("resetPeriod", resetPeriod.name)
        put("usedRxBytes", sanitizedRxBytes)
        put("usedTxBytes", sanitizedTxBytes)
        put("windowId", windowId)
        put("windowStartEpochMs", windowStartEpochMs.coerceAtLeast(0L))
        put("lastUpdatedEpochMs", lastUpdatedEpochMs.coerceAtLeast(0L))
        put("resetGeneration", resetGeneration.coerceAtLeast(0L))
    }

    companion object {
        fun fromJson(json: JSONObject): ClientQuotaRecord = ClientQuotaRecord(
            mac = json.optString("mac").uppercase().trim(),
            dataLimitBytes = json.optLong("dataLimitBytes", 0L).coerceAtLeast(0L),
            resetPeriod = QuotaResetPeriod.fromName(json.optString("resetPeriod", QuotaResetPeriod.MANUAL.name)),
            usedRxBytes = json.optLong("usedRxBytes", 0L).coerceAtLeast(0L),
            usedTxBytes = json.optLong("usedTxBytes", 0L).coerceAtLeast(0L),
            windowId = json.optString("windowId", ""),
            windowStartEpochMs = json.optLong("windowStartEpochMs", 0L).coerceAtLeast(0L),
            lastUpdatedEpochMs = json.optLong("lastUpdatedEpochMs", 0L).coerceAtLeast(0L),
            resetGeneration = json.optLong("resetGeneration", 0L).coerceAtLeast(0L),
        )
    }
}

object DataQuota {

    const val BYTES_PER_KB: Long = 1024L
    const val BYTES_PER_MB: Long = 1024L * 1024L // 1,048,576 bytes
    const val BYTES_PER_GB: Long = 1024L * BYTES_PER_MB // 1,073,741,824 bytes
    const val MAX_QUOTA_MB: Long = Long.MAX_VALUE / BYTES_PER_MB // 8,796,093,022,207 MB

    const val STABLE_CHECKPOINT_FILE_PATH = "/data/local/tmp/shizzyluna-quota-state.json"
    const val DEBUG_CHECKPOINT_FILE_PATH = "/data/local/tmp/shizzyluna-debug-quota-state.json"
    val DEFAULT_CHECKPOINT_FILE_PATH: String
        get() = if (BuildConfig.APPLICATION_ID.endsWith(".debug")) {
            DEBUG_CHECKPOINT_FILE_PATH
        } else {
            STABLE_CHECKPOINT_FILE_PATH
        }
    const val CHECKPOINT_MIN_INTERVAL_MS = 2_000L
    const val CHECKPOINT_BYTE_DELTA_THRESHOLD = 64L * 1024L // 64 KB

    private val STRICT_INTEGER_REGEX = Regex("""^\d+$""")
    private val NEXT_RESET_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.US)

    fun safeAddBytes(a: Long, b: Long): Long {
        val sa = a.coerceAtLeast(0L)
        val sb = b.coerceAtLeast(0L)
        return if (Long.MAX_VALUE - sa < sb) Long.MAX_VALUE else sa + sb
    }

    /**
     * Validates a user-entered integer MB string (`0 = Unlimited`, `1 MB = 1,048,576 bytes`).
     * Rejects empty, negative, fractional/decimal, non-numeric, and overflow values.
     */
    fun validateDataLimitMbInput(rawInput: String): DataLimitParseResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Enter a data limit in MB (0 = Unlimited).",
            )
        }
        if (trimmed.startsWith("-")) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Data limit cannot be negative.",
            )
        }
        if (trimmed.contains('.') || trimmed.contains(',')) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Enter a whole integer in MB (no decimals).",
            )
        }
        if (!STRICT_INTEGER_REGEX.matches(trimmed)) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Enter a valid non-negative integer in MB (e.g. 0, 500, 2048).",
            )
        }
        val mbValue = trimmed.toLongOrNull()
            ?: return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Data limit is too large (exceeds maximum supported MB).",
            )
        if (mbValue < 0L) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Data limit cannot be negative.",
            )
        }
        if (mbValue > MAX_QUOTA_MB) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Data limit is too large (max $MAX_QUOTA_MB MB).",
            )
        }
        val bytesValue = try {
            Math.multiplyExact(mbValue, BYTES_PER_MB)
        } catch (_: ArithmeticException) {
            return DataLimitParseResult(
                bytes = null,
                mb = null,
                errorMessage = "Data limit overflows byte counter.",
            )
        }
        return DataLimitParseResult(bytes = bytesValue, mb = mbValue, errorMessage = null)
    }

    fun parseMbToBytes(rawInput: String): Long? = validateDataLimitMbInput(rawInput).bytes

    fun parseDataLimitMbToBytes(rawInput: String): Long? = validateDataLimitMbInput(rawInput).bytes

    fun formatBytesAsMbInput(dataLimitBytes: Long): String {
        val sanitized = dataLimitBytes.coerceAtLeast(0L)
        if (sanitized == 0L) return "0"
        val mb = sanitized / BYTES_PER_MB
        return mb.coerceAtLeast(1L).toString()
    }

    /**
     * Formats byte quantities using `1 MB = 1,048,576 bytes` and `1 GB = 1024 MB`
     * with exact `BigDecimal` arithmetic (e.g. `1.4 GB`, `2 GB`, `512 MB`, `0 B`).
     */
    fun formatBytes(bytes: Long): String {
        val safe = bytes.coerceAtLeast(0L)
        if (safe == 0L) return "0 B"
        if (safe < BYTES_PER_KB) return "$safe B"
        if (safe < BYTES_PER_MB) {
            val kb = BigDecimal.valueOf(safe)
                .divide(BigDecimal.valueOf(BYTES_PER_KB), 1, RoundingMode.HALF_UP)
                .stripTrailingZeros()
                .toPlainString()
            return "$kb KB"
        }
        if (safe < BYTES_PER_GB) {
            if (safe % BYTES_PER_MB == 0L) {
                return "${safe / BYTES_PER_MB} MB"
            }
            val mb = BigDecimal.valueOf(safe)
                .divide(BigDecimal.valueOf(BYTES_PER_MB), 1, RoundingMode.HALF_UP)
                .stripTrailingZeros()
                .toPlainString()
            return "$mb MB"
        }
        if (safe % BYTES_PER_GB == 0L) {
            return "${safe / BYTES_PER_GB} GB"
        }
        val gb = BigDecimal.valueOf(safe)
            .divide(BigDecimal.valueOf(BYTES_PER_GB), 2, RoundingMode.HALF_UP)
            .stripTrailingZeros()
            .toPlainString()
        return "$gb GB"
    }

    fun formatUsageSummary(usedBytes: Long, limitBytes: Long): String {
        val usedStr = formatBytes(usedBytes)
        if (limitBytes <= 0L) {
            return "$usedStr / Unlimited"
        }
        val limitStr = formatBytes(limitBytes)
        return "$usedStr / $limitStr"
    }

    fun computeCurrentWindow(
        period: QuotaResetPeriod,
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): QuotaWindowSpec = computeWindow(period, nowEpochMs, zoneId)

    /**
     * Computes the active calendar window and next local reset timestamp for [period] at [nowEpochMs]
     * in [zoneId]:
     * - DAILY: starts at local 00:00 each day
     * - WEEKLY: starts at Monday 00:00 local time
     * - MONTHLY: starts on the 1st of the month at 00:00 local time
     * - MANUAL: never auto-resets (`Until manually reset`)
     */
    fun computeWindow(
        period: QuotaResetPeriod,
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): QuotaWindowSpec {
        if (period == QuotaResetPeriod.MANUAL) {
            return QuotaWindowSpec(
                period = QuotaResetPeriod.MANUAL,
                windowId = "MANUAL",
                windowStartEpochMs = 0L,
                nextResetEpochMs = null,
                nextResetFormatted = "Until manually reset",
            )
        }

        val zdt = Instant.ofEpochMilli(nowEpochMs).atZone(zoneId)
        val localDate = zdt.toLocalDate()

        return when (period) {
            QuotaResetPeriod.DAILY -> {
                val startZdt = localDate.atStartOfDay(zoneId)
                val nextZdt = localDate.plusDays(1).atStartOfDay(zoneId)
                QuotaWindowSpec(
                    period = QuotaResetPeriod.DAILY,
                    windowId = "DAILY:$localDate",
                    windowStartEpochMs = startZdt.toInstant().toEpochMilli(),
                    nextResetEpochMs = nextZdt.toInstant().toEpochMilli(),
                    nextResetFormatted = "${NEXT_RESET_FORMATTER.format(nextZdt)} (${zoneId.id})",
                )
            }
            QuotaResetPeriod.WEEKLY -> {
                val monday = localDate.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY))
                val startZdt = monday.atStartOfDay(zoneId)
                val nextZdt = monday.plusWeeks(1).atStartOfDay(zoneId)
                QuotaWindowSpec(
                    period = QuotaResetPeriod.WEEKLY,
                    windowId = "WEEKLY:$monday",
                    windowStartEpochMs = startZdt.toInstant().toEpochMilli(),
                    nextResetEpochMs = nextZdt.toInstant().toEpochMilli(),
                    nextResetFormatted = "${NEXT_RESET_FORMATTER.format(nextZdt)} (${zoneId.id})",
                )
            }
            QuotaResetPeriod.MONTHLY -> {
                val firstOfMonth = localDate.withDayOfMonth(1)
                val startZdt = firstOfMonth.atStartOfDay(zoneId)
                val nextZdt = firstOfMonth.plusMonths(1).atStartOfDay(zoneId)
                val ym = String.format(Locale.US, "%04d-%02d", firstOfMonth.year, firstOfMonth.monthValue)
                QuotaWindowSpec(
                    period = QuotaResetPeriod.MONTHLY,
                    windowId = "MONTHLY:$ym",
                    windowStartEpochMs = startZdt.toInstant().toEpochMilli(),
                    nextResetEpochMs = nextZdt.toInstant().toEpochMilli(),
                    nextResetFormatted = "${NEXT_RESET_FORMATTER.format(nextZdt)} (${zoneId.id})",
                )
            }
            QuotaResetPeriod.MANUAL -> error("unreachable")
        }
    }

    /**
     * Evaluates whether [record] has crossed into a strictly newer calendar period at [nowEpochMs]
     * in [zoneId].
     * - Protects against backward wall-clock adjustments and DST fall-back transitions:
     *   if the computed calendar window is older than or equal to the stored window, usage is NEVER reset.
     * - If the stored window is empty or belongs to a different [QuotaResetPeriod] (e.g. policy changed),
     *   re-anchors the window metadata to the current window without wiping accumulated usage.
     */
    fun evaluateWindowRollover(
        record: ClientQuotaRecord,
        nowEpochMs: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault(),
    ): ClientQuotaRecord {
        val period = record.resetPeriod
        if (period == QuotaResetPeriod.MANUAL) {
            return if (record.windowId == "MANUAL") {
                record
            } else {
                record.copy(
                    windowId = "MANUAL",
                    windowStartEpochMs = record.windowStartEpochMs.takeIf { it > 0L } ?: nowEpochMs,
                )
            }
        }

        val currentWindow = computeWindow(period, nowEpochMs, zoneId)
        val storedId = record.windowId.trim()
        val expectedPrefix = "${period.name}:"

        if (storedId.isEmpty() || !storedId.startsWith(expectedPrefix)) {
            return record.copy(
                windowId = currentWindow.windowId,
                windowStartEpochMs = currentWindow.windowStartEpochMs,
            )
        }

        if (storedId == currentWindow.windowId) {
            return record
        }

        val advancedForward = isStrictlyNewerWindow(
            period = period,
            storedWindowId = storedId,
            currentWindowId = currentWindow.windowId,
            storedStartEpochMs = record.windowStartEpochMs,
            currentStartEpochMs = currentWindow.windowStartEpochMs,
        )

        return if (advancedForward) {
            record.copy(
                usedRxBytes = 0L,
                usedTxBytes = 0L,
                windowId = currentWindow.windowId,
                windowStartEpochMs = currentWindow.windowStartEpochMs,
                lastUpdatedEpochMs = maxOf(nowEpochMs, record.lastUpdatedEpochMs),
            )
        } else {
            // Clock moved backward into an earlier calendar window: preserve usage and high-water windowId
            record
        }
    }

    private fun isStrictlyNewerWindow(
        period: QuotaResetPeriod,
        storedWindowId: String,
        currentWindowId: String,
        storedStartEpochMs: Long,
        currentStartEpochMs: Long,
    ): Boolean {
        val storedSuffix = storedWindowId.substringAfter(':', "")
        val currentSuffix = currentWindowId.substringAfter(':', "")
        return when (period) {
            QuotaResetPeriod.DAILY,
            QuotaResetPeriod.WEEKLY,
            -> {
                val storedDate = runCatching { LocalDate.parse(storedSuffix) }.getOrNull()
                val currentDate = runCatching { LocalDate.parse(currentSuffix) }.getOrNull()
                if (storedDate != null && currentDate != null) {
                    currentDate.isAfter(storedDate)
                } else {
                    currentStartEpochMs > storedStartEpochMs
                }
            }
            QuotaResetPeriod.MONTHLY -> {
                val storedYm = runCatching { YearMonth.parse(storedSuffix) }.getOrNull()
                val currentYm = runCatching { YearMonth.parse(currentSuffix) }.getOrNull()
                if (storedYm != null && currentYm != null) {
                    currentYm.isAfter(storedYm)
                } else {
                    currentStartEpochMs > storedStartEpochMs
                }
            }
            QuotaResetPeriod.MANUAL -> false
        }
    }

    fun serializeRecords(records: Collection<ClientQuotaRecord>): String {
        val arr = JSONArray()
        for (rec in records.sortedBy { it.cleanMac }) {
            arr.put(rec.toJson())
        }
        return JSONObject().apply {
            put("version", 1)
            put("records", arr)
        }.toString()
    }

    fun parseRecords(raw: String?): Map<String, ClientQuotaRecord> {
        if (raw.isNullOrBlank()) return emptyMap()
        return runCatching {
            val root = if (raw.trimStart().startsWith("[")) {
                JSONObject().put("records", JSONArray(raw))
            } else {
                JSONObject(raw)
            }
            val arr = root.optJSONArray("records") ?: return emptyMap()
            val map = LinkedHashMap<String, ClientQuotaRecord>()
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val rec = ClientQuotaRecord.fromJson(obj)
                if (rec.cleanMac.length == 17) {
                    map[rec.cleanMac] = rec
                }
            }
            map
        }.getOrDefault(emptyMap())
    }

    fun loadFromFile(file: File): Map<String, ClientQuotaRecord> {
        if (!file.exists() || !file.canRead()) return emptyMap()
        return runCatching {
            parseRecords(file.readText(Charsets.UTF_8))
        }.getOrDefault(emptyMap())
    }

    fun saveToFile(file: File, records: Collection<ClientQuotaRecord>): Boolean {
        return runCatching {
            file.parentFile?.mkdirs()
            val tmpFile = File(file.parentFile, "${file.name}.tmp")
            tmpFile.writeText(serializeRecords(records), Charsets.UTF_8)
            if (!tmpFile.renameTo(file)) {
                file.writeText(serializeRecords(records), Charsets.UTF_8)
                tmpFile.delete()
            }
            true
        }.getOrDefault(false)
    }
}
