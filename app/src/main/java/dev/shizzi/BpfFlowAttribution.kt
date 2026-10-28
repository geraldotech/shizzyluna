package dev.shizzi

import android.os.Binder
import android.system.Os
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.json.JSONArray
import org.json.JSONObject

/**
 * UI & diagnostic state for the experimental BPF NAT flow attribution integration.
 */
enum class ExperimentalBpfState {
    DISABLED,
    COLLECTING,
    MAPPINGS_AVAILABLE,
    PARTIAL_ENFORCEMENT,
    STALE_ENFORCEMENT_DEGRADED,
    STALE_OR_UNAVAILABLE,
}

/**
 * Outcome of a single `dumpsys tethering bpf` collection cycle.
 */
enum class BpfCollectionStatus {
    IDLE,
    OK,
    EMPTY_VALID,
    PERMISSION_DENIED,
    COMMAND_FAILED,
    TIMEOUT,
    TRUNCATED,
    PARSE_FAILURE,
    SERVICE_LOST,
}

/**
 * Explicit reason why a line inside a BPF dump was rejected by [BpfDumpParser].
 */
enum class BpfRejectionReason {
    TRUNCATED_LINE,
    INCOMPLETE_FLOW_LINE,
    INVALID_SYNTAX,
    UNSUPPORTED_PROTOCOL,
    INVALID_IP,
    INVALID_PORT,
    INVALID_MAC,
    INVALID_IFINDEX,
    INVALID_PMTU,
    INVALID_AGE,
}

/**
 * Explicit domain representation of the trailing flow age / last-used delta printed by
 * AOSP `BpfCoordinator.dumpIpv4ForwardingRuleMap`:
 *
 * - [KnownNonNegative]: standard non-negative age (`230026ms`, `227s`, `0ms`, `0`).
 * - [Unavailable]: literal `-` printed when `Tether4Value.lastUsed == 0` (rule installed in map,
 *   no packet timestamp recorded yet). Never silently coerced to `0ms`.
 * - [NegativeDelta]: small negative millisecond delta (`-3ms`, `-15ms`) printed when the kernel
 *   eBPF datapath updates `lastUsed = bpf_ktime_get_boot_ns()` on an in-flight packet a few
 *   milliseconds after `BpfCoordinator` sampled `now` at the start of map iteration.
 */
sealed class BpfFlowAge {
    abstract val rawAgeMs: Long?

    data class KnownNonNegative(val ageMs: Long) : BpfFlowAge() {
        override val rawAgeMs: Long = ageMs
    }

    data object Unavailable : BpfFlowAge() {
        override val rawAgeMs: Long? = null
    }

    data class NegativeDelta(val deltaMs: Long) : BpfFlowAge() {
        override val rawAgeMs: Long = deltaMs
    }
}

data class BpfRejectedLine(
    val lineNumber: Int,
    val section: String,
    val reason: BpfRejectionReason,
    val linePreview: String,
) {
    fun maskedPreview(): String = BpfDumpParser.maskSensitiveLinePreview(linePreview)

    fun previewForExport(includeSensitiveEndpoints: Boolean): String =
        if (includeSensitiveEndpoints) linePreview else maskedPreview()
}

/**
 * Parsed row from `IPv4 Upstream:` in `dumpsys tethering bpf`.
 *
 * Example:
 * `tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms`
 *
 * CRITICAL: [hotspotInDstMac] is the hotspot interface's MAC shared by all clients.
 * It is NEVER the client's source MAC.
 */
data class BpfIpv4UpstreamEntry(
    val protocol: Int, // 6 = TCP, 17 = UDP
    val protocolLabel: String,
    val hotspotInDstMac: String,
    val inIfIndex: Int,
    val inIfaceLabel: String,
    val origClientIp: String,
    val origClientPort: Int,
    val outIfIndex: Int,
    val outIfaceLabel: String,
    val translatedIp: String,
    val translatedPort: Int,
    val remoteIp: String,
    val remotePort: Int,
    val outDstMac: String,
    val pmtu: Int,
    val rawAgeMs: Long?,
    val flowAge: BpfFlowAge = if (rawAgeMs == null) {
        BpfFlowAge.Unavailable
    } else if (rawAgeMs < 0L) {
        BpfFlowAge.NegativeDelta(rawAgeMs)
    } else {
        BpfFlowAge.KnownNonNegative(rawAgeMs)
    },
)

/**
 * Parsed row from `IPv4 Downstream:` in `dumpsys tethering bpf`.
 *
 * Example:
 * `tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms`
 *
 * Here [clientOutDstMac] is the destination client MAC on the downstream interface.
 */
data class BpfIpv4DownstreamEntry(
    val protocol: Int, // 6 = TCP, 17 = UDP
    val protocolLabel: String,
    val inDstMac: String,
    val inIfIndex: Int,
    val inIfaceLabel: String,
    val remoteIp: String,
    val remotePort: Int,
    val outIfIndex: Int,
    val outIfaceLabel: String,
    val translatedIp: String,
    val translatedPort: Int,
    val origClientIp: String,
    val origClientPort: Int,
    val clientOutDstMac: String,
    val pmtu: Int,
    val rawAgeMs: Long?,
    val flowAge: BpfFlowAge = if (rawAgeMs == null) {
        BpfFlowAge.Unavailable
    } else if (rawAgeMs < 0L) {
        BpfFlowAge.NegativeDelta(rawAgeMs)
    } else {
        BpfFlowAge.KnownNonNegative(rawAgeMs)
    },
)

/**
 * Parsed row from `IPv6 Downstream:` or `IPv6 Upstream:` in `dumpsys tethering bpf`.
 */
data class BpfIpv6Entry(
    val isDownstream: Boolean,
    val iifIndex: Int,
    val iifLabel: String,
    val oifIndex: Int,
    val oifLabel: String,
    val addressOrPrefix: String,
    val srcMac: String,
    val dstMac: String,
    val pmtu: Int,
)

/**
 * Parsed output of `dumpsys tethering bpf`.
 */
data class BpfParsedDump(
    val parserVersion: Int = BpfDumpParser.PARSER_VERSION,
    val recognizedFormat: Boolean,
    val ipv4UpstreamEntries: List<BpfIpv4UpstreamEntry>,
    val ipv4DownstreamEntries: List<BpfIpv4DownstreamEntry>,
    val ipv6Entries: List<BpfIpv6Entry>,
    val rejectedLines: List<BpfRejectedLine>,
    val rawUpstreamMapRowCount: Int = 0,
    val wasTruncatedByReader: Boolean = false,
) {
    val hasRejections: Boolean get() = rejectedLines.isNotEmpty()
    val isEmptyValid: Boolean
        get() = recognizedFormat &&
            !wasTruncatedByReader &&
            ipv4UpstreamEntries.isEmpty() &&
            ipv4DownstreamEntries.isEmpty() &&
            rejectedLines.isEmpty()

    val knownAgeEntries: Int
        get() = ipv4UpstreamEntries.count { it.flowAge is BpfFlowAge.KnownNonNegative } +
            ipv4DownstreamEntries.count { it.flowAge is BpfFlowAge.KnownNonNegative }

    val unavailableAgeEntries: Int
        get() = ipv4UpstreamEntries.count { it.flowAge is BpfFlowAge.Unavailable } +
            ipv4DownstreamEntries.count { it.flowAge is BpfFlowAge.Unavailable }

    val negativeDeltaAgeEntries: Int
        get() = ipv4UpstreamEntries.count { it.flowAge is BpfFlowAge.NegativeDelta } +
            ipv4DownstreamEntries.count { it.flowAge is BpfFlowAge.NegativeDelta }

    fun rejectionCountsByReason(): Map<String, Int> {
        if (rejectedLines.isEmpty()) return emptyMap()
        val counts = LinkedHashMap<String, Int>()
        for (item in rejectedLines) {
            counts[item.reason.name] = (counts[item.reason.name] ?: 0) + 1
        }
        return counts
    }
}

/**
 * Pure parser for `dumpsys tethering bpf` text output and optional `bpfRawMap --upstream4` row count.
 */
object BpfDumpParser {

    const val PARSER_VERSION = 3

    /**
     * Maximum negative age delta (in milliseconds) accepted as a legitimate in-iteration timestamp
     * skew (`now - value.lastUsed < 0` when the kernel eBPF datapath updates `lastUsed` during map
     * iteration). Negative values outside this bound or using non-`ms` units are rejected as [BpfRejectionReason.INVALID_AGE].
     */
    const val MIN_LEGITIMATE_NEGATIVE_AGE_MS = -30_000L

    private enum class Section {
        NONE,
        CLIENT_INFO,
        IPV4_UPSTREAM,
        IPV4_DOWNSTREAM,
        IPV6_UPSTREAM,
        IPV6_DOWNSTREAM,
        RAW_MAP_UPSTREAM4,
    }

    // Matches IPv4 Upstream / Downstream rows while capturing the trailing age token in group 15
    // so we can validate KnownNonNegative ("230026ms", "227s", "0ms"), Unavailable ("-"),
    // NegativeDelta ("-3ms", "-15ms"), and reject invalid age tokens as INVALID_AGE:
    // tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
    private val IPV4_FLOW_ROW_REGEX = Regex(
        """^\s*(\S+)\s+\[([^\]]+)]\s+(-?\d+)\(([^)]*)\)\s+([^\s:]+):(-?\d+)\s*->\s*(-?\d+)\(([^)]*)\)\s+([^\s:]+):(-?\d+)\s*->\s*([^\s:]+):(-?\d+)\s+\[([^\]]+)]\s+(-?\d+)\s+(\S+)\s*$""",
        RegexOption.IGNORE_CASE,
    )

    // Strict pattern for the AOSP BpfCoordinator interface forwarding table header:
    // "ifindex (iface) -> ifindex (iface)"
    private val IFINDEX_TABLE_HEADER_REGEX = Regex(
        """^ifindex\s*\(\s*iface\s*\)\s*->\s*ifindex\s*\(\s*iface\s*\)$""",
        RegexOption.IGNORE_CASE,
    )

    private val NON_NEGATIVE_AGE_REGEX = Regex("""^(\d+)(ms|s)?$""", RegexOption.IGNORE_CASE)
    private val NEGATIVE_MS_AGE_REGEX = Regex("""^(-\d+)ms$""", RegexOption.IGNORE_CASE)

    private val MAC_REGEX = Regex("""^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$""")
    private val MASK_MAC_REGEX = Regex("""\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b""")
    private val MASK_IPV4_PORT_REGEX = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b""")
    private val MASK_IPV6_REGEX = Regex("""\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b""")
    private val MASK_TRAILING_PORT_REGEX = Regex("""(?<=[^\s:\]])(:)(-?\d{1,6})\b""")

    /**
     * Redacts IPv4, IPv6, MAC addresses, and port numbers from a line preview while keeping
     * the exact token/bracket/arrow syntax structure intact for parser diagnostics.
     */
    fun maskSensitiveLinePreview(rawPreview: String): String {
        if (rawPreview.isBlank()) return rawPreview
        var masked = MASK_MAC_REGEX.replace(rawPreview, "xx:xx:xx:xx:xx:xx")
        masked = MASK_IPV4_PORT_REGEX.replace(masked) { match ->
            if (match.value.contains(':')) "x.x.x.x:xxxx" else "x.x.x.x"
        }
        masked = MASK_IPV6_REGEX.replace(masked, "xxxx::xxxx")
        masked = MASK_TRAILING_PORT_REGEX.replace(masked, ":xxxx")
        return masked
    }

    /**
     * Parses the trailing age token from an AOSP `BpfCoordinator` IPv4 flow line:
     * - `"-"` -> [BpfFlowAge.Unavailable] (`rawAgeMs = null`)
     * - `"<non-negative>(ms|s)?"` -> [BpfFlowAge.KnownNonNegative] (with overflow check on `s` -> `ms`)
     * - `"-<digits>ms"` within `[MIN_LEGITIMATE_NEGATIVE_AGE_MS, -1]` -> [BpfFlowAge.NegativeDelta]
     * - Anything else -> `null` (caller rejects line with [BpfRejectionReason.INVALID_AGE]).
     */
    internal fun parseFlowAge(ageToken: String): BpfFlowAge? {
        val clean = ageToken.trim()
        if (clean == "-") {
            return BpfFlowAge.Unavailable
        }
        NON_NEGATIVE_AGE_REGEX.matchEntire(clean)?.let { m ->
            val rawVal = m.groupValues[1].toLongOrNull() ?: return null
            if (rawVal < 0L) return null
            val unit = m.groupValues[2].lowercase()
            val ageMs = if (unit == "s") {
                if (rawVal > Long.MAX_VALUE / 1_000L) return null
                rawVal * 1_000L
            } else {
                rawVal
            }
            return BpfFlowAge.KnownNonNegative(ageMs)
        }
        NEGATIVE_MS_AGE_REGEX.matchEntire(clean)?.let { m ->
            val deltaMs = m.groupValues[1].toLongOrNull() ?: return null
            if (deltaMs in MIN_LEGITIMATE_NEGATIVE_AGE_MS..-1L) {
                return BpfFlowAge.NegativeDelta(deltaMs)
            }
            return null
        }
        return null
    }

    fun parse(dumpText: String, wasTruncatedByReader: Boolean = false): BpfParsedDump {
        if (dumpText.isBlank()) {
            return BpfParsedDump(
                recognizedFormat = false,
                ipv4UpstreamEntries = emptyList(),
                ipv4DownstreamEntries = emptyList(),
                ipv6Entries = emptyList(),
                rejectedLines = emptyList(),
                wasTruncatedByReader = wasTruncatedByReader,
            )
        }

        val upstream4 = ArrayList<BpfIpv4UpstreamEntry>()
        val downstream4 = ArrayList<BpfIpv4DownstreamEntry>()
        val ipv6List = ArrayList<BpfIpv6Entry>()
        val rejected = ArrayList<BpfRejectedLine>()
        var recognizedHeader = false
        val rawMapRows = 0
        var currentSection = Section.NONE

        val lines = dumpText.lines()
        val lastNonBlankIdx = lines.indexOfLast { it.isNotBlank() }
        var readerTruncationRecordedOnLine = false

        for ((idx, rawLine) in lines.withIndex()) {
            val lineNumber = idx + 1
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) continue

            when {
                trimmed.startsWith("IPv4 Upstream:", ignoreCase = true) -> {
                    recognizedHeader = true
                    currentSection = Section.IPV4_UPSTREAM
                    continue
                }
                trimmed.startsWith("IPv4 Downstream:", ignoreCase = true) -> {
                    recognizedHeader = true
                    currentSection = Section.IPV4_DOWNSTREAM
                    continue
                }
                trimmed.startsWith("IPv6 Upstream:", ignoreCase = true) -> {
                    recognizedHeader = true
                    currentSection = Section.IPV6_UPSTREAM
                    continue
                }
                trimmed.startsWith("IPv6 Downstream:", ignoreCase = true) -> {
                    recognizedHeader = true
                    currentSection = Section.IPV6_DOWNSTREAM
                    continue
                }
                trimmed.startsWith("Client Information:", ignoreCase = true) -> {
                    recognizedHeader = true
                    currentSection = Section.CLIENT_INFO
                    continue
                }
                trimmed.startsWith("BPF offload", ignoreCase = true) ||
                    trimmed.startsWith("Polling interval:", ignoreCase = true) ||
                    trimmed.startsWith("Upstream:", ignoreCase = true) ||
                    trimmed.startsWith("Forwarding rules", ignoreCase = true) ||
                    trimmed.startsWith("Forwarding stats", ignoreCase = true) ||
                    trimmed.startsWith("Downstream:", ignoreCase = true) ||
                    trimmed.startsWith("Tethering BPF", ignoreCase = true) -> {
                    recognizedHeader = true
                    if (!trimmed.startsWith("IPv4 ", ignoreCase = true) &&
                        !trimmed.startsWith("IPv6 ", ignoreCase = true)
                    ) {
                        currentSection = Section.NONE
                    }
                    continue
                }
            }

            // Detect section change if an unindented colon header appears
            if (!rawLine.startsWith(" ") && !rawLine.startsWith("\t") && trimmed.endsWith(":")) {
                currentSection = Section.NONE
                continue
            }

            val isFinalCutLine = wasTruncatedByReader && idx == lastNonBlankIdx

            when (currentSection) {
                Section.IPV4_UPSTREAM -> {
                    if (!isFinalCutLine && isIgnorableSectionLine(trimmed)) continue
                    parseIpv4FlowLine(
                        line = rawLine,
                        lineNumber = lineNumber,
                        sectionName = "IPv4 Upstream",
                        isUpstream = true,
                        isTruncatedFinalLine = isFinalCutLine,
                        onUpstream = upstream4::add,
                        onDownstream = downstream4::add,
                        onRejected = { rej ->
                            if (rej.reason == BpfRejectionReason.TRUNCATED_LINE) {
                                readerTruncationRecordedOnLine = true
                            }
                            rejected.add(rej)
                        },
                    )
                }
                Section.IPV4_DOWNSTREAM -> {
                    if (!isFinalCutLine && isIgnorableSectionLine(trimmed)) continue
                    parseIpv4FlowLine(
                        line = rawLine,
                        lineNumber = lineNumber,
                        sectionName = "IPv4 Downstream",
                        isUpstream = false,
                        isTruncatedFinalLine = isFinalCutLine,
                        onUpstream = upstream4::add,
                        onDownstream = downstream4::add,
                        onRejected = { rej ->
                            if (rej.reason == BpfRejectionReason.TRUNCATED_LINE) {
                                readerTruncationRecordedOnLine = true
                            }
                            rejected.add(rej)
                        },
                    )
                }
                Section.IPV6_UPSTREAM, Section.IPV6_DOWNSTREAM -> {
                    if (isIgnorableSectionLine(trimmed)) continue
                    parseIpv6Line(
                        line = trimmed,
                        isDownstream = currentSection == Section.IPV6_DOWNSTREAM,
                        ipv6List = ipv6List,
                    )
                }
                Section.CLIENT_INFO -> {
                    // Client Information lines are optional supplementary evidence
                }
                Section.RAW_MAP_UPSTREAM4, Section.NONE -> {
                    // Ignore unrelated lines outside active flow sections
                }
            }
        }

        if (wasTruncatedByReader && !readerTruncationRecordedOnLine) {
            rejected.add(
                BpfRejectedLine(
                    lineNumber = lines.size.coerceAtLeast(1),
                    section = currentSection.name,
                    reason = BpfRejectionReason.TRUNCATED_LINE,
                    linePreview = "Reader output hit byte limit and was truncated",
                ),
            )
        }

        return BpfParsedDump(
            recognizedFormat = recognizedHeader,
            ipv4UpstreamEntries = upstream4,
            ipv4DownstreamEntries = downstream4,
            ipv6Entries = ipv6List,
            rejectedLines = rejected,
            rawUpstreamMapRowCount = rawMapRows,
            wasTruncatedByReader = wasTruncatedByReader,
        )
    }

    /**
     * Returns true when a line inside a flow section is a recognized non-flow marker,
     * sub-header, comment, or counter summary that should be ignored rather than counted
     * as a defective flow entry.
     */
    internal fun isIgnorableSectionLine(trimmed: String): Boolean {
        if (trimmed.isEmpty()) return true
        if (IFINDEX_TABLE_HEADER_REGEX.matches(trimmed)) {
            return true
        }
        val lower = trimmed.lowercase()
        if (lower == "none" || lower == "<empty>" || lower == "(none)" || lower == "(empty)" || lower == "empty") {
            return true
        }
        if (lower.startsWith("no ") ||
            lower.startsWith("#") ||
            lower.startsWith("//") ||
            lower.startsWith("---") ||
            lower.startsWith("===")
        ) {
            return true
        }
        // Sub-headers or summary lines that do not contain flow arrow "->"
        if (!trimmed.contains("->")) {
            if (trimmed.endsWith(":")) return true
            if (lower.startsWith("total") ||
                lower.startsWith("count") ||
                lower.startsWith("entries") ||
                lower.startsWith("size") ||
                lower.startsWith("map ") ||
                lower.startsWith("limit") ||
                lower.startsWith("stats") ||
                lower.startsWith("note:") ||
                lower.startsWith("offload") ||
                lower.startsWith("rules")
            ) {
                return true
            }
        }
        return false
    }

    /**
     * Parses `dumpsys tethering bpfRawMap --upstream4` text output strictly to count valid hex rows
     * without guessing unsupported binary layouts.
     */
    fun countRawUpstreamMapRows(rawMapOutput: String): Int {
        if (rawMapOutput.isBlank()) return 0
        var count = 0
        for (line in rawMapOutput.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            if (trimmed.contains("->") && HEX_RAW_ROW_REGEX.matches(trimmed)) {
                count++
            }
        }
        return count
    }

    private val HEX_RAW_ROW_REGEX = Regex("""^[0-9a-fA-F\s:]+\s*->\s*[0-9a-fA-F\s:]+$""")

    private fun parseIpv4FlowLine(
        line: String,
        lineNumber: Int,
        sectionName: String,
        isUpstream: Boolean,
        isTruncatedFinalLine: Boolean,
        onUpstream: (BpfIpv4UpstreamEntry) -> Unit,
        onDownstream: (BpfIpv4DownstreamEntry) -> Unit,
        onRejected: (BpfRejectedLine) -> Unit,
    ) {
        val trimmed = line.trim()
        val match = IPV4_FLOW_ROW_REGEX.matchEntire(line)
        if (match == null) {
            val reason = when {
                isTruncatedFinalLine -> BpfRejectionReason.TRUNCATED_LINE
                trimmed.contains("->") -> BpfRejectionReason.INCOMPLETE_FLOW_LINE
                else -> BpfRejectionReason.INVALID_SYNTAX
            }
            onRejected(
                BpfRejectedLine(
                    lineNumber = lineNumber,
                    section = sectionName,
                    reason = reason,
                    linePreview = trimmed.take(160),
                ),
            )
            return
        }

        // If the reader hit its byte limit on this very last line, never trust the final line even if
        // its trailing digits happened to match the regex (e.g. "230026ms" cut to "230").
        if (isTruncatedFinalLine) {
            onRejected(
                BpfRejectedLine(
                    lineNumber = lineNumber,
                    section = sectionName,
                    reason = BpfRejectionReason.TRUNCATED_LINE,
                    linePreview = trimmed.take(160),
                ),
            )
            return
        }

        val protoLabel = match.groupValues[1].lowercase()
        val protoNum = when (protoLabel) {
            "tcp", "6" -> 6
            "udp", "17" -> 17
            else -> {
                onRejected(
                    BpfRejectedLine(
                        lineNumber = lineNumber,
                        section = sectionName,
                        reason = BpfRejectionReason.UNSUPPORTED_PROTOCOL,
                        linePreview = trimmed.take(160),
                    ),
                )
                return
            }
        }

        val mac1 = match.groupValues[2].trim().uppercase()
        val ifIndex1 = match.groupValues[3].toIntOrNull()
        val ifaceLabel1 = match.groupValues[4].trim()
        val ip1 = match.groupValues[5].trim()
        val port1 = match.groupValues[6].toIntOrNull()

        val ifIndex2 = match.groupValues[7].toIntOrNull()
        val ifaceLabel2 = match.groupValues[8].trim()
        val ip2 = match.groupValues[9].trim()
        val port2 = match.groupValues[10].toIntOrNull()

        val ip3 = match.groupValues[11].trim()
        val port3 = match.groupValues[12].toIntOrNull()
        val mac2 = match.groupValues[13].trim().uppercase()
        val pmtu = match.groupValues[14].toIntOrNull()
        val ageToken = match.groupValues[15].trim()

        if (!isValidMac(mac1) || !isValidMac(mac2)) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_MAC, trimmed.take(160)))
            return
        }
        if (ifIndex1 == null || ifIndex2 == null || ifIndex1 <= 0 || ifIndex2 <= 0 || ifIndex1 == ifIndex2) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_IFINDEX, trimmed.take(160)))
            return
        }
        if (pmtu == null || pmtu <= 0) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_PMTU, trimmed.take(160)))
            return
        }
        val flowAge = parseFlowAge(ageToken)
        if (flowAge == null) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_AGE, trimmed.take(160)))
            return
        }

        if (!isValidIpv4(ip1) || !isValidIpv4(ip2) || !isValidIpv4(ip3)) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_IP, trimmed.take(160)))
            return
        }
        if (port1 == null || port2 == null || port3 == null ||
            port1 !in 1..65535 || port2 !in 1..65535 || port3 !in 1..65535
        ) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_PORT, trimmed.take(160)))
            return
        }

        if (isUpstream) {
            onUpstream(
                BpfIpv4UpstreamEntry(
                    protocol = protoNum,
                    protocolLabel = if (protoNum == 6) "tcp" else "udp",
                    hotspotInDstMac = mac1,
                    inIfIndex = ifIndex1,
                    inIfaceLabel = ifaceLabel1,
                    origClientIp = ip1,
                    origClientPort = port1,
                    outIfIndex = ifIndex2,
                    outIfaceLabel = ifaceLabel2,
                    translatedIp = ip2,
                    translatedPort = port2,
                    remoteIp = ip3,
                    remotePort = port3,
                    outDstMac = mac2,
                    pmtu = pmtu,
                    rawAgeMs = flowAge.rawAgeMs,
                    flowAge = flowAge,
                ),
            )
        } else {
            onDownstream(
                BpfIpv4DownstreamEntry(
                    protocol = protoNum,
                    protocolLabel = if (protoNum == 6) "tcp" else "udp",
                    inDstMac = mac1,
                    inIfIndex = ifIndex1,
                    inIfaceLabel = ifaceLabel1,
                    remoteIp = ip1,
                    remotePort = port1,
                    outIfIndex = ifIndex2,
                    outIfaceLabel = ifaceLabel2,
                    translatedIp = ip2,
                    translatedPort = port2,
                    origClientIp = ip3,
                    origClientPort = port3,
                    clientOutDstMac = mac2,
                    pmtu = pmtu,
                    rawAgeMs = flowAge.rawAgeMs,
                    flowAge = flowAge,
                ),
            )
        }
    }

    private fun parseIpv6Line(
        line: String,
        isDownstream: Boolean,
        ipv6List: MutableList<BpfIpv6Entry>,
    ) {
        val tokens = line.split(Regex("""\s+""")).filter { it.isNotBlank() }
        if (tokens.size < 4) return
        val macs = tokens.map { it.removePrefix("[").removeSuffix("]").uppercase() }
            .filter { isValidMac(it) && it != "00:00:00:00:00:00" }
        val ipv6Addr = tokens.firstOrNull { it.contains(":") && !isValidMac(it.removePrefix("[").removeSuffix("]")) }
            ?: return
        ipv6List.add(
            BpfIpv6Entry(
                isDownstream = isDownstream,
                iifIndex = 0,
                iifLabel = "",
                oifIndex = 0,
                oifLabel = "",
                addressOrPrefix = ipv6Addr,
                srcMac = macs.firstOrNull().orEmpty(),
                dstMac = macs.lastOrNull().orEmpty(),
                pmtu = 1500,
            ),
        )
    }

    internal fun isValidMac(mac: String): Boolean = MAC_REGEX.matches(mac)

    internal fun isValidIpv4(ip: String): Boolean {
        val parts = ip.split('.')
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || (p.length > 1 && p.startsWith('0'))) return false
            val n = p.toIntOrNull() ?: return false
            if (n !in 0..255) return false
        }
        return true
    }
}

/**
 * Full lookup key for a translated flow in a specific session/interface generation.
 */
data class NatFlowLookupKey(
    val sessionGeneration: Long,
    val downstreamIfIndex: Int,
    val upstreamIfIndex: Int,
    val family: Int = 4,
    val protocol: Int,
    val translatedIp: String,
    val translatedPort: Int,
    val remoteIp: String,
    val remotePort: Int,
)

/**
 * Packet-side translated tuple observed on the TUN interface.
 */
data class TranslatedFlowKey(
    val family: Int = 4,
    val protocol: Int,
    val translatedIp: String,
    val translatedPort: Int,
    val remoteIp: String,
    val remotePort: Int,
)

/**
 * Result of attempting to resolve a network interface's kernel `ifindex` from the OS.
 *
 * - [osIfIndex]: Positive kernel `ifindex` (`> 0`), or `null` if unavailable (`0` is never a valid `ifindex`).
 * - [source]: `"OS_IF_NAMETOINDEX"`, `"NETWORK_INTERFACE"`, `"SYSFS"`, `"CUSTOM_RESOLVER"`, `"UNSET"`, or `"UNAVAILABLE"`.
 * - [failureReason]: Diagnostic reason when [osIfIndex] is `null`.
 */
data class InterfaceIndexResolution(
    val ifaceName: String,
    val osIfIndex: Int?,
    val source: String,
    val failureReason: String = "",
)

/**
 * Immutable validated mapping for a single translated flow.
 */
data class NatFlowMapping(
    val sessionGeneration: Long,
    val bindingGeneration: Long,
    val downstreamIfIndex: Int,
    val downstreamIfaceLabel: String,
    val upstreamIfIndex: Int,
    val upstreamIfaceLabel: String,
    val family: Int,
    val protocol: Int,
    val origClientIp: String,
    val origClientPort: Int,
    val translatedIp: String,
    val translatedPort: Int,
    val remoteIp: String,
    val remotePort: Int,
    val verifiedMac: String,
    val reverseMapConfirmed: Boolean,
    val collectedAtMonotonicMs: Long,
    val rawDumpAgeMs: Long?,
    val flowAge: BpfFlowAge = if (rawDumpAgeMs == null) {
        BpfFlowAge.Unavailable
    } else if (rawDumpAgeMs < 0L) {
        BpfFlowAge.NegativeDelta(rawDumpAgeMs)
    } else {
        BpfFlowAge.KnownNonNegative(rawDumpAgeMs)
    },
    val source: String = "dumpsys_tethering_bpf",
)

sealed class AttributionOutcome {
    data class Matched(
        val mac: String,
        val mapping: NatFlowMapping,
    ) : AttributionOutcome()

    data class Ambiguous(
        val reason: String,
    ) : AttributionOutcome()

    data class StaleSnapshot(
        val ageMs: Long,
    ) : AttributionOutcome()

    data class StaleOrInvalidated(
        val reason: String,
    ) : AttributionOutcome()

    data object Unknown : AttributionOutcome()
}

data class ClientProtocolFlowCounts(
    val mac: String,
    val originalIpv4: String,
    val tcpFlows: Int,
    val udpFlows: Int,
) {
    val totalFlows: Int get() = tcpFlows + udpFlows
}

/**
 * Diagnostic record of the most recent `dumpsys tethering bpf` collection attempt, kept strictly
 * separate from the last published valid [NatFlowSnapshot] so failed or rejected attempts never
 * overwrite or contaminate a fresh published snapshot while still preserving full parser diagnostics.
 */
data class BpfCollectionAttemptDiagnostic(
    val attemptSessionGeneration: Long = 0L,
    val attemptAtMonotonicMs: Long = 0L,
    val attemptDurationMs: Long = 0L,
    val attemptStatus: BpfCollectionStatus = BpfCollectionStatus.IDLE,
    val attemptError: String = "",
    val recognizedFormat: Boolean = false,
    val snapshotPublished: Boolean = false,
    val decisionReason: String = "",
    val upstreamEntries: Int = 0,
    val downstreamEntries: Int = 0,
    val knownAgeEntries: Int = 0,
    val unavailableAgeEntries: Int = 0,
    val negativeDeltaAgeEntries: Int = 0,
    val rejectedLineCount: Int = 0,
    val rejectedByReason: Map<String, Int> = emptyMap(),
    val rejectedLines: List<BpfRejectedLine> = emptyList(),
)

/**
 * Immutable, validated snapshot published atomically by [NatFlowAttributor].
 */
data class NatFlowSnapshot(
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
    val collectedAtMonotonicMs: Long = 0L,
    val collectionDurationMs: Long = 0L,
    val collectionStatus: BpfCollectionStatus = BpfCollectionStatus.IDLE,
    val collectionError: String = "",
    val downstreamIfIndex: Int = 0,
    val downstreamIface: String = "",
    val upstreamIfIndex: Int = 0,
    val upstreamIface: String = "",
    val osDownstreamIfIndex: Int? = null,
    val osUpstreamIfIndex: Int? = null,
    val inferredDownstreamIfIndex: Int? = null,
    val inferredUpstreamIfIndex: Int? = null,
    val downstreamIfIndexSource: String = "UNSET",
    val upstreamIfIndexSource: String = "UNSET",
    val downstreamIfIndexError: String = "",
    val upstreamIfIndexError: String = "",
    val resolvedDownstreamIfIndex: Int = osDownstreamIfIndex ?: 0,
    val resolvedUpstreamIfIndex: Int = osUpstreamIfIndex ?: 0,
    val totalUpstreamEntries: Int = 0,
    val totalDownstreamEntries: Int = 0,
    val knownAgeEntries: Int = 0,
    val unavailableAgeEntries: Int = 0,
    val negativeDeltaAgeEntries: Int = 0,
    val reverseMatchedCount: Int = 0,
    val flowsByTuple: Map<TranslatedFlowKey, NatFlowMapping> = emptyMap(),
    val ambiguousTuples: Map<TranslatedFlowKey, String> = emptyMap(),
    val unverifiedOwnerEntries: Int = 0,
    val ifIndexMismatchCount: Int = 0,
    val rejectedLineCount: Int = 0,
    val coverageIncomplete: Boolean = false,
    val perClientCounts: List<ClientProtocolFlowCounts> = emptyList(),
)

/**
 * Session-scoped, thread-safe coordinator that validates parsed BPF dumps against the current
 * downstream client inventory and resolves translated TUN packets to verified client MACs.
 */
class NatFlowAttributor(
    private val monotonicClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    var maxFreshnessMs: Long = DEFAULT_MAX_FRESHNESS_MS,
    val maxMappedFlows: Int = DEFAULT_MAX_MAPPED_FLOWS,
    var allowSafePartialPublication: Boolean = false,
    private val interfaceIndexResolver: ((String) -> Int)? = null,
    private val interfaceResolutionProvider: (String) -> InterfaceIndexResolution = ::defaultResolveInterfaceIndex,
) {

    private val sessionGen = AtomicLong(1L)
    private val bindingGen = AtomicLong(1L)

    @Volatile
    var activeDownstreamIface: String = ""
        private set

    @Volatile
    var activeUpstreamIface: String = ""
        private set

    private val currentSnapshotRef = AtomicReference(NatFlowSnapshot())
    private val lastAttemptRef = AtomicReference(BpfCollectionAttemptDiagnostic())

    // Tracks translated tuples where a new upload TCP SYN was seen AFTER the current snapshot was collected,
    // preventing tuple-reuse ambiguity from assigning a brand-new connection to a previous owner.
    private val synPendingRefreshTuples = ConcurrentHashMap<TranslatedFlowKey, Long>()

    val rejectedOldGenerationCount = AtomicLong(0L)
    val rejectedTruncatedOrCorruptCount = AtomicLong(0L)
    val lookupMatchedCount = AtomicLong(0L)
    val lookupUnknownCount = AtomicLong(0L)
    val lookupAmbiguousOrStaleCount = AtomicLong(0L)
    val tupleReuseGuardTriggeredCount = AtomicLong(0L)

    val currentSessionGeneration: Long get() = sessionGen.get()
    val currentBindingGeneration: Long get() = bindingGen.get()

    fun currentSnapshot(): NatFlowSnapshot = currentSnapshotRef.get()
    fun lastAttemptDiagnostic(): BpfCollectionAttemptDiagnostic = lastAttemptRef.get()

    /**
     * Bumps the session generation and immediately invalidates all existing BPF mappings.
     * Call on hotspot start/stop, upstream replacement, or service restart.
     */
    fun onSessionOrUpstreamChanged(
        downstreamIface: String = activeDownstreamIface,
        upstreamIface: String = activeUpstreamIface,
    ): Long {
        val nextGen = sessionGen.incrementAndGet()
        bindingGen.incrementAndGet()
        activeDownstreamIface = downstreamIface.trim()
        activeUpstreamIface = upstreamIface.trim()
        synPendingRefreshTuples.clear()
        val nowMono = monotonicClockMs()
        currentSnapshotRef.set(
            NatFlowSnapshot(
                sessionGeneration = nextGen,
                bindingGeneration = bindingGen.get(),
                collectedAtMonotonicMs = 0L,
                collectionStatus = BpfCollectionStatus.IDLE,
                downstreamIface = activeDownstreamIface,
                upstreamIface = activeUpstreamIface,
            ),
        )
        lastAttemptRef.set(
            BpfCollectionAttemptDiagnostic(
                attemptSessionGeneration = nextGen,
                attemptAtMonotonicMs = nowMono,
                attemptStatus = BpfCollectionStatus.IDLE,
                snapshotPublished = false,
                decisionReason = "Session or upstream changed",
            ),
        )
        return nextGen
    }

    /**
     * Updates active interface names without bumping the session generation if they haven't changed,
     * or bumps the session generation if the upstream or downstream interface changed.
     */
    fun syncInterfaces(downstreamIface: String, upstreamIface: String) {
        val cleanDown = downstreamIface.trim()
        val cleanUp = upstreamIface.trim()
        if ((activeUpstreamIface.isNotEmpty() && cleanUp.isNotEmpty() && activeUpstreamIface != cleanUp) ||
            (activeDownstreamIface.isNotEmpty() && cleanDown.isNotEmpty() && activeDownstreamIface != cleanDown)
        ) {
            onSessionOrUpstreamChanged(cleanDown, cleanUp)
        } else {
            if (cleanDown.isNotEmpty()) activeDownstreamIface = cleanDown
            if (cleanUp.isNotEmpty()) activeUpstreamIface = cleanUp
        }
    }

    /**
     * Bumps the client binding generation when clients connect/disconnect or change IPs.
     */
    fun onClientBindingsUpdated() {
        bindingGen.incrementAndGet()
    }

    private fun resolveInterface(ifaceName: String): InterfaceIndexResolution {
        val clean = ifaceName.trim()
        if (clean.isEmpty()) {
            return InterfaceIndexResolution(
                ifaceName = "",
                osIfIndex = null,
                source = "UNSET",
                failureReason = "Interface name not configured",
            )
        }
        val custom = interfaceIndexResolver
        if (custom != null) {
            val idx = runCatching { custom(clean) }.getOrDefault(0)
            return if (idx > 0) {
                InterfaceIndexResolution(
                    ifaceName = clean,
                    osIfIndex = idx,
                    source = "CUSTOM_RESOLVER",
                    failureReason = "",
                )
            } else {
                InterfaceIndexResolution(
                    ifaceName = clean,
                    osIfIndex = null,
                    source = "UNAVAILABLE",
                    failureReason = "custom resolver returned $idx for $clean",
                )
            }
        }
        return interfaceResolutionProvider(clean)
    }

    /**
     * Validates and publishes a parsed BPF dump for [collectionSessionGeneration].
     *
     * Rules enforced:
     * 1. Rejects late results from an older [collectionSessionGeneration].
     * 2. Never uses upstream `hotspotInDstMac` as client MAC.
     * 3. Resolves `origClientIp` via [ipToMac] and cross-checks matching reverse downstream
     *    `clientOutDstMac` when present.
     * 4. Validates `ifindex` consistency and reverse parity (`down.inIfIndex == up.outIfIndex` and
     *    `down.outIfIndex == up.inIfIndex`). Never trusts an isolated numeric label (`251(251)`)
     *    unless corroborated by OS `ifindex` or a named interface label + reverse-direction parity.
     * 5. Marks duplicate or contradictory ownership as ambiguous instead of picking the first match.
     * 6. Keeps the last collection attempt diagnostic strictly separate from the last published
     *    valid snapshot; never overwrites a valid fresh snapshot with a failed/rejected attempt.
     */
    fun ingestParsedDump(
        parsed: BpfParsedDump,
        collectionSessionGeneration: Long,
        collectionStatus: BpfCollectionStatus,
        collectionDurationMs: Long,
        collectionError: String = "",
        ipToMac: Map<String, String>,
        activeConnectedMacs: Set<String>,
    ): Boolean {
        val expectedGen = sessionGen.get()
        if (collectionSessionGeneration != expectedGen) {
            rejectedOldGenerationCount.incrementAndGet()
            return false
        }

        val nowMono = monotonicClockMs()
        val curBindGen = bindingGen.get()
        val reasonCounts = parsed.rejectionCountsByReason()
        val capturedRejectedLines = parsed.rejectedLines.take(MAX_CAPTURED_REJECTED_LINES)
        val hasReaderTruncation = parsed.wasTruncatedByReader ||
            collectionStatus == BpfCollectionStatus.TRUNCATED ||
            parsed.rejectedLines.any { it.reason == BpfRejectionReason.TRUNCATED_LINE }

        // Case 1: Fatal collector error or reader truncation -> never publish snapshot.
        if (collectionStatus != BpfCollectionStatus.OK && collectionStatus != BpfCollectionStatus.EMPTY_VALID) {
            rejectedTruncatedOrCorruptCount.incrementAndGet()
            val errMsg = collectionError.ifBlank { "Collector status ${collectionStatus.name}" }
            lastAttemptRef.set(
                BpfCollectionAttemptDiagnostic(
                    attemptSessionGeneration = expectedGen,
                    attemptAtMonotonicMs = nowMono,
                    attemptDurationMs = collectionDurationMs,
                    attemptStatus = collectionStatus,
                    attemptError = errMsg,
                    recognizedFormat = parsed.recognizedFormat,
                    snapshotPublished = false,
                    decisionReason = "Rejected: collector status ${collectionStatus.name}",
                    upstreamEntries = parsed.ipv4UpstreamEntries.size,
                    downstreamEntries = parsed.ipv4DownstreamEntries.size,
                    knownAgeEntries = parsed.knownAgeEntries,
                    unavailableAgeEntries = parsed.unavailableAgeEntries,
                    negativeDeltaAgeEntries = parsed.negativeDeltaAgeEntries,
                    rejectedLineCount = parsed.rejectedLines.size,
                    rejectedByReason = reasonCounts,
                    rejectedLines = capturedRejectedLines,
                ),
            )
            return false
        }

        if (!parsed.recognizedFormat || hasReaderTruncation) {
            rejectedTruncatedOrCorruptCount.incrementAndGet()
            val effectiveStatus = if (hasReaderTruncation) {
                BpfCollectionStatus.TRUNCATED
            } else {
                BpfCollectionStatus.PARSE_FAILURE
            }
            val errMsg = collectionError.ifBlank {
                if (hasReaderTruncation) {
                    "Dump truncated by reader (${parsed.rejectedLines.size} rejected line(s))"
                } else {
                    "Unrecognized dumpsys tethering bpf format"
                }
            }
            lastAttemptRef.set(
                BpfCollectionAttemptDiagnostic(
                    attemptSessionGeneration = expectedGen,
                    attemptAtMonotonicMs = nowMono,
                    attemptDurationMs = collectionDurationMs,
                    attemptStatus = effectiveStatus,
                    attemptError = errMsg,
                    recognizedFormat = parsed.recognizedFormat,
                    snapshotPublished = false,
                    decisionReason = "Rejected: ${effectiveStatus.name}",
                    upstreamEntries = parsed.ipv4UpstreamEntries.size,
                    downstreamEntries = parsed.ipv4DownstreamEntries.size,
                    knownAgeEntries = parsed.knownAgeEntries,
                    unavailableAgeEntries = parsed.unavailableAgeEntries,
                    negativeDeltaAgeEntries = parsed.negativeDeltaAgeEntries,
                    rejectedLineCount = parsed.rejectedLines.size,
                    rejectedByReason = reasonCounts,
                    rejectedLines = capturedRejectedLines,
                ),
            )
            return false
        }

        // Case 3: Flow line parse rejections present.
        // Conservative default (allowSafePartialPublication == false): reject snapshot publication
        // and preserve previous valid snapshot while fresh, recording full rejected-line diagnostics.
        if (parsed.hasRejections && !allowSafePartialPublication) {
            rejectedTruncatedOrCorruptCount.incrementAndGet()
            val reasonSummary = reasonCounts.entries.joinToString(", ") { "${it.key}=${it.value}" }
            val errMsg = collectionError.ifBlank {
                "Rejected ${parsed.rejectedLines.size} flow line(s) [$reasonSummary]"
            }
            lastAttemptRef.set(
                BpfCollectionAttemptDiagnostic(
                    attemptSessionGeneration = expectedGen,
                    attemptAtMonotonicMs = nowMono,
                    attemptDurationMs = collectionDurationMs,
                    attemptStatus = BpfCollectionStatus.PARSE_FAILURE,
                    attemptError = errMsg,
                    recognizedFormat = true,
                    snapshotPublished = false,
                    decisionReason = "Rejected conservative policy: ${parsed.rejectedLines.size} invalid flow line(s) [$reasonSummary]",
                    upstreamEntries = parsed.ipv4UpstreamEntries.size,
                    downstreamEntries = parsed.ipv4DownstreamEntries.size,
                    knownAgeEntries = parsed.knownAgeEntries,
                    unavailableAgeEntries = parsed.unavailableAgeEntries,
                    negativeDeltaAgeEntries = parsed.negativeDeltaAgeEntries,
                    rejectedLineCount = parsed.rejectedLines.size,
                    rejectedByReason = reasonCounts,
                    rejectedLines = capturedRejectedLines,
                ),
            )
            return false
        }

        // If allowSafePartialPublication == true and there are rejections, require at least one valid flow
        // and quarantine any client IP, client MAC, or ip:port endpoint mentioned in any rejected line.
        val quarantinedClientIps = HashSet<String>()
        val quarantinedMacs = HashSet<String>()
        val quarantinedEndpoints = HashSet<String>()
        if (parsed.hasRejections) {
            if (parsed.ipv4UpstreamEntries.isEmpty() && parsed.ipv4DownstreamEntries.isEmpty()) {
                rejectedTruncatedOrCorruptCount.incrementAndGet()
                val reasonSummary = reasonCounts.entries.joinToString(", ") { "${it.key}=${it.value}" }
                lastAttemptRef.set(
                    BpfCollectionAttemptDiagnostic(
                        attemptSessionGeneration = expectedGen,
                        attemptAtMonotonicMs = nowMono,
                        attemptDurationMs = collectionDurationMs,
                        attemptStatus = BpfCollectionStatus.PARSE_FAILURE,
                        attemptError = "Rejected all lines [$reasonSummary]",
                        recognizedFormat = true,
                        snapshotPublished = false,
                        decisionReason = "Rejected: 0 valid flows and ${parsed.rejectedLines.size} rejected line(s)",
                        upstreamEntries = 0,
                        downstreamEntries = 0,
                        knownAgeEntries = 0,
                        unavailableAgeEntries = 0,
                        negativeDeltaAgeEntries = 0,
                        rejectedLineCount = parsed.rejectedLines.size,
                        rejectedByReason = reasonCounts,
                        rejectedLines = capturedRejectedLines,
                    ),
                )
                return false
            }
            for (rej in parsed.rejectedLines) {
                EXTRACT_IPV4_REGEX.findAll(rej.linePreview).forEach { m ->
                    val candidate = m.value
                    if (BpfDumpParser.isValidIpv4(candidate) && ipToMac.containsKey(candidate)) {
                        quarantinedClientIps.add(candidate)
                    }
                }
                EXTRACT_MAC_REGEX.findAll(rej.linePreview).forEach { m ->
                    val candidate = m.value.uppercase()
                    if (candidate != "00:00:00:00:00:00" && candidate in activeConnectedMacs) {
                        quarantinedMacs.add(candidate)
                    }
                }
                EXTRACT_ENDPOINT_REGEX.findAll(rej.linePreview).forEach { m ->
                    quarantinedEndpoints.add(m.value)
                }
            }
        }

        // 1. Resolve kernel ifindex from the OS (never treating 0 as a valid index)
        val downRes = resolveInterface(activeDownstreamIface)
        val upRes = resolveInterface(activeUpstreamIface)
        val osDownIfIndex: Int? = downRes.osIfIndex
        val osUpIfIndex: Int? = upRes.osIfIndex

        // 2. Infer interface indices from explicit non-numeric interface labels in the dump (e.g. "250(testtun58)")
        var namedDumpDownIfIndex: Int? = null
        var namedDumpUpIfIndex: Int? = null
        for (up in parsed.ipv4UpstreamEntries) {
            if (namedDumpDownIfIndex == null && up.inIfaceLabel.isNotEmpty() && !up.inIfaceLabel.all { it.isDigit() } &&
                matchesActiveDownstreamLabel(up.inIfaceLabel)
            ) {
                namedDumpDownIfIndex = up.inIfIndex
            }
            if (namedDumpUpIfIndex == null && up.outIfaceLabel.isNotEmpty() && !up.outIfaceLabel.all { it.isDigit() } &&
                matchesActiveUpstreamLabel(up.outIfaceLabel)
            ) {
                namedDumpUpIfIndex = up.outIfIndex
            }
        }
        for (down in parsed.ipv4DownstreamEntries) {
            if (namedDumpUpIfIndex == null && down.inIfaceLabel.isNotEmpty() && !down.inIfaceLabel.all { it.isDigit() } &&
                matchesActiveUpstreamLabel(down.inIfaceLabel)
            ) {
                namedDumpUpIfIndex = down.inIfIndex
            }
            if (namedDumpDownIfIndex == null && down.outIfaceLabel.isNotEmpty() && !down.outIfaceLabel.all { it.isDigit() } &&
                matchesActiveDownstreamLabel(down.outIfaceLabel)
            ) {
                namedDumpDownIfIndex = down.outIfIndex
            }
        }

        var inferredUpIfIndex: Int? = osUpIfIndex ?: namedDumpUpIfIndex
        var inferredDownIfIndex: Int? = osDownIfIndex ?: namedDumpDownIfIndex

        // 3. Corroborate numeric labels (e.g. "251(251)" paired with "250(testtun58)") ONLY when:
        //    - The paired interface has a verified OS or named dump ifindex (or neither active interface was configured), AND
        //    - Reverse-direction parity confirms the exact reversed pair (down.inIfIndex == up.outIfIndex && down.outIfIndex == up.inIfIndex)
        //      whenever downstream entries are present.
        val interfacesConfigured = activeDownstreamIface.isNotBlank() || activeUpstreamIface.isNotBlank()
        if (inferredDownIfIndex == null && (inferredUpIfIndex != null || !interfacesConfigured)) {
            val candidateDownIndices = LinkedHashSet<Int>()
            for (up in parsed.ipv4UpstreamEntries) {
                val upMatchesKnown = inferredUpIfIndex == null || up.outIfIndex == inferredUpIfIndex
                if (!upMatchesKnown || up.inIfIndex <= 0 || up.inIfIndex == up.outIfIndex) continue
                val reverseParityConfirmed = parsed.ipv4DownstreamEntries.isEmpty() ||
                    parsed.ipv4DownstreamEntries.any { down ->
                        down.inIfIndex == up.outIfIndex && down.outIfIndex == up.inIfIndex
                    }
                if (reverseParityConfirmed) {
                    candidateDownIndices.add(up.inIfIndex)
                }
            }
            if (candidateDownIndices.size == 1) {
                inferredDownIfIndex = candidateDownIndices.first()
            }
        }
        if (inferredUpIfIndex == null && (inferredDownIfIndex != null || !interfacesConfigured)) {
            val candidateUpIndices = LinkedHashSet<Int>()
            for (up in parsed.ipv4UpstreamEntries) {
                val downMatchesKnown = inferredDownIfIndex == null || up.inIfIndex == inferredDownIfIndex
                if (!downMatchesKnown || up.outIfIndex <= 0 || up.inIfIndex == up.outIfIndex) continue
                val reverseParityConfirmed = parsed.ipv4DownstreamEntries.isEmpty() ||
                    parsed.ipv4DownstreamEntries.any { down ->
                        down.inIfIndex == up.outIfIndex && down.outIfIndex == up.inIfIndex
                    }
                if (reverseParityConfirmed) {
                    candidateUpIndices.add(up.outIfIndex)
                }
            }
            if (candidateUpIndices.size == 1) {
                inferredUpIfIndex = candidateUpIndices.first()
            }
        }

        // Index ALL IPv4 Downstream entries by translated tuple so we can detect both matching
        // reverse entries AND contradictory/swapped ifindex entries for the same tuple.
        val allDownstreamByTuple = HashMap<TranslatedFlowKey, MutableList<BpfIpv4DownstreamEntry>>()
        for (down in parsed.ipv4DownstreamEntries) {
            val key = TranslatedFlowKey(
                family = 4,
                protocol = down.protocol,
                translatedIp = down.translatedIp,
                translatedPort = down.translatedPort,
                remoteIp = down.remoteIp,
                remotePort = down.remotePort,
            )
            allDownstreamByTuple.getOrPut(key) { ArrayList(1) }.add(down)
        }

        val normalizedIpToMac = HashMap<String, String>()
        for ((ip, mac) in ipToMac) {
            val cleanMac = mac.uppercase().trim()
            if (cleanMac in activeConnectedMacs) {
                normalizedIpToMac[ip.trim()] = cleanMac
            }
        }

        val validFlows = HashMap<TranslatedFlowKey, NatFlowMapping>()
        val ambiguousTuples = HashMap<TranslatedFlowKey, String>()
        var reverseMatched = 0
        var unverifiedOwners = 0
        var ifIndexMismatches = 0
        var coverageIncomplete = parsed.hasRejections
        var observedDownIfIndex = inferredDownIfIndex ?: 0
        var observedDownIface = activeDownstreamIface
        var observedUpIfIndex = inferredUpIfIndex ?: 0
        var observedUpIface = activeUpstreamIface

        val perClientTcp = HashMap<String, Int>()
        val perClientUdp = HashMap<String, Int>()
        val perClientIp = HashMap<String, String>()

        for (up in parsed.ipv4UpstreamEntries) {
            val tupleKey = TranslatedFlowKey(
                family = 4,
                protocol = up.protocol,
                translatedIp = up.translatedIp,
                translatedPort = up.translatedPort,
                remoteIp = up.remoteIp,
                remotePort = up.remotePort,
            )

            // Do not trust an isolated numeric label (e.g. "251(251) -> 250(250)") when active interfaces
            // are configured unless at least one side is corroborated by OS ifindex or an explicit named
            // interface label and inferredDownIfIndex / inferredUpIfIndex were established.
            val uncorroboratedNumericWhenConfigured = interfacesConfigured &&
                (inferredDownIfIndex == null || inferredUpIfIndex == null)

            // Validate upstream interface labels and ifindex consistency
            val labelMatches = matchesActiveDownstreamLabel(up.inIfaceLabel) &&
                matchesActiveUpstreamLabel(up.outIfaceLabel)
            val upIfIndexValid = !uncorroboratedNumericWhenConfigured &&
                up.inIfIndex > 0 && up.outIfIndex > 0 && up.inIfIndex != up.outIfIndex &&
                (osDownIfIndex == null || up.inIfIndex == osDownIfIndex) &&
                (osUpIfIndex == null || up.outIfIndex == osUpIfIndex) &&
                (inferredDownIfIndex == null || up.inIfIndex == inferredDownIfIndex) &&
                (inferredUpIfIndex == null || up.outIfIndex == inferredUpIfIndex) &&
                (inferredUpIfIndex == null || up.inIfIndex != inferredUpIfIndex) &&
                (inferredDownIfIndex == null || up.outIfIndex != inferredDownIfIndex) &&
                (observedDownIfIndex == 0 || up.inIfIndex == observedDownIfIndex) &&
                (observedUpIfIndex == 0 || up.outIfIndex == observedUpIfIndex)

            if (!labelMatches || !upIfIndexValid) {
                ifIndexMismatches++
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] =
                    "Incompatible upstream interface/ifindex: ${up.inIfIndex}(${up.inIfaceLabel}) -> ${up.outIfIndex}(${up.outIfaceLabel})"
                continue
            }

            if (observedDownIfIndex == 0) observedDownIfIndex = up.inIfIndex
            if (observedDownIface.isEmpty() && !up.inIfaceLabel.all { it.isDigit() }) {
                observedDownIface = up.inIfaceLabel
            }
            if (observedUpIfIndex == 0) observedUpIfIndex = up.outIfIndex
            if (observedUpIface.isEmpty() && !up.outIfaceLabel.all { it.isDigit() }) {
                observedUpIface = up.outIfaceLabel
            }

            if (ambiguousTuples.containsKey(tupleKey)) {
                continue
            }

            // Quarantine check when safe partial publication is enabled
            val ownerFromIpBinding = normalizedIpToMac[up.origClientIp]
            val origEndpoint = "${up.origClientIp}:${up.origClientPort}"
            val translatedEndpoint = "${up.translatedIp}:${up.translatedPort}"
            if (parsed.hasRejections && (
                    up.origClientIp in quarantinedClientIps ||
                        origEndpoint in quarantinedEndpoints ||
                        translatedEndpoint in quarantinedEndpoints ||
                        (ownerFromIpBinding != null && ownerFromIpBinding in quarantinedMacs)
                    )
            ) {
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] = "Quarantined due to rejected flow line touching endpoint"
                continue
            }

            val candidateDownList = allDownstreamByTuple[tupleKey].orEmpty()
            // Check if any downstream entry for this tuple has swapped or incompatible ifindex or labels
            val hasIncompatibleDownIfIndex = candidateDownList.any { down ->
                !matchesActiveUpstreamLabel(down.inIfaceLabel) ||
                    !matchesActiveDownstreamLabel(down.outIfaceLabel) ||
                    down.inIfIndex != up.outIfIndex ||
                    down.outIfIndex != up.inIfIndex
            }
            if (hasIncompatibleDownIfIndex) {
                ifIndexMismatches++
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] =
                    "Incompatible or swapped downstream ifindex for tuple $tupleKey"
                continue
            }

            val exactDown = candidateDownList.filter {
                it.origClientIp == up.origClientIp &&
                    it.origClientPort == up.origClientPort &&
                    it.inIfIndex == up.outIfIndex &&
                    it.outIfIndex == up.inIfIndex
            }

            val reverseMacs = exactDown
                .map { it.clientOutDstMac.uppercase().trim() }
                .filter { it != "00:00:00:00:00:00" && BpfDumpParser.isValidMac(it) }
                .toSet()

            if (reverseMacs.size > 1) {
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] = "Multiple conflicting reverse outDstMac values: $reverseMacs"
                continue
            }

            val reverseMac = reverseMacs.firstOrNull()
            if (parsed.hasRejections && reverseMac != null && reverseMac in quarantinedMacs) {
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] = "Quarantined due to rejected flow line touching MAC"
                continue
            }

            // Cross-check IP binding against reverse downstream outDstMac when both are present
            if (ownerFromIpBinding != null && reverseMac != null && ownerFromIpBinding != reverseMac) {
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] =
                    "Contradictory ownership for ${up.origClientIp}: binding=$ownerFromIpBinding vs reverseMac=$reverseMac"
                continue
            }

            // Determine verified MAC owner:
            // - Never use up.hotspotInDstMac!
            // - Require either a verified ipToMac binding, or a reverse downstream outDstMac that belongs
            //   to activeConnectedMacs (and does not conflict with any other client's IP binding).
            val verifiedMac = when {
                ownerFromIpBinding != null -> ownerFromIpBinding
                reverseMac != null && reverseMac in activeConnectedMacs -> reverseMac
                else -> null
            }

            if (verifiedMac == null) {
                unverifiedOwners++
                continue
            }

            val hasReverseConfirm = exactDown.isNotEmpty() && (reverseMac == null || reverseMac == verifiedMac)
            if (hasReverseConfirm) {
                reverseMatched++
            }

            // Check if another upstream entry in the same dump already claimed this translated tuple
            val existing = validFlows[tupleKey]
            if (existing != null) {
                if (existing.verifiedMac != verifiedMac ||
                    existing.origClientIp != up.origClientIp ||
                    existing.origClientPort != up.origClientPort
                ) {
                    validFlows.remove(tupleKey)
                    ambiguousTuples[tupleKey] =
                        "Duplicate translated tuple collision between ${existing.verifiedMac} (${existing.origClientIp}:${existing.origClientPort}) and $verifiedMac (${up.origClientIp}:${up.origClientPort})"
                    continue
                }
            }

            if (validFlows.size >= maxMappedFlows) {
                coverageIncomplete = true
                continue
            }

            val mapping = NatFlowMapping(
                sessionGeneration = expectedGen,
                bindingGeneration = curBindGen,
                downstreamIfIndex = up.inIfIndex,
                downstreamIfaceLabel = up.inIfaceLabel,
                upstreamIfIndex = up.outIfIndex,
                upstreamIfaceLabel = up.outIfaceLabel,
                family = 4,
                protocol = up.protocol,
                origClientIp = up.origClientIp,
                origClientPort = up.origClientPort,
                translatedIp = up.translatedIp,
                translatedPort = up.translatedPort,
                remoteIp = up.remoteIp,
                remotePort = up.remotePort,
                verifiedMac = verifiedMac,
                reverseMapConfirmed = hasReverseConfirm,
                collectedAtMonotonicMs = nowMono,
                rawDumpAgeMs = up.rawAgeMs,
                flowAge = up.flowAge,
            )
            validFlows[tupleKey] = mapping
            // Clear any pending SYN refresh flag now that a newer snapshot has arrived
            synPendingRefreshTuples.remove(tupleKey)

            perClientIp[verifiedMac] = up.origClientIp
            if (up.protocol == 6) {
                perClientTcp[verifiedMac] = (perClientTcp[verifiedMac] ?: 0) + 1
            } else if (up.protocol == 17) {
                perClientUdp[verifiedMac] = (perClientUdp[verifiedMac] ?: 0) + 1
            }
        }

        val allClientMacs = (perClientTcp.keys + perClientUdp.keys).sorted()
        val clientSummaries = allClientMacs.map { mac ->
            ClientProtocolFlowCounts(
                mac = mac,
                originalIpv4 = perClientIp[mac].orEmpty(),
                tcpFlows = perClientTcp[mac] ?: 0,
                udpFlows = perClientUdp[mac] ?: 0,
            )
        }

        val finalStatus = if (parsed.ipv4UpstreamEntries.isEmpty() && parsed.ipv4DownstreamEntries.isEmpty()) {
            BpfCollectionStatus.EMPTY_VALID
        } else {
            BpfCollectionStatus.OK
        }

        val finalInferredDown = observedDownIfIndex.takeIf { it > 0 } ?: inferredDownIfIndex
        val finalInferredUp = observedUpIfIndex.takeIf { it > 0 } ?: inferredUpIfIndex

        val snapshot = NatFlowSnapshot(
            sessionGeneration = expectedGen,
            bindingGeneration = curBindGen,
            collectedAtMonotonicMs = nowMono,
            collectionDurationMs = collectionDurationMs,
            collectionStatus = finalStatus,
            collectionError = collectionError,
            downstreamIfIndex = finalInferredDown ?: osDownIfIndex ?: 0,
            downstreamIface = observedDownIface,
            upstreamIfIndex = finalInferredUp ?: osUpIfIndex ?: 0,
            upstreamIface = observedUpIface,
            osDownstreamIfIndex = osDownIfIndex,
            osUpstreamIfIndex = osUpIfIndex,
            inferredDownstreamIfIndex = finalInferredDown,
            inferredUpstreamIfIndex = finalInferredUp,
            downstreamIfIndexSource = downRes.source,
            upstreamIfIndexSource = upRes.source,
            downstreamIfIndexError = downRes.failureReason,
            upstreamIfIndexError = upRes.failureReason,
            resolvedDownstreamIfIndex = osDownIfIndex ?: 0,
            resolvedUpstreamIfIndex = osUpIfIndex ?: 0,
            totalUpstreamEntries = parsed.ipv4UpstreamEntries.size,
            totalDownstreamEntries = parsed.ipv4DownstreamEntries.size,
            knownAgeEntries = parsed.knownAgeEntries,
            unavailableAgeEntries = parsed.unavailableAgeEntries,
            negativeDeltaAgeEntries = parsed.negativeDeltaAgeEntries,
            reverseMatchedCount = reverseMatched,
            flowsByTuple = validFlows,
            ambiguousTuples = ambiguousTuples,
            unverifiedOwnerEntries = unverifiedOwners,
            ifIndexMismatchCount = ifIndexMismatches,
            rejectedLineCount = parsed.rejectedLines.size,
            coverageIncomplete = coverageIncomplete,
            perClientCounts = clientSummaries,
        )

        if (sessionGen.get() != expectedGen) {
            rejectedOldGenerationCount.incrementAndGet()
            return false
        }
        currentSnapshotRef.set(snapshot)
        lastAttemptRef.set(
            BpfCollectionAttemptDiagnostic(
                attemptSessionGeneration = expectedGen,
                attemptAtMonotonicMs = nowMono,
                attemptDurationMs = collectionDurationMs,
                attemptStatus = finalStatus,
                attemptError = collectionError,
                recognizedFormat = true,
                snapshotPublished = true,
                decisionReason = if (coverageIncomplete) {
                    "Published partial snapshot with quarantine (coverageIncomplete=true)"
                } else {
                    "Published verified snapshot (${validFlows.size} active flow(s))"
                },
                upstreamEntries = parsed.ipv4UpstreamEntries.size,
                downstreamEntries = parsed.ipv4DownstreamEntries.size,
                knownAgeEntries = parsed.knownAgeEntries,
                unavailableAgeEntries = parsed.unavailableAgeEntries,
                negativeDeltaAgeEntries = parsed.negativeDeltaAgeEntries,
                rejectedLineCount = parsed.rejectedLines.size,
                rejectedByReason = reasonCounts,
                rejectedLines = capturedRejectedLines,
            ),
        )
        return true
    }

    /**
     * Resolves the client MAC for a translated IPv4 TCP/UDP packet on the TUN interface.
     *
     * - For upload (`isUpload = true`): packet `srcIp:srcPort` is `translatedIp:translatedPort`,
     *   and `dstIp:dstPort` is `remoteIp:remotePort`.
     * - For download (`isUpload = false`): packet `srcIp:srcPort` is `remoteIp:remotePort`,
     *   and `dstIp:dstPort` is `translatedIp:translatedPort` (endpoints reversed before lookup).
     */
    fun resolveTranslatedPacket(
        family: Int,
        protocol: Int,
        packetSrcIp: String,
        packetSrcPort: Int,
        packetDstIp: String,
        packetDstPort: Int,
        isUpload: Boolean,
        isTcpSyn: Boolean,
        ipToMac: Map<String, String>,
        activeConnectedMacs: Set<String>,
    ): AttributionOutcome {
        if (family != 4 || (protocol != 6 && protocol != 17)) {
            lookupUnknownCount.incrementAndGet()
            return AttributionOutcome.Unknown
        }
        if (packetSrcPort !in 1..65535 || packetDstPort !in 1..65535) {
            lookupUnknownCount.incrementAndGet()
            return AttributionOutcome.Unknown
        }

        val translatedIp = if (isUpload) packetSrcIp else packetDstIp
        val translatedPort = if (isUpload) packetSrcPort else packetDstPort
        val remoteIp = if (isUpload) packetDstIp else packetSrcIp
        val remotePort = if (isUpload) packetDstPort else packetSrcPort

        val tupleKey = TranslatedFlowKey(
            family = 4,
            protocol = protocol,
            translatedIp = translatedIp,
            translatedPort = translatedPort,
            remoteIp = remoteIp,
            remotePort = remotePort,
        )

        val snapshot = currentSnapshotRef.get()
        val expectedGen = sessionGen.get()
        if (snapshot.sessionGeneration != expectedGen ||
            snapshot.collectedAtMonotonicMs <= 0L ||
            (snapshot.collectionStatus != BpfCollectionStatus.OK && snapshot.collectionStatus != BpfCollectionStatus.EMPTY_VALID)
        ) {
            lookupUnknownCount.incrementAndGet()
            return AttributionOutcome.Unknown
        }

        val nowMono = monotonicClockMs()
        val ageMs = (nowMono - snapshot.collectedAtMonotonicMs).coerceAtLeast(0L)
        if (ageMs > maxFreshnessMs) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleSnapshot(ageMs)
        }

        snapshot.ambiguousTuples[tupleKey]?.let { reason ->
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.Ambiguous(reason)
        }

        val mapping = snapshot.flowsByTuple[tupleKey]
        if (mapping == null) {
            lookupUnknownCount.incrementAndGet()
            return AttributionOutcome.Unknown
        }

        // Verify the client MAC is still actively connected
        if (mapping.verifiedMac !in activeConnectedMacs) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleOrInvalidated("Client ${mapping.verifiedMac} is no longer connected")
        }

        // Verify the original IPv4 ownership has not been reassigned to a different client
        val currentOwnerForOrigIp = ipToMac[mapping.origClientIp]?.uppercase()?.trim()
        if (currentOwnerForOrigIp != null && currentOwnerForOrigIp != mapping.verifiedMac) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleOrInvalidated(
                "Original IP ${mapping.origClientIp} reassigned from ${mapping.verifiedMac} to $currentOwnerForOrigIp",
            )
        }
        if (ipToMac.isNotEmpty() && currentOwnerForOrigIp == null) {
            // Client's IP was removed or changed since snapshot was collected
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleOrInvalidated(
                "Original IP ${mapping.origClientIp} is no longer bound to ${mapping.verifiedMac}",
            )
        }

        // Conservative tuple-reuse guard for TCP:
        // If a brand-new upload TCP SYN arrives on a tuple that was already in an older snapshot,
        // the port may have been reused by a new connection before the next BPF dump poll.
        if (protocol == 6 && isUpload && isTcpSyn) {
            synPendingRefreshTuples[tupleKey] = nowMono
            tupleReuseGuardTriggeredCount.incrementAndGet()
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleOrInvalidated(
                "New upload TCP SYN on existing tuple $tupleKey; awaiting next BPF snapshot to prevent port-reuse misattribution",
            )
        }

        val pendingSynAt = synPendingRefreshTuples[tupleKey]
        if (pendingSynAt != null && snapshot.collectedAtMonotonicMs <= pendingSynAt) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return AttributionOutcome.StaleOrInvalidated(
                "Tuple $tupleKey had a new TCP SYN after snapshot timestamp; awaiting refreshed BPF dump",
            )
        }

        lookupMatchedCount.incrementAndGet()
        return AttributionOutcome.Matched(mapping.verifiedMac, mapping)
    }

    private fun matchesActiveDownstreamLabel(dumpIfaceLabel: String): Boolean {
        val active = activeDownstreamIface
        if (active.isEmpty() || dumpIfaceLabel.isEmpty()) return true
        if (dumpIfaceLabel.all { it.isDigit() }) return true // e.g., 251(251), corroborated via reverse ifindex parity
        return dumpIfaceLabel.equals(active, ignoreCase = true)
    }

    private fun matchesActiveUpstreamLabel(dumpIfaceLabel: String): Boolean {
        val active = activeUpstreamIface
        if (active.isEmpty() || dumpIfaceLabel.isEmpty()) return true
        if (dumpIfaceLabel.all { it.isDigit() }) return true // corroborated via reverse ifindex parity
        return dumpIfaceLabel.equals(active, ignoreCase = true)
    }

    companion object {
        const val DEFAULT_MAX_FRESHNESS_MS = 4_500L
        const val DEFAULT_MAX_MAPPED_FLOWS = 4_096
        const val MAX_CAPTURED_REJECTED_LINES = 50
        const val MAX_EXPORTED_REJECTED_LINES = 20

        private val EXTRACT_IPV4_REGEX = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}\b""")
        private val EXTRACT_MAC_REGEX = Regex("""\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b""")
        private val EXTRACT_ENDPOINT_REGEX = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b""")

        /**
         * Resolves the kernel `ifindex` for [ifaceName] using:
         * 1. `Os.if_nametoindex(clean)` (direct POSIX `SIOCGIFINDEX` ioctl)
         * 2. `NetworkInterface.getByName(clean)?.index`
         * 3. `/sys/class/net/<ifaceName>/ifindex`
         *
         * Never treats `0` as a valid `ifindex`: returns `osIfIndex = null` with a concrete
         * [InterfaceIndexResolution.failureReason] when all OS resolution paths fail.
         */
        fun defaultResolveInterfaceIndex(ifaceName: String): InterfaceIndexResolution {
            val clean = ifaceName.trim()
            if (clean.isEmpty()) {
                return InterfaceIndexResolution(
                    ifaceName = "",
                    osIfIndex = null,
                    source = "UNSET",
                    failureReason = "Interface name is blank",
                )
            }
            val errors = ArrayList<String>(3)

            // 1. POSIX Os.if_nametoindex (SIOCGIFINDEX ioctl)
            try {
                val osIdx = Os.if_nametoindex(clean)
                if (osIdx > 0) {
                    return InterfaceIndexResolution(
                        ifaceName = clean,
                        osIfIndex = osIdx,
                        source = "OS_IF_NAMETOINDEX",
                        failureReason = "",
                    )
                }
                errors.add("Os.if_nametoindex($clean)=0")
            } catch (t: Throwable) {
                errors.add("Os.if_nametoindex: ${t.javaClass.simpleName}(${t.message ?: "error"})")
            }

            // 2. java.net.NetworkInterface.getByName
            try {
                val netIf = java.net.NetworkInterface.getByName(clean)
                val netIdx = netIf?.index ?: 0
                if (netIdx > 0) {
                    return InterfaceIndexResolution(
                        ifaceName = clean,
                        osIfIndex = netIdx,
                        source = "NETWORK_INTERFACE",
                        failureReason = "",
                    )
                }
                errors.add(if (netIf == null) "NetworkInterface.getByName($clean)=null" else "NetworkInterface.index=$netIdx")
            } catch (t: Throwable) {
                errors.add("NetworkInterface: ${t.javaClass.simpleName}(${t.message ?: "error"})")
            }

            // 3. /sys/class/net/<iface>/ifindex
            try {
                val f = java.io.File("/sys/class/net/$clean/ifindex")
                if (f.isFile && f.canRead()) {
                    val sysIdx = f.readText().trim().toIntOrNull() ?: 0
                    if (sysIdx > 0) {
                        return InterfaceIndexResolution(
                            ifaceName = clean,
                            osIfIndex = sysIdx,
                            source = "SYSFS",
                            failureReason = "",
                        )
                    }
                    errors.add("sysfs($clean)=$sysIdx")
                } else {
                    errors.add("sysfs($clean): exists=${f.exists()}, canRead=${f.canRead()}")
                }
            } catch (t: Throwable) {
                errors.add("sysfs: ${t.javaClass.simpleName}(${t.message ?: "error"})")
            }

            return InterfaceIndexResolution(
                ifaceName = clean,
                osIfIndex = null,
                source = "UNAVAILABLE",
                failureReason = errors.joinToString("; "),
            )
        }

        fun defaultResolveIfIndex(ifaceName: String): Int =
            defaultResolveInterfaceIndex(ifaceName).osIfIndex ?: 0
    }
}

/**
 * Result of executing `dumpsys tethering bpf` inside the Shizuku UserService.
 */
data class BpfRawCollectionResult(
    val status: BpfCollectionStatus,
    val exitCode: Int,
    val durationMs: Long,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean,
    val wasTruncated: Boolean,
    val errorSummary: String = "",
)

/**
 * Background worker that executes `dumpsys tethering bpf` strictly off the packet forwarding path.
 *
 * - Runs inside the Shizuku UserService process (UID 2000 shell identity).
 * - Ensures at most one collection is in flight at any time.
 * - Enforces a real execution deadline and byte cap, reading stdout/stderr concurrently.
 * - Uses exponential backoff on repeated permission or command failures.
 */
class BpfMapReader(
    private val attributor: NatFlowAttributor,
    private val commandRunner: (timeoutMs: Long, maxBytes: Int) -> BpfRawCollectionResult = ::defaultDumpsysRunner,
    private val clientBindingsProvider: () -> Pair<Map<String, String>, Set<String>> = {
        TunTrafficEngine.getVerifiedClientBindingsSnapshot()
    },
    private val monotonicClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
) {

    private val inFlight = AtomicBoolean(false)
    private var executor: ScheduledExecutorService? = null
    private var scheduledFuture: ScheduledFuture<*>? = null

    @Volatile
    var isEnabled: Boolean = false
        private set

    @Volatile
    var pollIntervalMs: Long = DEFAULT_POLL_INTERVAL_MS
        private set

    @Volatile
    var consecutiveFailures: Int = 0
        private set

    @Volatile
    var nextAllowedCollectMonoMs: Long = 0L
        private set

    val totalCollectionsAttempted = AtomicLong(0L)
    val totalCollectionsSucceeded = AtomicLong(0L)
    val totalCollectionsFailed = AtomicLong(0L)

    @Volatile
    var lastRawResult: BpfRawCollectionResult? = null
        private set

    @Synchronized
    fun configure(enabled: Boolean, intervalMs: Long = DEFAULT_POLL_INTERVAL_MS, sessionActive: Boolean) {
        val clampedInterval = intervalMs.coerceIn(MIN_POLL_INTERVAL_MS, MAX_POLL_INTERVAL_MS)
        val intervalChanged = pollIntervalMs != clampedInterval
        val enabledChanged = isEnabled != enabled
        isEnabled = enabled
        pollIntervalMs = clampedInterval

        if (!enabled || !sessionActive) {
            stopWorker()
            if (enabledChanged && !enabled) {
                SessionLog.info("BPF Attribution: experimental BPF NAT flow attribution disabled")
            }
            return
        }

        if (enabledChanged) {
            consecutiveFailures = 0
            nextAllowedCollectMonoMs = 0L
            SessionLog.info(
                "BPF Attribution: experimental BPF NAT flow attribution enabled (pollInterval=${pollIntervalMs}ms)",
            )
        }
        if (executor == null || scheduledFuture == null || intervalChanged) {
            startWorker()
        }
    }

    @Synchronized
    fun startWorker() {
        stopWorker()
        if (!isEnabled) return
        val exec = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "shizzi-bpf-collector").apply { isDaemon = true }
        }
        executor = exec
        scheduledFuture = exec.scheduleWithFixedDelay(
            { runCatching { collectOnce(respectBackoff = true) } },
            0L,
            pollIntervalMs,
            TimeUnit.MILLISECONDS,
        )
    }

    @Synchronized
    fun stopWorker() {
        scheduledFuture?.cancel(false)
        scheduledFuture = null
        executor?.shutdownNow()
        executor = null
    }

    /**
     * Performs a single bounded collection cycle if none is currently in flight.
     */
    fun collectOnce(respectBackoff: Boolean = false): BpfCollectionStatus {
        val nowMono = monotonicClockMs()
        if (respectBackoff && nowMono < nextAllowedCollectMonoMs) {
            return lastRawResult?.status ?: BpfCollectionStatus.IDLE
        }
        if (!inFlight.compareAndSet(false, true)) {
            return lastRawResult?.status ?: BpfCollectionStatus.OK
        }

        val generationAtStart = attributor.currentSessionGeneration
        totalCollectionsAttempted.incrementAndGet()
        try {
            val raw = commandRunner(COMMAND_TIMEOUT_MS, MAX_DUMP_BYTES)
            lastRawResult = raw

            if (raw.status != BpfCollectionStatus.OK && raw.status != BpfCollectionStatus.TRUNCATED) {
                totalCollectionsFailed.incrementAndGet()
                recordFailureAndBackoff(raw.status)
                attributor.ingestParsedDump(
                    parsed = BpfParsedDump(
                        recognizedFormat = false,
                        ipv4UpstreamEntries = emptyList(),
                        ipv4DownstreamEntries = emptyList(),
                        ipv6Entries = emptyList(),
                        rejectedLines = emptyList(),
                        wasTruncatedByReader = raw.wasTruncated,
                    ),
                    collectionSessionGeneration = generationAtStart,
                    collectionStatus = raw.status,
                    collectionDurationMs = raw.durationMs,
                    collectionError = raw.errorSummary,
                    ipToMac = emptyMap(),
                    activeConnectedMacs = emptySet(),
                )
                return raw.status
            }

            val parsed = BpfDumpParser.parse(raw.stdout, wasTruncatedByReader = raw.wasTruncated)
            val (ipToMac, connectedMacs) = clientBindingsProvider()
            val reasonSummary = parsed.rejectionCountsByReason()
                .entries
                .joinToString(", ") { "${it.key}=${it.value}" }
            val ingested = attributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = generationAtStart,
                collectionStatus = when {
                    raw.wasTruncated || raw.status == BpfCollectionStatus.TRUNCATED -> BpfCollectionStatus.TRUNCATED
                    parsed.isEmptyValid -> BpfCollectionStatus.EMPTY_VALID
                    else -> BpfCollectionStatus.OK
                },
                collectionDurationMs = raw.durationMs,
                collectionError = when {
                    raw.errorSummary.isNotBlank() -> raw.errorSummary
                    parsed.hasRejections -> "Rejected ${parsed.rejectedLines.size} line(s) [$reasonSummary]"
                    else -> ""
                },
                ipToMac = ipToMac,
                activeConnectedMacs = connectedMacs,
            )

            return if (ingested) {
                consecutiveFailures = 0
                nextAllowedCollectMonoMs = 0L
                totalCollectionsSucceeded.incrementAndGet()
                attributor.currentSnapshot().collectionStatus
            } else {
                totalCollectionsFailed.incrementAndGet()
                val failStatus = attributor.lastAttemptDiagnostic().attemptStatus.takeIf {
                    it != BpfCollectionStatus.IDLE && it != BpfCollectionStatus.OK && it != BpfCollectionStatus.EMPTY_VALID
                } ?: if (!parsed.recognizedFormat || parsed.hasRejections) {
                    BpfCollectionStatus.PARSE_FAILURE
                } else {
                    BpfCollectionStatus.COMMAND_FAILED
                }
                recordFailureAndBackoff(failStatus)
                failStatus
            }
        } finally {
            inFlight.set(false)
        }
    }

    private fun recordFailureAndBackoff(status: BpfCollectionStatus) {
        consecutiveFailures++
        val backoffMultiplier = when (status) {
            BpfCollectionStatus.PERMISSION_DENIED, BpfCollectionStatus.SERVICE_LOST ->
                (1L shl consecutiveFailures.coerceAtMost(5)) * 2_000L
            else ->
                (1L shl consecutiveFailures.coerceAtMost(4)) * 1_000L
        }
        nextAllowedCollectMonoMs = monotonicClockMs() + backoffMultiplier.coerceAtMost(30_000L)
    }

    companion object {
        const val DEFAULT_POLL_INTERVAL_MS = 1_000L
        const val MIN_POLL_INTERVAL_MS = 500L
        const val MAX_POLL_INTERVAL_MS = 5_000L
        const val COMMAND_TIMEOUT_MS = 1_500L
        const val MAX_DUMP_BYTES = 256 * 1024

        fun defaultDumpsysRunner(timeoutMs: Long, maxBytes: Int): BpfRawCollectionResult {
            val token = Binder.clearCallingIdentity()
            val startNs = System.nanoTime()
            return try {
                val process = ProcessBuilder("dumpsys", "tethering", "bpf")
                    .redirectErrorStream(false)
                    .start()

                val stdoutCapture = BoundedStreamBuffer(maxBytes)
                val stderrCapture = BoundedStreamBuffer(16 * 1024)

                val outThread = thread(start = true, isDaemon = true, name = "shizzi-bpf-stdout") {
                    stdoutCapture.consume(process.inputStream)
                }
                val errThread = thread(start = true, isDaemon = true, name = "shizzi-bpf-stderr") {
                    stderrCapture.consume(process.errorStream)
                }

                val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
                if (!finished) {
                    process.destroyForcibly()
                }
                outThread.join(250)
                errThread.join(250)

                val durationMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(0L)
                val exitCode = if (finished) runCatching { process.exitValue() }.getOrDefault(-1) else -1
                val stdout = stdoutCapture.text
                val stderr = stderrCapture.text
                val truncated = stdoutCapture.truncated

                val status = when {
                    !finished -> BpfCollectionStatus.TIMEOUT
                    truncated -> BpfCollectionStatus.TRUNCATED
                    exitCode != 0 || stderr.contains("Permission Denial", ignoreCase = true) ||
                        stdout.contains("Permission Denial", ignoreCase = true) -> {
                        val combined = "$stderr $stdout".lowercase()
                        if (combined.contains("permission denial") ||
                            combined.contains("permission denied") ||
                            combined.contains("operation not permitted") ||
                            combined.contains("securityexception")
                        ) {
                            BpfCollectionStatus.PERMISSION_DENIED
                        } else {
                            BpfCollectionStatus.COMMAND_FAILED
                        }
                    }
                    stdout.isBlank() -> BpfCollectionStatus.PARSE_FAILURE
                    else -> BpfCollectionStatus.OK
                }

                val errSummary = when (status) {
                    BpfCollectionStatus.OK -> ""
                    BpfCollectionStatus.TIMEOUT -> "dumpsys tethering bpf timed out after ${timeoutMs}ms"
                    BpfCollectionStatus.TRUNCATED -> "dumpsys tethering bpf exceeded ${maxBytes}B limit"
                    else -> stderr.ifBlank { stdout.take(160) }.trim()
                }

                BpfRawCollectionResult(
                    status = status,
                    exitCode = exitCode,
                    durationMs = durationMs,
                    stdout = stdout,
                    stderr = stderr,
                    timedOut = !finished,
                    wasTruncated = truncated,
                    errorSummary = errSummary,
                )
            } catch (e: Throwable) {
                val durationMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(0L)
                val msg = "${e.javaClass.simpleName}: ${e.message ?: "unknown error"}"
                BpfRawCollectionResult(
                    status = statusForException(e),
                    exitCode = -1,
                    durationMs = durationMs,
                    stdout = "",
                    stderr = msg,
                    timedOut = false,
                    wasTruncated = false,
                    errorSummary = msg,
                )
            } finally {
                Binder.restoreCallingIdentity(token)
            }
        }

        private fun statusForException(e: Throwable): BpfCollectionStatus {
            val msg = (e.message ?: "").lowercase()
            return if (e is SecurityException || msg.contains("permission")) {
                BpfCollectionStatus.PERMISSION_DENIED
            } else {
                BpfCollectionStatus.COMMAND_FAILED
            }
        }
    }

    private class BoundedStreamBuffer(private val maxBytes: Int) {
        @Volatile
        var text: String = ""
            private set

        @Volatile
        var truncated: Boolean = false
            private set

        fun consume(stream: InputStream) {
            try {
                stream.use { input ->
                    val out = java.io.ByteArrayOutputStream(minOf(maxBytes, 16_384))
                    val buf = ByteArray(4096)
                    var total = 0
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        val remaining = maxBytes - total
                        if (remaining > 0) {
                            val toWrite = minOf(n, remaining)
                            out.write(buf, 0, toWrite)
                            total += toWrite
                            if (n > remaining) {
                                truncated = true
                            }
                        } else {
                            truncated = true
                        }
                    }
                    text = out.toString(Charsets.UTF_8.name())
                }
            } catch (_: Throwable) {
            }
        }
    }
}

/**
 * Bounded diagnostic summary for the UI and exportable report.
 *
 * Explicitly separates:
 * 1. **Last Published Snapshot** (`collectionStatus`, `snapshotAgeMs`, `activeMappedFlows`, etc.)
 * 2. **Last Collection Attempt** (`lastAttemptStatus`, `lastAttemptSnapshotPublished`,
 *    `lastAttemptRejectedLines`, `lastAttemptRejectedByReason`, etc.)
 * 3. **OS vs. Inferred Interface Index (`ifindex`)**:
 *    - `osDownstreamIfIndex` / `osUpstreamIfIndex`: `Int?` (`null` when unavailable from OS)
 *    - `inferredDownstreamIfIndex` / `inferredUpstreamIfIndex`: `Int?` (`null` when not inferred from dump)
 */
data class BpfAttributionStatusReport(
    val experimentalEnabled: Boolean = false,
    val state: ExperimentalBpfState = ExperimentalBpfState.DISABLED,
    val collectionStatus: BpfCollectionStatus = BpfCollectionStatus.IDLE,
    val collectionError: String = "",
    val parserVersion: Int = BpfDumpParser.PARSER_VERSION,
    val pollIntervalMs: Long = BpfMapReader.DEFAULT_POLL_INTERVAL_MS,
    val snapshotAgeMs: Long = 0L,
    val lastCollectionDurationMs: Long = 0L,
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
    val downstreamIface: String = "",
    val downstreamIfIndex: Int = 0,
    val upstreamIface: String = "",
    val upstreamIfIndex: Int = 0,
    val osDownstreamIfIndex: Int? = null,
    val osUpstreamIfIndex: Int? = null,
    val inferredDownstreamIfIndex: Int? = null,
    val inferredUpstreamIfIndex: Int? = null,
    val downstreamIfIndexSource: String = "UNSET",
    val upstreamIfIndexSource: String = "UNSET",
    val downstreamIfIndexError: String = "",
    val upstreamIfIndexError: String = "",
    val resolvedDownstreamIfIndex: Int = osDownstreamIfIndex ?: 0,
    val resolvedUpstreamIfIndex: Int = osUpstreamIfIndex ?: 0,
    val totalUpstreamEntries: Int = 0,
    val totalDownstreamEntries: Int = 0,
    val knownAgeEntries: Int = 0,
    val unavailableAgeEntries: Int = 0,
    val negativeDeltaAgeEntries: Int = 0,
    val reverseMatchedCount: Int = 0,
    val activeMappedFlows: Int = 0,
    val ambiguousTupleCount: Int = 0,
    val unverifiedOwnerEntries: Int = 0,
    val ifIndexMismatchCount: Int = 0,
    val rejectedLineCount: Int = 0,
    val coverageIncomplete: Boolean = false,
    val perClientCounts: List<ClientProtocolFlowCounts> = emptyList(),
    val lastAttemptStatus: BpfCollectionStatus = BpfCollectionStatus.IDLE,
    val lastAttemptError: String = "",
    val lastAttemptAgeMs: Long = 0L,
    val lastAttemptDurationMs: Long = 0L,
    val lastAttemptRecognizedFormat: Boolean = false,
    val lastAttemptSnapshotPublished: Boolean = false,
    val lastAttemptDecisionReason: String = "",
    val lastAttemptUpstreamEntries: Int = 0,
    val lastAttemptDownstreamEntries: Int = 0,
    val lastAttemptKnownAgeEntries: Int = 0,
    val lastAttemptUnavailableAgeEntries: Int = 0,
    val lastAttemptNegativeDeltaAgeEntries: Int = 0,
    val lastAttemptRejectedLineCount: Int = 0,
    val lastAttemptRejectedByReason: Map<String, Int> = emptyMap(),
    val lastAttemptRejectedLines: List<BpfRejectedLine> = emptyList(),
    val directAttributedPackets: Long = 0L,
    val bpfAttributedPackets: Long = 0L,
    val unknownForwardedPackets: Long = 0L,
    val unknownForwardedBytes: Long = 0L,
    val ambiguousOrStaleLookups: Long = 0L,
    val localControlPackets: Long = 0L,
    val unsupportedOrFragmentPackets: Long = 0L,
    val blockedDropPackets: Long = 0L,
    val shapingDropPackets: Long = 0L,
    val shapedPackets: Long = 0L,
    val rejectedOldGenerationCount: Long = 0L,
    val tupleReuseGuardTriggeredCount: Long = 0L,
) {
    val omittedRejectedLineCount: Int
        get() = (lastAttemptRejectedLineCount - minOf(lastAttemptRejectedLines.size, NatFlowAttributor.MAX_EXPORTED_REJECTED_LINES))
            .coerceAtLeast(0)

    fun toJson(includeSensitiveEndpoints: Boolean = false): JSONObject = JSONObject().apply {
        put("experimentalEnabled", experimentalEnabled)
        put("state", state.name)
        put("collectionStatus", collectionStatus.name)
        put("collectionError", collectionError)
        put("parserVersion", parserVersion)
        put("pollIntervalMs", pollIntervalMs)
        put("snapshotAgeMs", snapshotAgeMs)
        put("lastCollectionDurationMs", lastCollectionDurationMs)
        put("sessionGeneration", sessionGeneration)
        put("bindingGeneration", bindingGeneration)
        put("downstreamIface", downstreamIface)
        put("downstreamIfIndex", downstreamIfIndex)
        put("upstreamIface", upstreamIface)
        put("upstreamIfIndex", upstreamIfIndex)
        put("osDownstreamIfIndex", osDownstreamIfIndex ?: JSONObject.NULL)
        put("osUpstreamIfIndex", osUpstreamIfIndex ?: JSONObject.NULL)
        put("inferredDownstreamIfIndex", inferredDownstreamIfIndex ?: JSONObject.NULL)
        put("inferredUpstreamIfIndex", inferredUpstreamIfIndex ?: JSONObject.NULL)
        put("downstreamIfIndexSource", downstreamIfIndexSource)
        put("upstreamIfIndexSource", upstreamIfIndexSource)
        put("downstreamIfIndexError", downstreamIfIndexError)
        put("upstreamIfIndexError", upstreamIfIndexError)
        put("resolvedDownstreamIfIndex", resolvedDownstreamIfIndex)
        put("resolvedUpstreamIfIndex", resolvedUpstreamIfIndex)
        put("totalUpstreamEntries", totalUpstreamEntries)
        put("totalDownstreamEntries", totalDownstreamEntries)
        put("knownAgeEntries", knownAgeEntries)
        put("unavailableAgeEntries", unavailableAgeEntries)
        put("negativeDeltaAgeEntries", negativeDeltaAgeEntries)
        put("reverseMatchedCount", reverseMatchedCount)
        put("activeMappedFlows", activeMappedFlows)
        put("ambiguousTupleCount", ambiguousTupleCount)
        put("unverifiedOwnerEntries", unverifiedOwnerEntries)
        put("ifIndexMismatchCount", ifIndexMismatchCount)
        put("rejectedLineCount", rejectedLineCount)
        put("coverageIncomplete", coverageIncomplete)
        put("lastAttemptStatus", lastAttemptStatus.name)
        put("lastAttemptError", lastAttemptError)
        put("lastAttemptAgeMs", lastAttemptAgeMs)
        put("lastAttemptDurationMs", lastAttemptDurationMs)
        put("lastAttemptRecognizedFormat", lastAttemptRecognizedFormat)
        put("lastAttemptSnapshotPublished", lastAttemptSnapshotPublished)
        put("lastAttemptDecisionReason", lastAttemptDecisionReason)
        put("lastAttemptUpstreamEntries", lastAttemptUpstreamEntries)
        put("lastAttemptDownstreamEntries", lastAttemptDownstreamEntries)
        put("lastAttemptKnownAgeEntries", lastAttemptKnownAgeEntries)
        put("lastAttemptUnavailableAgeEntries", lastAttemptUnavailableAgeEntries)
        put("lastAttemptNegativeDeltaAgeEntries", lastAttemptNegativeDeltaAgeEntries)
        put("lastAttemptRejectedLineCount", lastAttemptRejectedLineCount)
        put("omittedRejectedLineCount", omittedRejectedLineCount)
        val reasonsObj = JSONObject()
        for ((reasonKey, count) in lastAttemptRejectedByReason) {
            reasonsObj.put(reasonKey, count)
        }
        put("lastAttemptRejectedByReason", reasonsObj)

        val rejectedArr = JSONArray()
        lastAttemptRejectedLines
            .take(NatFlowAttributor.MAX_EXPORTED_REJECTED_LINES)
            .forEach { rej ->
                rejectedArr.put(
                    JSONObject().apply {
                        put("lineNumber", rej.lineNumber)
                        put("section", rej.section)
                        put("reason", rej.reason.name)
                        put("linePreview", rej.previewForExport(includeSensitiveEndpoints))
                    },
                )
            }
        put("lastAttemptRejectedLines", rejectedArr)

        put("directAttributedPackets", directAttributedPackets)
        put("bpfAttributedPackets", bpfAttributedPackets)
        put("unknownForwardedPackets", unknownForwardedPackets)
        put("unknownForwardedBytes", unknownForwardedBytes)
        put("ambiguousOrStaleLookups", ambiguousOrStaleLookups)
        put("localControlPackets", localControlPackets)
        put("unsupportedOrFragmentPackets", unsupportedOrFragmentPackets)
        put("blockedDropPackets", blockedDropPackets)
        put("shapingDropPackets", shapingDropPackets)
        put("shapedPackets", shapedPackets)
        put("rejectedOldGenerationCount", rejectedOldGenerationCount)
        put("tupleReuseGuardTriggeredCount", tupleReuseGuardTriggeredCount)

        val clientsArr = JSONArray()
        perClientCounts.forEachIndexed { index, c ->
            clientsArr.put(
                JSONObject().apply {
                    put("mac", if (includeSensitiveEndpoints) c.mac else "Client-${index + 1}")
                    put("originalIpv4", if (includeSensitiveEndpoints) c.originalIpv4 else "redacted")
                    put("tcpFlows", c.tcpFlows)
                    put("udpFlows", c.udpFlows)
                    put("totalFlows", c.totalFlows)
                },
            )
        }
        put("perClientCounts", clientsArr)
    }

    fun toMarkdownReport(
        apkVersion: String,
        sourceCommit: String,
        serviceBuildId: Int,
        includeSensitiveEndpoints: Boolean = false,
    ): String = buildString {
        appendLine("# Shizzi — Experimental BPF NAT Flow Attribution Report")
        appendLine()
        appendLine("- **APK Version**: `$apkVersion` (serviceBuildId `$serviceBuildId`)")
        appendLine("- **Base Commit**: `$sourceCommit`")
        appendLine("- **Experimental BPF Enabled**: `$experimentalEnabled`")
        appendLine("- **Feature State**: `${state.name}`")
        appendLine("- **Published Snapshot Status**: `${collectionStatus.name}` (${lastCollectionDurationMs}ms, age ${snapshotAgeMs}ms, poll ${pollIntervalMs}ms)")
        if (collectionError.isNotBlank()) {
            appendLine("- **Published Snapshot Error**: `$collectionError`")
        }
        appendLine("- **Parser Version**: `$parserVersion`")
        appendLine("- **Session / Binding Generation**: `session=$sessionGeneration`, `binding=$bindingGeneration`")
        appendLine(
            "- **Downstream Interface**: `${downstreamIface.ifBlank { "unknown" }}` " +
                "(inferred ifindex `${inferredDownstreamIfIndex ?: "unavailable"}`, " +
                "OS ifindex `${osDownstreamIfIndex ?: "unavailable"}` [$downstreamIfIndexSource]" +
                (if (downstreamIfIndexError.isNotBlank()) " — `$downstreamIfIndexError`" else "") + ")",
        )
        appendLine(
            "- **Upstream Interface**: `${upstreamIface.ifBlank { "unknown" }}` " +
                "(inferred ifindex `${inferredUpstreamIfIndex ?: "unavailable"}`, " +
                "OS ifindex `${osUpstreamIfIndex ?: "unavailable"}` [$upstreamIfIndexSource]" +
                (if (upstreamIfIndexError.isNotBlank()) " — `$upstreamIfIndexError`" else "") + ")",
        )
        appendLine()
        appendLine("## 1. Last Published Valid Snapshot Summary")
        appendLine("- **IPv4 Upstream Entries (Published)**: `$totalUpstreamEntries`")
        appendLine("- **IPv4 Downstream Entries (Published)**: `$totalDownstreamEntries`")
        appendLine("- **Flow Age Distribution (Published)**: knownNonNegative=`$knownAgeEntries`, unavailable(`-`)=`$unavailableAgeEntries`, negativeDelta=`$negativeDeltaAgeEntries`")
        appendLine("- **Reverse-Confirmed Mappings**: `$reverseMatchedCount`")
        appendLine("- **Active Validated Flow Mappings**: `$activeMappedFlows`")
        appendLine("- **Ambiguous / Conflicting Tuples**: `$ambiguousTupleCount`")
        appendLine("- **Unverified Owner Entries**: `$unverifiedOwnerEntries`")
        appendLine("- **Interface / ifindex Mismatches**: `$ifIndexMismatchCount`")
        appendLine("- **Rejected Parse Lines (Published Snapshot)**: `$rejectedLineCount`")
        appendLine("- **Coverage Incomplete**: `$coverageIncomplete`")
        appendLine()
        appendLine("### Flows per Client")
        if (perClientCounts.isEmpty()) {
            appendLine("_No mapped client flows in current published snapshot._")
        } else {
            appendLine("| Client | Original IPv4 | TCP Upstream | UDP Upstream | Total |")
            appendLine("| --- | --- | ---: | ---: | ---: |")
            perClientCounts.forEachIndexed { idx, c ->
                val macLabel = if (includeSensitiveEndpoints) c.mac else "Client-${idx + 1}"
                val ipLabel = if (includeSensitiveEndpoints) c.originalIpv4 else "redacted"
                appendLine("| `$macLabel` | `$ipLabel` | ${c.tcpFlows} | ${c.udpFlows} | ${c.totalFlows} |")
            }
        }
        appendLine()
        appendLine("## 2. Last Collection Attempt Diagnostics")
        appendLine("- **Last Attempt Status**: `${lastAttemptStatus.name}` (duration ${lastAttemptDurationMs}ms, age ${lastAttemptAgeMs}ms)")
        appendLine("- **Snapshot Published by Last Attempt**: `$lastAttemptSnapshotPublished`")
        appendLine("- **Recognized Format**: `$lastAttemptRecognizedFormat`")
        if (lastAttemptDecisionReason.isNotBlank()) {
            appendLine("- **Publication Decision**: `$lastAttemptDecisionReason`")
        }
        if (lastAttemptError.isNotBlank()) {
            appendLine("- **Last Attempt Error**: `$lastAttemptError`")
        }
        appendLine("- **Parsed Entries in Last Attempt**: upstream `$lastAttemptUpstreamEntries`, downstream `$lastAttemptDownstreamEntries` (knownAge=`$lastAttemptKnownAgeEntries`, unavailable(`-`)=`$lastAttemptUnavailableAgeEntries`, negativeDelta=`$lastAttemptNegativeDeltaAgeEntries`)")
        appendLine("- **Rejected Flow Lines in Last Attempt**: `$lastAttemptRejectedLineCount` (omitted from sample: `$omittedRejectedLineCount`)")
        if (lastAttemptRejectedByReason.isNotEmpty()) {
            val summary = lastAttemptRejectedByReason.entries.joinToString(", ") { "`${it.key}`=${it.value}" }
            appendLine("- **Rejections by Reason**: $summary")
        }
        if (lastAttemptRejectedLines.isNotEmpty()) {
            appendLine()
            appendLine("### Rejected Lines Sample (max ${NatFlowAttributor.MAX_EXPORTED_REJECTED_LINES})")
            appendLine("| Line # | Section | Reason | Preview (${if (includeSensitiveEndpoints) "Raw" else "Masked"}) |")
            appendLine("| ---: | --- | --- | --- |")
            lastAttemptRejectedLines
                .take(NatFlowAttributor.MAX_EXPORTED_REJECTED_LINES)
                .forEach { rej ->
                    val safePreview = rej.previewForExport(includeSensitiveEndpoints).replace("|", "\\|")
                    appendLine("| ${rej.lineNumber} | `${rej.section}` | `${rej.reason.name}` | `$safePreview` |")
                }
        }
        appendLine()
        appendLine("## 3. Packet Engine Attribution & Enforcement Deltas")
        appendLine("- **Directly Attributed Packets (Pre-NAT / Verified IPv6)**: `$directAttributedPackets`")
        appendLine("- **BPF-Attributed Packets (Post-NAT Mapped)**: `$bpfAttributedPackets`")
        appendLine("- **Unknown Forwarded Packets / Bytes**: `$unknownForwardedPackets` pkts (`$unknownForwardedBytes` B)")
        appendLine("- **Ambiguous or Stale Lookups**: `$ambiguousOrStaleLookups`")
        appendLine("- **Local Control Traffic (IPv6 RS/RA/MLD)**: `$localControlPackets`")
        appendLine("- **Unsupported / Non-Initial Fragment Packets**: `$unsupportedOrFragmentPackets`")
        appendLine("- **Policy-Block Dropped Packets**: `$blockedDropPackets`")
        appendLine("- **Bandwidth Shaping AQM Drops / Paced Packets**: `$shapingDropPackets` dropped / `$shapedPackets` paced")
        appendLine("- **Rejected Old-Generation Snapshots**: `$rejectedOldGenerationCount`")
        appendLine("- **TCP SYN Tuple-Reuse Guards Triggered**: `$tupleReuseGuardTriggeredCount`")
        appendLine()
        appendLine("## 4. Architectural Scope & First-Packet Limitation")
        appendLine("- **Experimental status**: BPF offload entries appear only after a flow has progressed. A readable established-flow map is not a synchronous pre-NAT classifier.")
        appendLine("- **Unknown traffic**: Initial packets of brand-new flows arriving before the next `dumpsys tethering bpf` snapshot remain unattributed (`unknownForwardedPackets`) and are not globally dropped so other connected clients are not disrupted.")
    }

    companion object {
        private fun JSONObject.optPositiveIntOrNull(key: String): Int? {
            if (isNull(key)) return null
            val v = optInt(key, 0)
            return if (v > 0) v else null
        }

        fun fromJson(json: JSONObject?): BpfAttributionStatusReport {
            if (json == null) return BpfAttributionStatusReport()
            val perClientList = mutableListOf<ClientProtocolFlowCounts>()
            val arr = json.optJSONArray("perClientCounts")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    perClientList.add(
                        ClientProtocolFlowCounts(
                            mac = item.optString("mac"),
                            originalIpv4 = item.optString("originalIpv4"),
                            tcpFlows = item.optInt("tcpFlows", 0),
                            udpFlows = item.optInt("udpFlows", 0),
                        ),
                    )
                }
            }
            val reasonMap = LinkedHashMap<String, Int>()
            val reasonsObj = json.optJSONObject("lastAttemptRejectedByReason")
            if (reasonsObj != null) {
                val keys = reasonsObj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    reasonMap[k] = reasonsObj.optInt(k, 0)
                }
            }
            val rejectedList = mutableListOf<BpfRejectedLine>()
            val rejArr = json.optJSONArray("lastAttemptRejectedLines")
            if (rejArr != null) {
                for (i in 0 until rejArr.length()) {
                    val item = rejArr.optJSONObject(i) ?: continue
                    val reason = runCatching {
                        BpfRejectionReason.valueOf(item.optString("reason", BpfRejectionReason.INVALID_SYNTAX.name))
                    }.getOrDefault(BpfRejectionReason.INVALID_SYNTAX)
                    rejectedList.add(
                        BpfRejectedLine(
                            lineNumber = item.optInt("lineNumber", 0),
                            section = item.optString("section", ""),
                            reason = reason,
                            linePreview = item.optString("linePreview", ""),
                        ),
                    )
                }
            }
            val osDown = json.optPositiveIntOrNull("osDownstreamIfIndex")
                ?: json.optPositiveIntOrNull("resolvedDownstreamIfIndex")
            val osUp = json.optPositiveIntOrNull("osUpstreamIfIndex")
                ?: json.optPositiveIntOrNull("resolvedUpstreamIfIndex")
            val inferredDown = json.optPositiveIntOrNull("inferredDownstreamIfIndex")
                ?: json.optPositiveIntOrNull("downstreamIfIndex")
            val inferredUp = json.optPositiveIntOrNull("inferredUpstreamIfIndex")
                ?: json.optPositiveIntOrNull("upstreamIfIndex")

            return BpfAttributionStatusReport(
                experimentalEnabled = json.optBoolean("experimentalEnabled", false),
                state = runCatching {
                    ExperimentalBpfState.valueOf(json.optString("state", ExperimentalBpfState.DISABLED.name))
                }.getOrDefault(ExperimentalBpfState.DISABLED),
                collectionStatus = runCatching {
                    BpfCollectionStatus.valueOf(json.optString("collectionStatus", BpfCollectionStatus.IDLE.name))
                }.getOrDefault(BpfCollectionStatus.IDLE),
                collectionError = json.optString("collectionError", ""),
                parserVersion = json.optInt("parserVersion", BpfDumpParser.PARSER_VERSION),
                pollIntervalMs = json.optLong("pollIntervalMs", BpfMapReader.DEFAULT_POLL_INTERVAL_MS),
                snapshotAgeMs = json.optLong("snapshotAgeMs", 0L),
                lastCollectionDurationMs = json.optLong("lastCollectionDurationMs", 0L),
                sessionGeneration = json.optLong("sessionGeneration", 0L),
                bindingGeneration = json.optLong("bindingGeneration", 0L),
                downstreamIface = json.optString("downstreamIface", ""),
                downstreamIfIndex = json.optInt("downstreamIfIndex", inferredDown ?: osDown ?: 0),
                upstreamIface = json.optString("upstreamIface", ""),
                upstreamIfIndex = json.optInt("upstreamIfIndex", inferredUp ?: osUp ?: 0),
                osDownstreamIfIndex = osDown,
                osUpstreamIfIndex = osUp,
                inferredDownstreamIfIndex = inferredDown,
                inferredUpstreamIfIndex = inferredUp,
                downstreamIfIndexSource = json.optString("downstreamIfIndexSource", "UNSET"),
                upstreamIfIndexSource = json.optString("upstreamIfIndexSource", "UNSET"),
                downstreamIfIndexError = json.optString("downstreamIfIndexError", ""),
                upstreamIfIndexError = json.optString("upstreamIfIndexError", ""),
                resolvedDownstreamIfIndex = osDown ?: 0,
                resolvedUpstreamIfIndex = osUp ?: 0,
                totalUpstreamEntries = json.optInt("totalUpstreamEntries", 0),
                totalDownstreamEntries = json.optInt("totalDownstreamEntries", 0),
                knownAgeEntries = json.optInt("knownAgeEntries", 0),
                unavailableAgeEntries = json.optInt("unavailableAgeEntries", 0),
                negativeDeltaAgeEntries = json.optInt("negativeDeltaAgeEntries", 0),
                reverseMatchedCount = json.optInt("reverseMatchedCount", 0),
                activeMappedFlows = json.optInt("activeMappedFlows", 0),
                ambiguousTupleCount = json.optInt("ambiguousTupleCount", 0),
                unverifiedOwnerEntries = json.optInt("unverifiedOwnerEntries", 0),
                ifIndexMismatchCount = json.optInt("ifIndexMismatchCount", 0),
                rejectedLineCount = json.optInt("rejectedLineCount", 0),
                coverageIncomplete = json.optBoolean("coverageIncomplete", false),
                perClientCounts = perClientList,
                lastAttemptStatus = runCatching {
                    BpfCollectionStatus.valueOf(json.optString("lastAttemptStatus", BpfCollectionStatus.IDLE.name))
                }.getOrDefault(BpfCollectionStatus.IDLE),
                lastAttemptError = json.optString("lastAttemptError", ""),
                lastAttemptAgeMs = json.optLong("lastAttemptAgeMs", 0L),
                lastAttemptDurationMs = json.optLong("lastAttemptDurationMs", 0L),
                lastAttemptRecognizedFormat = json.optBoolean("lastAttemptRecognizedFormat", false),
                lastAttemptSnapshotPublished = json.optBoolean("lastAttemptSnapshotPublished", false),
                lastAttemptDecisionReason = json.optString("lastAttemptDecisionReason", ""),
                lastAttemptUpstreamEntries = json.optInt("lastAttemptUpstreamEntries", 0),
                lastAttemptDownstreamEntries = json.optInt("lastAttemptDownstreamEntries", 0),
                lastAttemptKnownAgeEntries = json.optInt("lastAttemptKnownAgeEntries", 0),
                lastAttemptUnavailableAgeEntries = json.optInt("lastAttemptUnavailableAgeEntries", 0),
                lastAttemptNegativeDeltaAgeEntries = json.optInt("lastAttemptNegativeDeltaAgeEntries", 0),
                lastAttemptRejectedLineCount = json.optInt("lastAttemptRejectedLineCount", 0),
                lastAttemptRejectedByReason = reasonMap,
                lastAttemptRejectedLines = rejectedList,
                directAttributedPackets = json.optLong("directAttributedPackets", 0L),
                bpfAttributedPackets = json.optLong("bpfAttributedPackets", 0L),
                unknownForwardedPackets = json.optLong("unknownForwardedPackets", 0L),
                unknownForwardedBytes = json.optLong("unknownForwardedBytes", 0L),
                ambiguousOrStaleLookups = json.optLong("ambiguousOrStaleLookups", 0L),
                localControlPackets = json.optLong("localControlPackets", 0L),
                unsupportedOrFragmentPackets = json.optLong("unsupportedOrFragmentPackets", 0L),
                blockedDropPackets = json.optLong("blockedDropPackets", 0L),
                shapingDropPackets = json.optLong("shapingDropPackets", 0L),
                shapedPackets = json.optLong("shapedPackets", 0L),
                rejectedOldGenerationCount = json.optLong("rejectedOldGenerationCount", 0L),
                tupleReuseGuardTriggeredCount = json.optLong("tupleReuseGuardTriggeredCount", 0L),
            )
        }
    }
}
