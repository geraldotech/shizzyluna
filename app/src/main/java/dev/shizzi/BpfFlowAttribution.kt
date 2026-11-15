package dev.shizzi

import android.os.Binder
import android.system.Os
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
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
 * High-level BPF collection health indicator for the Developer Settings diagnostics panel.
 */
enum class BpfSnapshotHealth {
    OK,
    STALE,
    UNAVAILABLE,
    PARSE_FAILURE,
}

/**
 * Structured diagnostic reason explaining why an inspected packet could not be attributed to a
 * verified hotspot client MAC (`matchedMac == null`).
 */
enum class UnattributedReason(val description: String) {
    NO_ACTIVE_SNAPSHOT("No valid BPF snapshot has ever been published in this session"),
    SNAPSHOT_STALE("Published snapshot age exceeded maxFreshnessMs"),
    SNAPSHOT_INVALID_OR_COLLECTION_FAILED("Last collection failed, timed out, or had parse/truncation rejection with no usable fresh snapshot"),
    TUPLE_NOT_PRESENT("Snapshot is valid & fresh, but packet's 5-tuple is not in flowsByTuple (e.g., first packets before BPF offload)"),
    TUPLE_AMBIGUOUS("Tuple was quarantined due to duplicate ownership, reverse-MAC conflict, or ifindex mismatch"),
    TCP_TUPLE_REUSE_AWAITING_REFRESH("New upload TCP SYN arrived on an existing tuple after snapshot timestamp"),
    CLIENT_DISCONNECTED("Mapped client MAC is no longer in activeConnectedMacs"),
    CLIENT_IP_REASSIGNED("Original client IPv4 is now bound to a different connected MAC"),
    IP_BINDING_MISSING_OR_CHANGED("Original IPv4 binding disappeared or client acquired a conflicting IPv4"),
    NON_INITIAL_FRAGMENT("IPv4/IPv6 non-initial fragment lacking transport ports"),
    UNSUPPORTED_PROTOCOL("Post-NAT packet is not TCP (6) or UDP (17) (e.g., ICMP, GRE, ESP)"),
    INVALID_OR_MISSING_PORTS("TCP/UDP packet had truncated header or port outside 1..65535"),
    IPV6_NOT_SUPPORTED_BY_BPF_MAP("Post-NAT IPv6 packet where BPF IPv4 NAT map does not apply and direct/EUI-64/neighbor/conntrack lookup missed"),
    OTHER_UNKNOWN("Any other unattributed packet"),
}

/**
 * Privacy-preserving pseudonymizer and redaction verifier for BPF attribution diagnostic exports.
 *
 * - Default export (`includePseudonymousIds = false`): omits client/flow identifiers or uses generic labels.
 * - Opt-in export (`includePseudonymousIds = true`): emits salted, truncated SHA-256 pseudonymous tokens
 *   (`Client#a1b2c3`, `Flow#9f8e7d`, `IP#c4d5e6`) and NEVER raw MACs, raw client IPs, or raw remote IPs.
 */
object DiagnosticRedactor {
    @Volatile
    var sessionSalt: String = UUID.randomUUID().toString()

    private val RAW_MAC_DETECT_REGEX = Regex("""\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b""")
    private val RAW_IPV4_DETECT_REGEX = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}\b""")
    private val RAW_IPV6_DETECT_REGEX = Regex("""\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b""")

    val redactedExportRecordsCount = AtomicLong(0L)

    fun rotateSalt(customSalt: String? = null) {
        sessionSalt = customSalt?.takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString()
    }

    private fun shortHash(domain: String, rawValue: String, hexBytes: Int = 3): String {
        val clean = rawValue.trim().uppercase(Locale.US)
        if (clean.isEmpty()) return "0".repeat(hexBytes * 2)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$sessionSalt:$domain:$clean".toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(hexBytes * 2)
        for (i in 0 until hexBytes.coerceAtMost(digest.size)) {
            sb.append(String.format(Locale.US, "%02x", digest[i].toInt() and 0xFF))
        }
        redactedExportRecordsCount.incrementAndGet()
        return sb.toString()
    }

    fun pseudonymizeClient(mac: String): String = "Client#${shortHash("mac", mac, 3)}"

    fun pseudonymizeIp(ip: String): String = "IP#${shortHash("ip", ip, 3)}"

    fun pseudonymizeFlow(tuple: TranslatedFlowKey): String =
        "Flow#${shortHash("flow", "${tuple.protocol}:${tuple.translatedIp}:${tuple.translatedPort}:${tuple.remoteIp}:${tuple.remotePort}", 3)}"

    fun ephemeralFlowHash(tuple: CanonicalFlowTuple): String =
        "ephemeral:${shortHash("canonical_flow", "${tuple.ipFamily}:${tuple.transportProtocol}:${tuple.direction}:${tuple.srcIp}:${tuple.srcPortOrIcmpId}:${tuple.dstIp}:${tuple.dstPortOrIcmpId}", 6)}"

    /**
     * Verifies that [reportText] contains no raw MAC addresses, raw IPv4 addresses, or raw IPv6 addresses.
     */
    fun containsUnredactedPii(reportText: String): Boolean {
        if (RAW_MAC_DETECT_REGEX.findAll(reportText).any { !it.value.equals("xx:xx:xx:xx:xx:xx", ignoreCase = true) }) {
            return true
        }
        if (RAW_IPV4_DETECT_REGEX.containsMatchIn(reportText)) {
            return true
        }
        if (RAW_IPV6_DETECT_REGEX.findAll(reportText).any { !it.value.equals("xxxx::xxxx", ignoreCase = true) }) {
            return true
        }
        return false
    }
}

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

    // Strict anchored pattern for AOSP BpfCoordinator interface forwarding mapping rows
    // without protocol or endpoints, e.g.:
    // "269 (testtun64) -> 269 (testtun64)"
    // "270 (270) -> 270 (270)"
    // "26 (rmnet_data0) -> 26 (rmnet_data0)"
    // "31 (rmnet_data5) -> 31 (rmnet_data5)"
    private val IFINDEX_MAPPING_ROW_REGEX = Regex(
        """^\d+\s*\([^()]+\)\s*->\s*\d+\s*\([^()]+\)$""",
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
        if (IFINDEX_TABLE_HEADER_REGEX.matches(trimmed) || IFINDEX_MAPPING_ROW_REGEX.matches(trimmed)) {
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
    val boundInIpToMacAtIngest: Boolean = false,
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

data class DetailedAttributionResult(
    val outcome: AttributionOutcome,
    val failureReason: UnattributedReason? = null,
)

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
    val snapshotSequence: Long = 0L,
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
    val collectedAtMonotonicMs: Long = 0L,
    val publishedAtEpochMs: Long = 0L,
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
    val ipv6ClientBindings: Map<String, String> = emptyMap(),
)

/**
 * Session-scoped, thread-safe coordinator that validates parsed BPF dumps against the current
 * downstream client inventory and resolves translated TUN packets to verified client MACs.
 */
class NatFlowAttributor(
    @Volatile var monotonicClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    var maxFreshnessMs: Long = DEFAULT_MAX_FRESHNESS_MS,
    val maxMappedFlows: Int = DEFAULT_MAX_MAPPED_FLOWS,
    var allowSafePartialPublication: Boolean = false,
    private val interfaceIndexResolver: ((String) -> Int)? = null,
    private val interfaceResolutionProvider: (String) -> InterfaceIndexResolution = ::defaultResolveInterfaceIndex,
) {

    private val sessionGen = AtomicLong(1L)
    private val bindingGen = AtomicLong(1L)
    private val snapshotSequenceCounter = AtomicLong(0L)

    @Volatile
    var onSnapshotPublished: ((NatFlowSnapshot) -> Unit)? = null

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
    val snapshotPublishRejectedByReason = ConcurrentHashMap<String, AtomicLong>()

    val currentSessionGeneration: Long get() = sessionGen.get()
    val currentBindingGeneration: Long get() = bindingGen.get()
    val currentSnapshotSequence: Long get() = currentSnapshotRef.get().snapshotSequence

    fun currentSnapshot(): NatFlowSnapshot = currentSnapshotRef.get()
    fun lastAttemptDiagnostic(): BpfCollectionAttemptDiagnostic = lastAttemptRef.get()

    fun getPublishRejectedByReasonSnapshot(): Map<String, Long> {
        if (snapshotPublishRejectedByReason.isEmpty()) return emptyMap()
        val out = LinkedHashMap<String, Long>()
        for ((k, v) in snapshotPublishRejectedByReason.entries.sortedBy { it.key }) {
            val count = v.get()
            if (count > 0L) out[k] = count
        }
        return out
    }

    private fun recordPublishRejection(reasonKey: String) {
        snapshotPublishRejectedByReason.computeIfAbsent(reasonKey) { AtomicLong(0L) }.incrementAndGet()
    }

    /**
     * Resets only diagnostic lookup and rejection counters without invalidating the active snapshot
     * or altering client bindings.
     */
    fun resetDiagnosticCounters() {
        rejectedOldGenerationCount.set(0L)
        rejectedTruncatedOrCorruptCount.set(0L)
        lookupMatchedCount.set(0L)
        lookupUnknownCount.set(0L)
        lookupAmbiguousOrStaleCount.set(0L)
        tupleReuseGuardTriggeredCount.set(0L)
        snapshotPublishRejectedByReason.clear()
    }

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
                snapshotSequence = 0L,
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
            recordPublishRejection("GENERATION_MISMATCH")
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
            recordPublishRejection(collectionStatus.name)
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
            recordPublishRejection(effectiveStatus.name)
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
            recordPublishRejection("PARSE_FAILURE")
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
                recordPublishRejection("PARSE_FAILURE")
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

            // If ownerFromIpBinding is absent, ensure reverseMac is not already bound to a DIFFERENT IPv4 in normalizedIpToMac
            val hasConflictingIpv4BindingForReverseMac = ownerFromIpBinding == null &&
                reverseMac != null &&
                normalizedIpToMac.entries.any { (ipKey, macVal) ->
                    !ipKey.contains(':') && macVal == reverseMac && ipKey != up.origClientIp
                }
            if (hasConflictingIpv4BindingForReverseMac) {
                validFlows.remove(tupleKey)
                ambiguousTuples[tupleKey] =
                    "Reverse MAC $reverseMac is bound to a different IPv4 than ${up.origClientIp}"
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
                boundInIpToMacAtIngest = ownerFromIpBinding != null,
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

        // Also ingest verified IPv4 Downstream-only entries (e.g., server-pushed or asymmetric established flows
        // where upstream entry aged out first) when both clientOutDstMac and origClientIp are verified and unambiguous.
        for (down in parsed.ipv4DownstreamEntries) {
            val tupleKey = TranslatedFlowKey(
                family = 4,
                protocol = down.protocol,
                translatedIp = down.translatedIp,
                translatedPort = down.translatedPort,
                remoteIp = down.remoteIp,
                remotePort = down.remotePort,
            )
            if (tupleKey in validFlows || tupleKey in ambiguousTuples) continue

            val uncorroboratedNumericWhenConfigured = interfacesConfigured &&
                (inferredDownIfIndex == null || inferredUpIfIndex == null)
            val labelMatches = matchesActiveUpstreamLabel(down.inIfaceLabel) &&
                matchesActiveDownstreamLabel(down.outIfaceLabel)
            val downIfIndexValid = !uncorroboratedNumericWhenConfigured &&
                down.inIfIndex > 0 && down.outIfIndex > 0 && down.inIfIndex != down.outIfIndex &&
                (osUpIfIndex == null || down.inIfIndex == osUpIfIndex) &&
                (osDownIfIndex == null || down.outIfIndex == osDownIfIndex) &&
                (inferredUpIfIndex == null || down.inIfIndex == inferredUpIfIndex) &&
                (inferredDownIfIndex == null || down.outIfIndex == inferredDownIfIndex) &&
                (observedUpIfIndex == 0 || down.inIfIndex == observedUpIfIndex) &&
                (observedDownIfIndex == 0 || down.outIfIndex == observedDownIfIndex)
            if (!labelMatches || !downIfIndexValid) continue

            val downMac = down.clientOutDstMac.uppercase().trim()
            if (downMac == "00:00:00:00:00:00" || !BpfDumpParser.isValidMac(downMac) || downMac !in activeConnectedMacs) {
                continue
            }
            val ownerFromIpBinding = normalizedIpToMac[down.origClientIp]
            if (ownerFromIpBinding != null && ownerFromIpBinding != downMac) {
                ambiguousTuples[tupleKey] =
                    "Downstream-only contradictory ownership for ${down.origClientIp}: binding=$ownerFromIpBinding vs downMac=$downMac"
                continue
            }
            val hasConflictingIpv4ForMac = ownerFromIpBinding == null &&
                normalizedIpToMac.entries.any { (ipKey, macVal) ->
                    !ipKey.contains(':') && macVal == downMac && ipKey != down.origClientIp
                }
            if (hasConflictingIpv4ForMac) continue

            val origEndpoint = "${down.origClientIp}:${down.origClientPort}"
            val translatedEndpoint = "${down.translatedIp}:${down.translatedPort}"
            if (parsed.hasRejections && (
                    down.origClientIp in quarantinedClientIps ||
                        origEndpoint in quarantinedEndpoints ||
                        translatedEndpoint in quarantinedEndpoints ||
                        downMac in quarantinedMacs
                    )
            ) {
                ambiguousTuples[tupleKey] = "Quarantined downstream-only entry due to rejected line"
                continue
            }
            if (validFlows.size >= maxMappedFlows) {
                coverageIncomplete = true
                continue
            }

            if (observedUpIfIndex == 0) observedUpIfIndex = down.inIfIndex
            if (observedDownIfIndex == 0) observedDownIfIndex = down.outIfIndex
            val mapping = NatFlowMapping(
                sessionGeneration = expectedGen,
                bindingGeneration = curBindGen,
                downstreamIfIndex = down.outIfIndex,
                downstreamIfaceLabel = down.outIfaceLabel,
                upstreamIfIndex = down.inIfIndex,
                upstreamIfaceLabel = down.inIfaceLabel,
                family = 4,
                protocol = down.protocol,
                origClientIp = down.origClientIp,
                origClientPort = down.origClientPort,
                translatedIp = down.translatedIp,
                translatedPort = down.translatedPort,
                remoteIp = down.remoteIp,
                remotePort = down.remotePort,
                verifiedMac = downMac,
                reverseMapConfirmed = true,
                boundInIpToMacAtIngest = ownerFromIpBinding != null,
                collectedAtMonotonicMs = nowMono,
                rawDumpAgeMs = down.rawAgeMs,
                flowAge = down.flowAge,
            )
            validFlows[tupleKey] = mapping
            synPendingRefreshTuples.remove(tupleKey)
            perClientIp[downMac] = down.origClientIp
            if (down.protocol == 6) {
                perClientTcp[downMac] = (perClientTcp[downMac] ?: 0) + 1
            } else if (down.protocol == 17) {
                perClientUdp[downMac] = (perClientUdp[downMac] ?: 0) + 1
            }
        }

        // Extract verified IPv6 Downstream client address bindings (for RFC 4941 privacy IPv6 addresses)
        val ipv6Bindings = LinkedHashMap<String, String>()
        val conflictedIpv6 = HashSet<String>()
        for (v6 in parsed.ipv6Entries) {
            if (!v6.isDownstream) continue
            val mac = v6.dstMac.uppercase().trim()
            if (mac == "00:00:00:00:00:00" || !BpfDumpParser.isValidMac(mac) || mac !in activeConnectedMacs) continue
            val addrClean = v6.addressOrPrefix.substringBefore('/').trim().lowercase(Locale.US)
            if (addrClean.isEmpty() || !addrClean.contains(':') || addrClean.startsWith("fe80:") || addrClean.startsWith("ff")) continue
            if (addrClean in conflictedIpv6) continue
            val existingOwner = ipv6Bindings[addrClean] ?: normalizedIpToMac[addrClean]
            if (existingOwner != null && existingOwner != mac) {
                ipv6Bindings.remove(addrClean)
                conflictedIpv6.add(addrClean)
                continue
            }
            ipv6Bindings[addrClean] = mac
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

        if (ifIndexMismatches > 0) {
            snapshotPublishRejectedByReason
                .computeIfAbsent("IFINDEX_MISMATCH") { AtomicLong(0L) }
                .addAndGet(ifIndexMismatches.toLong())
        }

        // If an active snapshot with validated flows already exists, and 100% of upstream entries in this
        // dump failed interface/ifindex parity, reject publication to preserve the last valid snapshot.
        val previousSnapshot = currentSnapshotRef.get()
        if (previousSnapshot.sessionGeneration == expectedGen &&
            previousSnapshot.flowsByTuple.isNotEmpty() &&
            parsed.ipv4UpstreamEntries.isNotEmpty() &&
            validFlows.isEmpty() &&
            ifIndexMismatches == parsed.ipv4UpstreamEntries.size
        ) {
            lastAttemptRef.set(
                BpfCollectionAttemptDiagnostic(
                    attemptSessionGeneration = expectedGen,
                    attemptAtMonotonicMs = nowMono,
                    attemptDurationMs = collectionDurationMs,
                    attemptStatus = BpfCollectionStatus.PARSE_FAILURE,
                    attemptError = "All ${parsed.ipv4UpstreamEntries.size} upstream entry(ies) had ifindex mismatch",
                    recognizedFormat = true,
                    snapshotPublished = false,
                    decisionReason = "Rejected: all ${parsed.ipv4UpstreamEntries.size} upstream entry(ies) failed ifindex validation; preserved previous valid snapshot",
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

        val finalStatus = if (parsed.ipv4UpstreamEntries.isEmpty() && parsed.ipv4DownstreamEntries.isEmpty()) {
            BpfCollectionStatus.EMPTY_VALID
        } else {
            BpfCollectionStatus.OK
        }

        val finalInferredDown = observedDownIfIndex.takeIf { it > 0 } ?: inferredDownIfIndex
        val finalInferredUp = observedUpIfIndex.takeIf { it > 0 } ?: inferredUpIfIndex

        if (sessionGen.get() != expectedGen) {
            recordPublishRejection("STALE_GENERATION")
            rejectedOldGenerationCount.incrementAndGet()
            return false
        }

        val seq = snapshotSequenceCounter.incrementAndGet()
        val snapshot = NatFlowSnapshot(
            sessionGeneration = expectedGen,
            bindingGeneration = curBindGen,
            snapshotSequence = seq,
            collectedAtMonotonicMs = nowMono,
            publishedAtEpochMs = System.currentTimeMillis(),
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
            ipv6ClientBindings = ipv6Bindings,
        )

        if (sessionGen.get() != expectedGen) {
            recordPublishRejection("STALE_GENERATION")
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
                    "Published partial snapshot seq=$seq with quarantine (coverageIncomplete=true)"
                } else {
                    "Published verified snapshot seq=$seq (${validFlows.size} active flow(s))"
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
        runCatching { onSnapshotPublished?.invoke(snapshot) }
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
    ): AttributionOutcome = resolveTranslatedPacketDetailed(
        family = family,
        protocol = protocol,
        packetSrcIp = packetSrcIp,
        packetSrcPort = packetSrcPort,
        packetDstIp = packetDstIp,
        packetDstPort = packetDstPort,
        isUpload = isUpload,
        isTcpSyn = isTcpSyn,
        ipToMac = ipToMac,
        activeConnectedMacs = activeConnectedMacs,
    ).outcome

    /**
     * Resolves the client MAC for a translated packet and returns the structured
     * [UnattributedReason] whenever attribution fails, without altering datapath enforcement.
     */
    fun resolveTranslatedPacketDetailed(
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
    ): DetailedAttributionResult {
        if (family == 6) {
            lookupUnknownCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Unknown,
                failureReason = UnattributedReason.IPV6_NOT_SUPPORTED_BY_BPF_MAP,
            )
        }
        if (family != 4 || (protocol != 6 && protocol != 17)) {
            lookupUnknownCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Unknown,
                failureReason = UnattributedReason.UNSUPPORTED_PROTOCOL,
            )
        }
        if (packetSrcPort !in 1..65535 || packetDstPort !in 1..65535) {
            lookupUnknownCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Unknown,
                failureReason = UnattributedReason.INVALID_OR_MISSING_PORTS,
            )
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
        val lastAttempt = lastAttemptRef.get()
        if (snapshot.sessionGeneration != expectedGen ||
            snapshot.collectedAtMonotonicMs <= 0L ||
            (snapshot.collectionStatus != BpfCollectionStatus.OK && snapshot.collectionStatus != BpfCollectionStatus.EMPTY_VALID)
        ) {
            lookupUnknownCount.incrementAndGet()
            val reason = if (lastAttempt.attemptSessionGeneration == expectedGen &&
                lastAttempt.attemptStatus != BpfCollectionStatus.IDLE &&
                lastAttempt.attemptStatus != BpfCollectionStatus.OK &&
                lastAttempt.attemptStatus != BpfCollectionStatus.EMPTY_VALID
            ) {
                UnattributedReason.SNAPSHOT_INVALID_OR_COLLECTION_FAILED
            } else {
                UnattributedReason.NO_ACTIVE_SNAPSHOT
            }
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Unknown,
                failureReason = reason,
            )
        }

        val nowMono = monotonicClockMs()
        val ageMs = (nowMono - snapshot.collectedAtMonotonicMs).coerceAtLeast(0L)
        if (ageMs > maxFreshnessMs) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleSnapshot(ageMs),
                failureReason = UnattributedReason.SNAPSHOT_STALE,
            )
        }

        snapshot.ambiguousTuples[tupleKey]?.let { reason ->
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Ambiguous(reason),
                failureReason = UnattributedReason.TUPLE_AMBIGUOUS,
            )
        }

        val mapping = snapshot.flowsByTuple[tupleKey]
        if (mapping == null) {
            lookupUnknownCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.Unknown,
                failureReason = UnattributedReason.TUPLE_NOT_PRESENT,
            )
        }

        // Verify the client MAC is still actively connected
        if (mapping.verifiedMac !in activeConnectedMacs) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleOrInvalidated("Client ${mapping.verifiedMac} is no longer connected"),
                failureReason = UnattributedReason.CLIENT_DISCONNECTED,
            )
        }

        // Verify the original IPv4 ownership has not been reassigned to a different client
        val currentOwnerForOrigIp = ipToMac[mapping.origClientIp]?.uppercase()?.trim()
        if (currentOwnerForOrigIp != null && currentOwnerForOrigIp != mapping.verifiedMac) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleOrInvalidated(
                    "Original IP ${mapping.origClientIp} reassigned from ${mapping.verifiedMac} to $currentOwnerForOrigIp",
                ),
                failureReason = UnattributedReason.CLIENT_IP_REASSIGNED,
            )
        }
        if (mapping.boundInIpToMacAtIngest && currentOwnerForOrigIp == null) {
            // Client's IP was in ipToMac when snapshot was collected, but was removed or changed since then
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleOrInvalidated(
                    "Original IP ${mapping.origClientIp} is no longer bound to ${mapping.verifiedMac}",
                ),
                failureReason = UnattributedReason.IP_BINDING_MISSING_OR_CHANGED,
            )
        }
        if (!mapping.boundInIpToMacAtIngest && currentOwnerForOrigIp == null) {
            // If ownership was verified by reverse downstream MAC (e.g. ipToMac only had IPv6),
            // invalidate if ipToMac now binds a DIFFERENT IPv4 address to mapping.verifiedMac.
            val hasDifferentIpv4ForMac = ipToMac.entries.any { (ipKey, macVal) ->
                !ipKey.contains(':') &&
                    macVal.equals(mapping.verifiedMac, ignoreCase = true) &&
                    ipKey.trim() != mapping.origClientIp
            }
            if (hasDifferentIpv4ForMac) {
                lookupAmbiguousOrStaleCount.incrementAndGet()
                return DetailedAttributionResult(
                    outcome = AttributionOutcome.StaleOrInvalidated(
                        "Client ${mapping.verifiedMac} now has a different IPv4 binding than ${mapping.origClientIp}",
                    ),
                    failureReason = UnattributedReason.IP_BINDING_MISSING_OR_CHANGED,
                )
            }
        }

        // Conservative tuple-reuse guard for TCP:
        // If a brand-new upload TCP SYN arrives on a tuple that was already in an older snapshot,
        // the port may have been reused by a new connection before the next BPF dump poll.
        if (protocol == 6 && isUpload && isTcpSyn) {
            synPendingRefreshTuples[tupleKey] = nowMono
            tupleReuseGuardTriggeredCount.incrementAndGet()
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleOrInvalidated(
                    "New upload TCP SYN on existing tuple $tupleKey; awaiting next BPF snapshot to prevent port-reuse misattribution",
                ),
                failureReason = UnattributedReason.TCP_TUPLE_REUSE_AWAITING_REFRESH,
            )
        }

        val pendingSynAt = synPendingRefreshTuples[tupleKey]
        if (pendingSynAt != null && snapshot.collectedAtMonotonicMs <= pendingSynAt) {
            lookupAmbiguousOrStaleCount.incrementAndGet()
            return DetailedAttributionResult(
                outcome = AttributionOutcome.StaleOrInvalidated(
                    "Tuple $tupleKey had a new TCP SYN after snapshot timestamp; awaiting refreshed BPF dump",
                ),
                failureReason = UnattributedReason.TCP_TUPLE_REUSE_AWAITING_REFRESH,
            )
        }

        lookupMatchedCount.incrementAndGet()
        return DetailedAttributionResult(
            outcome = AttributionOutcome.Matched(mapping.verifiedMac, mapping),
            failureReason = null,
        )
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
 * Phase B circuit breaker states (`v0.10.4-debug`).
 */
enum class RefreshCircuitBreakerState {
    CLOSED,
    OPEN,
    HALF_OPEN,
}

/**
 * Percentile summary of Phase B refresh-on-miss execution latencies.
 */
data class RefreshLatencyPercentiles(
    val sampleCount: Int = 0,
    val p50Ms: Long = 0L,
    val p95Ms: Long = 0L,
    val p99Ms: Long = 0L,
    val maxMs: Long = 0L,
)

/**
 * Background worker that executes `dumpsys tethering bpf` strictly off the packet forwarding path.
 *
 * - Runs inside the Shizuku UserService process (UID 2000 shell identity).
 * - Ensures at most one collection is in flight at any time.
 * - Enforces a real execution deadline and byte cap, reading stdout/stderr concurrently.
 * - Uses exponential backoff on repeated permission or command failures.
 * - Supports Phase B non-blocking single-flight cooldown-bounded refresh-on-miss with a
 *   `CLOSED -> OPEN -> HALF_OPEN -> CLOSED` circuit breaker (`v0.10.4-debug`).
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
    private var missRefreshExecutor: ScheduledExecutorService? = null

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

    // Phase B: Controlled Async Refresh-on-Miss telemetry & safeguards
    @Volatile
    var refreshOnMissCooldownMs: Long = DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS
        set(value) {
            field = value.coerceAtLeast(MIN_REFRESH_ON_MISS_COOLDOWN_MS)
        }

    @Volatile
    var refreshOnMissMinGlobalIntervalMs: Long = DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS
        set(value) {
            field = value.coerceAtLeast(MIN_REFRESH_ON_MISS_COOLDOWN_MS)
        }

    @Volatile
    var maxConsecutiveFailuresForAutoDisable: Int = DEFAULT_MAX_FAILURES_FOR_AUTO_DISABLE

    @Volatile
    var refreshOnMissBreakerCooldownMs: Long = DEFAULT_BREAKER_COOLDOWN_MS

    @Volatile
    var circuitBreakerState: RefreshCircuitBreakerState = RefreshCircuitBreakerState.CLOSED
        private set

    @Volatile
    var breakerOpenedAtMonoMs: Long = 0L
        private set

    private val halfOpenProbeInFlight = AtomicBoolean(false)

    @Volatile
    var refreshOnMissAutoDisabled: Boolean = false
        private set

    @Volatile
    var refreshOnMissAutoDisableReason: String = ""
        private set

    @Volatile
    var synchronousRefreshOnMissForTesting: Boolean = false

    val refreshOnMissTriggeredCount = AtomicLong(0L)
    val refreshOnMissCoalescedInFlightCount = AtomicLong(0L)
    val refreshOnMissSuppressedCooldownCount = AtomicLong(0L)
    val refreshOnMissCompletedCount = AtomicLong(0L)
    val missRefreshFailedCount = AtomicLong(0L)
    val missRefreshSuppressedBreakerCount = AtomicLong(0L)
    val missRefreshSuppressedIneligibleCount = AtomicLong(0L)
    val missRefreshQueueOverflowCount = AtomicLong(0L)
    val refreshOnMissLastLatencyMs = AtomicLong(0L)
    val refreshOnMissMaxLatencyMs = AtomicLong(0L)
    val lastRefreshOnMissTriggerMonoMs = AtomicLong(0L)
    val lastRefreshOnMissPublishedSnapshotMonoMs = AtomicLong(0L)

    private val latencyRingLock = Any()
    private val latencySamplesMs = LongArray(MAX_LATENCY_SAMPLES)
    private var latencySampleWriteIdx = 0
    private var latencySampleCount = 0

    @Volatile
    var lastRawResult: BpfRawCollectionResult? = null
        private set

    private fun recordRefreshLatencySample(latencyMs: Long) {
        refreshOnMissLastLatencyMs.set(latencyMs)
        while (true) {
            val prevMax = refreshOnMissMaxLatencyMs.get()
            if (latencyMs <= prevMax || refreshOnMissMaxLatencyMs.compareAndSet(prevMax, latencyMs)) {
                break
            }
        }
        synchronized(latencyRingLock) {
            latencySamplesMs[latencySampleWriteIdx] = latencyMs
            latencySampleWriteIdx = (latencySampleWriteIdx + 1) % MAX_LATENCY_SAMPLES
            if (latencySampleCount < MAX_LATENCY_SAMPLES) {
                latencySampleCount++
            }
        }
    }

    fun getRefreshLatencyPercentiles(): RefreshLatencyPercentiles {
        val copy: LongArray
        synchronized(latencyRingLock) {
            if (latencySampleCount == 0) {
                return RefreshLatencyPercentiles()
            }
            copy = latencySamplesMs.copyOf(latencySampleCount)
        }
        copy.sort()
        fun percentile(p: Double): Long {
            val idx = ((copy.size - 1) * p).toInt().coerceIn(0, copy.size - 1)
            return copy[idx]
        }
        return RefreshLatencyPercentiles(
            sampleCount = copy.size,
            p50Ms = percentile(0.50),
            p95Ms = percentile(0.95),
            p99Ms = percentile(0.99),
            maxMs = maxOf(copy.last(), refreshOnMissMaxLatencyMs.get()),
        )
    }

    /**
     * Resets only diagnostic collection and Phase B refresh-on-miss counters without stopping
     * the worker or invalidating active mappings.
     */
    fun resetDiagnosticCounters() {
        totalCollectionsAttempted.set(0L)
        totalCollectionsSucceeded.set(0L)
        totalCollectionsFailed.set(0L)
        refreshOnMissTriggeredCount.set(0L)
        refreshOnMissCoalescedInFlightCount.set(0L)
        refreshOnMissSuppressedCooldownCount.set(0L)
        refreshOnMissCompletedCount.set(0L)
        missRefreshFailedCount.set(0L)
        missRefreshSuppressedBreakerCount.set(0L)
        missRefreshSuppressedIneligibleCount.set(0L)
        missRefreshQueueOverflowCount.set(0L)
        refreshOnMissLastLatencyMs.set(0L)
        refreshOnMissMaxLatencyMs.set(0L)
        lastRefreshOnMissTriggerMonoMs.set(0L)
        lastRefreshOnMissPublishedSnapshotMonoMs.set(0L)
        synchronized(latencyRingLock) {
            latencySampleWriteIdx = 0
            latencySampleCount = 0
        }
        circuitBreakerState = RefreshCircuitBreakerState.CLOSED
        breakerOpenedAtMonoMs = 0L
        halfOpenProbeInFlight.set(false)
        refreshOnMissAutoDisabled = false
        refreshOnMissAutoDisableReason = ""
    }

    /**
     * Phase B non-blocking single-flight cooldown-bounded refresh-on-miss trigger.
     *
     * Never blocks or sleeps on the packet thread. Returns `true` if a refresh was scheduled
     * (or executed in test mode), or `false` if coalesced/suppressed/disabled.
     */
    fun requestAsyncRefreshOnMiss(reason: UnattributedReason): Boolean {
        if (reason != UnattributedReason.TUPLE_NOT_PRESENT && reason != UnattributedReason.SNAPSHOT_STALE) {
            missRefreshSuppressedIneligibleCount.incrementAndGet()
            return false
        }
        val nowMono = monotonicClockMs()

        // Circuit breaker state check: CLOSED -> OPEN -> HALF_OPEN -> CLOSED
        var isHalfOpenProbe = false
        when (circuitBreakerState) {
            RefreshCircuitBreakerState.OPEN -> {
                val elapsedInOpen = (nowMono - breakerOpenedAtMonoMs).coerceAtLeast(0L)
                if (refreshOnMissBreakerCooldownMs <= 0L || elapsedInOpen < refreshOnMissBreakerCooldownMs) {
                    missRefreshSuppressedBreakerCount.incrementAndGet()
                    return false
                }
                if (!halfOpenProbeInFlight.compareAndSet(false, true)) {
                    missRefreshSuppressedBreakerCount.incrementAndGet()
                    return false
                }
                circuitBreakerState = RefreshCircuitBreakerState.HALF_OPEN
                isHalfOpenProbe = true
            }
            RefreshCircuitBreakerState.HALF_OPEN -> {
                missRefreshSuppressedBreakerCount.incrementAndGet()
                return false
            }
            RefreshCircuitBreakerState.CLOSED -> {
                if (refreshOnMissAutoDisabled) {
                    missRefreshSuppressedBreakerCount.incrementAndGet()
                    return false
                }
            }
        }

        if (!isHalfOpenProbe && nowMono < nextAllowedCollectMonoMs) {
            refreshOnMissSuppressedCooldownCount.incrementAndGet()
            return false
        }
        if (inFlight.get()) {
            if (isHalfOpenProbe) {
                halfOpenProbeInFlight.set(false)
                circuitBreakerState = RefreshCircuitBreakerState.OPEN
            }
            refreshOnMissCoalescedInFlightCount.incrementAndGet()
            return false
        }
        val effectiveCooldownMs = maxOf(refreshOnMissCooldownMs, refreshOnMissMinGlobalIntervalMs)
            .coerceAtLeast(MIN_REFRESH_ON_MISS_COOLDOWN_MS)
        val lastTrigger = lastRefreshOnMissTriggerMonoMs.get()
        if (!isHalfOpenProbe && lastTrigger > 0L && (nowMono - lastTrigger) < effectiveCooldownMs) {
            refreshOnMissSuppressedCooldownCount.incrementAndGet()
            return false
        }
        if (!lastRefreshOnMissTriggerMonoMs.compareAndSet(lastTrigger, nowMono)) {
            if (isHalfOpenProbe) {
                halfOpenProbeInFlight.set(false)
                circuitBreakerState = RefreshCircuitBreakerState.OPEN
            }
            refreshOnMissCoalescedInFlightCount.incrementAndGet()
            return false
        }

        refreshOnMissTriggeredCount.incrementAndGet()
        val task = Runnable {
            val startMono = monotonicClockMs()
            val status = try {
                collectOnce(respectBackoff = !isHalfOpenProbe)
            } catch (_: Throwable) {
                BpfCollectionStatus.COMMAND_FAILED
            } finally {
                if (isHalfOpenProbe) {
                    halfOpenProbeInFlight.set(false)
                }
            }
            val endMono = monotonicClockMs()
            val latency = (endMono - startMono).coerceAtLeast(0L)
            recordRefreshLatencySample(latency)
            if (status == BpfCollectionStatus.OK || status == BpfCollectionStatus.EMPTY_VALID) {
                refreshOnMissCompletedCount.incrementAndGet()
                circuitBreakerState = RefreshCircuitBreakerState.CLOSED
                refreshOnMissAutoDisabled = false
                refreshOnMissAutoDisableReason = ""
                val snapMono = attributor.currentSnapshot().collectedAtMonotonicMs
                if (snapMono > 0L) {
                    lastRefreshOnMissPublishedSnapshotMonoMs.set(snapMono)
                }
            } else {
                missRefreshFailedCount.incrementAndGet()
                if (isHalfOpenProbe || consecutiveFailures >= maxConsecutiveFailuresForAutoDisable) {
                    tripCircuitBreaker(status, endMono)
                }
            }
        }

        if (synchronousRefreshOnMissForTesting) {
            task.run()
        } else {
            val exec = ensureMissRefreshExecutor()
            val submitted = runCatching { exec.execute(task); true }.getOrDefault(false)
            if (!submitted) {
                if (isHalfOpenProbe) {
                    halfOpenProbeInFlight.set(false)
                    circuitBreakerState = RefreshCircuitBreakerState.OPEN
                }
                missRefreshQueueOverflowCount.incrementAndGet()
                return false
            }
        }
        return true
    }

    private fun tripCircuitBreaker(status: BpfCollectionStatus, nowMono: Long) {
        circuitBreakerState = RefreshCircuitBreakerState.OPEN
        breakerOpenedAtMonoMs = nowMono
        refreshOnMissAutoDisabled = true
        refreshOnMissAutoDisableReason =
            "Circuit breaker OPEN after $consecutiveFailures consecutive failures (last=${status.name})"
    }

    @Synchronized
    private fun ensureMissRefreshExecutor(): ScheduledExecutorService {
        val existing = missRefreshExecutor
        if (existing != null && !existing.isShutdown) return existing
        val created = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "shizzi-bpf-miss-refresh").apply { isDaemon = true }
        }
        missRefreshExecutor = created
        return created
    }

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
            circuitBreakerState = RefreshCircuitBreakerState.CLOSED
            breakerOpenedAtMonoMs = 0L
            halfOpenProbeInFlight.set(false)
            refreshOnMissAutoDisabled = false
            refreshOnMissAutoDisableReason = ""
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
        missRefreshExecutor?.shutdownNow()
        missRefreshExecutor = null
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
                circuitBreakerState = RefreshCircuitBreakerState.CLOSED
                refreshOnMissAutoDisabled = false
                refreshOnMissAutoDisableReason = ""
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
        val nowMono = monotonicClockMs()
        if (consecutiveFailures >= maxConsecutiveFailuresForAutoDisable) {
            tripCircuitBreaker(status, nowMono)
        }
        val backoffMultiplier = when (status) {
            BpfCollectionStatus.PERMISSION_DENIED, BpfCollectionStatus.SERVICE_LOST ->
                (1L shl consecutiveFailures.coerceAtMost(5)) * 2_000L
            else ->
                (1L shl consecutiveFailures.coerceAtMost(4)) * 1_000L
        }
        nextAllowedCollectMonoMs = nowMono + backoffMultiplier.coerceAtMost(30_000L)
    }

    companion object {
        const val DEFAULT_POLL_INTERVAL_MS = 1_000L
        const val MIN_POLL_INTERVAL_MS = 500L
        const val MAX_POLL_INTERVAL_MS = 5_000L
        const val COMMAND_TIMEOUT_MS = 1_500L
        const val MAX_DUMP_BYTES = 256 * 1024
        const val DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS = 500L
        const val MIN_REFRESH_ON_MISS_COOLDOWN_MS = 100L
        const val DEFAULT_MAX_FAILURES_FOR_AUTO_DISABLE = 3
        const val DEFAULT_BREAKER_COOLDOWN_MS = 30_000L
        const val MAX_LATENCY_SAMPLES = 256

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
 * Role of an IPv4/IPv6 tuple relative to hotspot NAT (`v0.10.4-debug` Phase C).
 */
enum class PreNatOrPostNatRole {
    PRE_NAT_CLIENT,
    POST_NAT_UPSTREAM,
    POST_NAT_DOWNSTREAM,
    UNKNOWN,
}

/**
 * Origin of a tuple observation (`v0.10.4-debug` Phase C).
 */
enum class TupleRoleOrigin {
    TUN_PACKET_POST_NAT,
    TUN_PACKET_PRE_NAT,
    BPF_UPSTREAM,
    BPF_DOWNSTREAM,
    SOFTAP_NEIGHBOR_CALLBACK,
}

/**
 * Confidence level of packet direction classification (`v0.10.4-debug` Phase C).
 */
enum class DirectionConfidence {
    KNOWN,
    INFERRED,
}

/**
 * Ownership confidence level (`v0.10.4-debug` Phase C).
 */
enum class OwnerConfidence {
    VERIFIED,
    UNKNOWN_OWNER,
}

/**
 * Per-flow miss classification state machine (`v0.10.4-debug` Phase C).
 *
 * **Safety Invariant**: `KEY_MISMATCH_SUSPECTED` and all miss states are diagnostic-only and
 * are NEVER used to attribute or block traffic.
 */
enum class FlowMissState {
    NEW_MISS,
    REPEATED_MISS,
    PERSISTENT_AFTER_REFRESH,
    RESOLVED_AFTER_REFRESH,
    KEY_MISMATCH_SUSPECTED,
    NOT_OFFLOADED_OR_NOT_OBSERVABLE,
    EXPIRED,
    EVICTED,
}

/**
 * Canonical flow tuple representation (`v0.10.4-debug` Phase C, Section 5.1).
 *
 * ### Byte-Order & Normalization Contract
 * - Raw IPv4/IPv6 packet headers on the TUN interface carry IP addresses and TCP/UDP ports in
 *   **Network Byte Order (`BigEndian`)**.
 * - At the `TunTrafficEngine` parser boundary (`parsePacketMetadata` / [fromRawIpv4Packet]),
 *   IPv4 octets are formatted as dotted-quad strings (`b0.b1.b2.b3` in network byte order) and
 *   16-bit TCP/UDP ports are decoded via `((bHi & 0xFF) shl 8) or (bLo & 0xFF)` into unsigned
 *   host-order `Int` (`1..65535`).
 * - At the `BpfDumpParser` boundary ([fromBpfUpstreamEntry]), `dumpsys tethering bpf` prints
 *   IPv4 addresses in dotted-quad order and ports as decimal unsigned 16-bit integers, which are
 *   parsed into the identical canonical string + host-order `Int` representation.
 * - [toNetworkByteOrderBytes] serializes the normalized post-NAT tuple back into an explicit
 *   network-byte-order (`BigEndian`) binary structure (`family[1] + proto[1] + translatedIp[4] +
 *   translatedPort[2] + remoteIp[4] + remotePort[2]`) so unit tests can prove bit-for-bit parity
 *   between raw packet headers and parsed BPF offload entries.
 */
data class CanonicalFlowTuple(
    val networkSessionGeneration: Long,
    val bindingGeneration: Long,
    val ipFamily: Int,
    val transportProtocol: Int,
    val direction: String,
    val srcIp: String,
    val srcPortOrIcmpId: Int,
    val dstIp: String,
    val dstPortOrIcmpId: Int,
    val downstreamIfindex: Int? = null,
    val upstreamIfindex: Int? = null,
    val preNatOrPostNatRole: PreNatOrPostNatRole = PreNatOrPostNatRole.POST_NAT_UPSTREAM,
) {
    val ipFamilyLabel: String
        get() = if (ipFamily == 6) "IPV6" else "IPV4"

    val transportProtocolLabel: String
        get() = when (transportProtocol) {
            6 -> "TCP"
            17 -> "UDP"
            1, 58 -> "ICMP"
            else -> "OTHER($transportProtocol)"
        }

    /**
     * Converts this canonical tuple into the direction-independent post-NAT [TranslatedFlowKey]
     * used by [NatFlowAttributor].
     */
    fun toTranslatedFlowKey(): TranslatedFlowKey {
        val isDownload = direction.equals("DOWNLOAD", ignoreCase = true) ||
            preNatOrPostNatRole == PreNatOrPostNatRole.POST_NAT_DOWNSTREAM
        val translatedIp = if (isDownload) dstIp else srcIp
        val translatedPort = if (isDownload) dstPortOrIcmpId else srcPortOrIcmpId
        val remoteIp = if (isDownload) srcIp else dstIp
        val remotePort = if (isDownload) srcPortOrIcmpId else dstPortOrIcmpId
        return TranslatedFlowKey(
            family = ipFamily,
            protocol = transportProtocol,
            translatedIp = translatedIp.trim(),
            translatedPort = translatedPort,
            remoteIp = remoteIp.trim(),
            remotePort = remotePort,
        )
    }

    /**
     * Returns the reversed-endpoint [TranslatedFlowKey] to detect potential direction-reversal
     * key mismatches (`KEY_MISMATCH_SUSPECTED`) in diagnostic mode.
     */
    fun reversedDirectionFlowKey(): TranslatedFlowKey {
        val normal = toTranslatedFlowKey()
        return TranslatedFlowKey(
            family = normal.family,
            protocol = normal.protocol,
            translatedIp = normal.remoteIp,
            translatedPort = normal.remotePort,
            remoteIp = normal.translatedIp,
            remotePort = normal.translatedPort,
        )
    }

    /**
     * Serializes the normalized post-NAT flow key into a 14-byte (IPv4) network-byte-order
     * (`BigEndian`) array:
     * `[ipFamily:1][protocol:1][translatedIp:4][translatedPort:2][remoteIp:4][remotePort:2]`.
     */
    fun toNetworkByteOrderBytes(): ByteArray {
        val key = toTranslatedFlowKey()
        val transIpBytes = ipv4ToNetworkOrderBytes(key.translatedIp)
        val rmtIpBytes = ipv4ToNetworkOrderBytes(key.remoteIp)
        val out = ByteArray(14)
        out[0] = (key.family and 0xFF).toByte()
        out[1] = (key.protocol and 0xFF).toByte()
        System.arraycopy(transIpBytes, 0, out, 2, 4)
        out[6] = ((key.translatedPort ushr 8) and 0xFF).toByte()
        out[7] = (key.translatedPort and 0xFF).toByte()
        System.arraycopy(rmtIpBytes, 0, out, 8, 4)
        out[12] = ((key.remotePort ushr 8) and 0xFF).toByte()
        out[13] = (key.remotePort and 0xFF).toByte()
        return out
    }

    companion object {
        fun ipv4ToNetworkOrderBytes(ip: String): ByteArray {
            val parts = ip.trim().split('.')
            if (parts.size != 4) return ByteArray(4)
            val bytes = ByteArray(4)
            for (i in 0..3) {
                val octet = parts[i].toIntOrNull() ?: return ByteArray(4)
                if (octet !in 0..255) return ByteArray(4)
                bytes[i] = (octet and 0xFF).toByte()
            }
            return bytes
        }

        fun networkOrderBytesToIpv4(bytes: ByteArray, offset: Int = 0): String {
            if (offset < 0 || offset + 4 > bytes.size) return "0.0.0.0"
            return "${bytes[offset].toInt() and 0xFF}." +
                "${bytes[offset + 1].toInt() and 0xFF}." +
                "${bytes[offset + 2].toInt() and 0xFF}." +
                "${bytes[offset + 3].toInt() and 0xFF}"
        }

        fun readUint16BigEndian(bytes: ByteArray, offset: Int): Int {
            if (offset < 0 || offset + 2 > bytes.size) return 0
            return ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        }

        /**
         * Parses a raw IPv4 packet in network byte order (`BigEndian`) into a [CanonicalFlowTuple].
         */
        fun fromRawIpv4Packet(
            packet: ByteArray,
            length: Int = packet.size,
            isUpload: Boolean,
            sessionGeneration: Long = 0L,
            bindingGeneration: Long = 0L,
            downstreamIfindex: Int? = null,
            upstreamIfindex: Int? = null,
            preNatOrPostNatRole: PreNatOrPostNatRole = if (isUpload) {
                PreNatOrPostNatRole.POST_NAT_UPSTREAM
            } else {
                PreNatOrPostNatRole.POST_NAT_DOWNSTREAM
            },
        ): CanonicalFlowTuple? {
            if (length < 20 || packet.size < length) return null
            val version = (packet[0].toInt() ushr 4) and 0x0F
            if (version != 4) return null
            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (ihl < 20 || length < ihl) return null
            val proto = packet[9].toInt() and 0xFF
            val srcIp = networkOrderBytesToIpv4(packet, 12)
            val dstIp = networkOrderBytesToIpv4(packet, 16)
            var srcPort = 0
            var dstPort = 0
            if ((proto == 6 || proto == 17) && length >= ihl + 4) {
                srcPort = readUint16BigEndian(packet, ihl)
                dstPort = readUint16BigEndian(packet, ihl + 2)
            } else if (proto == 1 && length >= ihl + 6) {
                val icmpId = readUint16BigEndian(packet, ihl + 4)
                srcPort = icmpId
                dstPort = icmpId
            }
            return CanonicalFlowTuple(
                networkSessionGeneration = sessionGeneration,
                bindingGeneration = bindingGeneration,
                ipFamily = 4,
                transportProtocol = proto,
                direction = if (isUpload) "UPLOAD" else "DOWNLOAD",
                srcIp = srcIp,
                srcPortOrIcmpId = srcPort,
                dstIp = dstIp,
                dstPortOrIcmpId = dstPort,
                downstreamIfindex = downstreamIfindex,
                upstreamIfindex = upstreamIfindex,
                preNatOrPostNatRole = preNatOrPostNatRole,
            )
        }

        /**
         * Builds a post-NAT [CanonicalFlowTuple] from a parsed [BpfIpv4UpstreamEntry].
         */
        fun fromBpfUpstreamEntry(
            entry: BpfIpv4UpstreamEntry,
            isUpload: Boolean = true,
            sessionGeneration: Long = 0L,
            bindingGeneration: Long = 0L,
        ): CanonicalFlowTuple = CanonicalFlowTuple(
            networkSessionGeneration = sessionGeneration,
            bindingGeneration = bindingGeneration,
            ipFamily = 4,
            transportProtocol = entry.protocol,
            direction = if (isUpload) "UPLOAD" else "DOWNLOAD",
            srcIp = if (isUpload) entry.translatedIp else entry.remoteIp,
            srcPortOrIcmpId = if (isUpload) entry.translatedPort else entry.remotePort,
            dstIp = if (isUpload) entry.remoteIp else entry.translatedIp,
            dstPortOrIcmpId = if (isUpload) entry.remotePort else entry.translatedPort,
            downstreamIfindex = entry.inIfIndex,
            upstreamIfindex = entry.outIfIndex,
            preNatOrPostNatRole = if (isUpload) {
                PreNatOrPostNatRole.POST_NAT_UPSTREAM
            } else {
                PreNatOrPostNatRole.POST_NAT_DOWNSTREAM
            },
        )
    }
}

/**
 * Schema v2 structured diagnostic sample record for a missed/tracked flow (`v0.10.4-debug`, Section 5.5).
 */
data class TupleDiagnosticSampleRecord(
    val schemaVersion: Int = 4,
    val featureVersion: String = "0.10.6-debug",
    val sessionGeneration: Long,
    val bindingGeneration: Long,
    val snapshotSequence: Long,
    val snapshotAgeMs: Long,
    val flowHash: String,
    val ipFamily: String,
    val protocol: String,
    val direction: String,
    val directionConfidence: String,
    val tupleRoleOrigin: String,
    val missReason: String,
    val flowMissState: String,
    val snapshotsSurvived: Int,
    val packetsSeenOnFlow: Long,
    val bytesSeenOnFlow: Long,
    val firstSeenRelativeMs: Long,
    val lastSeenRelativeMs: Long,
    val ownerConfidence: String = OwnerConfidence.UNKNOWN_OWNER.name,
    val decision: String = "ALLOW",
    val enforcementGuarantee: String = "NONE_FOR_UNKNOWN_OWNER",
    val rawSrcEndpoint: String = "",
    val rawDstEndpoint: String = "",
) {
    fun toJson(includeSensitiveEndpoints: Boolean = false): JSONObject {
        if (!includeSensitiveEndpoints) {
            DiagnosticRedactor.redactedExportRecordsCount.incrementAndGet()
        }
        return JSONObject().apply {
            put("schemaVersion", schemaVersion)
            put("featureVersion", featureVersion)
            put("sessionGeneration", sessionGeneration)
            put("bindingGeneration", bindingGeneration)
            put("snapshotSequence", snapshotSequence)
            put("snapshotAgeMs", snapshotAgeMs)
            put("flowHash", flowHash)
            put("ipFamily", ipFamily)
            put("protocol", protocol)
            put("direction", direction)
            put("directionConfidence", directionConfidence)
            put("tupleRoleOrigin", tupleRoleOrigin)
            put("missReason", missReason)
            put("flowMissState", flowMissState)
            put("snapshotsSurvived", snapshotsSurvived)
            put("packetsSeenOnFlow", packetsSeenOnFlow)
            put("bytesSeenOnFlow", bytesSeenOnFlow)
            put("firstSeenRelativeMs", firstSeenRelativeMs)
            put("lastSeenRelativeMs", lastSeenRelativeMs)
            put("ownerConfidence", ownerConfidence)
            put("decision", decision)
            put("enforcementGuarantee", enforcementGuarantee)
            if (includeSensitiveEndpoints && rawSrcEndpoint.isNotBlank()) {
                put("rawSrcEndpoint", rawSrcEndpoint)
                put("rawDstEndpoint", rawDstEndpoint)
            }
        }
    }

    companion object {
        fun fromJson(json: JSONObject): TupleDiagnosticSampleRecord = TupleDiagnosticSampleRecord(
            schemaVersion = json.optInt("schemaVersion", 4),
            featureVersion = json.optString("featureVersion", "0.10.6-debug"),
            sessionGeneration = json.optLong("sessionGeneration", 0L),
            bindingGeneration = json.optLong("bindingGeneration", 0L),
            snapshotSequence = json.optLong("snapshotSequence", 0L),
            snapshotAgeMs = json.optLong("snapshotAgeMs", 0L),
            flowHash = json.optString("flowHash", ""),
            ipFamily = json.optString("ipFamily", "IPV4"),
            protocol = json.optString("protocol", "TCP"),
            direction = json.optString("direction", "UPLOAD"),
            directionConfidence = json.optString("directionConfidence", DirectionConfidence.INFERRED.name),
            tupleRoleOrigin = json.optString("tupleRoleOrigin", TupleRoleOrigin.TUN_PACKET_POST_NAT.name),
            missReason = json.optString("missReason", UnattributedReason.TUPLE_NOT_PRESENT.name),
            flowMissState = json.optString("flowMissState", FlowMissState.NEW_MISS.name),
            snapshotsSurvived = json.optInt("snapshotsSurvived", 0),
            packetsSeenOnFlow = json.optLong("packetsSeenOnFlow", 0L),
            bytesSeenOnFlow = json.optLong("bytesSeenOnFlow", 0L),
            firstSeenRelativeMs = json.optLong("firstSeenRelativeMs", 0L),
            lastSeenRelativeMs = json.optLong("lastSeenRelativeMs", 0L),
            ownerConfidence = json.optString("ownerConfidence", OwnerConfidence.UNKNOWN_OWNER.name),
            decision = json.optString("decision", "ALLOW"),
            enforcementGuarantee = json.optString("enforcementGuarantee", "NONE_FOR_UNKNOWN_OWNER"),
            rawSrcEndpoint = json.optString("rawSrcEndpoint", ""),
            rawDstEndpoint = json.optString("rawDstEndpoint", ""),
        )
    }
}

/**
 * Multi-client verified traffic accounting summary (`v0.10.4-debug`, Section 6.1).
 *
 * Includes ONLY `VERIFIED` ownership traffic (`DIRECT_IP`, `BPF_NAT`, or `CONNTRACK_PROCFS`).
 * `UNKNOWN_OWNER` traffic is never assigned to any client.
 */
data class PerClientVerifiedTrafficSummary(
    val mac: String,
    val originalIpv4: String,
    val activeFlows: Int = 0,
    val verifiedUploadPackets: Long = 0L,
    val verifiedUploadBytes: Long = 0L,
    val verifiedDownloadPackets: Long = 0L,
    val verifiedDownloadBytes: Long = 0L,
    val directIpPackets: Long = 0L,
    val bpfNatPackets: Long = 0L,
    val conntrackPackets: Long = 0L,
    val blockedDropPackets: Long = 0L,
    val blockedDropBytes: Long = 0L,
    val isBlocked: Boolean = false,
    val isQuotaExhausted: Boolean = false,
    val isThrottled: Boolean = false,
) {
    val totalVerifiedPackets: Long
        get() = verifiedUploadPackets + verifiedDownloadPackets

    val totalVerifiedBytes: Long
        get() = verifiedUploadBytes + verifiedDownloadBytes
}

/**
 * Phase D switchable operating mode (`v0.10.5-debug`, Section 2.1):
 * - [DIAGNOSTIC] (default): preserves `0.10.4-debug` packet decisions while adding full Phase D
 *   policy-transition correlation, existing-flow/cache auditing, and post-block diagnostics.
 * - [EXPERIMENTAL_ENFORCEMENT] (opt-in): immediately re-evaluates verified-owner flows on
 *   `BLOCK` / `QUOTA_EXHAUSTED`, purges stale-allow pacing queues, enforces mid-stream quota
 *   boundary packets, and uses generation-scoped verified flow ownership pins to drop packets
 *   on already-verified long-lived TCP/UDP flows across snapshot intervals — while NEVER
 *   globally dropping `UNKNOWN_OWNER`.
 */
enum class PhaseDEnforcementMode {
    DIAGNOSTIC,
    EXPERIMENTAL_ENFORCEMENT,
}

/**
 * Phase D evidence confidence classification (`v0.10.5-debug`, Section 6.3).
 */
enum class PhaseDEvidenceConfidence {
    VERIFIED_OWNER,
    UNKNOWN_OWNER,
    PATH_NOT_OBSERVABLE,
}

/**
 * Phase D interface lifecycle state (`v0.10.5-debug`, Section 6.2).
 */
enum class PhaseDInterfaceLifecycleState {
    WAITING_FOR_INTERFACES,
    BINDING_INTERFACES,
    ATTRIBUTION_READY,
    DEGRADED_OR_STOPPED,
}

/**
 * Monotonic policy transition / lifecycle event for Phase D (`v0.10.5-debug`, Workstream D1).
 */
data class PhaseDPolicyTransitionEvent(
    val eventSequence: Long,
    val timestampMonoMs: Long,
    val timestampEpochMs: Long,
    val transitionType: String,
    val clientMac: String = "",
    val clientIp: String = "",
    val policyGeneration: Long = 0L,
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
    val snapshotSequence: Long = 0L,
    val activePolicyFlags: String = "ALLOW",
    val verifiedFlowsAtTransition: Int = 0,
    val queuedPacketsPurged: Int = 0,
    val detail: String = "",
) {
    fun toJson(
        includeSensitiveEndpoints: Boolean = false,
        includePseudonymousIds: Boolean = false,
    ): JSONObject = JSONObject().apply {
        val macLabel = when {
            clientMac.isBlank() -> ""
            includeSensitiveEndpoints -> clientMac
            includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(clientMac)
            else -> "Client-Redacted"
        }
        val ipLabel = when {
            clientIp.isBlank() -> ""
            includeSensitiveEndpoints -> clientIp
            includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(clientIp)
            else -> "redacted"
        }
        put("eventSequence", eventSequence)
        put("timestampMonoMs", timestampMonoMs)
        put("timestampEpochMs", timestampEpochMs)
        put("transitionType", transitionType)
        put("clientMac", macLabel)
        put("clientIp", ipLabel)
        put("policyGeneration", policyGeneration)
        put("sessionGeneration", sessionGeneration)
        put("bindingGeneration", bindingGeneration)
        put("snapshotSequence", snapshotSequence)
        put("activePolicyFlags", activePolicyFlags)
        put("verifiedFlowsAtTransition", verifiedFlowsAtTransition)
        put("queuedPacketsPurged", queuedPacketsPurged)
        put(
            "detail",
            if (includeSensitiveEndpoints) detail else BpfDumpParser.maskSensitiveLinePreview(detail),
        )
    }

    companion object {
        fun fromJson(json: JSONObject): PhaseDPolicyTransitionEvent = PhaseDPolicyTransitionEvent(
            eventSequence = json.optLong("eventSequence", 0L),
            timestampMonoMs = json.optLong("timestampMonoMs", 0L),
            timestampEpochMs = json.optLong("timestampEpochMs", 0L),
            transitionType = json.optString("transitionType", ""),
            clientMac = json.optString("clientMac", ""),
            clientIp = json.optString("clientIp", ""),
            policyGeneration = json.optLong("policyGeneration", 0L),
            sessionGeneration = json.optLong("sessionGeneration", 0L),
            bindingGeneration = json.optLong("bindingGeneration", 0L),
            snapshotSequence = json.optLong("snapshotSequence", 0L),
            activePolicyFlags = json.optString("activePolicyFlags", "ALLOW"),
            verifiedFlowsAtTransition = json.optInt("verifiedFlowsAtTransition", 0),
            queuedPacketsPurged = json.optInt("queuedPacketsPurged", 0),
            detail = json.optString("detail", ""),
        )
    }
}

/**
 * Per-client post-transition verified traffic & cache audit summary (`v0.10.5-debug`, Workstreams D1 & D2).
 */
data class PhaseDClientPostTransitionSummary(
    val mac: String,
    val originalIpv4: String = "",
    val policyGeneration: Long = 1L,
    val lastTransitionType: String = "NONE",
    val lastTransitionMonoMs: Long = 0L,
    val verifiedFlowsAtTransition: Int = 0,
    val decisionsRecomputed: Long = 0L,
    val staleAllowCacheHitsPrevented: Long = 0L,
    val verifiedAllowedAfterBlockPackets: Long = 0L,
    val verifiedAllowedAfterBlockBytes: Long = 0L,
    val verifiedDroppedAfterBlockPackets: Long = 0L,
    val verifiedDroppedAfterBlockBytes: Long = 0L,
    val pinnedFlowEnforcedPackets: Long = 0L,
    val pinnedFlowEnforcedBytes: Long = 0L,
) {
    fun toJson(
        index: Int,
        includeSensitiveEndpoints: Boolean = false,
        includePseudonymousIds: Boolean = false,
    ): JSONObject = JSONObject().apply {
        val macLabel = when {
            includeSensitiveEndpoints -> mac
            includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(mac)
            else -> "Client-${index + 1}"
        }
        val ipLabel = when {
            originalIpv4.isBlank() -> ""
            includeSensitiveEndpoints -> originalIpv4
            includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(originalIpv4)
            else -> "redacted"
        }
        put("mac", macLabel)
        put("originalIpv4", ipLabel)
        put("policyGeneration", policyGeneration)
        put("lastTransitionType", lastTransitionType)
        put("lastTransitionMonoMs", lastTransitionMonoMs)
        put("verifiedFlowsAtTransition", verifiedFlowsAtTransition)
        put("decisionsRecomputed", decisionsRecomputed)
        put("staleAllowCacheHitsPrevented", staleAllowCacheHitsPrevented)
        put("verifiedAllowedAfterBlockPackets", verifiedAllowedAfterBlockPackets)
        put("verifiedAllowedAfterBlockBytes", verifiedAllowedAfterBlockBytes)
        put("verifiedDroppedAfterBlockPackets", verifiedDroppedAfterBlockPackets)
        put("verifiedDroppedAfterBlockBytes", verifiedDroppedAfterBlockBytes)
        put("pinnedFlowEnforcedPackets", pinnedFlowEnforcedPackets)
        put("pinnedFlowEnforcedBytes", pinnedFlowEnforcedBytes)
    }

    companion object {
        fun fromJson(json: JSONObject): PhaseDClientPostTransitionSummary = PhaseDClientPostTransitionSummary(
            mac = json.optString("mac", ""),
            originalIpv4 = json.optString("originalIpv4", ""),
            policyGeneration = json.optLong("policyGeneration", 1L),
            lastTransitionType = json.optString("lastTransitionType", "NONE"),
            lastTransitionMonoMs = json.optLong("lastTransitionMonoMs", 0L),
            verifiedFlowsAtTransition = json.optInt("verifiedFlowsAtTransition", 0),
            decisionsRecomputed = json.optLong("decisionsRecomputed", 0L),
            staleAllowCacheHitsPrevented = json.optLong("staleAllowCacheHitsPrevented", 0L),
            verifiedAllowedAfterBlockPackets = json.optLong("verifiedAllowedAfterBlockPackets", 0L),
            verifiedAllowedAfterBlockBytes = json.optLong("verifiedAllowedAfterBlockBytes", 0L),
            verifiedDroppedAfterBlockPackets = json.optLong("verifiedDroppedAfterBlockPackets", 0L),
            verifiedDroppedAfterBlockBytes = json.optLong("verifiedDroppedAfterBlockBytes", 0L),
            pinnedFlowEnforcedPackets = json.optLong("pinnedFlowEnforcedPackets", 0L),
            pinnedFlowEnforcedBytes = json.optLong("pinnedFlowEnforcedBytes", 0L),
        )
    }
}

/**
 * Interface lifecycle transition event (`v0.10.5-debug`, Workstream D4).
 */
data class PhaseDInterfaceLifecycleEvent(
    val eventSequence: Long,
    val timestampMonoMs: Long,
    val state: String,
    val downstreamIface: String = "",
    val upstreamIface: String = "",
    val osDownstreamIfIndex: Int? = null,
    val osUpstreamIfIndex: Int? = null,
    val inferredDownstreamIfIndex: Int? = null,
    val inferredUpstreamIfIndex: Int? = null,
    val sessionGeneration: Long = 0L,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("eventSequence", eventSequence)
        put("timestampMonoMs", timestampMonoMs)
        put("state", state)
        put("downstreamIface", downstreamIface)
        put("upstreamIface", upstreamIface)
        put("osDownstreamIfIndex", osDownstreamIfIndex ?: JSONObject.NULL)
        put("osUpstreamIfIndex", osUpstreamIfIndex ?: JSONObject.NULL)
        put("inferredDownstreamIfIndex", inferredDownstreamIfIndex ?: JSONObject.NULL)
        put("inferredUpstreamIfIndex", inferredUpstreamIfIndex ?: JSONObject.NULL)
        put("sessionGeneration", sessionGeneration)
    }

    companion object {
        private fun JSONObject.optPosIntOrNull(key: String): Int? {
            if (isNull(key)) return null
            val v = optInt(key, 0)
            return if (v > 0) v else null
        }

        fun fromJson(json: JSONObject): PhaseDInterfaceLifecycleEvent = PhaseDInterfaceLifecycleEvent(
            eventSequence = json.optLong("eventSequence", 0L),
            timestampMonoMs = json.optLong("timestampMonoMs", 0L),
            state = json.optString("state", PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES.name),
            downstreamIface = json.optString("downstreamIface", ""),
            upstreamIface = json.optString("upstreamIface", ""),
            osDownstreamIfIndex = json.optPosIntOrNull("osDownstreamIfIndex"),
            osUpstreamIfIndex = json.optPosIntOrNull("osUpstreamIfIndex"),
            inferredDownstreamIfIndex = json.optPosIntOrNull("inferredDownstreamIfIndex"),
            inferredUpstreamIfIndex = json.optPosIntOrNull("inferredUpstreamIfIndex"),
            sessionGeneration = json.optLong("sessionGeneration", 0L),
        )
    }
}

/**
 * Delivery verification test-session marker (`v0.10.5-debug`, Workstream D5).
 */
data class PhaseDDeliveryTestMarker(
    val markerSequence: Long,
    val markerType: String,
    val timestampMonoMs: Long,
    val timestampEpochMs: Long,
    val phaseDMode: String,
    val sessionGeneration: Long,
    val snapshotSequence: Long,
    val blockedClientsCount: Int,
    val quotaExhaustedClientsCount: Int,
    val note: String = "",
) {
    fun toJson(includeSensitiveEndpoints: Boolean = false): JSONObject = JSONObject().apply {
        put("markerSequence", markerSequence)
        put("markerType", markerType)
        put("timestampMonoMs", timestampMonoMs)
        put("timestampEpochMs", timestampEpochMs)
        put("phaseDMode", phaseDMode)
        put("sessionGeneration", sessionGeneration)
        put("snapshotSequence", snapshotSequence)
        put("blockedClientsCount", blockedClientsCount)
        put("quotaExhaustedClientsCount", quotaExhaustedClientsCount)
        put(
            "note",
            if (includeSensitiveEndpoints) note else BpfDumpParser.maskSensitiveLinePreview(note),
        )
    }

    companion object {
        fun fromJson(json: JSONObject): PhaseDDeliveryTestMarker = PhaseDDeliveryTestMarker(
            markerSequence = json.optLong("markerSequence", 0L),
            markerType = json.optString("markerType", "TEST_SESSION_START"),
            timestampMonoMs = json.optLong("timestampMonoMs", 0L),
            timestampEpochMs = json.optLong("timestampEpochMs", 0L),
            phaseDMode = json.optString("phaseDMode", PhaseDEnforcementMode.DIAGNOSTIC.name),
            sessionGeneration = json.optLong("sessionGeneration", 0L),
            snapshotSequence = json.optLong("snapshotSequence", 0L),
            blockedClientsCount = json.optInt("blockedClientsCount", 0),
            quotaExhaustedClientsCount = json.optInt("quotaExhaustedClientsCount", 0),
            note = json.optString("note", ""),
        )
    }
}

/**
 * Encapsulated Phase D status report (`v0.10.5-debug`, Schema v3).
 */
data class PhaseDStatusReport(
    val phaseDMode: PhaseDEnforcementMode = PhaseDEnforcementMode.DIAGNOSTIC,
    val evidenceConfidence: PhaseDEvidenceConfidence = PhaseDEvidenceConfidence.UNKNOWN_OWNER,
    val interfaceLifecycleState: PhaseDInterfaceLifecycleState = PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES,
    val policyTransitionEvents: List<PhaseDPolicyTransitionEvent> = emptyList(),
    val postTransitionVerifiedClientTraffic: List<PhaseDClientPostTransitionSummary> = emptyList(),
    val unknownForwardedAfterBlockPackets: Long = 0L,
    val unknownForwardedAfterBlockBytes: Long = 0L,
    val unknownPostBlockByProtocolAndDirection: Map<String, Long> = emptyMap(),
    val unknownPostBlockBytesByProtocolAndDirection: Map<String, Long> = emptyMap(),
    val verifiedFlowsAtTransitionTotal: Long = 0L,
    val staleAllowCacheHitsPreventedTotal: Long = 0L,
    val decisionsRecomputedTotal: Long = 0L,
    val verifiedAllowedAfterBlockPacketsTotal: Long = 0L,
    val verifiedAllowedAfterBlockBytesTotal: Long = 0L,
    val verifiedDroppedAfterBlockPacketsTotal: Long = 0L,
    val verifiedDroppedAfterBlockBytesTotal: Long = 0L,
    val activePinnedVerifiedFlowsCount: Int = 0,
    val pinnedFlowHitsInDiagnosticMode: Long = 0L,
    val pinnedFlowEnforcedDropsInEnforcementMode: Long = 0L,
    val queuedPacketsPurgedOnTransitionTotal: Long = 0L,
    val establishedTcpMissingFromBpfPackets: Long = 0L,
    val establishedTcpMissingFromBpfBytes: Long = 0L,
    val establishedTcpPinnedMatchedPackets: Long = 0L,
    val establishedTcpPinnedMatchedBytes: Long = 0L,
    val tcpKeepaliveOrAckOnlyPackets: Long = 0L,
    val tcpSynPacketsSeen: Long = 0L,
    val tcpFinOrRstPacketsSeen: Long = 0L,
    val udp443PostBlockUnattributedPackets: Long = 0L,
    val udp443PostBlockUnattributedBytes: Long = 0L,
    val udp53PostBlockUnattributedPackets: Long = 0L,
    val udp53PostBlockUnattributedBytes: Long = 0L,
    val interfaceLifecycleEvents: List<PhaseDInterfaceLifecycleEvent> = emptyList(),
    val deliveryTestMarkers: List<PhaseDDeliveryTestMarker> = emptyList(),
    val lastPolicyActivatedEpochMs: Long = 0L,
)

/**
 * Immutable snapshot of Phase C deep tuple & survival diagnostics (`v0.10.4-debug`).
 */
data class DeepTupleDiagnosticsSnapshot(
    val activeTrackedFlowsCount: Int = 0,
    val newMissFlowsCount: Long = 0L,
    val repeatedMissFlowsCount: Long = 0L,
    val persistentAfterRefreshFlowsCount: Long = 0L,
    val resolvedAfterRefreshFlowsCount: Long = 0L,
    val keyMismatchSuspectedFlowsCount: Long = 0L,
    val notOffloadedOrNotObservableFlowsCount: Long = 0L,
    val expiredFlowsCount: Long = 0L,
    val evictedFlowsCount: Long = 0L,
    val survived0SnapshotsCount: Int = 0,
    val survived1SnapshotCount: Int = 0,
    val survived2SnapshotsCount: Int = 0,
    val survived3PlusSnapshotsCount: Int = 0,
    val udp443MissingFlowsCount: Long = 0L,
    val udp443MissingPacketsCount: Long = 0L,
    val udp443MissingBytesCount: Long = 0L,
    val udp443ResolvedAfterRefreshFlowsCount: Long = 0L,
    val udp53MissingFlowsCount: Long = 0L,
    val udp53MissingPacketsCount: Long = 0L,
    val udp53MissingBytesCount: Long = 0L,
    val udp53ResolvedAfterRefreshFlowsCount: Long = 0L,
    val tcpMissingFlowsCount: Long = 0L,
    val udpOtherMissingFlowsCount: Long = 0L,
    val postRefreshFlowKeysResolved: Long = 0L,
    val postRefreshFirstSubsequentAttributedPackets: Long = 0L,
    val postRefreshFirstSubsequentAttributedBytes: Long = 0L,
    val sampleRecords: List<TupleDiagnosticSampleRecord> = emptyList(),
)

/**
 * Bounded LRU per-flow miss & survival tracker (`v0.10.4-debug` Phase C, Section 5).
 *
 * - Bounded to `maxTrackedFlows = 2,048` entries with `flowTtlMs = 60,000 ms` TTL.
 * - Bounded sample ring buffer of `maxSampleRecords = 256` [TupleDiagnosticSampleRecord] entries.
 * - Keyed by `(sessionGeneration, bindingGeneration, TranslatedFlowKey)`; automatically clears
 *   or invalidates entries when `sessionGeneration` or `bindingGeneration` advances.
 * - Strictly diagnostic: `KEY_MISMATCH_SUSPECTED` and all other miss states never attribute or
 *   drop packets.
 */
class DeepTupleDiagnosticsTracker(
    private val monotonicClockMs: () -> Long = { System.nanoTime() / 1_000_000L },
    @Volatile var maxTrackedFlows: Int = DEFAULT_MAX_TRACKED_FLOWS,
    @Volatile var maxSampleRecords: Int = DEFAULT_MAX_SAMPLE_RECORDS,
    @Volatile var flowTtlMs: Long = DEFAULT_FLOW_TTL_MS,
) {
    private data class TrackedFlowEntry(
        val sessionGeneration: Long,
        val bindingGeneration: Long,
        val canonicalTuple: CanonicalFlowTuple,
        val flowKey: TranslatedFlowKey,
        val flowHash: String,
        val firstSeenMonoMs: Long,
        var lastSeenMonoMs: Long,
        val firstSnapshotSequence: Long,
        var lastSnapshotSequence: Long,
        var lastSnapshotAgeMs: Long,
        var snapshotsSurvived: Int,
        var packetsSeenOnFlow: Long,
        var bytesSeenOnFlow: Long,
        var lastMissReason: UnattributedReason,
        var directionConfidence: DirectionConfidence,
        var tupleRoleOrigin: TupleRoleOrigin,
        var state: FlowMissState,
        var countedRepeatedMiss: Boolean = false,
        var countedPersistentAfterRefresh: Boolean = false,
        var countedResolvedAfterRefresh: Boolean = false,
        var countedKeyMismatchSuspected: Boolean = false,
        var countedNotOffloaded: Boolean = false,
        var firstSubsequentAttributedRecorded: Boolean = false,
    )

    private val lock = Any()
    private var activeSessionGeneration: Long = 0L
    private var activeBindingGeneration: Long = 0L

    // Access-ordered LinkedHashMap for O(1) LRU tracking
    private val trackedFlows = LinkedHashMap<TranslatedFlowKey, TrackedFlowEntry>(256, 0.75f, true)
    private val sampleRingBuffer = ArrayDeque<TupleDiagnosticSampleRecord>(DEFAULT_MAX_SAMPLE_RECORDS)

    private var newMissFlowsCount = 0L
    private var repeatedMissFlowsCount = 0L
    private var persistentAfterRefreshFlowsCount = 0L
    private var resolvedAfterRefreshFlowsCount = 0L
    private var keyMismatchSuspectedFlowsCount = 0L
    private var notOffloadedOrNotObservableFlowsCount = 0L
    private var expiredFlowsCount = 0L
    private var evictedFlowsCount = 0L

    private var udp443MissingFlowsCount = 0L
    private var udp443MissingPacketsCount = 0L
    private var udp443MissingBytesCount = 0L
    private var udp443ResolvedAfterRefreshFlowsCount = 0L

    private var udp53MissingFlowsCount = 0L
    private var udp53MissingPacketsCount = 0L
    private var udp53MissingBytesCount = 0L
    private var udp53ResolvedAfterRefreshFlowsCount = 0L

    private var tcpMissingFlowsCount = 0L
    private var udpOtherMissingFlowsCount = 0L

    private var postRefreshFlowKeysResolved = 0L
    private var postRefreshFirstSubsequentAttributedPackets = 0L
    private var postRefreshFirstSubsequentAttributedBytes = 0L

    fun reset() {
        synchronized(lock) {
            trackedFlows.clear()
            sampleRingBuffer.clear()
            newMissFlowsCount = 0L
            repeatedMissFlowsCount = 0L
            persistentAfterRefreshFlowsCount = 0L
            resolvedAfterRefreshFlowsCount = 0L
            keyMismatchSuspectedFlowsCount = 0L
            notOffloadedOrNotObservableFlowsCount = 0L
            expiredFlowsCount = 0L
            evictedFlowsCount = 0L
            udp443MissingFlowsCount = 0L
            udp443MissingPacketsCount = 0L
            udp443MissingBytesCount = 0L
            udp443ResolvedAfterRefreshFlowsCount = 0L
            udp53MissingFlowsCount = 0L
            udp53MissingPacketsCount = 0L
            udp53MissingBytesCount = 0L
            udp53ResolvedAfterRefreshFlowsCount = 0L
            tcpMissingFlowsCount = 0L
            udpOtherMissingFlowsCount = 0L
            postRefreshFlowKeysResolved = 0L
            postRefreshFirstSubsequentAttributedPackets = 0L
            postRefreshFirstSubsequentAttributedBytes = 0L
        }
    }

    fun onGenerationChanged(sessionGeneration: Long, bindingGeneration: Long) {
        synchronized(lock) {
            if (sessionGeneration != activeSessionGeneration || bindingGeneration != activeBindingGeneration) {
                activeSessionGeneration = sessionGeneration
                activeBindingGeneration = bindingGeneration
                trackedFlows.clear()
            }
        }
    }

    private fun pruneExpiredLocked(nowMono: Long) {
        val ttl = flowTtlMs.coerceAtLeast(1_000L)
        val iter = trackedFlows.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next().value
            if ((nowMono - entry.lastSeenMonoMs) > ttl) {
                entry.state = FlowMissState.EXPIRED
                expiredFlowsCount++
                appendSampleRecordLocked(entry)
                iter.remove()
            }
        }
    }

    private fun detectCandidateKeyMismatchLocked(
        tuple: CanonicalFlowTuple,
        flowKey: TranslatedFlowKey,
        snapshot: NatFlowSnapshot,
    ): Boolean {
        if (snapshot.flowsByTuple.isEmpty() && snapshot.ifIndexMismatchCount == 0) return false
        // 1. Reversed direction key present in snapshot
        val reversedKey = tuple.reversedDirectionFlowKey()
        if (reversedKey != flowKey && snapshot.flowsByTuple.containsKey(reversedKey)) {
            return true
        }
        // 2. Candidate flow with matching pre-NAT origClient endpoint or matching ports/protocol
        for ((candKey, mapping) in snapshot.flowsByTuple) {
            if (candKey == flowKey) continue
            if (mapping.protocol == flowKey.protocol) {
                // Pre-NAT vs Post-NAT endpoint role mismatch
                if (mapping.origClientIp == flowKey.translatedIp &&
                    mapping.origClientPort == flowKey.translatedPort &&
                    mapping.remoteIp == flowKey.remoteIp &&
                    mapping.remotePort == flowKey.remotePort
                ) {
                    return true
                }
                // Reversed pre-NAT match
                if (mapping.origClientIp == flowKey.remoteIp &&
                    mapping.origClientPort == flowKey.remotePort &&
                    mapping.remoteIp == flowKey.translatedIp &&
                    mapping.remotePort == flowKey.translatedPort
                ) {
                    return true
                }
                // Same translated port & remote endpoint but different translated IP
                if (mapping.translatedPort == flowKey.translatedPort &&
                    mapping.remoteIp == flowKey.remoteIp &&
                    mapping.remotePort == flowKey.remotePort
                ) {
                    return true
                }
            }
        }
        return false
    }

    /**
     * Records an unattributed packet miss in the bounded tracker.
     */
    fun onPacketMiss(
        tuple: CanonicalFlowTuple,
        packetBytes: Int,
        missReason: UnattributedReason,
        snapshot: NatFlowSnapshot,
        directionConfidence: DirectionConfidence = DirectionConfidence.INFERRED,
        tupleRoleOrigin: TupleRoleOrigin = TupleRoleOrigin.TUN_PACKET_POST_NAT,
    ): FlowMissState {
        val nowMono = monotonicClockMs()
        val flowKey = tuple.toTranslatedFlowKey()
        val isUdp443 = flowKey.protocol == 17 && (flowKey.remotePort == 443 || flowKey.translatedPort == 443)
        val isUdp53 = flowKey.protocol == 17 && (flowKey.remotePort == 53 || flowKey.translatedPort == 53)

        synchronized(lock) {
            if (tuple.networkSessionGeneration != activeSessionGeneration ||
                tuple.bindingGeneration != activeBindingGeneration
            ) {
                activeSessionGeneration = tuple.networkSessionGeneration
                activeBindingGeneration = tuple.bindingGeneration
                trackedFlows.clear()
            }

            pruneExpiredLocked(nowMono)

            if (isUdp443) {
                udp443MissingPacketsCount++
                udp443MissingBytesCount += packetBytes.toLong()
            } else if (isUdp53) {
                udp53MissingPacketsCount++
                udp53MissingBytesCount += packetBytes.toLong()
            }

            val snapshotAgeMs = if (snapshot.collectedAtMonotonicMs > 0L) {
                (nowMono - snapshot.collectedAtMonotonicMs).coerceAtLeast(0L)
            } else {
                0L
            }
            val candidateMismatch = detectCandidateKeyMismatchLocked(tuple, flowKey, snapshot)

            val existing = trackedFlows[flowKey]
            if (existing == null) {
                val cap = maxTrackedFlows.coerceAtLeast(16)
                while (trackedFlows.size >= cap) {
                    val eldestKey = trackedFlows.keys.firstOrNull() ?: break
                    val evicted = trackedFlows.remove(eldestKey)
                    if (evicted != null) {
                        evicted.state = FlowMissState.EVICTED
                        evictedFlowsCount++
                        appendSampleRecordLocked(evicted)
                    }
                }

                val initialState = if (candidateMismatch) {
                    FlowMissState.KEY_MISMATCH_SUSPECTED
                } else {
                    FlowMissState.NEW_MISS
                }
                newMissFlowsCount++
                if (isUdp443) {
                    udp443MissingFlowsCount++
                } else if (isUdp53) {
                    udp53MissingFlowsCount++
                } else if (flowKey.protocol == 6) {
                    tcpMissingFlowsCount++
                } else if (flowKey.protocol == 17) {
                    udpOtherMissingFlowsCount++
                }

                val created = TrackedFlowEntry(
                    sessionGeneration = tuple.networkSessionGeneration,
                    bindingGeneration = tuple.bindingGeneration,
                    canonicalTuple = tuple,
                    flowKey = flowKey,
                    flowHash = DiagnosticRedactor.ephemeralFlowHash(tuple),
                    firstSeenMonoMs = nowMono,
                    lastSeenMonoMs = nowMono,
                    firstSnapshotSequence = snapshot.snapshotSequence,
                    lastSnapshotSequence = snapshot.snapshotSequence,
                    lastSnapshotAgeMs = snapshotAgeMs,
                    snapshotsSurvived = 0,
                    packetsSeenOnFlow = 1L,
                    bytesSeenOnFlow = packetBytes.toLong(),
                    lastMissReason = missReason,
                    directionConfidence = directionConfidence,
                    tupleRoleOrigin = tupleRoleOrigin,
                    state = initialState,
                    countedKeyMismatchSuspected = candidateMismatch,
                )
                if (candidateMismatch) {
                    keyMismatchSuspectedFlowsCount++
                }
                trackedFlows[flowKey] = created
                appendSampleRecordLocked(created)
                return created.state
            }

            // Update existing tracked flow
            existing.lastSeenMonoMs = nowMono
            existing.packetsSeenOnFlow += 1L
            existing.bytesSeenOnFlow += packetBytes.toLong()
            existing.lastMissReason = missReason
            existing.lastSnapshotAgeMs = snapshotAgeMs

            if (snapshot.snapshotSequence > existing.lastSnapshotSequence) {
                val deltaSeq = (snapshot.snapshotSequence - existing.lastSnapshotSequence).toInt().coerceAtLeast(1)
                existing.snapshotsSurvived += deltaSeq
                existing.lastSnapshotSequence = snapshot.snapshotSequence
            }

            val prevState = existing.state
            val nextState = when {
                candidateMismatch -> {
                    if (!existing.countedKeyMismatchSuspected) {
                        existing.countedKeyMismatchSuspected = true
                        keyMismatchSuspectedFlowsCount++
                    }
                    FlowMissState.KEY_MISMATCH_SUSPECTED
                }
                existing.snapshotsSurvived >= 3 && (nowMono - existing.firstSeenMonoMs) >= NOT_OFFLOADED_MIN_AGE_MS -> {
                    if (!existing.countedNotOffloaded) {
                        existing.countedNotOffloaded = true
                        notOffloadedOrNotObservableFlowsCount++
                    }
                    FlowMissState.NOT_OFFLOADED_OR_NOT_OBSERVABLE
                }
                existing.snapshotsSurvived >= 1 -> {
                    if (!existing.countedPersistentAfterRefresh) {
                        existing.countedPersistentAfterRefresh = true
                        persistentAfterRefreshFlowsCount++
                    }
                    FlowMissState.PERSISTENT_AFTER_REFRESH
                }
                existing.packetsSeenOnFlow >= 2L -> {
                    if (!existing.countedRepeatedMiss) {
                        existing.countedRepeatedMiss = true
                        repeatedMissFlowsCount++
                    }
                    FlowMissState.REPEATED_MISS
                }
                else -> FlowMissState.NEW_MISS
            }
            existing.state = nextState
            if (nextState != prevState) {
                appendSampleRecordLocked(existing)
            }
            return nextState
        }
    }

    /**
     * Evaluates all active tracked flows when a new validated [NatFlowSnapshot] is published.
     */
    fun onSnapshotPublished(snapshot: NatFlowSnapshot) {
        val nowMono = snapshot.collectedAtMonotonicMs.takeIf { it > 0L } ?: monotonicClockMs()
        synchronized(lock) {
            if (snapshot.sessionGeneration != activeSessionGeneration ||
                snapshot.bindingGeneration != activeBindingGeneration
            ) {
                activeSessionGeneration = snapshot.sessionGeneration
                activeBindingGeneration = snapshot.bindingGeneration
                trackedFlows.clear()
                return
            }

            pruneExpiredLocked(nowMono)

            for ((flowKey, entry) in trackedFlows) {
                if (snapshot.snapshotSequence > entry.lastSnapshotSequence) {
                    entry.lastSnapshotSequence = snapshot.snapshotSequence
                }
                entry.lastSnapshotAgeMs = 0L

                if (snapshot.flowsByTuple.containsKey(flowKey)) {
                    if (!entry.countedResolvedAfterRefresh) {
                        entry.countedResolvedAfterRefresh = true
                        resolvedAfterRefreshFlowsCount++
                        postRefreshFlowKeysResolved++
                        val isUdp443 = flowKey.protocol == 17 && (flowKey.remotePort == 443 || flowKey.translatedPort == 443)
                        val isUdp53 = flowKey.protocol == 17 && (flowKey.remotePort == 53 || flowKey.translatedPort == 53)
                        if (isUdp443) {
                            udp443ResolvedAfterRefreshFlowsCount++
                        } else if (isUdp53) {
                            udp53ResolvedAfterRefreshFlowsCount++
                        }
                    }
                    if (entry.state != FlowMissState.RESOLVED_AFTER_REFRESH) {
                        entry.state = FlowMissState.RESOLVED_AFTER_REFRESH
                        appendSampleRecordLocked(entry)
                    }
                } else if (entry.state != FlowMissState.RESOLVED_AFTER_REFRESH) {
                    entry.snapshotsSurvived += 1
                    val candidateMismatch = detectCandidateKeyMismatchLocked(entry.canonicalTuple, flowKey, snapshot)
                    val prevState = entry.state
                    val nextState = when {
                        candidateMismatch -> {
                            if (!entry.countedKeyMismatchSuspected) {
                                entry.countedKeyMismatchSuspected = true
                                keyMismatchSuspectedFlowsCount++
                            }
                            FlowMissState.KEY_MISMATCH_SUSPECTED
                        }
                        entry.snapshotsSurvived >= 3 && (nowMono - entry.firstSeenMonoMs) >= NOT_OFFLOADED_MIN_AGE_MS -> {
                            if (!entry.countedNotOffloaded) {
                                entry.countedNotOffloaded = true
                                notOffloadedOrNotObservableFlowsCount++
                            }
                            FlowMissState.NOT_OFFLOADED_OR_NOT_OBSERVABLE
                        }
                        else -> {
                            if (!entry.countedPersistentAfterRefresh) {
                                entry.countedPersistentAfterRefresh = true
                                persistentAfterRefreshFlowsCount++
                            }
                            FlowMissState.PERSISTENT_AFTER_REFRESH
                        }
                    }
                    entry.state = nextState
                    if (nextState != prevState) {
                        appendSampleRecordLocked(entry)
                    }
                }
            }
        }
    }

    /**
     * Notifies the tracker when a packet is attributed via `BPF_NAT`.
     * If the flow previously missed, records `RESOLVED_AFTER_REFRESH` and increments
     * `postRefreshFirstSubsequentAttributedPackets` / `postRefreshFirstSubsequentAttributedBytes`
     * on its first attributed packet after refresh.
     */
    fun onPacketAttributedByBpf(
        flowKey: TranslatedFlowKey,
        packetBytes: Int,
        snapshot: NatFlowSnapshot,
    ): Boolean {
        val nowMono = monotonicClockMs()
        synchronized(lock) {
            if (snapshot.sessionGeneration != activeSessionGeneration ||
                snapshot.bindingGeneration != activeBindingGeneration
            ) {
                return false
            }
            val entry = trackedFlows[flowKey] ?: return false
            entry.lastSeenMonoMs = nowMono
            if (!entry.countedResolvedAfterRefresh) {
                entry.countedResolvedAfterRefresh = true
                resolvedAfterRefreshFlowsCount++
                postRefreshFlowKeysResolved++
                val isUdp443 = flowKey.protocol == 17 && (flowKey.remotePort == 443 || flowKey.translatedPort == 443)
                val isUdp53 = flowKey.protocol == 17 && (flowKey.remotePort == 53 || flowKey.translatedPort == 53)
                if (isUdp443) {
                    udp443ResolvedAfterRefreshFlowsCount++
                } else if (isUdp53) {
                    udp53ResolvedAfterRefreshFlowsCount++
                }
            }
            if (entry.state != FlowMissState.RESOLVED_AFTER_REFRESH) {
                entry.state = FlowMissState.RESOLVED_AFTER_REFRESH
                appendSampleRecordLocked(entry)
            }
            if (!entry.firstSubsequentAttributedRecorded) {
                entry.firstSubsequentAttributedRecorded = true
                postRefreshFirstSubsequentAttributedPackets += 1L
                postRefreshFirstSubsequentAttributedBytes += packetBytes.toLong()
                return true
            }
            return false
        }
    }

    private fun appendSampleRecordLocked(entry: TrackedFlowEntry) {
        val cap = maxSampleRecords.coerceAtLeast(16)
        while (sampleRingBuffer.size >= cap) {
            sampleRingBuffer.removeFirst()
        }
        val relLastMs = (entry.lastSeenMonoMs - entry.firstSeenMonoMs).coerceAtLeast(0L)
        sampleRingBuffer.addLast(
            TupleDiagnosticSampleRecord(
                schemaVersion = 4,
                featureVersion = "0.10.6-debug",
                sessionGeneration = entry.sessionGeneration,
                bindingGeneration = entry.bindingGeneration,
                snapshotSequence = entry.lastSnapshotSequence,
                snapshotAgeMs = entry.lastSnapshotAgeMs,
                flowHash = entry.flowHash,
                ipFamily = entry.canonicalTuple.ipFamilyLabel,
                protocol = entry.canonicalTuple.transportProtocolLabel,
                direction = entry.canonicalTuple.direction,
                directionConfidence = entry.directionConfidence.name,
                tupleRoleOrigin = entry.tupleRoleOrigin.name,
                missReason = entry.lastMissReason.name,
                flowMissState = entry.state.name,
                snapshotsSurvived = entry.snapshotsSurvived,
                packetsSeenOnFlow = entry.packetsSeenOnFlow,
                bytesSeenOnFlow = entry.bytesSeenOnFlow,
                firstSeenRelativeMs = 0L,
                lastSeenRelativeMs = relLastMs,
                ownerConfidence = if (entry.state == FlowMissState.RESOLVED_AFTER_REFRESH) {
                    OwnerConfidence.VERIFIED.name
                } else {
                    OwnerConfidence.UNKNOWN_OWNER.name
                },
                decision = "ALLOW",
                enforcementGuarantee = "NONE_FOR_UNKNOWN_OWNER",
                rawSrcEndpoint = "${entry.canonicalTuple.srcIp}:${entry.canonicalTuple.srcPortOrIcmpId}",
                rawDstEndpoint = "${entry.canonicalTuple.dstIp}:${entry.canonicalTuple.dstPortOrIcmpId}",
            ),
        )
    }

    fun snapshot(): DeepTupleDiagnosticsSnapshot {
        val nowMono = monotonicClockMs()
        synchronized(lock) {
            pruneExpiredLocked(nowMono)
            var surv0 = 0
            var surv1 = 0
            var surv2 = 0
            var surv3Plus = 0
            for (entry in trackedFlows.values) {
                when {
                    entry.snapshotsSurvived <= 0 -> surv0++
                    entry.snapshotsSurvived == 1 -> surv1++
                    entry.snapshotsSurvived == 2 -> surv2++
                    else -> surv3Plus++
                }
            }
            return DeepTupleDiagnosticsSnapshot(
                activeTrackedFlowsCount = trackedFlows.size,
                newMissFlowsCount = newMissFlowsCount,
                repeatedMissFlowsCount = repeatedMissFlowsCount,
                persistentAfterRefreshFlowsCount = persistentAfterRefreshFlowsCount,
                resolvedAfterRefreshFlowsCount = resolvedAfterRefreshFlowsCount,
                keyMismatchSuspectedFlowsCount = keyMismatchSuspectedFlowsCount,
                notOffloadedOrNotObservableFlowsCount = notOffloadedOrNotObservableFlowsCount,
                expiredFlowsCount = expiredFlowsCount,
                evictedFlowsCount = evictedFlowsCount,
                survived0SnapshotsCount = surv0,
                survived1SnapshotCount = surv1,
                survived2SnapshotsCount = surv2,
                survived3PlusSnapshotsCount = surv3Plus,
                udp443MissingFlowsCount = udp443MissingFlowsCount,
                udp443MissingPacketsCount = udp443MissingPacketsCount,
                udp443MissingBytesCount = udp443MissingBytesCount,
                udp443ResolvedAfterRefreshFlowsCount = udp443ResolvedAfterRefreshFlowsCount,
                udp53MissingFlowsCount = udp53MissingFlowsCount,
                udp53MissingPacketsCount = udp53MissingPacketsCount,
                udp53MissingBytesCount = udp53MissingBytesCount,
                udp53ResolvedAfterRefreshFlowsCount = udp53ResolvedAfterRefreshFlowsCount,
                tcpMissingFlowsCount = tcpMissingFlowsCount,
                udpOtherMissingFlowsCount = udpOtherMissingFlowsCount,
                postRefreshFlowKeysResolved = postRefreshFlowKeysResolved,
                postRefreshFirstSubsequentAttributedPackets = postRefreshFirstSubsequentAttributedPackets,
                postRefreshFirstSubsequentAttributedBytes = postRefreshFirstSubsequentAttributedBytes,
                sampleRecords = sampleRingBuffer.toList(),
            )
        }
    }

    companion object {
        const val DEFAULT_MAX_TRACKED_FLOWS = 2_048
        const val DEFAULT_MAX_SAMPLE_RECORDS = 256
        const val DEFAULT_FLOW_TTL_MS = 60_000L
        const val NOT_OFFLOADED_MIN_AGE_MS = 2_000L
    }
}

/**
 * Bounded diagnostic summary for the UI and exportable report (`v0.10.5-debug`, Schema v3).
 */
data class BpfTrafficSplitCounters(
    val ipv4EligiblePackets: Long = 0L,
    val ipv4EligibleBytes: Long = 0L,
    val ipv4AttributedPackets: Long = 0L,
    val ipv4AttributedBytes: Long = 0L,
    val ipv4UnattributedPackets: Long = 0L,
    val ipv4UnattributedBytes: Long = 0L,
    val ipv6EligiblePackets: Long = 0L,
    val ipv6EligibleBytes: Long = 0L,
    val ipv6AttributedPackets: Long = 0L,
    val ipv6AttributedBytes: Long = 0L,
    val ipv6UnattributedPackets: Long = 0L,
    val ipv6UnattributedBytes: Long = 0L,
    val tcpEligiblePackets: Long = 0L,
    val tcpEligibleBytes: Long = 0L,
    val tcpAttributedPackets: Long = 0L,
    val tcpAttributedBytes: Long = 0L,
    val tcpUnattributedPackets: Long = 0L,
    val tcpUnattributedBytes: Long = 0L,
    val udpEligiblePackets: Long = 0L,
    val udpEligibleBytes: Long = 0L,
    val udpAttributedPackets: Long = 0L,
    val udpAttributedBytes: Long = 0L,
    val udpUnattributedPackets: Long = 0L,
    val udpUnattributedBytes: Long = 0L,
    val icmpEligiblePackets: Long = 0L,
    val icmpEligibleBytes: Long = 0L,
    val icmpAttributedPackets: Long = 0L,
    val icmpAttributedBytes: Long = 0L,
    val icmpUnattributedPackets: Long = 0L,
    val icmpUnattributedBytes: Long = 0L,
    val otherProtoEligiblePackets: Long = 0L,
    val otherProtoEligibleBytes: Long = 0L,
    val otherProtoAttributedPackets: Long = 0L,
    val otherProtoAttributedBytes: Long = 0L,
    val otherProtoUnattributedPackets: Long = 0L,
    val otherProtoUnattributedBytes: Long = 0L,
    val uploadEligiblePackets: Long = 0L,
    val uploadEligibleBytes: Long = 0L,
    val uploadAttributedPackets: Long = 0L,
    val uploadAttributedBytes: Long = 0L,
    val uploadUnattributedPackets: Long = 0L,
    val uploadUnattributedBytes: Long = 0L,
    val downloadEligiblePackets: Long = 0L,
    val downloadEligibleBytes: Long = 0L,
    val downloadAttributedPackets: Long = 0L,
    val downloadAttributedBytes: Long = 0L,
    val downloadUnattributedPackets: Long = 0L,
    val downloadUnattributedBytes: Long = 0L,
)

data class BpfAttributionStatusReport(
    val experimentalEnabled: Boolean = false,
    val state: ExperimentalBpfState = ExperimentalBpfState.DISABLED,
    val snapshotHealth: BpfSnapshotHealth = BpfSnapshotHealth.UNAVAILABLE,
    val collectionStatus: BpfCollectionStatus = BpfCollectionStatus.IDLE,
    val collectionError: String = "",
    val parserVersion: Int = BpfDumpParser.PARSER_VERSION,
    val pollIntervalMs: Long = BpfMapReader.DEFAULT_POLL_INTERVAL_MS,
    val snapshotSequence: Long = 0L,
    val snapshotAgeMs: Long = 0L,
    val lastSuccessfulRefreshEpochMs: Long = 0L,
    val lastCollectionDurationMs: Long = 0L,
    val totalCollectionsAttempted: Long = 0L,
    val totalCollectionsSucceeded: Long = 0L,
    val totalCollectionsFailed: Long = 0L,
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
    val snapshotPublishRejectedByReason: Map<String, Long> = emptyMap(),
    val totalEligiblePackets: Long = 0L,
    val totalEligibleBytes: Long = 0L,
    val totalAttributedPackets: Long = 0L,
    val totalAttributedBytes: Long = 0L,
    val directAttributedPackets: Long = 0L,
    val directAttributedBytes: Long = 0L,
    val bpfAttributedPackets: Long = 0L,
    val bpfAttributedBytes: Long = 0L,
    val conntrackAttributedPackets: Long = 0L,
    val conntrackAttributedBytes: Long = 0L,
    val unknownForwardedPackets: Long = 0L,
    val unknownForwardedBytes: Long = 0L,
    val unattributedPacketsByReason: Map<String, Long> = emptyMap(),
    val unattributedBytesByReason: Map<String, Long> = emptyMap(),
    val trafficSplit: BpfTrafficSplitCounters = BpfTrafficSplitCounters(),
    val conntrackFallbackAttemptedCount: Long = 0L,
    val conntrackFallbackSucceededCount: Long = 0L,
    val conntrackFallbackFailedCount: Long = 0L,
    val conntrackPermissionDeniedCount: Long = 0L,
    val conntrackBackoffActive: Boolean = false,
    val conntrackBackoffRemainingMs: Long = 0L,
    val conntrackBackoffSkippedCount: Long = 0L,
    val activeConnectedClientsCount: Int = 0,
    val blockedClientsCount: Int = 0,
    val quotaExhaustedClientsCount: Int = 0,
    val throttledClientsCount: Int = 0,
    val bpfRefreshOnMissEnabled: Boolean = false,
    val refreshOnMissCooldownMs: Long = BpfMapReader.DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS,
    val refreshCircuitBreakerState: String = RefreshCircuitBreakerState.CLOSED.name,
    val refreshOnMissTriggeredCount: Long = 0L,
    val refreshOnMissCoalescedInFlightCount: Long = 0L,
    val refreshOnMissSuppressedCooldownCount: Long = 0L,
    val refreshOnMissCompletedCount: Long = 0L,
    val missRefreshFailedCount: Long = 0L,
    val missRefreshSuppressedBreakerCount: Long = 0L,
    val missRefreshSuppressedIneligibleCount: Long = 0L,
    val missRefreshQueueOverflowCount: Long = 0L,
    val refreshOnMissLastLatencyMs: Long = 0L,
    val missRefreshLatency: RefreshLatencyPercentiles = RefreshLatencyPercentiles(),
    val postRefreshAttributedPackets: Long = 0L,
    val postRefreshAttributedBytes: Long = 0L,
    val postRefreshFlowKeysResolved: Long = 0L,
    val postRefreshFirstSubsequentAttributedPackets: Long = 0L,
    val postRefreshFirstSubsequentAttributedBytes: Long = 0L,
    val refreshOnMissAutoDisabled: Boolean = false,
    val refreshOnMissAutoDisableReason: String = "",
    // Phase C: Deep Tuple & Owner Diagnostics
    val deepTupleDiagnosticsEnabled: Boolean = false,
    val unknownOwnerPacketPolicy: String = "ALLOW",
    val deepTupleDiagnostics: DeepTupleDiagnosticsSnapshot = DeepTupleDiagnosticsSnapshot(),
    val perClientVerifiedSummaries: List<PerClientVerifiedTrafficSummary> = emptyList(),
    // Phase D: Persistent Connection Leak Investigation & Experimental Enforcement (`v0.10.5-debug`)
    val phaseD: PhaseDStatusReport = PhaseDStatusReport(),
    // v0.10.6-debug: Exclusive Blocking Mode & Pre-NAT Firewall Feasibility
    val preNatDiagnostics: PreNatModeDiagnosticReport = PreNatModeDiagnosticReport(),
    // v0.10.7-debug: Native SoftAP MAC Blocklist & Exclusive Diagnostics
    val softApDiagnostics: SoftApModeDiagnosticReport = SoftApModeDiagnosticReport(
        capabilityReport = SoftApCapabilityReport(
            executionIdentity = SoftApExecutionIdentity(
                shizukuState = "SHIZUKU_NOT_RUNNING",
                shizukuRunning = false,
                shizukuPermissionGranted = false,
            ),
        ),
    ),
    // v0.10.8-debug: Domain Blocking Engine & DNS/SNI Filtering Diagnostics
    val domainDiagnostics: DomainFilterDiagnosticReport = DomainFilterDiagnosticReport(),
    // v0.10.9-debug: VPN Loss Recovery & Fail-Closed Diagnostics (Schema v7)
    val vpnRecoveryDiagnostics: VpnRecoveryDiagnostics = VpnRecoveryDiagnostics(),
    val ambiguousOrStaleLookups: Long = 0L,
    val localControlPackets: Long = 0L,
    val localControlBytes: Long = 0L,
    val unsupportedOrFragmentPackets: Long = 0L,
    val blockedDropPackets: Long = 0L,
    val blockedDropBytes: Long = 0L,
    val shapingDropPackets: Long = 0L,
    val shapedPackets: Long = 0L,
    val rejectedOldGenerationCount: Long = 0L,
    val tupleReuseGuardTriggeredCount: Long = 0L,
) {
    val ipv4EligiblePackets: Long get() = trafficSplit.ipv4EligiblePackets
    val ipv4EligibleBytes: Long get() = trafficSplit.ipv4EligibleBytes
    val ipv4AttributedPackets: Long get() = trafficSplit.ipv4AttributedPackets
    val ipv4AttributedBytes: Long get() = trafficSplit.ipv4AttributedBytes
    val ipv4UnattributedPackets: Long get() = trafficSplit.ipv4UnattributedPackets
    val ipv4UnattributedBytes: Long get() = trafficSplit.ipv4UnattributedBytes
    val ipv6EligiblePackets: Long get() = trafficSplit.ipv6EligiblePackets
    val ipv6EligibleBytes: Long get() = trafficSplit.ipv6EligibleBytes
    val ipv6AttributedPackets: Long get() = trafficSplit.ipv6AttributedPackets
    val ipv6AttributedBytes: Long get() = trafficSplit.ipv6AttributedBytes
    val ipv6UnattributedPackets: Long get() = trafficSplit.ipv6UnattributedPackets
    val ipv6UnattributedBytes: Long get() = trafficSplit.ipv6UnattributedBytes
    val tcpEligiblePackets: Long get() = trafficSplit.tcpEligiblePackets
    val tcpEligibleBytes: Long get() = trafficSplit.tcpEligibleBytes
    val tcpAttributedPackets: Long get() = trafficSplit.tcpAttributedPackets
    val tcpAttributedBytes: Long get() = trafficSplit.tcpAttributedBytes
    val tcpUnattributedPackets: Long get() = trafficSplit.tcpUnattributedPackets
    val tcpUnattributedBytes: Long get() = trafficSplit.tcpUnattributedBytes
    val udpEligiblePackets: Long get() = trafficSplit.udpEligiblePackets
    val udpEligibleBytes: Long get() = trafficSplit.udpEligibleBytes
    val udpAttributedPackets: Long get() = trafficSplit.udpAttributedPackets
    val udpAttributedBytes: Long get() = trafficSplit.udpAttributedBytes
    val udpUnattributedPackets: Long get() = trafficSplit.udpUnattributedPackets
    val udpUnattributedBytes: Long get() = trafficSplit.udpUnattributedBytes
    val icmpEligiblePackets: Long get() = trafficSplit.icmpEligiblePackets
    val icmpEligibleBytes: Long get() = trafficSplit.icmpEligibleBytes
    val icmpAttributedPackets: Long get() = trafficSplit.icmpAttributedPackets
    val icmpAttributedBytes: Long get() = trafficSplit.icmpAttributedBytes
    val icmpUnattributedPackets: Long get() = trafficSplit.icmpUnattributedPackets
    val icmpUnattributedBytes: Long get() = trafficSplit.icmpUnattributedBytes
    val otherProtoEligiblePackets: Long get() = trafficSplit.otherProtoEligiblePackets
    val otherProtoEligibleBytes: Long get() = trafficSplit.otherProtoEligibleBytes
    val otherProtoAttributedPackets: Long get() = trafficSplit.otherProtoAttributedPackets
    val otherProtoAttributedBytes: Long get() = trafficSplit.otherProtoAttributedBytes
    val otherProtoUnattributedPackets: Long get() = trafficSplit.otherProtoUnattributedPackets
    val otherProtoUnattributedBytes: Long get() = trafficSplit.otherProtoUnattributedBytes
    val uploadEligiblePackets: Long get() = trafficSplit.uploadEligiblePackets
    val uploadEligibleBytes: Long get() = trafficSplit.uploadEligibleBytes
    val uploadAttributedPackets: Long get() = trafficSplit.uploadAttributedPackets
    val uploadAttributedBytes: Long get() = trafficSplit.uploadAttributedBytes
    val uploadUnattributedPackets: Long get() = trafficSplit.uploadUnattributedPackets
    val uploadUnattributedBytes: Long get() = trafficSplit.uploadUnattributedBytes
    val downloadEligiblePackets: Long get() = trafficSplit.downloadEligiblePackets
    val downloadEligibleBytes: Long get() = trafficSplit.downloadEligibleBytes
    val downloadAttributedPackets: Long get() = trafficSplit.downloadAttributedPackets
    val downloadAttributedBytes: Long get() = trafficSplit.downloadAttributedBytes
    val downloadUnattributedPackets: Long get() = trafficSplit.downloadUnattributedPackets
    val downloadUnattributedBytes: Long get() = trafficSplit.downloadUnattributedBytes

    val missRefreshLatencyP50Ms: Long get() = missRefreshLatency.p50Ms
    val missRefreshLatencyP95Ms: Long get() = missRefreshLatency.p95Ms
    val missRefreshLatencyP99Ms: Long get() = missRefreshLatency.p99Ms
    val missRefreshLatencyMaxMs: Long get() = maxOf(missRefreshLatency.maxMs, refreshOnMissLastLatencyMs)

    val activeTrackedFlowsCount: Int get() = deepTupleDiagnostics.activeTrackedFlowsCount
    val newMissFlowsCount: Long get() = deepTupleDiagnostics.newMissFlowsCount
    val repeatedMissFlowsCount: Long get() = deepTupleDiagnostics.repeatedMissFlowsCount
    val persistentAfterRefreshFlowsCount: Long get() = deepTupleDiagnostics.persistentAfterRefreshFlowsCount
    val resolvedAfterRefreshFlowsCount: Long get() = deepTupleDiagnostics.resolvedAfterRefreshFlowsCount
    val keyMismatchSuspectedFlowsCount: Long get() = deepTupleDiagnostics.keyMismatchSuspectedFlowsCount
    val notOffloadedOrNotObservableFlowsCount: Long get() = deepTupleDiagnostics.notOffloadedOrNotObservableFlowsCount
    val expiredFlowsCount: Long get() = deepTupleDiagnostics.expiredFlowsCount
    val evictedFlowsCount: Long get() = deepTupleDiagnostics.evictedFlowsCount
    val survived0SnapshotsCount: Int get() = deepTupleDiagnostics.survived0SnapshotsCount
    val survived1SnapshotCount: Int get() = deepTupleDiagnostics.survived1SnapshotCount
    val survived2SnapshotsCount: Int get() = deepTupleDiagnostics.survived2SnapshotsCount
    val survived3PlusSnapshotsCount: Int get() = deepTupleDiagnostics.survived3PlusSnapshotsCount
    val udp443MissingFlowsCount: Long get() = deepTupleDiagnostics.udp443MissingFlowsCount
    val udp443MissingPacketsCount: Long get() = deepTupleDiagnostics.udp443MissingPacketsCount
    val udp443MissingBytesCount: Long get() = deepTupleDiagnostics.udp443MissingBytesCount
    val udp443ResolvedAfterRefreshFlowsCount: Long get() = deepTupleDiagnostics.udp443ResolvedAfterRefreshFlowsCount
    val udp53MissingFlowsCount: Long get() = deepTupleDiagnostics.udp53MissingFlowsCount
    val udp53MissingPacketsCount: Long get() = deepTupleDiagnostics.udp53MissingPacketsCount
    val udp53MissingBytesCount: Long get() = deepTupleDiagnostics.udp53MissingBytesCount
    val udp53ResolvedAfterRefreshFlowsCount: Long get() = deepTupleDiagnostics.udp53ResolvedAfterRefreshFlowsCount
    val tcpMissingFlowsCount: Long get() = deepTupleDiagnostics.tcpMissingFlowsCount
    val udpOtherMissingFlowsCount: Long get() = deepTupleDiagnostics.udpOtherMissingFlowsCount
    val tupleDiagnosticSampleRecords: List<TupleDiagnosticSampleRecord> get() = deepTupleDiagnostics.sampleRecords

    // Phase D flat convenience getters
    val phaseDMode: PhaseDEnforcementMode get() = phaseD.phaseDMode
    val evidenceConfidence: PhaseDEvidenceConfidence get() = phaseD.evidenceConfidence
    val interfaceLifecycleState: PhaseDInterfaceLifecycleState get() = phaseD.interfaceLifecycleState
    val policyTransitionEvents: List<PhaseDPolicyTransitionEvent> get() = phaseD.policyTransitionEvents
    val postTransitionVerifiedClientTraffic: List<PhaseDClientPostTransitionSummary> get() = phaseD.postTransitionVerifiedClientTraffic
    val unknownForwardedAfterBlockPackets: Long get() = phaseD.unknownForwardedAfterBlockPackets
    val unknownForwardedAfterBlockBytes: Long get() = phaseD.unknownForwardedAfterBlockBytes
    val unknownPostBlockByProtocolAndDirection: Map<String, Long> get() = phaseD.unknownPostBlockByProtocolAndDirection
    val verifiedFlowsAtTransitionTotal: Long get() = phaseD.verifiedFlowsAtTransitionTotal
    val verifiedFlowsAtTransition: Int get() = phaseD.verifiedFlowsAtTransitionTotal.toInt()
    val staleAllowCacheHitsPreventedTotal: Long get() = phaseD.staleAllowCacheHitsPreventedTotal
    val staleAllowCacheHitsPrevented: Long get() = phaseD.staleAllowCacheHitsPreventedTotal
    val decisionsRecomputedTotal: Long get() = phaseD.decisionsRecomputedTotal
    val decisionsRecomputed: Long get() = phaseD.decisionsRecomputedTotal
    val verifiedAllowedAfterBlockPacketsTotal: Long get() = phaseD.verifiedAllowedAfterBlockPacketsTotal
    val verifiedAllowedAfterBlockPackets: Long get() = phaseD.verifiedAllowedAfterBlockPacketsTotal
    val verifiedAllowedAfterBlockBytesTotal: Long get() = phaseD.verifiedAllowedAfterBlockBytesTotal
    val verifiedAllowedAfterBlockBytes: Long get() = phaseD.verifiedAllowedAfterBlockBytesTotal
    val verifiedDroppedAfterBlockPacketsTotal: Long get() = phaseD.verifiedDroppedAfterBlockPacketsTotal
    val verifiedDroppedAfterBlockPackets: Long get() = phaseD.verifiedDroppedAfterBlockPacketsTotal
    val verifiedDroppedAfterBlockBytesTotal: Long get() = phaseD.verifiedDroppedAfterBlockBytesTotal
    val verifiedDroppedAfterBlockBytes: Long get() = phaseD.verifiedDroppedAfterBlockBytesTotal
    val activePinnedVerifiedFlowsCount: Int get() = phaseD.activePinnedVerifiedFlowsCount
    val pinnedFlowHitsInDiagnosticMode: Long get() = phaseD.pinnedFlowHitsInDiagnosticMode
    val pinnedFlowEnforcedDropsInEnforcementMode: Long get() = phaseD.pinnedFlowEnforcedDropsInEnforcementMode
    val queuedPacketsPurgedOnTransitionTotal: Long get() = phaseD.queuedPacketsPurgedOnTransitionTotal
    val establishedTcpMissingFromBpfPackets: Long get() = phaseD.establishedTcpMissingFromBpfPackets
    val establishedTcpMissingFromBpfBytes: Long get() = phaseD.establishedTcpMissingFromBpfBytes
    val establishedTcpPinnedMatchedPackets: Long get() = phaseD.establishedTcpPinnedMatchedPackets
    val establishedTcpPinnedMatchedBytes: Long get() = phaseD.establishedTcpPinnedMatchedBytes
    val pinnedVerifiedFlowHitsPackets: Long get() = phaseD.establishedTcpPinnedMatchedPackets
    val pinnedVerifiedFlowHitsBytes: Long get() = phaseD.establishedTcpPinnedMatchedBytes
    val tcpKeepaliveOrAckOnlyPackets: Long get() = phaseD.tcpKeepaliveOrAckOnlyPackets
    val tcpSynPacketsSeen: Long get() = phaseD.tcpSynPacketsSeen
    val tcpFinOrRstPacketsSeen: Long get() = phaseD.tcpFinOrRstPacketsSeen
    val udp443PostBlockUnattributedPackets: Long get() = phaseD.udp443PostBlockUnattributedPackets
    val udp443PostBlockUnattributedBytes: Long get() = phaseD.udp443PostBlockUnattributedBytes
    val udp53PostBlockUnattributedPackets: Long get() = phaseD.udp53PostBlockUnattributedPackets
    val udp53PostBlockUnattributedBytes: Long get() = phaseD.udp53PostBlockUnattributedBytes
    val interfaceLifecycleEvents: List<PhaseDInterfaceLifecycleEvent> get() = phaseD.interfaceLifecycleEvents
    val deliveryTestMarkers: List<PhaseDDeliveryTestMarker> get() = phaseD.deliveryTestMarkers

    // v0.10.6-debug Schema v4 flat convenience getters
    val requestedBlockingMode: BlockingMode get() = preNatDiagnostics.requestedMode
    val effectiveBlockingMode: BlockingMode get() = preNatDiagnostics.effectiveMode
    val exclusiveEngineInvariant: Boolean get() = preNatDiagnostics.exclusiveEngineInvariant
    val preNatCapabilityStatus: PreNatCapabilityStatus get() = preNatDiagnostics.capability.status
    val preNatRuntimeState: PreNatRuntimeState get() = preNatDiagnostics.runtimeState
    val preNatGoNoGoVerdict: String get() = preNatDiagnostics.goNoGoVerdict

    val omittedRejectedLineCount: Int
        get() = (lastAttemptRejectedLineCount - minOf(lastAttemptRejectedLines.size, NatFlowAttributor.MAX_EXPORTED_REJECTED_LINES))
            .coerceAtLeast(0)

    val packetCoveragePercent: Double?
        get() = if (totalEligiblePackets > 0L) {
            (totalAttributedPackets.toDouble() * 100.0) / totalEligiblePackets.toDouble()
        } else {
            null
        }

    val byteCoveragePercent: Double?
        get() = if (totalEligibleBytes > 0L) {
            (totalAttributedBytes.toDouble() * 100.0) / totalEligibleBytes.toDouble()
        } else {
            null
        }

    fun formattedPacketCoverage(): String =
        packetCoveragePercent?.let { String.format(Locale.US, "%.2f%%", it) } ?: "N/A"

    fun formattedByteCoverage(): String =
        byteCoveragePercent?.let { String.format(Locale.US, "%.2f%%", it) } ?: "N/A"

    fun toJson(
        includeSensitiveEndpoints: Boolean = false,
        includePseudonymousIds: Boolean = false,
    ): JSONObject = JSONObject().apply {
        if (!includeSensitiveEndpoints) {
            DiagnosticRedactor.redactedExportRecordsCount.incrementAndGet()
        }
        put("schemaVersion", 7)
        put("featureVersion", "0.10.9-debug")
        put("requestedMode", preNatDiagnostics.requestedMode.name)
        put("effectiveMode", preNatDiagnostics.effectiveModeNullable?.name ?: "NONE")
        put("exclusiveEngineInvariant", preNatDiagnostics.exclusiveEngineInvariant && softApDiagnostics.exclusiveEngineInvariant)
        put("experimentalEnabled", experimentalEnabled)
        put("state", state.name)
        put("snapshotHealth", snapshotHealth.name)
        put("collectionStatus", collectionStatus.name)
        put(
            "collectionError",
            if (includeSensitiveEndpoints) collectionError else BpfDumpParser.maskSensitiveLinePreview(collectionError),
        )
        put("parserVersion", parserVersion)
        put("pollIntervalMs", pollIntervalMs)
        put("snapshotSequence", snapshotSequence)
        put("snapshotAgeMs", snapshotAgeMs)
        put("lastSuccessfulRefreshEpochMs", lastSuccessfulRefreshEpochMs)
        put("lastCollectionDurationMs", lastCollectionDurationMs)
        put("totalCollectionsAttempted", totalCollectionsAttempted)
        put("totalCollectionsSucceeded", totalCollectionsSucceeded)
        put("totalCollectionsFailed", totalCollectionsFailed)
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
        put(
            "downstreamIfIndexError",
            if (includeSensitiveEndpoints) downstreamIfIndexError else BpfDumpParser.maskSensitiveLinePreview(downstreamIfIndexError),
        )
        put(
            "upstreamIfIndexError",
            if (includeSensitiveEndpoints) upstreamIfIndexError else BpfDumpParser.maskSensitiveLinePreview(upstreamIfIndexError),
        )
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
        put(
            "lastAttemptError",
            if (includeSensitiveEndpoints) lastAttemptError else BpfDumpParser.maskSensitiveLinePreview(lastAttemptError),
        )
        put("lastAttemptAgeMs", lastAttemptAgeMs)
        put("lastAttemptDurationMs", lastAttemptDurationMs)
        put("lastAttemptRecognizedFormat", lastAttemptRecognizedFormat)
        put("lastAttemptSnapshotPublished", lastAttemptSnapshotPublished)
        put(
            "lastAttemptDecisionReason",
            if (includeSensitiveEndpoints) lastAttemptDecisionReason else BpfDumpParser.maskSensitiveLinePreview(lastAttemptDecisionReason),
        )
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

        val pubRejObj = JSONObject()
        for ((rk, rv) in snapshotPublishRejectedByReason) {
            pubRejObj.put(rk, rv)
        }
        put("snapshotPublishRejectedByReason", pubRejObj)

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

        put("totalEligiblePackets", totalEligiblePackets)
        put("totalEligibleBytes", totalEligibleBytes)
        put("totalAttributedPackets", totalAttributedPackets)
        put("totalAttributedBytes", totalAttributedBytes)
        put("packetCoverage", formattedPacketCoverage())
        put("byteCoverage", formattedByteCoverage())
        put("directAttributedPackets", directAttributedPackets)
        put("directAttributedBytes", directAttributedBytes)
        put("bpfAttributedPackets", bpfAttributedPackets)
        put("bpfAttributedBytes", bpfAttributedBytes)
        put("conntrackAttributedPackets", conntrackAttributedPackets)
        put("conntrackAttributedBytes", conntrackAttributedBytes)
        put("unknownForwardedPackets", unknownForwardedPackets)
        put("unknownForwardedBytes", unknownForwardedBytes)

        val unattrPktsObj = JSONObject()
        for ((k, v) in unattributedPacketsByReason) {
            unattrPktsObj.put(k, v)
        }
        put("unattributedPacketsByReason", unattrPktsObj)

        val unattrBytesObj = JSONObject()
        for ((k, v) in unattributedBytesByReason) {
            unattrBytesObj.put(k, v)
        }
        put("unattributedBytesByReason", unattrBytesObj)

        put("ipv4EligiblePackets", ipv4EligiblePackets)
        put("ipv4EligibleBytes", ipv4EligibleBytes)
        put("ipv4AttributedPackets", ipv4AttributedPackets)
        put("ipv4AttributedBytes", ipv4AttributedBytes)
        put("ipv4UnattributedPackets", ipv4UnattributedPackets)
        put("ipv4UnattributedBytes", ipv4UnattributedBytes)
        put("ipv6EligiblePackets", ipv6EligiblePackets)
        put("ipv6EligibleBytes", ipv6EligibleBytes)
        put("ipv6AttributedPackets", ipv6AttributedPackets)
        put("ipv6AttributedBytes", ipv6AttributedBytes)
        put("ipv6UnattributedPackets", ipv6UnattributedPackets)
        put("ipv6UnattributedBytes", ipv6UnattributedBytes)

        put("tcpEligiblePackets", tcpEligiblePackets)
        put("tcpEligibleBytes", tcpEligibleBytes)
        put("tcpAttributedPackets", tcpAttributedPackets)
        put("tcpAttributedBytes", tcpAttributedBytes)
        put("tcpUnattributedPackets", tcpUnattributedPackets)
        put("tcpUnattributedBytes", tcpUnattributedBytes)
        put("udpEligiblePackets", udpEligiblePackets)
        put("udpEligibleBytes", udpEligibleBytes)
        put("udpAttributedPackets", udpAttributedPackets)
        put("udpAttributedBytes", udpAttributedBytes)
        put("udpUnattributedPackets", udpUnattributedPackets)
        put("udpUnattributedBytes", udpUnattributedBytes)
        put("icmpEligiblePackets", icmpEligiblePackets)
        put("icmpEligibleBytes", icmpEligibleBytes)
        put("icmpAttributedPackets", icmpAttributedPackets)
        put("icmpAttributedBytes", icmpAttributedBytes)
        put("icmpUnattributedPackets", icmpUnattributedPackets)
        put("icmpUnattributedBytes", icmpUnattributedBytes)
        put("otherProtoEligiblePackets", otherProtoEligiblePackets)
        put("otherProtoEligibleBytes", otherProtoEligibleBytes)
        put("otherProtoAttributedPackets", otherProtoAttributedPackets)
        put("otherProtoAttributedBytes", otherProtoAttributedBytes)
        put("otherProtoUnattributedPackets", otherProtoUnattributedPackets)
        put("otherProtoUnattributedBytes", otherProtoUnattributedBytes)

        put("uploadEligiblePackets", uploadEligiblePackets)
        put("uploadEligibleBytes", uploadEligibleBytes)
        put("uploadAttributedPackets", uploadAttributedPackets)
        put("uploadAttributedBytes", uploadAttributedBytes)
        put("uploadUnattributedPackets", uploadUnattributedPackets)
        put("uploadUnattributedBytes", uploadUnattributedBytes)
        put("downloadEligiblePackets", downloadEligiblePackets)
        put("downloadEligibleBytes", downloadEligibleBytes)
        put("downloadAttributedPackets", downloadAttributedPackets)
        put("downloadAttributedBytes", downloadAttributedBytes)
        put("downloadUnattributedPackets", downloadUnattributedPackets)
        put("downloadUnattributedBytes", downloadUnattributedBytes)

        put("conntrackFallbackAttemptedCount", conntrackFallbackAttemptedCount)
        put("conntrackFallbackSucceededCount", conntrackFallbackSucceededCount)
        put("conntrackFallbackFailedCount", conntrackFallbackFailedCount)
        put("conntrackPermissionDeniedCount", conntrackPermissionDeniedCount)
        put("conntrackBackoffActive", conntrackBackoffActive)
        put("conntrackBackoffRemainingMs", conntrackBackoffRemainingMs)
        put("conntrackBackoffSkippedCount", conntrackBackoffSkippedCount)

        put("activeConnectedClientsCount", activeConnectedClientsCount)
        put("blockedClientsCount", blockedClientsCount)
        put("quotaExhaustedClientsCount", quotaExhaustedClientsCount)
        put("throttledClientsCount", throttledClientsCount)

        put("bpfRefreshOnMissEnabled", bpfRefreshOnMissEnabled)
        put("refreshOnMissCooldownMs", refreshOnMissCooldownMs)
        put("refreshCircuitBreakerState", refreshCircuitBreakerState)
        put("refreshOnMissTriggeredCount", refreshOnMissTriggeredCount)
        put("missRefreshTriggered", refreshOnMissTriggeredCount)
        put("refreshOnMissCoalescedInFlightCount", refreshOnMissCoalescedInFlightCount)
        put("missRefreshCoalesced", refreshOnMissCoalescedInFlightCount)
        put("refreshOnMissSuppressedCooldownCount", refreshOnMissSuppressedCooldownCount)
        put("missRefreshSuppressedCooldown", refreshOnMissSuppressedCooldownCount)
        put("refreshOnMissCompletedCount", refreshOnMissCompletedCount)
        put("missRefreshCompleted", refreshOnMissCompletedCount)
        put("missRefreshFailedCount", missRefreshFailedCount)
        put("missRefreshFailed", missRefreshFailedCount)
        put("missRefreshSuppressedBreakerCount", missRefreshSuppressedBreakerCount)
        put("missRefreshSuppressedBreaker", missRefreshSuppressedBreakerCount)
        put("missRefreshSuppressedIneligibleCount", missRefreshSuppressedIneligibleCount)
        put("missRefreshSuppressedIneligible", missRefreshSuppressedIneligibleCount)
        put("missRefreshQueueOverflowCount", missRefreshQueueOverflowCount)
        put("missRefreshQueueOverflow", missRefreshQueueOverflowCount)
        put("refreshOnMissLastLatencyMs", refreshOnMissLastLatencyMs)
        put("missRefreshLatencyP50Ms", missRefreshLatencyP50Ms)
        put("missRefreshLatencyP95Ms", missRefreshLatencyP95Ms)
        put("missRefreshLatencyP99Ms", missRefreshLatencyP99Ms)
        put("missRefreshLatencyMaxMs", missRefreshLatencyMaxMs)
        put("postRefreshAttributedPackets", postRefreshAttributedPackets)
        put("postRefreshAttributedBytes", postRefreshAttributedBytes)
        put("postRefreshFlowKeysResolved", postRefreshFlowKeysResolved)
        put("postRefreshFirstSubsequentAttributedPackets", postRefreshFirstSubsequentAttributedPackets)
        put("postRefreshFirstSubsequentAttributedBytes", postRefreshFirstSubsequentAttributedBytes)
        put("refreshOnMissAutoDisabled", refreshOnMissAutoDisabled)
        put("refreshOnMissAutoDisableReason", refreshOnMissAutoDisableReason)

        // Phase C fields
        put("deepTupleDiagnosticsEnabled", deepTupleDiagnosticsEnabled)
        put("unknownOwnerPacketPolicy", unknownOwnerPacketPolicy)
        put("activeTrackedFlowsCount", activeTrackedFlowsCount)
        put("newMissFlowsCount", newMissFlowsCount)
        put("repeatedMissFlowsCount", repeatedMissFlowsCount)
        put("persistentAfterRefreshFlowsCount", persistentAfterRefreshFlowsCount)
        put("resolvedAfterRefreshFlowsCount", resolvedAfterRefreshFlowsCount)
        put("keyMismatchSuspectedFlowsCount", keyMismatchSuspectedFlowsCount)
        put("notOffloadedOrNotObservableFlowsCount", notOffloadedOrNotObservableFlowsCount)
        put("expiredFlowsCount", expiredFlowsCount)
        put("evictedFlowsCount", evictedFlowsCount)
        put("survived0SnapshotsCount", survived0SnapshotsCount)
        put("survived1SnapshotCount", survived1SnapshotCount)
        put("survived2SnapshotsCount", survived2SnapshotsCount)
        put("survived3PlusSnapshotsCount", survived3PlusSnapshotsCount)
        put("udp443MissingFlowsCount", udp443MissingFlowsCount)
        put("udp443MissingPacketsCount", udp443MissingPacketsCount)
        put("udp443MissingBytesCount", udp443MissingBytesCount)
        put("udp443ResolvedAfterRefreshFlowsCount", udp443ResolvedAfterRefreshFlowsCount)
        put("udp53MissingFlowsCount", udp53MissingFlowsCount)
        put("udp53MissingPacketsCount", udp53MissingPacketsCount)
        put("udp53MissingBytesCount", udp53MissingBytesCount)
        put("udp53ResolvedAfterRefreshFlowsCount", udp53ResolvedAfterRefreshFlowsCount)
        put("tcpMissingFlowsCount", tcpMissingFlowsCount)
        put("udpOtherMissingFlowsCount", udpOtherMissingFlowsCount)

        val sampleArr = JSONArray()
        tupleDiagnosticSampleRecords
            .take(DeepTupleDiagnosticsTracker.DEFAULT_MAX_SAMPLE_RECORDS)
            .forEach { sample ->
                sampleArr.put(sample.toJson(includeSensitiveEndpoints))
            }
        put("tupleDiagnosticSampleRecords", sampleArr)

        val verifiedClientsArr = JSONArray()
        perClientVerifiedSummaries.forEachIndexed { idx, summary ->
            val macLabel = when {
                includeSensitiveEndpoints -> summary.mac
                includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(summary.mac)
                else -> "Client-${idx + 1}"
            }
            val ipLabel = when {
                includeSensitiveEndpoints -> summary.originalIpv4
                includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(summary.originalIpv4)
                else -> "redacted"
            }
            verifiedClientsArr.put(
                JSONObject().apply {
                    put("mac", macLabel)
                    put("originalIpv4", ipLabel)
                    put("activeFlows", summary.activeFlows)
                    put("verifiedUploadPackets", summary.verifiedUploadPackets)
                    put("verifiedUploadBytes", summary.verifiedUploadBytes)
                    put("verifiedDownloadPackets", summary.verifiedDownloadPackets)
                    put("verifiedDownloadBytes", summary.verifiedDownloadBytes)
                    put("directIpPackets", summary.directIpPackets)
                    put("bpfNatPackets", summary.bpfNatPackets)
                    put("conntrackPackets", summary.conntrackPackets)
                    put("blockedDropPackets", summary.blockedDropPackets)
                    put("blockedDropBytes", summary.blockedDropBytes)
                    put("isBlocked", summary.isBlocked)
                    put("isQuotaExhausted", summary.isQuotaExhausted)
                    put("isThrottled", summary.isThrottled)
                },
            )
        }
        put("perClientVerifiedSummaries", verifiedClientsArr)

        // Phase D Schema v3 fields
        put("phaseDMode", phaseD.phaseDMode.name)
        put("evidenceConfidence", phaseD.evidenceConfidence.name)
        put("interfaceLifecycleState", phaseD.interfaceLifecycleState.name)
        put("lastPolicyActivatedEpochMs", phaseD.lastPolicyActivatedEpochMs)

        val transitionArr = JSONArray()
        phaseD.policyTransitionEvents.forEach { ev ->
            transitionArr.put(ev.toJson(includeSensitiveEndpoints, includePseudonymousIds))
        }
        put("policyTransitionEvents", transitionArr)

        val postTransVerifiedArr = JSONArray()
        phaseD.postTransitionVerifiedClientTraffic.forEachIndexed { idx, item ->
            postTransVerifiedArr.put(item.toJson(idx, includeSensitiveEndpoints, includePseudonymousIds))
        }
        put("postTransitionVerifiedClientTraffic", postTransVerifiedArr)

        val postTransUnknownObj = JSONObject().apply {
            put("unknownForwardedAfterBlockPackets", phaseD.unknownForwardedAfterBlockPackets)
            put("unknownForwardedAfterBlockBytes", phaseD.unknownForwardedAfterBlockBytes)
            val protoDirPkts = JSONObject()
            for ((k, v) in phaseD.unknownPostBlockByProtocolAndDirection) {
                protoDirPkts.put(k, v)
            }
            put("unknownPostBlockByProtocolAndDirection", protoDirPkts)
            val protoDirBytes = JSONObject()
            for ((k, v) in phaseD.unknownPostBlockBytesByProtocolAndDirection) {
                protoDirBytes.put(k, v)
            }
            put("unknownPostBlockBytesByProtocolAndDirection", protoDirBytes)
        }
        put("postTransitionUnknownTraffic", postTransUnknownObj)
        put("unknownForwardedAfterBlockPackets", phaseD.unknownForwardedAfterBlockPackets)
        put("unknownForwardedAfterBlockBytes", phaseD.unknownForwardedAfterBlockBytes)

        val existingFlowCacheObj = JSONObject().apply {
            put("verifiedFlowsAtTransitionTotal", phaseD.verifiedFlowsAtTransitionTotal)
            put("staleAllowCacheHitsPreventedTotal", phaseD.staleAllowCacheHitsPreventedTotal)
            put("decisionsRecomputedTotal", phaseD.decisionsRecomputedTotal)
            put("verifiedAllowedAfterBlockPacketsTotal", phaseD.verifiedAllowedAfterBlockPacketsTotal)
            put("verifiedAllowedAfterBlockBytesTotal", phaseD.verifiedAllowedAfterBlockBytesTotal)
            put("verifiedDroppedAfterBlockPacketsTotal", phaseD.verifiedDroppedAfterBlockPacketsTotal)
            put("verifiedDroppedAfterBlockBytesTotal", phaseD.verifiedDroppedAfterBlockBytesTotal)
            put("activePinnedVerifiedFlowsCount", phaseD.activePinnedVerifiedFlowsCount)
            put("pinnedFlowHitsInDiagnosticMode", phaseD.pinnedFlowHitsInDiagnosticMode)
            put("pinnedFlowEnforcedDropsInEnforcementMode", phaseD.pinnedFlowEnforcedDropsInEnforcementMode)
            put("queuedPacketsPurgedOnTransitionTotal", phaseD.queuedPacketsPurgedOnTransitionTotal)
        }
        put("existingFlowCacheDiagnostics", existingFlowCacheObj)
        put("verifiedFlowsAtTransition", phaseD.verifiedFlowsAtTransitionTotal)
        put("staleAllowCacheHitsPrevented", phaseD.staleAllowCacheHitsPreventedTotal)
        put("decisionsRecomputed", phaseD.decisionsRecomputedTotal)
        put("verifiedAllowedAfterBlockPackets", phaseD.verifiedAllowedAfterBlockPacketsTotal)
        put("verifiedAllowedAfterBlockBytes", phaseD.verifiedAllowedAfterBlockBytesTotal)
        put("verifiedDroppedAfterBlockPackets", phaseD.verifiedDroppedAfterBlockPacketsTotal)
        put("verifiedDroppedAfterBlockBytes", phaseD.verifiedDroppedAfterBlockBytesTotal)

        val tcpLongLivedObj = JSONObject().apply {
            put("establishedTcpMissingFromBpfPackets", phaseD.establishedTcpMissingFromBpfPackets)
            put("establishedTcpMissingFromBpfBytes", phaseD.establishedTcpMissingFromBpfBytes)
            put("establishedTcpPinnedMatchedPackets", phaseD.establishedTcpPinnedMatchedPackets)
            put("establishedTcpPinnedMatchedBytes", phaseD.establishedTcpPinnedMatchedBytes)
            put("tcpKeepaliveOrAckOnlyPackets", phaseD.tcpKeepaliveOrAckOnlyPackets)
            put("tcpSynPacketsSeen", phaseD.tcpSynPacketsSeen)
            put("tcpFinOrRstPacketsSeen", phaseD.tcpFinOrRstPacketsSeen)
            put("udp443PostBlockUnattributedPackets", phaseD.udp443PostBlockUnattributedPackets)
            put("udp443PostBlockUnattributedBytes", phaseD.udp443PostBlockUnattributedBytes)
            put("udp53PostBlockUnattributedPackets", phaseD.udp53PostBlockUnattributedPackets)
            put("udp53PostBlockUnattributedBytes", phaseD.udp53PostBlockUnattributedBytes)
        }
        put("tcpLongLivedDiagnostics", tcpLongLivedObj)

        val ifaceEventsArr = JSONArray()
        phaseD.interfaceLifecycleEvents.forEach { ev ->
            ifaceEventsArr.put(ev.toJson())
        }
        put("interfaceLifecycleEvents", ifaceEventsArr)

        val markersArr = JSONArray()
        phaseD.deliveryTestMarkers.forEach { m ->
            markersArr.put(m.toJson(includeSensitiveEndpoints))
        }
        put("deliveryTestMarkers", markersArr)

        put("redactedExportRecordsCount", DiagnosticRedactor.redactedExportRecordsCount.get())

        put("ambiguousOrStaleLookups", ambiguousOrStaleLookups)
        put("localControlPackets", localControlPackets)
        put("localControlBytes", localControlBytes)
        put("unsupportedOrFragmentPackets", unsupportedOrFragmentPackets)
        put("blockedDropPackets", blockedDropPackets)
        put("blockedDropBytes", blockedDropBytes)
        put("shapingDropPackets", shapingDropPackets)
        put("shapedPackets", shapedPackets)
        put("rejectedOldGenerationCount", rejectedOldGenerationCount)
        put("tupleReuseGuardTriggeredCount", tupleReuseGuardTriggeredCount)

        val clientsArr = JSONArray()
        perClientCounts.forEachIndexed { index, c ->
            val macLabel = when {
                includeSensitiveEndpoints -> c.mac
                includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(c.mac)
                else -> "Client-${index + 1}"
            }
            val ipLabel = when {
                includeSensitiveEndpoints -> c.originalIpv4
                includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(c.originalIpv4)
                else -> "redacted"
            }
            clientsArr.put(
                JSONObject().apply {
                    put("mac", macLabel)
                    put("originalIpv4", ipLabel)
                    put("tcpFlows", c.tcpFlows)
                    put("udpFlows", c.udpFlows)
                    put("totalFlows", c.totalFlows)
                },
            )
        }
        put("perClientCounts", clientsArr)

        // Schema v6 (`v0.10.8-debug`) Exclusive Blocking Mode, SoftAP MAC Blocklist & Domain Filtering objects
        val preNatJson = preNatDiagnostics.toJson(includeSensitiveEndpoints)
        put("preNatDiagnostics", preNatJson)
        put("capability", preNatJson.optJSONObject("capability") ?: JSONObject())
        put("activation", preNatJson.optJSONObject("activation") ?: JSONObject())
        put("clientValidation", preNatJson.optJSONObject("clientValidation") ?: JSONObject())
        put("testMatrix", preNatJson.optJSONArray("testMatrix") ?: JSONArray())
        put("softApDiagnostics", softApDiagnostics.toJson(includeSensitiveEndpoints, includePseudonymousIds))
        put("domainDiagnostics", domainDiagnostics.toJson())
        put("vpnRecoveryDiagnostics", vpnRecoveryDiagnostics.toJson())
    }

    fun toMarkdownReport(
        apkVersion: String = BuildConfig.VERSION_NAME,
        sourceCommit: String = BuildConfig.SOURCE_COMMIT,
        serviceBuildId: Int = BuildConfig.SERVICE_BUILD_ID,
        includeSensitiveEndpoints: Boolean = false,
        includePseudonymousIds: Boolean = false,
    ): String = buildString {
        if (!includeSensitiveEndpoints) {
            DiagnosticRedactor.redactedExportRecordsCount.incrementAndGet()
        }
        val safeCollectionError = if (includeSensitiveEndpoints) {
            collectionError
        } else {
            BpfDumpParser.maskSensitiveLinePreview(collectionError)
        }
        val safeDownErr = if (includeSensitiveEndpoints) {
            downstreamIfIndexError
        } else {
            BpfDumpParser.maskSensitiveLinePreview(downstreamIfIndexError)
        }
        val safeUpErr = if (includeSensitiveEndpoints) {
            upstreamIfIndexError
        } else {
            BpfDumpParser.maskSensitiveLinePreview(upstreamIfIndexError)
        }
        val safeAttemptDecision = if (includeSensitiveEndpoints) {
            lastAttemptDecisionReason
        } else {
            BpfDumpParser.maskSensitiveLinePreview(lastAttemptDecisionReason)
        }
        val safeAttemptError = if (includeSensitiveEndpoints) {
            lastAttemptError
        } else {
            BpfDumpParser.maskSensitiveLinePreview(lastAttemptError)
        }

        appendLine("# Shizzy Luna v0.10.9-debug — Per-Host Domain Enforcement, VPN Loss Recovery, Blocking Modes & BPF Attribution Report")
        appendLine()
        appendLine("## 1. Build & Session Metadata")
        appendLine("- **APK Version**: `$apkVersion` (serviceBuildId `$serviceBuildId`, schemaVersion `7`, featureVersion `0.10.9-debug`)")
        appendLine("- **Base Commit**: `$sourceCommit`")
        appendLine("- **Blocking Mode (Exclusive)**: requested=`${preNatDiagnostics.requestedMode.name}`, effective=`${preNatDiagnostics.effectiveModeNullable?.name ?: "NONE"}`, runtimeState=`${preNatDiagnostics.runtimeState.name}`, softApState=`${softApDiagnostics.engineState.code}`, exclusiveEngineInvariant=`${preNatDiagnostics.exclusiveEngineInvariant && softApDiagnostics.exclusiveEngineInvariant}`")
        appendLine("- **Domain Filtering Status**: `${domainDiagnostics.capabilityStatus}` (globalRules=`${domainDiagnostics.enabledGlobalRuleCount}/${domainDiagnostics.globalRuleCount}`, perClientRules=`${domainDiagnostics.enabledPerClientRuleCount}/${domainDiagnostics.perClientRuleCount}`, dnsBlockedGlobal=`${domainDiagnostics.dnsQueriesBlockedGlobal}`, dnsBlockedPerClient=`${domainDiagnostics.dnsQueriesBlockedPerClient}`, unknownOwnerSkips=`${domainDiagnostics.unknownOwnerClientRuleSkips}`, dnsRetryEnabled=`${domainDiagnostics.dnsAttributionRetryEnabled}`)")
        appendLine("- **VPN Recovery Status**: state=`${vpnRecoveryDiagnostics.vpnLifecycleState.name}`, stopHotspotOnDisconnect=`${vpnRecoveryDiagnostics.stopHotspotOnVpnDisconnect}`, failClosedGate=`${vpnRecoveryDiagnostics.vpnForwardingGateClosed}`, outages=`${vpnRecoveryDiagnostics.vpnOutageCount}`, recoveries=`${vpnRecoveryDiagnostics.vpnRecoveryCount}`")
        appendLine("- **Legacy Pre-NAT Retirement Status**: **${preNatDiagnostics.goNoGoVerdict}**")
        appendLine("- **Phase D Mode**: `${phaseD.phaseDMode.name}` (evidenceConfidence `${phaseD.evidenceConfidence.name}`, interfaceLifecycle `${phaseD.interfaceLifecycleState.name}`)")
        appendLine("- **Experimental BPF Enabled**: `$experimentalEnabled`")
        appendLine("- **Phase B Refresh-on-Miss Enabled**: `$bpfRefreshOnMissEnabled` (cooldown `${refreshOnMissCooldownMs}ms`, breaker `$refreshCircuitBreakerState`)")
        appendLine("- **Phase C Deep Tuple Diagnostics Enabled**: `$deepTupleDiagnosticsEnabled`")
        appendLine("- **Unknown-Owner Packet Policy**: `$unknownOwnerPacketPolicy` (`PARTIAL_ENFORCEMENT`)")
        appendLine("- **Feature State / Snapshot Health**: `${state.name}` / `${snapshotHealth.name}`")
        appendLine("- **Published Snapshot Status**: `${collectionStatus.name}` (seq `$snapshotSequence`, ${lastCollectionDurationMs}ms, age ${snapshotAgeMs}ms, poll ${pollIntervalMs}ms, lastRefreshEpochMs `$lastSuccessfulRefreshEpochMs`)")
        appendLine("- **Collection Counters**: attempted=`$totalCollectionsAttempted`, succeeded=`$totalCollectionsSucceeded`, failed=`$totalCollectionsFailed`")
        if (safeCollectionError.isNotBlank()) {
            appendLine("- **Published Snapshot Error**: `$safeCollectionError`")
        }
        appendLine("- **Parser Version**: `$parserVersion`")
        appendLine("- **Session / Binding Generation**: `session=$sessionGeneration`, `binding=$bindingGeneration`")
        appendLine(
            "- **Downstream Interface**: `${downstreamIface.ifBlank { "unknown" }}` " +
                "(inferred ifindex `${inferredDownstreamIfIndex ?: "unavailable"}`, " +
                "OS ifindex `${osDownstreamIfIndex ?: "unavailable"}` [$downstreamIfIndexSource]" +
                (if (safeDownErr.isNotBlank()) " — `$safeDownErr`" else "") + ")",
        )
        appendLine(
            "- **Upstream Interface**: `${upstreamIface.ifBlank { "unknown" }}` " +
                "(inferred ifindex `${inferredUpstreamIfIndex ?: "unavailable"}`, " +
                "OS ifindex `${osUpstreamIfIndex ?: "unavailable"}` [$upstreamIfIndexSource]" +
                (if (safeUpErr.isNotBlank()) " — `$safeUpErr`" else "") + ")",
        )
        appendLine("- **Active Client Policy Summary**: connected=`$activeConnectedClientsCount`, blocked=`$blockedClientsCount`, quotaExhausted=`$quotaExhaustedClientsCount`, throttled=`$throttledClientsCount`")
        appendLine()
        appendLine("## 2. Global Attribution Summary")
        appendLine("- **Total Eligible Packets / Bytes**: `$totalEligiblePackets` pkts / `$totalEligibleBytes` B")
        appendLine("- **Total Attributed Packets / Bytes**: `$totalAttributedPackets` pkts (${formattedPacketCoverage()}) / `$totalAttributedBytes` B (${formattedByteCoverage()})")
        appendLine("- **Directly Attributed (`DIRECT_IP`)**: `$directAttributedPackets` pkts / `$directAttributedBytes` B")
        appendLine("- **BPF NAT Mapped (`BPF_NAT`)**: `$bpfAttributedPackets` pkts / `$bpfAttributedBytes` B")
        appendLine("- **Conntrack Fallback (`CONNTRACK_PROCFS`)**: `$conntrackAttributedPackets` pkts / `$conntrackAttributedBytes` B (attempted=`$conntrackFallbackAttemptedCount`, succeeded=`$conntrackFallbackSucceededCount`, failed=`$conntrackFallbackFailedCount`, permDenied=`$conntrackPermissionDeniedCount`, backoffActive=`$conntrackBackoffActive` [${conntrackBackoffRemainingMs}ms], skippedByBackoff=`$conntrackBackoffSkippedCount`)")
        appendLine("- **Unattributed Forwarded (`matchedMac == null => ALLOW`)**: `$unknownForwardedPackets` pkts / `$unknownForwardedBytes` B")
        appendLine("- **Local Control Traffic Excluded from Denominator (IPv6 RS/RA/NS/NA/MLD)**: `$localControlPackets` pkts / `$localControlBytes` B")
        appendLine("- **Policy-Block Dropped Packets / Bytes (`VERIFIED` owner only)**: `$blockedDropPackets` pkts / `$blockedDropBytes` B")
        appendLine()
        appendLine("### Protocol, IP Family & Direction Breakdown")
        appendLine("| Dimension | Eligible Pkts / Bytes | Attributed Pkts / Bytes | Unattributed Pkts / Bytes |")
        appendLine("| --- | ---: | ---: | ---: |")
        appendLine("| **IPv4** | $ipv4EligiblePackets / $ipv4EligibleBytes B | $ipv4AttributedPackets / $ipv4AttributedBytes B | $ipv4UnattributedPackets / $ipv4UnattributedBytes B |")
        appendLine("| **IPv6** | $ipv6EligiblePackets / $ipv6EligibleBytes B | $ipv6AttributedPackets / $ipv6AttributedBytes B | $ipv6UnattributedPackets / $ipv6UnattributedBytes B |")
        appendLine("| **TCP** | $tcpEligiblePackets / $tcpEligibleBytes B | $tcpAttributedPackets / $tcpAttributedBytes B | $tcpUnattributedPackets / $tcpUnattributedBytes B |")
        appendLine("| **UDP** | $udpEligiblePackets / $udpEligibleBytes B | $udpAttributedPackets / $udpAttributedBytes B | $udpUnattributedPackets / $udpUnattributedBytes B |")
        appendLine("| **ICMP** | $icmpEligiblePackets / $icmpEligibleBytes B | $icmpAttributedPackets / $icmpAttributedBytes B | $icmpUnattributedPackets / $icmpUnattributedBytes B |")
        appendLine("| **Other** | $otherProtoEligiblePackets / $otherProtoEligibleBytes B | $otherProtoAttributedPackets / $otherProtoAttributedBytes B | $otherProtoUnattributedPackets / $otherProtoUnattributedBytes B |")
        appendLine("| **Upload** | $uploadEligiblePackets / $uploadEligibleBytes B | $uploadAttributedPackets / $uploadAttributedBytes B | $uploadUnattributedPackets / $uploadUnattributedBytes B |")
        appendLine("| **Download** | $downloadEligiblePackets / $downloadEligibleBytes B | $downloadAttributedPackets / $downloadAttributedBytes B | $downloadUnattributedPackets / $downloadUnattributedBytes B |")
        appendLine()
        appendLine("## 3. Unattributed Traffic by Structured Reason")
        appendLine("| Failure Reason | Packets | Bytes |")
        appendLine("| --- | ---: | ---: |")
        UnattributedReason.entries.forEach { r ->
            val pkts = unattributedPacketsByReason[r.name] ?: 0L
            val bytes = unattributedBytesByReason[r.name] ?: 0L
            if (pkts > 0L || bytes > 0L || r == UnattributedReason.TUPLE_NOT_PRESENT || r == UnattributedReason.SNAPSHOT_STALE || r == UnattributedReason.NO_ACTIVE_SNAPSHOT) {
                appendLine("| `${r.name}` | $pkts | $bytes |")
            }
        }
        appendLine()
        appendLine("## 4. Phase B: Refresh-on-Miss Telemetry")
        appendLine("- **Refresh-on-Miss Enabled**: `$bpfRefreshOnMissEnabled` (cooldown `${refreshOnMissCooldownMs}ms`)")
        appendLine("- **Circuit Breaker State**: `$refreshCircuitBreakerState` (autoDisabled=`$refreshOnMissAutoDisabled`" + (if (refreshOnMissAutoDisableReason.isNotBlank()) " — `$refreshOnMissAutoDisableReason`" else "") + ")")
        appendLine("- **Miss-Triggered Refreshes**: triggered=`$refreshOnMissTriggeredCount`, completed=`$refreshOnMissCompletedCount`, failed=`$missRefreshFailedCount`, coalescedInFlight=`$refreshOnMissCoalescedInFlightCount`, suppressedCooldown=`$refreshOnMissSuppressedCooldownCount`, suppressedBreaker=`$missRefreshSuppressedBreakerCount`, suppressedIneligible=`$missRefreshSuppressedIneligibleCount`, queueOverflow=`$missRefreshQueueOverflowCount`")
        appendLine("- **Refresh Latency (ms)**: last=`${refreshOnMissLastLatencyMs}ms`, p50=`${missRefreshLatencyP50Ms}ms`, p95=`${missRefreshLatencyP95Ms}ms`, p99=`${missRefreshLatencyP99Ms}ms`, max=`${missRefreshLatencyMaxMs}ms`")
        appendLine("- **Post-Refresh Flow Keys Resolved**: `$postRefreshFlowKeysResolved`")
        appendLine("- **Post-Refresh First-Subsequent Attributed Traffic**: `$postRefreshFirstSubsequentAttributedPackets` pkts / `$postRefreshFirstSubsequentAttributedBytes` B")
        appendLine("- **Post-Refresh Window Attributed Traffic**: `$postRefreshAttributedPackets` pkts / `$postRefreshAttributedBytes` B")
        if (snapshotPublishRejectedByReason.isNotEmpty()) {
            val pubRejSummary = snapshotPublishRejectedByReason.entries.joinToString(", ") { "`${it.key}`=${it.value}" }
            appendLine("- **Snapshot Publish Rejections by Reason**: $pubRejSummary")
        }
        appendLine()
        appendLine("## 5. Phase C: Deep Tuple & Survival Diagnostics")
        appendLine("- **Deep Tuple Diagnostics Enabled**: `$deepTupleDiagnosticsEnabled` (activeTrackedFlows=`$activeTrackedFlowsCount`)")
        appendLine("- **Per-Flow Miss State Counts**: `NEW_MISS`=`$newMissFlowsCount`, `REPEATED_MISS`=`$repeatedMissFlowsCount`, `PERSISTENT_AFTER_REFRESH`=`$persistentAfterRefreshFlowsCount`, `RESOLVED_AFTER_REFRESH`=`$resolvedAfterRefreshFlowsCount`, `KEY_MISMATCH_SUSPECTED`=`$keyMismatchSuspectedFlowsCount`, `NOT_OFFLOADED_OR_NOT_OBSERVABLE`=`$notOffloadedOrNotObservableFlowsCount`, `EXPIRED`=`$expiredFlowsCount`, `EVICTED`=`$evictedFlowsCount`")
        appendLine("- **Snapshot Survival Histogram (Active Tracked Flows)**: `0 snapshots`=`$survived0SnapshotsCount`, `1 snapshot`=`$survived1SnapshotCount`, `2 snapshots`=`$survived2SnapshotsCount`, `3+ snapshots`=`$survived3PlusSnapshotsCount`")
        appendLine("- **UDP/443 (QUIC-capable) Misses**: missingFlows=`$udp443MissingFlowsCount` (`$udp443MissingPacketsCount` pkts / `$udp443MissingBytesCount` B), resolvedAfterRefresh=`$udp443ResolvedAfterRefreshFlowsCount`")
        appendLine("- **UDP/53 (DNS) Misses**: missingFlows=`$udp53MissingFlowsCount` (`$udp53MissingPacketsCount` pkts / `$udp53MissingBytesCount` B), resolvedAfterRefresh=`$udp53ResolvedAfterRefreshFlowsCount`")
        appendLine("- **Other Protocol Miss Flows**: TCP=`$tcpMissingFlowsCount`, UDP(other)=`$udpOtherMissingFlowsCount`")
        if (tupleDiagnosticSampleRecords.isNotEmpty()) {
            appendLine()
            appendLine("### Tuple Diagnostic Sample Ring Buffer (showing up to 10 of ${tupleDiagnosticSampleRecords.size})")
            appendLine("| Flow Hash | Proto | Dir (Conf) | Role Origin | Reason | State | Survived | Pkts / Bytes | Owner | Decision |")
            appendLine("| --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |")
            tupleDiagnosticSampleRecords.takeLast(10).forEach { s ->
                appendLine(
                    "| `${s.flowHash}` | `${s.ipFamily}/${s.protocol}` | `${s.direction}` (`${s.directionConfidence}`) | `${s.tupleRoleOrigin}` | `${s.missReason}` | `${s.flowMissState}` | ${s.snapshotsSurvived} | ${s.packetsSeenOnFlow} / ${s.bytesSeenOnFlow} B | `${s.ownerConfidence}` | `${s.decision}` |",
                )
            }
        }
        appendLine()
        appendLine("## 6. Multi-Client Verified Traffic Summary")
        appendLine("- **Unattributed (`UNKNOWN_OWNER`) Forwarded Traffic (Excluded from all client rows)**: `$unknownForwardedPackets` pkts / `$unknownForwardedBytes` B")
        if (perClientVerifiedSummaries.isEmpty() && perClientCounts.isEmpty()) {
            appendLine("_No verified client traffic or mapped flows in current session._")
        } else if (perClientVerifiedSummaries.isNotEmpty()) {
            appendLine("| Client | IPv4 | Active Flows | Verified Up (Pkts/B) | Verified Down (Pkts/B) | Direct / BPF / Conntrack Pkts | Policy Drops (Pkts/B) | Policy Flags |")
            appendLine("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |")
            perClientVerifiedSummaries.forEachIndexed { idx, s ->
                val macLabel = when {
                    includeSensitiveEndpoints -> s.mac
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(s.mac)
                    else -> "Client-${idx + 1}"
                }
                val ipLabel = when {
                    includeSensitiveEndpoints -> s.originalIpv4
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(s.originalIpv4)
                    else -> "redacted"
                }
                val flags = buildList {
                    if (s.isBlocked) add("BLOCKED")
                    if (s.isQuotaExhausted) add("QUOTA_EXHAUSTED")
                    if (s.isThrottled) add("THROTTLED")
                }.ifEmpty { listOf("ALLOW") }.joinToString(",")
                appendLine(
                    "| `$macLabel` | `$ipLabel` | ${s.activeFlows} | ${s.verifiedUploadPackets} / ${s.verifiedUploadBytes} B | ${s.verifiedDownloadPackets} / ${s.verifiedDownloadBytes} B | ${s.directIpPackets} / ${s.bpfNatPackets} / ${s.conntrackPackets} | ${s.blockedDropPackets} / ${s.blockedDropBytes} B | `$flags` |",
                )
            }
        } else {
            appendLine("| Client | Original IPv4 | TCP Upstream | UDP Upstream | Total |")
            appendLine("| --- | --- | ---: | ---: | ---: |")
            perClientCounts.forEachIndexed { idx, c ->
                val macLabel = when {
                    includeSensitiveEndpoints -> c.mac
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(c.mac)
                    else -> "Client-${idx + 1}"
                }
                val ipLabel = when {
                    includeSensitiveEndpoints -> c.originalIpv4
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(c.originalIpv4)
                    else -> "redacted"
                }
                appendLine("| `$macLabel` | `$ipLabel` | ${c.tcpFlows} | ${c.udpFlows} | ${c.totalFlows} |")
            }
        }
        appendLine()
        appendLine("## 7. Phase D: Persistent Connection Leak Investigation & Experimental Enforcement")
        appendLine("- **Phase D Operating Mode**: `${phaseD.phaseDMode.name}`")
        appendLine("- **Evidence Confidence**: `${phaseD.evidenceConfidence.name}`")
        appendLine("- **Interface Lifecycle State**: `${phaseD.interfaceLifecycleState.name}`")
        appendLine("- **Existing-Flow & Cache Audit (D2)**: verifiedFlowsAtTransition=`${phaseD.verifiedFlowsAtTransitionTotal}`, decisionsRecomputed=`${phaseD.decisionsRecomputedTotal}`, staleAllowCacheHitsPrevented=`${phaseD.staleAllowCacheHitsPreventedTotal}`, queuedPacketsPurgedOnTransition=`${phaseD.queuedPacketsPurgedOnTransitionTotal}`, activePinnedVerifiedFlows=`${phaseD.activePinnedVerifiedFlowsCount}`, pinnedHitsDiagnostic=`${phaseD.pinnedFlowHitsInDiagnosticMode}`, pinnedEnforcedDrops=`${phaseD.pinnedFlowEnforcedDropsInEnforcementMode}`")
        appendLine("- **Post-Transition Verified Client Traffic (D2)**: verifiedDroppedAfterBlock=`${phaseD.verifiedDroppedAfterBlockPacketsTotal}` pkts / `${phaseD.verifiedDroppedAfterBlockBytesTotal}` B, verifiedAllowedAfterBlock=`${phaseD.verifiedAllowedAfterBlockPacketsTotal}` pkts / `${phaseD.verifiedAllowedAfterBlockBytesTotal}` B (target: `0`)")
        appendLine("- **Post-Transition Unknown Traffic (D3, Global — Never Assigned to Any Client)**: unknownForwardedAfterBlock=`${phaseD.unknownForwardedAfterBlockPackets}` pkts / `${phaseD.unknownForwardedAfterBlockBytes}` B (`UNPROVEN_OWNER` => `ALLOW`)")
        if (phaseD.unknownPostBlockByProtocolAndDirection.isNotEmpty()) {
            val protoSummary = phaseD.unknownPostBlockByProtocolAndDirection.entries
                .filter { it.value > 0L }
                .joinToString(", ") { (k, pkts) ->
                    val b = phaseD.unknownPostBlockBytesByProtocolAndDirection[k] ?: 0L
                    "`$k`=${pkts}p (${b}B)"
                }
            if (protoSummary.isNotBlank()) {
                appendLine("- **Post-Block Unknown Breakdown by Protocol & Direction**: $protoSummary")
            }
        }
        appendLine("- **Long-Lived TCP & Protocol Path Audit (D4)**: establishedTcpMissingFromBpf=`${phaseD.establishedTcpMissingFromBpfPackets}` pkts / `${phaseD.establishedTcpMissingFromBpfBytes}` B, establishedTcpPinnedMatched=`${phaseD.establishedTcpPinnedMatchedPackets}` pkts / `${phaseD.establishedTcpPinnedMatchedBytes}` B, tcpKeepaliveOrAckOnly=`${phaseD.tcpKeepaliveOrAckOnlyPackets}`, tcpSyn=`${phaseD.tcpSynPacketsSeen}`, tcpFinOrRst=`${phaseD.tcpFinOrRstPacketsSeen}`, udp443PostBlockUnattributed=`${phaseD.udp443PostBlockUnattributedPackets}` pkts / `${phaseD.udp443PostBlockUnattributedBytes}` B, udp53PostBlockUnattributed=`${phaseD.udp53PostBlockUnattributedPackets}` pkts / `${phaseD.udp53PostBlockUnattributedBytes}` B")
        if (phaseD.postTransitionVerifiedClientTraffic.isNotEmpty()) {
            appendLine()
            appendLine("### Per-Client Post-Transition Verified Enforcement Summary")
            appendLine("| Client | IPv4 | Policy Gen | Last Transition | Flows @ Trans | Recomputed | Stale Prevented | Verified Allowed After Block | Verified Dropped After Block (Pkts/B) | Pinned Enforced (Pkts/B) |")
            appendLine("| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
            phaseD.postTransitionVerifiedClientTraffic.forEachIndexed { idx, c ->
                val macLabel = when {
                    includeSensitiveEndpoints -> c.mac
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(c.mac)
                    else -> "Client-${idx + 1}"
                }
                val ipLabel = when {
                    c.originalIpv4.isBlank() -> "redacted"
                    includeSensitiveEndpoints -> c.originalIpv4
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeIp(c.originalIpv4)
                    else -> "redacted"
                }
                appendLine(
                    "| `$macLabel` | `$ipLabel` | ${c.policyGeneration} | `${c.lastTransitionType}` | ${c.verifiedFlowsAtTransition} | ${c.decisionsRecomputed} | ${c.staleAllowCacheHitsPrevented} | ${c.verifiedAllowedAfterBlockPackets} / ${c.verifiedAllowedAfterBlockBytes} B | ${c.verifiedDroppedAfterBlockPackets} / ${c.verifiedDroppedAfterBlockBytes} B | ${c.pinnedFlowEnforcedPackets} / ${c.pinnedFlowEnforcedBytes} B |",
                )
            }
        }
        if (phaseD.policyTransitionEvents.isNotEmpty()) {
            appendLine()
            appendLine("### Policy Transition & Generation Audit Log (showing up to 15 of ${phaseD.policyTransitionEvents.size})")
            appendLine("| Seq | Transition | Client | Policy Gen | Session/Bind Gen | Snapshot Seq | Flags | Flows @ Trans | Queued Purged | Detail |")
            appendLine("| ---: | --- | --- | ---: | --- | ---: | --- | ---: | ---: | --- |")
            phaseD.policyTransitionEvents.takeLast(15).forEach { ev ->
                val macLabel = when {
                    ev.clientMac.isBlank() -> "-"
                    includeSensitiveEndpoints -> ev.clientMac
                    includePseudonymousIds -> DiagnosticRedactor.pseudonymizeClient(ev.clientMac)
                    else -> "Client-Redacted"
                }
                val safeDetail = (if (includeSensitiveEndpoints) ev.detail else BpfDumpParser.maskSensitiveLinePreview(ev.detail)).replace("|", "\\|")
                appendLine(
                    "| ${ev.eventSequence} | `${ev.transitionType}` | `$macLabel` | ${ev.policyGeneration} | `${ev.sessionGeneration}/${ev.bindingGeneration}` | ${ev.snapshotSequence} | `${ev.activePolicyFlags}` | ${ev.verifiedFlowsAtTransition} | ${ev.queuedPacketsPurged} | `$safeDetail` |",
                )
            }
        }
        if (phaseD.deliveryTestMarkers.isNotEmpty()) {
            appendLine()
            appendLine("### Delivery Verification Test Markers (D5)")
            appendLine("| Marker Seq | Type | Epoch (ms) | Mode | Session Gen | Snapshot Seq | Blocked / Quota | Note |")
            appendLine("| ---: | --- | ---: | --- | ---: | ---: | --- | --- |")
            phaseD.deliveryTestMarkers.takeLast(10).forEach { m ->
                val safeNote = (if (includeSensitiveEndpoints) m.note else BpfDumpParser.maskSensitiveLinePreview(m.note)).replace("|", "\\|")
                appendLine(
                    "| ${m.markerSequence} | `${m.markerType}` | ${m.timestampEpochMs} | `${m.phaseDMode}` | ${m.sessionGeneration} | ${m.snapshotSequence} | `${m.blockedClientsCount}/${m.quotaExhaustedClientsCount}` | `$safeNote` |",
                )
            }
        }
        appendLine()
        appendLine("### Phase D Three-Part Result Summary")
        val verifiedCorrectness = if (phaseD.verifiedAllowedAfterBlockPacketsTotal == 0L) {
            "PASS (`verifiedAllowedAfterBlockPackets = 0`, `verifiedDroppedAfterBlockPackets = ${phaseD.verifiedDroppedAfterBlockPacketsTotal}`)"
        } else {
            "WARN (`verifiedAllowedAfterBlockPackets = ${phaseD.verifiedAllowedAfterBlockPacketsTotal}`)"
        }
        appendLine("1. **Verified-Flow Policy Correctness**: $verifiedCorrectness")
        appendLine("2. **Multi-Client Isolation**: `UNKNOWN_OWNER => ALLOW` preserved in `${phaseD.phaseDMode.name}` mode; unattributed traffic is never assigned to or dropped against any connected client.")
        appendLine("3. **Independently Confirmed Post-Block Application Delivery**: Host counters alone never claim end-to-end messaging block unless independently confirmed on the receiving device between `TEST_SESSION_START` / `POLICY_ACTIVATED` and `TEST_SESSION_STOP` markers.")
        appendLine()
        appendLine("## 8. Snapshot & Parser Health")
        appendLine("- **Snapshot Sequence**: `$snapshotSequence`")
        appendLine("- **IPv4 Upstream / Downstream Entries (Published)**: `$totalUpstreamEntries` / `$totalDownstreamEntries`")
        appendLine("- **Flow Age Distribution (Published)**: knownNonNegative=`$knownAgeEntries`, unavailable(`-`)=`$unavailableAgeEntries`, negativeDelta=`$negativeDeltaAgeEntries`")
        appendLine("- **Reverse-Confirmed / Active Validated Flows**: `$reverseMatchedCount` / `$activeMappedFlows`")
        appendLine("- **Ambiguous Tuples / Unverified Owners / ifindex Mismatches**: `$ambiguousTupleCount` / `$unverifiedOwnerEntries` / `$ifIndexMismatchCount`")
        appendLine("- **Rejected Parse Lines (Published Snapshot)**: `$rejectedLineCount` (coverageIncomplete=`$coverageIncomplete`)")
        appendLine("- **Last Attempt Status**: `${lastAttemptStatus.name}` (duration ${lastAttemptDurationMs}ms, age ${lastAttemptAgeMs}ms, published=`$lastAttemptSnapshotPublished`, recognizedFormat=`$lastAttemptRecognizedFormat`)")
        if (safeAttemptDecision.isNotBlank()) {
            appendLine("- **Publication Decision**: `$safeAttemptDecision`")
        }
        if (safeAttemptError.isNotBlank()) {
            appendLine("- **Last Attempt Error**: `$safeAttemptError`")
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
        appendLine("## 9. Explicit Limitations & Enforcement Status")
        appendLine("- **Enforcement Status**: `PARTIAL_ENFORCEMENT: unknown-owner NAT traffic is forwarded (ALLOW) and cannot be blocked without synchronous pre-NAT identity or kernel-level packet marking.`")
        appendLine("- **First-packet & unoffloaded-flow limitation**: Kernel BPF offload entries appear only after a flow has progressed and been offloaded. Initial packets of new flows and non-offloaded flows (e.g., short UDP/53 or non-offloaded UDP/443) remain `UNKNOWN_OWNER` and are forwarded (`ALLOW`) to prevent collateral drops across connected hotspot clients.")
        appendLine()
        appendLine("## 10. Exclusive Blocking Mode & Legacy Pre-NAT Retirement (`v0.10.8-debug`, Schema v6)")
        val cap = preNatDiagnostics.capability
        appendLine("- **Requested Mode**: `${preNatDiagnostics.requestedMode.name}` (`${preNatDiagnostics.requestedMode.displayTitle}`)")
        appendLine("- **Effective (Active) Mode**: `${preNatDiagnostics.effectiveMode.name}` (`${preNatDiagnostics.effectiveMode.displayTitle}`)")
        appendLine("- **Previous Stable Mode**: `${preNatDiagnostics.previousStableMode.name}`")
        appendLine("- **Runtime State**: `${preNatDiagnostics.runtimeState.name}` (transitionId `${preNatDiagnostics.transitionId}`, policyGeneration `${preNatDiagnostics.policyGeneration}`)")
        appendLine("- **Exclusive Engine Invariant**: `${preNatDiagnostics.exclusiveEngineInvariant}` (`bpfNatVpnActive=${preNatDiagnostics.bpfNatVpnActive}`, `preNatFirewallActive=${preNatDiagnostics.preNatFirewallActive}`)")
        appendLine("- **Capability Status**: `${cap.status.name}` (IPv4=`${cap.ipv4Coverage.name}`, IPv6=`${cap.ipv6Coverage.name}`)")
        appendLine("- **Shizuku / Execution Identity**: state=`${cap.shizukuState}`, mode=`${cap.shizukuMode}`, uid=`${cap.realUid}`, gid=`${cap.realGid}`, selinux=`${cap.selinuxContext}`, CapEff=`0x${cap.capEffHex}`, `CAP_NET_ADMIN`=`${cap.hasCapNetAdmin}`")
        appendLine("- **Candidate Hook Status**: `iptables`=`${cap.iptablesStatus}`, `ip6tables`=`${cap.ip6tablesStatus}`, `nft`=`${cap.nftStatus}`, `tc`=`${cap.tcStatus}`, `ip rule`=`${cap.ipRuleStatus}`")
        appendLine("- **Scoped Probe Executed / Passed**: `${cap.probeExecuted}` / `${cap.probePassed}` (userApproved=`${cap.userApprovedProbe}`)")
        appendLine("- **Activation / Rollback Status**: activationAttempted=`${preNatDiagnostics.activationAttempted}`, activationSucceeded=`${preNatDiagnostics.activationSucceeded}`, rollbackPerformed=`${preNatDiagnostics.rollbackPerformed}`, rollbackVerified=`${preNatDiagnostics.rollbackVerified}`, rollbackStatus=`${preNatDiagnostics.rollbackStatus.name}`")
        appendLine("- **Engineering Go / No-Go Verdict**: **${preNatDiagnostics.goNoGoVerdict}** (${cap.reason})")
        if (preNatDiagnostics.testMatrix.isNotEmpty()) {
            appendLine()
            appendLine("### Pre-NAT Test Matrix (`PN01`–`PN16`)")
            appendLine("| ID | Scenario | Status | Evidence |")
            appendLine("| --- | --- | --- | --- |")
            preNatDiagnostics.testMatrix.forEach { row ->
                val safeEvidence = (if (includeSensitiveEndpoints) row.evidence else BpfDumpParser.maskSensitiveLinePreview(row.evidence)).replace("|", "\\|")
                appendLine("| `${row.testId}` | ${row.scenario} | `${row.status}` | `$safeEvidence` |")
            }
        }
        appendLine()
        append(
            softApDiagnostics.toMarkdownSection(
                includeSensitiveEndpoints = includeSensitiveEndpoints,
                includePseudonymousIds = includePseudonymousIds,
            ),
        )
        appendLine()
        append(domainDiagnostics.toMarkdownSection())
        appendLine()
        append(vpnRecoveryDiagnostics.toMarkdownSection())
    }

    companion object {
        private fun JSONObject.optPositiveIntOrNull(key: String): Int? {
            if (isNull(key)) return null
            val v = optInt(key, 0)
            return if (v > 0) v else null
        }

        private fun JSONObject.optLongMap(key: String): Map<String, Long> {
            val obj = optJSONObject(key) ?: return emptyMap()
            val map = LinkedHashMap<String, Long>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                map[k] = obj.optLong(k, 0L)
            }
            return map
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
            val verifiedSummariesList = mutableListOf<PerClientVerifiedTrafficSummary>()
            val verArr = json.optJSONArray("perClientVerifiedSummaries")
            if (verArr != null) {
                for (i in 0 until verArr.length()) {
                    val item = verArr.optJSONObject(i) ?: continue
                    verifiedSummariesList.add(
                        PerClientVerifiedTrafficSummary(
                            mac = item.optString("mac"),
                            originalIpv4 = item.optString("originalIpv4"),
                            activeFlows = item.optInt("activeFlows", 0),
                            verifiedUploadPackets = item.optLong("verifiedUploadPackets", 0L),
                            verifiedUploadBytes = item.optLong("verifiedUploadBytes", 0L),
                            verifiedDownloadPackets = item.optLong("verifiedDownloadPackets", 0L),
                            verifiedDownloadBytes = item.optLong("verifiedDownloadBytes", 0L),
                            directIpPackets = item.optLong("directIpPackets", 0L),
                            bpfNatPackets = item.optLong("bpfNatPackets", 0L),
                            conntrackPackets = item.optLong("conntrackPackets", 0L),
                            blockedDropPackets = item.optLong("blockedDropPackets", 0L),
                            blockedDropBytes = item.optLong("blockedDropBytes", 0L),
                            isBlocked = item.optBoolean("isBlocked", false),
                            isQuotaExhausted = item.optBoolean("isQuotaExhausted", false),
                            isThrottled = item.optBoolean("isThrottled", false),
                        ),
                    )
                }
            }
            val sampleRecordsList = mutableListOf<TupleDiagnosticSampleRecord>()
            val sampArr = json.optJSONArray("tupleDiagnosticSampleRecords")
            if (sampArr != null) {
                for (i in 0 until sampArr.length()) {
                    val item = sampArr.optJSONObject(i) ?: continue
                    sampleRecordsList.add(TupleDiagnosticSampleRecord.fromJson(item))
                }
            }
            val transitionEventsList = mutableListOf<PhaseDPolicyTransitionEvent>()
            val transArr = json.optJSONArray("policyTransitionEvents")
            if (transArr != null) {
                for (i in 0 until transArr.length()) {
                    val item = transArr.optJSONObject(i) ?: continue
                    transitionEventsList.add(PhaseDPolicyTransitionEvent.fromJson(item))
                }
            }
            val postTransVerifiedList = mutableListOf<PhaseDClientPostTransitionSummary>()
            val postVerArr = json.optJSONArray("postTransitionVerifiedClientTraffic")
            if (postVerArr != null) {
                for (i in 0 until postVerArr.length()) {
                    val item = postVerArr.optJSONObject(i) ?: continue
                    postTransVerifiedList.add(PhaseDClientPostTransitionSummary.fromJson(item))
                }
            }
            val ifaceLifecycleList = mutableListOf<PhaseDInterfaceLifecycleEvent>()
            val ifaceArr = json.optJSONArray("interfaceLifecycleEvents")
            if (ifaceArr != null) {
                for (i in 0 until ifaceArr.length()) {
                    val item = ifaceArr.optJSONObject(i) ?: continue
                    ifaceLifecycleList.add(PhaseDInterfaceLifecycleEvent.fromJson(item))
                }
            }
            val markersList = mutableListOf<PhaseDDeliveryTestMarker>()
            val markArr = json.optJSONArray("deliveryTestMarkers")
            if (markArr != null) {
                for (i in 0 until markArr.length()) {
                    val item = markArr.optJSONObject(i) ?: continue
                    markersList.add(PhaseDDeliveryTestMarker.fromJson(item))
                }
            }
            val postTransUnknownObj = json.optJSONObject("postTransitionUnknownTraffic")
            val existingCacheObj = json.optJSONObject("existingFlowCacheDiagnostics")
            val tcpLongLivedObj = json.optJSONObject("tcpLongLivedDiagnostics")

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

            val directPkts = json.optLong("directAttributedPackets", 0L)
            val bpfPkts = json.optLong("bpfAttributedPackets", 0L)
            val conntrackPkts = json.optLong("conntrackAttributedPackets", 0L)
            val unknownPkts = json.optLong("unknownForwardedPackets", 0L)
            val defaultTotalAttrPkts = directPkts + bpfPkts + conntrackPkts
            val defaultTotalEligPkts = defaultTotalAttrPkts + unknownPkts

            val phaseDReport = PhaseDStatusReport(
                phaseDMode = runCatching {
                    PhaseDEnforcementMode.valueOf(json.optString("phaseDMode", PhaseDEnforcementMode.DIAGNOSTIC.name))
                }.getOrDefault(PhaseDEnforcementMode.DIAGNOSTIC),
                evidenceConfidence = runCatching {
                    PhaseDEvidenceConfidence.valueOf(json.optString("evidenceConfidence", PhaseDEvidenceConfidence.UNKNOWN_OWNER.name))
                }.getOrDefault(PhaseDEvidenceConfidence.UNKNOWN_OWNER),
                interfaceLifecycleState = runCatching {
                    PhaseDInterfaceLifecycleState.valueOf(
                        json.optString("interfaceLifecycleState", PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES.name),
                    )
                }.getOrDefault(PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES),
                policyTransitionEvents = transitionEventsList,
                postTransitionVerifiedClientTraffic = postTransVerifiedList,
                unknownForwardedAfterBlockPackets = postTransUnknownObj?.optLong("unknownForwardedAfterBlockPackets")
                    ?: json.optLong("unknownForwardedAfterBlockPackets", 0L),
                unknownForwardedAfterBlockBytes = postTransUnknownObj?.optLong("unknownForwardedAfterBlockBytes")
                    ?: json.optLong("unknownForwardedAfterBlockBytes", 0L),
                unknownPostBlockByProtocolAndDirection = postTransUnknownObj?.optLongMap("unknownPostBlockByProtocolAndDirection")
                    ?: emptyMap(),
                unknownPostBlockBytesByProtocolAndDirection = postTransUnknownObj?.optLongMap("unknownPostBlockBytesByProtocolAndDirection")
                    ?: emptyMap(),
                verifiedFlowsAtTransitionTotal = existingCacheObj?.optLong("verifiedFlowsAtTransitionTotal")
                    ?: json.optLong("verifiedFlowsAtTransition", 0L),
                staleAllowCacheHitsPreventedTotal = existingCacheObj?.optLong("staleAllowCacheHitsPreventedTotal")
                    ?: json.optLong("staleAllowCacheHitsPrevented", 0L),
                decisionsRecomputedTotal = existingCacheObj?.optLong("decisionsRecomputedTotal")
                    ?: json.optLong("decisionsRecomputed", 0L),
                verifiedAllowedAfterBlockPacketsTotal = existingCacheObj?.optLong("verifiedAllowedAfterBlockPacketsTotal")
                    ?: json.optLong("verifiedAllowedAfterBlockPackets", 0L),
                verifiedAllowedAfterBlockBytesTotal = existingCacheObj?.optLong("verifiedAllowedAfterBlockBytesTotal")
                    ?: json.optLong("verifiedAllowedAfterBlockBytes", 0L),
                verifiedDroppedAfterBlockPacketsTotal = existingCacheObj?.optLong("verifiedDroppedAfterBlockPacketsTotal")
                    ?: json.optLong("verifiedDroppedAfterBlockPackets", 0L),
                verifiedDroppedAfterBlockBytesTotal = existingCacheObj?.optLong("verifiedDroppedAfterBlockBytesTotal")
                    ?: json.optLong("verifiedDroppedAfterBlockBytes", 0L),
                activePinnedVerifiedFlowsCount = existingCacheObj?.optInt("activePinnedVerifiedFlowsCount", 0) ?: 0,
                pinnedFlowHitsInDiagnosticMode = existingCacheObj?.optLong("pinnedFlowHitsInDiagnosticMode", 0L) ?: 0L,
                pinnedFlowEnforcedDropsInEnforcementMode = existingCacheObj?.optLong("pinnedFlowEnforcedDropsInEnforcementMode", 0L) ?: 0L,
                queuedPacketsPurgedOnTransitionTotal = existingCacheObj?.optLong("queuedPacketsPurgedOnTransitionTotal", 0L) ?: 0L,
                establishedTcpMissingFromBpfPackets = tcpLongLivedObj?.optLong("establishedTcpMissingFromBpfPackets", 0L) ?: 0L,
                establishedTcpMissingFromBpfBytes = tcpLongLivedObj?.optLong("establishedTcpMissingFromBpfBytes", 0L) ?: 0L,
                establishedTcpPinnedMatchedPackets = tcpLongLivedObj?.optLong("establishedTcpPinnedMatchedPackets", 0L) ?: 0L,
                establishedTcpPinnedMatchedBytes = tcpLongLivedObj?.optLong("establishedTcpPinnedMatchedBytes", 0L) ?: 0L,
                tcpKeepaliveOrAckOnlyPackets = tcpLongLivedObj?.optLong("tcpKeepaliveOrAckOnlyPackets", 0L) ?: 0L,
                tcpSynPacketsSeen = tcpLongLivedObj?.optLong("tcpSynPacketsSeen", 0L) ?: 0L,
                tcpFinOrRstPacketsSeen = tcpLongLivedObj?.optLong("tcpFinOrRstPacketsSeen", 0L) ?: 0L,
                udp443PostBlockUnattributedPackets = tcpLongLivedObj?.optLong("udp443PostBlockUnattributedPackets", 0L) ?: 0L,
                udp443PostBlockUnattributedBytes = tcpLongLivedObj?.optLong("udp443PostBlockUnattributedBytes", 0L) ?: 0L,
                udp53PostBlockUnattributedPackets = tcpLongLivedObj?.optLong("udp53PostBlockUnattributedPackets", 0L) ?: 0L,
                udp53PostBlockUnattributedBytes = tcpLongLivedObj?.optLong("udp53PostBlockUnattributedBytes", 0L) ?: 0L,
                interfaceLifecycleEvents = ifaceLifecycleList,
                deliveryTestMarkers = markersList,
                lastPolicyActivatedEpochMs = json.optLong("lastPolicyActivatedEpochMs", 0L),
            )

            return BpfAttributionStatusReport(
                experimentalEnabled = json.optBoolean("experimentalEnabled", false),
                state = runCatching {
                    ExperimentalBpfState.valueOf(json.optString("state", ExperimentalBpfState.DISABLED.name))
                }.getOrDefault(ExperimentalBpfState.DISABLED),
                snapshotHealth = runCatching {
                    BpfSnapshotHealth.valueOf(json.optString("snapshotHealth", BpfSnapshotHealth.UNAVAILABLE.name))
                }.getOrDefault(BpfSnapshotHealth.UNAVAILABLE),
                collectionStatus = runCatching {
                    BpfCollectionStatus.valueOf(json.optString("collectionStatus", BpfCollectionStatus.IDLE.name))
                }.getOrDefault(BpfCollectionStatus.IDLE),
                collectionError = json.optString("collectionError", ""),
                parserVersion = json.optInt("parserVersion", BpfDumpParser.PARSER_VERSION),
                pollIntervalMs = json.optLong("pollIntervalMs", BpfMapReader.DEFAULT_POLL_INTERVAL_MS),
                snapshotSequence = json.optLong("snapshotSequence", 0L),
                snapshotAgeMs = json.optLong("snapshotAgeMs", 0L),
                lastSuccessfulRefreshEpochMs = json.optLong("lastSuccessfulRefreshEpochMs", 0L),
                lastCollectionDurationMs = json.optLong("lastCollectionDurationMs", 0L),
                totalCollectionsAttempted = json.optLong("totalCollectionsAttempted", 0L),
                totalCollectionsSucceeded = json.optLong("totalCollectionsSucceeded", 0L),
                totalCollectionsFailed = json.optLong("totalCollectionsFailed", 0L),
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
                snapshotPublishRejectedByReason = json.optLongMap("snapshotPublishRejectedByReason"),
                totalEligiblePackets = json.optLong("totalEligiblePackets", defaultTotalEligPkts),
                totalEligibleBytes = json.optLong("totalEligibleBytes", 0L),
                totalAttributedPackets = json.optLong("totalAttributedPackets", defaultTotalAttrPkts),
                totalAttributedBytes = json.optLong("totalAttributedBytes", 0L),
                directAttributedPackets = directPkts,
                directAttributedBytes = json.optLong("directAttributedBytes", 0L),
                bpfAttributedPackets = bpfPkts,
                bpfAttributedBytes = json.optLong("bpfAttributedBytes", 0L),
                conntrackAttributedPackets = conntrackPkts,
                conntrackAttributedBytes = json.optLong("conntrackAttributedBytes", 0L),
                unknownForwardedPackets = unknownPkts,
                unknownForwardedBytes = json.optLong("unknownForwardedBytes", 0L),
                unattributedPacketsByReason = json.optLongMap("unattributedPacketsByReason"),
                unattributedBytesByReason = json.optLongMap("unattributedBytesByReason"),
                trafficSplit = BpfTrafficSplitCounters(
                    ipv4EligiblePackets = json.optLong("ipv4EligiblePackets", 0L),
                    ipv4EligibleBytes = json.optLong("ipv4EligibleBytes", 0L),
                    ipv4AttributedPackets = json.optLong("ipv4AttributedPackets", 0L),
                    ipv4AttributedBytes = json.optLong("ipv4AttributedBytes", 0L),
                    ipv4UnattributedPackets = json.optLong("ipv4UnattributedPackets", 0L),
                    ipv4UnattributedBytes = json.optLong("ipv4UnattributedBytes", 0L),
                    ipv6EligiblePackets = json.optLong("ipv6EligiblePackets", 0L),
                    ipv6EligibleBytes = json.optLong("ipv6EligibleBytes", 0L),
                    ipv6AttributedPackets = json.optLong("ipv6AttributedPackets", 0L),
                    ipv6AttributedBytes = json.optLong("ipv6AttributedBytes", 0L),
                    ipv6UnattributedPackets = json.optLong("ipv6UnattributedPackets", 0L),
                    ipv6UnattributedBytes = json.optLong("ipv6UnattributedBytes", 0L),
                    tcpEligiblePackets = json.optLong("tcpEligiblePackets", 0L),
                    tcpEligibleBytes = json.optLong("tcpEligibleBytes", 0L),
                    tcpAttributedPackets = json.optLong("tcpAttributedPackets", 0L),
                    tcpAttributedBytes = json.optLong("tcpAttributedBytes", 0L),
                    tcpUnattributedPackets = json.optLong("tcpUnattributedPackets", 0L),
                    tcpUnattributedBytes = json.optLong("tcpUnattributedBytes", 0L),
                    udpEligiblePackets = json.optLong("udpEligiblePackets", 0L),
                    udpEligibleBytes = json.optLong("udpEligibleBytes", 0L),
                    udpAttributedPackets = json.optLong("udpAttributedPackets", 0L),
                    udpAttributedBytes = json.optLong("udpAttributedBytes", 0L),
                    udpUnattributedPackets = json.optLong("udpUnattributedPackets", 0L),
                    udpUnattributedBytes = json.optLong("udpUnattributedBytes", 0L),
                    icmpEligiblePackets = json.optLong("icmpEligiblePackets", 0L),
                    icmpEligibleBytes = json.optLong("icmpEligibleBytes", 0L),
                    icmpAttributedPackets = json.optLong("icmpAttributedPackets", 0L),
                    icmpAttributedBytes = json.optLong("icmpAttributedBytes", 0L),
                    icmpUnattributedPackets = json.optLong("icmpUnattributedPackets", 0L),
                    icmpUnattributedBytes = json.optLong("icmpUnattributedBytes", 0L),
                    otherProtoEligiblePackets = json.optLong("otherProtoEligiblePackets", 0L),
                    otherProtoEligibleBytes = json.optLong("otherProtoEligibleBytes", 0L),
                    otherProtoAttributedPackets = json.optLong("otherProtoAttributedPackets", 0L),
                    otherProtoAttributedBytes = json.optLong("otherProtoAttributedBytes", 0L),
                    otherProtoUnattributedPackets = json.optLong("otherProtoUnattributedPackets", 0L),
                    otherProtoUnattributedBytes = json.optLong("otherProtoUnattributedBytes", 0L),
                    uploadEligiblePackets = json.optLong("uploadEligiblePackets", 0L),
                    uploadEligibleBytes = json.optLong("uploadEligibleBytes", 0L),
                    uploadAttributedPackets = json.optLong("uploadAttributedPackets", 0L),
                    uploadAttributedBytes = json.optLong("uploadAttributedBytes", 0L),
                    uploadUnattributedPackets = json.optLong("uploadUnattributedPackets", 0L),
                    uploadUnattributedBytes = json.optLong("uploadUnattributedBytes", 0L),
                    downloadEligiblePackets = json.optLong("downloadEligiblePackets", 0L),
                    downloadEligibleBytes = json.optLong("downloadEligibleBytes", 0L),
                    downloadAttributedPackets = json.optLong("downloadAttributedPackets", 0L),
                    downloadAttributedBytes = json.optLong("downloadAttributedBytes", 0L),
                    downloadUnattributedPackets = json.optLong("downloadUnattributedPackets", 0L),
                    downloadUnattributedBytes = json.optLong("downloadUnattributedBytes", 0L),
                ),
                conntrackFallbackAttemptedCount = json.optLong("conntrackFallbackAttemptedCount", 0L),
                conntrackFallbackSucceededCount = json.optLong("conntrackFallbackSucceededCount", 0L),
                conntrackFallbackFailedCount = json.optLong("conntrackFallbackFailedCount", 0L),
                conntrackPermissionDeniedCount = json.optLong("conntrackPermissionDeniedCount", 0L),
                conntrackBackoffActive = json.optBoolean("conntrackBackoffActive", false),
                conntrackBackoffRemainingMs = json.optLong("conntrackBackoffRemainingMs", 0L),
                conntrackBackoffSkippedCount = json.optLong("conntrackBackoffSkippedCount", 0L),
                activeConnectedClientsCount = json.optInt("activeConnectedClientsCount", 0),
                blockedClientsCount = json.optInt("blockedClientsCount", 0),
                quotaExhaustedClientsCount = json.optInt("quotaExhaustedClientsCount", 0),
                throttledClientsCount = json.optInt("throttledClientsCount", 0),
                bpfRefreshOnMissEnabled = json.optBoolean("bpfRefreshOnMissEnabled", false),
                refreshOnMissCooldownMs = json.optLong("refreshOnMissCooldownMs", BpfMapReader.DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS),
                refreshCircuitBreakerState = json.optString("refreshCircuitBreakerState", RefreshCircuitBreakerState.CLOSED.name),
                refreshOnMissTriggeredCount = json.optLong("refreshOnMissTriggeredCount", json.optLong("missRefreshTriggered", 0L)),
                refreshOnMissCoalescedInFlightCount = json.optLong("refreshOnMissCoalescedInFlightCount", json.optLong("missRefreshCoalesced", 0L)),
                refreshOnMissSuppressedCooldownCount = json.optLong("refreshOnMissSuppressedCooldownCount", json.optLong("missRefreshSuppressedCooldown", 0L)),
                refreshOnMissCompletedCount = json.optLong("refreshOnMissCompletedCount", json.optLong("missRefreshCompleted", 0L)),
                missRefreshFailedCount = json.optLong("missRefreshFailedCount", json.optLong("missRefreshFailed", 0L)),
                missRefreshSuppressedBreakerCount = json.optLong("missRefreshSuppressedBreakerCount", json.optLong("missRefreshSuppressedBreaker", 0L)),
                missRefreshSuppressedIneligibleCount = json.optLong("missRefreshSuppressedIneligibleCount", json.optLong("missRefreshSuppressedIneligible", 0L)),
                missRefreshQueueOverflowCount = json.optLong("missRefreshQueueOverflowCount", json.optLong("missRefreshQueueOverflow", 0L)),
                refreshOnMissLastLatencyMs = json.optLong("refreshOnMissLastLatencyMs", 0L),
                missRefreshLatency = RefreshLatencyPercentiles(
                    p50Ms = json.optLong("missRefreshLatencyP50Ms", 0L),
                    p95Ms = json.optLong("missRefreshLatencyP95Ms", 0L),
                    p99Ms = json.optLong("missRefreshLatencyP99Ms", 0L),
                    maxMs = json.optLong("missRefreshLatencyMaxMs", 0L),
                ),
                postRefreshAttributedPackets = json.optLong("postRefreshAttributedPackets", 0L),
                postRefreshAttributedBytes = json.optLong("postRefreshAttributedBytes", 0L),
                postRefreshFlowKeysResolved = json.optLong("postRefreshFlowKeysResolved", 0L),
                postRefreshFirstSubsequentAttributedPackets = json.optLong("postRefreshFirstSubsequentAttributedPackets", 0L),
                postRefreshFirstSubsequentAttributedBytes = json.optLong("postRefreshFirstSubsequentAttributedBytes", 0L),
                refreshOnMissAutoDisabled = json.optBoolean("refreshOnMissAutoDisabled", false),
                refreshOnMissAutoDisableReason = json.optString("refreshOnMissAutoDisableReason", ""),
                deepTupleDiagnosticsEnabled = json.optBoolean("deepTupleDiagnosticsEnabled", false),
                unknownOwnerPacketPolicy = json.optString("unknownOwnerPacketPolicy", "ALLOW"),
                deepTupleDiagnostics = DeepTupleDiagnosticsSnapshot(
                    activeTrackedFlowsCount = json.optInt("activeTrackedFlowsCount", 0),
                    newMissFlowsCount = json.optLong("newMissFlowsCount", 0L),
                    repeatedMissFlowsCount = json.optLong("repeatedMissFlowsCount", 0L),
                    persistentAfterRefreshFlowsCount = json.optLong("persistentAfterRefreshFlowsCount", 0L),
                    resolvedAfterRefreshFlowsCount = json.optLong("resolvedAfterRefreshFlowsCount", 0L),
                    keyMismatchSuspectedFlowsCount = json.optLong("keyMismatchSuspectedFlowsCount", 0L),
                    notOffloadedOrNotObservableFlowsCount = json.optLong("notOffloadedOrNotObservableFlowsCount", 0L),
                    expiredFlowsCount = json.optLong("expiredFlowsCount", 0L),
                    evictedFlowsCount = json.optLong("evictedFlowsCount", 0L),
                    survived0SnapshotsCount = json.optInt("survived0SnapshotsCount", 0),
                    survived1SnapshotCount = json.optInt("survived1SnapshotCount", 0),
                    survived2SnapshotsCount = json.optInt("survived2SnapshotsCount", 0),
                    survived3PlusSnapshotsCount = json.optInt("survived3PlusSnapshotsCount", 0),
                    udp443MissingFlowsCount = json.optLong("udp443MissingFlowsCount", 0L),
                    udp443MissingPacketsCount = json.optLong("udp443MissingPacketsCount", 0L),
                    udp443MissingBytesCount = json.optLong("udp443MissingBytesCount", 0L),
                    udp443ResolvedAfterRefreshFlowsCount = json.optLong("udp443ResolvedAfterRefreshFlowsCount", 0L),
                    udp53MissingFlowsCount = json.optLong("udp53MissingFlowsCount", 0L),
                    udp53MissingPacketsCount = json.optLong("udp53MissingPacketsCount", 0L),
                    udp53MissingBytesCount = json.optLong("udp53MissingBytesCount", 0L),
                    udp53ResolvedAfterRefreshFlowsCount = json.optLong("udp53ResolvedAfterRefreshFlowsCount", 0L),
                    tcpMissingFlowsCount = json.optLong("tcpMissingFlowsCount", 0L),
                    udpOtherMissingFlowsCount = json.optLong("udpOtherMissingFlowsCount", 0L),
                    postRefreshFlowKeysResolved = json.optLong("postRefreshFlowKeysResolved", 0L),
                    postRefreshFirstSubsequentAttributedPackets = json.optLong("postRefreshFirstSubsequentAttributedPackets", 0L),
                    postRefreshFirstSubsequentAttributedBytes = json.optLong("postRefreshFirstSubsequentAttributedBytes", 0L),
                    sampleRecords = sampleRecordsList,
                ),
                perClientVerifiedSummaries = verifiedSummariesList,
                phaseD = phaseDReport,
                preNatDiagnostics = PreNatModeDiagnosticReport.fromJson(json.optJSONObject("preNatDiagnostics") ?: json),
                softApDiagnostics = json.optJSONObject("softApDiagnostics")?.let { SoftApModeDiagnosticReport.fromJson(it) }
                    ?: SoftApModeDiagnosticReport(
                        capabilityReport = SoftApCapabilityReport(
                            executionIdentity = SoftApExecutionIdentity(
                                shizukuState = "SHIZUKU_NOT_RUNNING",
                                shizukuRunning = false,
                                shizukuPermissionGranted = false,
                            ),
                        ),
                    ),
                domainDiagnostics = DomainFilterDiagnosticReport.fromJson(json.optJSONObject("domainDiagnostics")),
                vpnRecoveryDiagnostics = VpnRecoveryDiagnostics.fromJson(json.optJSONObject("vpnRecoveryDiagnostics")),
                ambiguousOrStaleLookups = json.optLong("ambiguousOrStaleLookups", 0L),
                localControlPackets = json.optLong("localControlPackets", 0L),
                localControlBytes = json.optLong("localControlBytes", 0L),
                unsupportedOrFragmentPackets = json.optLong("unsupportedOrFragmentPackets", 0L),
                blockedDropPackets = json.optLong("blockedDropPackets", 0L),
                blockedDropBytes = json.optLong("blockedDropBytes", 0L),
                shapingDropPackets = json.optLong("shapingDropPackets", 0L),
                shapedPackets = json.optLong("shapedPackets", 0L),
                rejectedOldGenerationCount = json.optLong("rejectedOldGenerationCount", 0L),
                tupleReuseGuardTriggeredCount = json.optLong("tupleReuseGuardTriggeredCount", 0L),
            )
        }
    }
}
