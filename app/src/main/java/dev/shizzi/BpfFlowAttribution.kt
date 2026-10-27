package dev.shizzi

import android.os.Binder
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
    INVALID_SYNTAX,
    UNSUPPORTED_PROTOCOL,
    INVALID_IP,
    INVALID_PORT,
    INVALID_MAC,
    INVALID_IFINDEX,
}

data class BpfRejectedLine(
    val lineNumber: Int,
    val section: String,
    val reason: BpfRejectionReason,
    val linePreview: String,
)

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
    val rawAgeMs: Long,
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
    val rawAgeMs: Long,
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
) {
    val hasRejections: Boolean get() = rejectedLines.isNotEmpty()
    val isEmptyValid: Boolean
        get() = recognizedFormat &&
            ipv4UpstreamEntries.isEmpty() &&
            ipv4DownstreamEntries.isEmpty() &&
            rejectedLines.isEmpty()
}

/**
 * Pure parser for `dumpsys tethering bpf` text output and optional `bpfRawMap --upstream4` row count.
 */
object BpfDumpParser {

    const val PARSER_VERSION = 1

    private enum class Section {
        NONE,
        CLIENT_INFO,
        IPV4_UPSTREAM,
        IPV4_DOWNSTREAM,
        IPV6_UPSTREAM,
        IPV6_DOWNSTREAM,
        RAW_MAP_UPSTREAM4,
    }

    // Matches:
    // tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
    private val IPV4_FLOW_ROW_REGEX = Regex(
        """^\s*(\S+)\s+\[([^\]]+)]\s+(\d+)\(([^)]*)\)\s+([^\s:]+):(\d+)\s*->\s*(\d+)\(([^)]*)\)\s+([^\s:]+):(\d+)\s*->\s*([^\s:]+):(\d+)\s+\[([^\]]+)]\s+(\d+)\s+(\d+)ms\s*$""",
    )

    private val MAC_REGEX = Regex("""^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$""")

    fun parse(dumpText: String, wasTruncatedByReader: Boolean = false): BpfParsedDump {
        if (dumpText.isBlank()) {
            return BpfParsedDump(
                recognizedFormat = false,
                ipv4UpstreamEntries = emptyList(),
                ipv4DownstreamEntries = emptyList(),
                ipv6Entries = emptyList(),
                rejectedLines = emptyList(),
            )
        }

        val upstream4 = ArrayList<BpfIpv4UpstreamEntry>()
        val downstream4 = ArrayList<BpfIpv4DownstreamEntry>()
        val ipv6List = ArrayList<BpfIpv6Entry>()
        val rejected = ArrayList<BpfRejectedLine>()
        var recognizedHeader = false
        var rawMapRows = 0
        var currentSection = Section.NONE

        val lines = dumpText.lines()
        for ((idx, rawLine) in lines.withIndex()) {
            val lineNumber = idx + 1
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) continue

            when {
                trimmed.startsWith("IPv4 Upstream:") -> {
                    recognizedHeader = true
                    currentSection = Section.IPV4_UPSTREAM
                    continue
                }
                trimmed.startsWith("IPv4 Downstream:") -> {
                    recognizedHeader = true
                    currentSection = Section.IPV4_DOWNSTREAM
                    continue
                }
                trimmed.startsWith("IPv6 Upstream:") -> {
                    recognizedHeader = true
                    currentSection = Section.IPV6_UPSTREAM
                    continue
                }
                trimmed.startsWith("IPv6 Downstream:") -> {
                    recognizedHeader = true
                    currentSection = Section.IPV6_DOWNSTREAM
                    continue
                }
                trimmed.startsWith("Client Information:") -> {
                    recognizedHeader = true
                    currentSection = Section.CLIENT_INFO
                    continue
                }
                trimmed.startsWith("BPF offload") ||
                    trimmed.startsWith("Polling interval:") ||
                    trimmed.startsWith("Upstream:") ||
                    trimmed.startsWith("Forwarding rules") ||
                    trimmed.startsWith("Forwarding stats") ||
                    trimmed.startsWith("Downstream:") ||
                    trimmed.startsWith("Tethering BPF") -> {
                    recognizedHeader = true
                    if (!trimmed.startsWith("IPv4 ") && !trimmed.startsWith("IPv6 ")) {
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

            when (currentSection) {
                Section.IPV4_UPSTREAM -> {
                    if (trimmed.equals("none", ignoreCase = true) || trimmed.startsWith("No ")) continue
                    parseIpv4FlowLine(
                        line = rawLine,
                        lineNumber = lineNumber,
                        sectionName = "IPv4 Upstream",
                        isUpstream = true,
                        onUpstream = upstream4::add,
                        onDownstream = downstream4::add,
                        onRejected = rejected::add,
                    )
                }
                Section.IPV4_DOWNSTREAM -> {
                    if (trimmed.equals("none", ignoreCase = true) || trimmed.startsWith("No ")) continue
                    parseIpv4FlowLine(
                        line = rawLine,
                        lineNumber = lineNumber,
                        sectionName = "IPv4 Downstream",
                        isUpstream = false,
                        onUpstream = upstream4::add,
                        onDownstream = downstream4::add,
                        onRejected = rejected::add,
                    )
                }
                Section.IPV6_UPSTREAM, Section.IPV6_DOWNSTREAM -> {
                    if (trimmed.equals("none", ignoreCase = true) || trimmed.startsWith("No ")) continue
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

        if (wasTruncatedByReader) {
            rejected.add(
                BpfRejectedLine(
                    lineNumber = lines.size,
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
        )
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
        onUpstream: (BpfIpv4UpstreamEntry) -> Unit,
        onDownstream: (BpfIpv4DownstreamEntry) -> Unit,
        onRejected: (BpfRejectedLine) -> Unit,
    ) {
        val trimmed = line.trim()
        if (!trimmed.endsWith("ms")) {
            val reason = if (trimmed.contains("->")) {
                BpfRejectionReason.TRUNCATED_LINE
            } else {
                BpfRejectionReason.INVALID_SYNTAX
            }
            onRejected(BpfRejectedLine(lineNumber, sectionName, reason, trimmed.take(120)))
            return
        }

        val match = IPV4_FLOW_ROW_REGEX.matchEntire(line)
        if (match == null) {
            onRejected(
                BpfRejectedLine(
                    lineNumber = lineNumber,
                    section = sectionName,
                    reason = BpfRejectionReason.INVALID_SYNTAX,
                    linePreview = trimmed.take(120),
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
                        linePreview = trimmed.take(120),
                    ),
                )
                return
            }
        }

        val mac1 = match.groupValues[2].trim().uppercase()
        val ifIndex1 = match.groupValues[3].toIntOrNull() ?: -1
        val ifaceLabel1 = match.groupValues[4].trim()
        val ip1 = match.groupValues[5].trim()
        val port1 = match.groupValues[6].toIntOrNull() ?: -1

        val ifIndex2 = match.groupValues[7].toIntOrNull() ?: -1
        val ifaceLabel2 = match.groupValues[8].trim()
        val ip2 = match.groupValues[9].trim()
        val port2 = match.groupValues[10].toIntOrNull() ?: -1

        val ip3 = match.groupValues[11].trim()
        val port3 = match.groupValues[12].toIntOrNull() ?: -1
        val mac2 = match.groupValues[13].trim().uppercase()
        val pmtu = match.groupValues[14].toIntOrNull() ?: -1
        val ageMs = match.groupValues[15].toLongOrNull() ?: -1L

        if (!isValidMac(mac1) || !isValidMac(mac2)) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_MAC, trimmed.take(120)))
            return
        }
        if (ifIndex1 <= 0 || ifIndex2 <= 0 || pmtu <= 0 || ageMs < 0L) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_IFINDEX, trimmed.take(120)))
            return
        }
        if (!isValidIpv4(ip1) || !isValidIpv4(ip2) || !isValidIpv4(ip3)) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_IP, trimmed.take(120)))
            return
        }
        if (port1 !in 1..65535 || port2 !in 1..65535 || port3 !in 1..65535) {
            onRejected(BpfRejectedLine(lineNumber, sectionName, BpfRejectionReason.INVALID_PORT, trimmed.take(120)))
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
                    rawAgeMs = ageMs,
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
                    rawAgeMs = ageMs,
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
    val rawDumpAgeMs: Long,
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
    val totalUpstreamEntries: Int = 0,
    val totalDownstreamEntries: Int = 0,
    val reverseMatchedCount: Int = 0,
    val flowsByTuple: Map<TranslatedFlowKey, NatFlowMapping> = emptyMap(),
    val ambiguousTuples: Map<TranslatedFlowKey, String> = emptyMap(),
    val unverifiedOwnerEntries: Int = 0,
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
        currentSnapshotRef.set(
            NatFlowSnapshot(
                sessionGeneration = nextGen,
                bindingGeneration = bindingGen.get(),
                collectedAtMonotonicMs = monotonicClockMs(),
                collectionStatus = BpfCollectionStatus.IDLE,
                downstreamIface = activeDownstreamIface,
                upstreamIface = activeUpstreamIface,
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

    /**
     * Validates and publishes a parsed BPF dump for [collectionSessionGeneration].
     *
     * Rules enforced:
     * 1. Rejects late results from an older [collectionSessionGeneration].
     * 2. Never uses upstream `hotspotInDstMac` as client MAC.
     * 3. Resolves `origClientIp` via [ipToMac] and cross-checks matching reverse downstream
     *    `clientOutDstMac` when present.
     * 4. Marks duplicate or contradictory ownership as ambiguous instead of picking the first match.
     * 5. Does not overwrite the snapshot with a partial/truncated/corrupt dump.
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

        // If collection failed or was truncated/corrupted, do NOT replace a valid recent snapshot
        // with partial data; instead record the error status if no fresh snapshot exists.
        if (collectionStatus != BpfCollectionStatus.OK && collectionStatus != BpfCollectionStatus.EMPTY_VALID) {
            rejectedTruncatedOrCorruptCount.incrementAndGet()
            val prev = currentSnapshotRef.get()
            if (prev.sessionGeneration != expectedGen || (nowMono - prev.collectedAtMonotonicMs) > maxFreshnessMs) {
                currentSnapshotRef.set(
                    prev.copy(
                        sessionGeneration = expectedGen,
                        bindingGeneration = curBindGen,
                        collectionStatus = collectionStatus,
                        collectionError = collectionError,
                        rejectedLineCount = parsed.rejectedLines.size,
                    ),
                )
            }
            return false
        }

        if (!parsed.recognizedFormat || parsed.hasRejections) {
            rejectedTruncatedOrCorruptCount.incrementAndGet()
            val prev = currentSnapshotRef.get()
            if (prev.sessionGeneration != expectedGen || (nowMono - prev.collectedAtMonotonicMs) > maxFreshnessMs) {
                currentSnapshotRef.set(
                    prev.copy(
                        sessionGeneration = expectedGen,
                        bindingGeneration = curBindGen,
                        collectionStatus = BpfCollectionStatus.PARSE_FAILURE,
                        collectionError = collectionError.ifBlank {
                            "Rejected ${parsed.rejectedLines.size} invalid/truncated line(s)"
                        },
                        rejectedLineCount = parsed.rejectedLines.size,
                    ),
                )
            }
            return false
        }

        // Index IPv4 Downstream entries by (protocol, translatedIp, translatedPort, remoteIp, remotePort)
        // for reverse verification and MAC cross-check.
        val downstreamByTuple = HashMap<TranslatedFlowKey, MutableList<BpfIpv4DownstreamEntry>>()
        for (down in parsed.ipv4DownstreamEntries) {
            if (!matchesActiveUpstreamLabel(down.inIfaceLabel)) continue
            if (!matchesActiveDownstreamLabel(down.outIfaceLabel)) continue
            val key = TranslatedFlowKey(
                family = 4,
                protocol = down.protocol,
                translatedIp = down.translatedIp,
                translatedPort = down.translatedPort,
                remoteIp = down.remoteIp,
                remotePort = down.remotePort,
            )
            downstreamByTuple.getOrPut(key) { ArrayList(1) }.add(down)
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
        var coverageIncomplete = false
        var observedDownIfIndex = 0
        var observedDownIface = activeDownstreamIface
        var observedUpIfIndex = 0
        var observedUpIface = activeUpstreamIface

        val perClientTcp = HashMap<String, Int>()
        val perClientUdp = HashMap<String, Int>()
        val perClientIp = HashMap<String, String>()

        for (up in parsed.ipv4UpstreamEntries) {
            if (!matchesActiveDownstreamLabel(up.inIfaceLabel)) continue
            if (!matchesActiveUpstreamLabel(up.outIfaceLabel)) continue

            if (observedDownIfIndex == 0) observedDownIfIndex = up.inIfIndex
            if (observedDownIface.isEmpty() && !up.inIfaceLabel.all { it.isDigit() }) {
                observedDownIface = up.inIfaceLabel
            }
            if (observedUpIfIndex == 0) observedUpIfIndex = up.outIfIndex
            if (observedUpIface.isEmpty() && !up.outIfaceLabel.all { it.isDigit() }) {
                observedUpIface = up.outIfaceLabel
            }

            val tupleKey = TranslatedFlowKey(
                family = 4,
                protocol = up.protocol,
                translatedIp = up.translatedIp,
                translatedPort = up.translatedPort,
                remoteIp = up.remoteIp,
                remotePort = up.remotePort,
            )

            if (ambiguousTuples.containsKey(tupleKey)) {
                continue
            }

            val matchingDownList = downstreamByTuple[tupleKey].orEmpty()
            val exactDown = matchingDownList.filter {
                it.origClientIp == up.origClientIp &&
                    it.origClientPort == up.origClientPort &&
                    it.inIfIndex == up.outIfIndex &&
                    it.outIfIndex == up.inIfIndex
            }

            val ownerFromIpBinding = normalizedIpToMac[up.origClientIp]
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

        val snapshot = NatFlowSnapshot(
            sessionGeneration = expectedGen,
            bindingGeneration = curBindGen,
            collectedAtMonotonicMs = nowMono,
            collectionDurationMs = collectionDurationMs,
            collectionStatus = finalStatus,
            collectionError = collectionError,
            downstreamIfIndex = observedDownIfIndex,
            downstreamIface = observedDownIface,
            upstreamIfIndex = observedUpIfIndex,
            upstreamIface = observedUpIface,
            totalUpstreamEntries = parsed.ipv4UpstreamEntries.size,
            totalDownstreamEntries = parsed.ipv4DownstreamEntries.size,
            reverseMatchedCount = reverseMatched,
            flowsByTuple = validFlows,
            ambiguousTuples = ambiguousTuples,
            unverifiedOwnerEntries = unverifiedOwners,
            rejectedLineCount = parsed.rejectedLines.size,
            coverageIncomplete = coverageIncomplete,
            perClientCounts = clientSummaries,
        )

        if (sessionGen.get() != expectedGen) {
            rejectedOldGenerationCount.incrementAndGet()
            return false
        }
        currentSnapshotRef.set(snapshot)
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
        if (dumpIfaceLabel.all { it.isDigit() }) return true // e.g., 215(215)
        return dumpIfaceLabel.equals(active, ignoreCase = true)
    }

    private fun matchesActiveUpstreamLabel(dumpIfaceLabel: String): Boolean {
        val active = activeUpstreamIface
        if (active.isEmpty() || dumpIfaceLabel.isEmpty()) return true
        if (dumpIfaceLabel.all { it.isDigit() }) return true
        return dumpIfaceLabel.equals(active, ignoreCase = true)
    }

    companion object {
        const val DEFAULT_MAX_FRESHNESS_MS = 4_500L
        const val DEFAULT_MAX_MAPPED_FLOWS = 4_096
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

            if (raw.status != BpfCollectionStatus.OK) {
                totalCollectionsFailed.incrementAndGet()
                recordFailureAndBackoff(raw.status)
                attributor.ingestParsedDump(
                    parsed = BpfParsedDump(
                        recognizedFormat = false,
                        ipv4UpstreamEntries = emptyList(),
                        ipv4DownstreamEntries = emptyList(),
                        ipv6Entries = emptyList(),
                        rejectedLines = emptyList(),
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
            val ingested = attributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = generationAtStart,
                collectionStatus = if (parsed.isEmptyValid) BpfCollectionStatus.EMPTY_VALID else BpfCollectionStatus.OK,
                collectionDurationMs = raw.durationMs,
                collectionError = if (parsed.hasRejections) {
                    "Rejected ${parsed.rejectedLines.size} line(s): ${parsed.rejectedLines.first().reason}"
                } else {
                    ""
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
                val failStatus = if (!parsed.recognizedFormat || parsed.hasRejections) {
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
                    status = BpfCollectionStatus.COMMAND_FAILED,
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
    val totalUpstreamEntries: Int = 0,
    val totalDownstreamEntries: Int = 0,
    val reverseMatchedCount: Int = 0,
    val activeMappedFlows: Int = 0,
    val ambiguousTupleCount: Int = 0,
    val unverifiedOwnerEntries: Int = 0,
    val rejectedLineCount: Int = 0,
    val coverageIncomplete: Boolean = false,
    val perClientCounts: List<ClientProtocolFlowCounts> = emptyList(),
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
    fun toJson(includeSensitiveEndpoints: Boolean = true): JSONObject = JSONObject().apply {
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
        put("totalUpstreamEntries", totalUpstreamEntries)
        put("totalDownstreamEntries", totalDownstreamEntries)
        put("reverseMatchedCount", reverseMatchedCount)
        put("activeMappedFlows", activeMappedFlows)
        put("ambiguousTupleCount", ambiguousTupleCount)
        put("unverifiedOwnerEntries", unverifiedOwnerEntries)
        put("rejectedLineCount", rejectedLineCount)
        put("coverageIncomplete", coverageIncomplete)
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
        includeSensitiveEndpoints: Boolean = true,
    ): String = buildString {
        appendLine("# Shizzi — Experimental BPF NAT Flow Attribution Report")
        appendLine()
        appendLine("- **APK Version**: `$apkVersion` (serviceBuildId `$serviceBuildId`)")
        appendLine("- **Base Commit**: `$sourceCommit`")
        appendLine("- **Experimental BPF Enabled**: `$experimentalEnabled`")
        appendLine("- **Feature State**: `${state.name}`")
        appendLine("- **Collection Status**: `${collectionStatus.name}` (${lastCollectionDurationMs}ms, age ${snapshotAgeMs}ms, poll ${pollIntervalMs}ms)")
        if (collectionError.isNotBlank()) {
            appendLine("- **Collection Error**: `$collectionError`")
        }
        appendLine("- **Parser Version**: `$parserVersion`")
        appendLine("- **Session / Binding Generation**: `session=$sessionGeneration`, `binding=$bindingGeneration`")
        appendLine("- **Interfaces**: downstream `${downstreamIface.ifBlank { "unknown" }}` (ifindex `$downstreamIfIndex`) -> upstream `${upstreamIface.ifBlank { "unknown" }}` (ifindex `$upstreamIfIndex`)")
        appendLine()
        appendLine("## 1. BPF Map Snapshot Summary")
        appendLine("- **IPv4 Upstream Entries**: `$totalUpstreamEntries`")
        appendLine("- **IPv4 Downstream Entries**: `$totalDownstreamEntries`")
        appendLine("- **Reverse-Confirmed Mappings**: `$reverseMatchedCount`")
        appendLine("- **Active Validated Flow Mappings**: `$activeMappedFlows`")
        appendLine("- **Ambiguous / Conflicting Tuples**: `$ambiguousTupleCount`")
        appendLine("- **Unverified Owner Entries**: `$unverifiedOwnerEntries`")
        appendLine("- **Rejected Parse Lines**: `$rejectedLineCount`")
        appendLine("- **Coverage Incomplete (Cap Reached)**: `$coverageIncomplete`")
        appendLine()
        appendLine("### Flows per Client")
        if (perClientCounts.isEmpty()) {
            appendLine("_No mapped client flows in current snapshot._")
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
        appendLine("## 2. Packet Engine Attribution & Enforcement Deltas")
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
        appendLine("## 3. Architectural Scope & First-Packet Limitation")
        appendLine("- **Experimental status**: BPF offload entries appear only after a flow has progressed. A readable established-flow map is not a synchronous pre-NAT classifier.")
        appendLine("- **Unknown traffic**: Initial packets of brand-new flows arriving before the next `dumpsys tethering bpf` snapshot remain unattributed (`unknownForwardedPackets`) and are not globally dropped so other connected clients are not disrupted.")
    }

    companion object {
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
                downstreamIfIndex = json.optInt("downstreamIfIndex", 0),
                upstreamIface = json.optString("upstreamIface", ""),
                upstreamIfIndex = json.optInt("upstreamIfIndex", 0),
                totalUpstreamEntries = json.optInt("totalUpstreamEntries", 0),
                totalDownstreamEntries = json.optInt("totalDownstreamEntries", 0),
                reverseMatchedCount = json.optInt("reverseMatchedCount", 0),
                activeMappedFlows = json.optInt("activeMappedFlows", 0),
                ambiguousTupleCount = json.optInt("ambiguousTupleCount", 0),
                unverifiedOwnerEntries = json.optInt("unverifiedOwnerEntries", 0),
                rejectedLineCount = json.optInt("rejectedLineCount", 0),
                coverageIncomplete = json.optBoolean("coverageIncomplete", false),
                perClientCounts = perClientList,
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
