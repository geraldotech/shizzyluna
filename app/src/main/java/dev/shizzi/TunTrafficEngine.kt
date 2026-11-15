package dev.shizzi

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.min

enum class DatapathMode {
    INACTIVE,
    USERSPACE_PROXY,
    DIRECT_TUN_FALLBACK,
}

enum class PacketDecision {
    ALLOW,
    DROP,
    RATE_LIMIT,
    DROP_AQM,
}

enum class AttributionSource {
    DIRECT_IP,
    BPF_NAT,
    CONNTRACK_PROCFS,
    UNMATCHED_AMBIGUOUS_OR_STALE,
    UNMATCHED_UNSUPPORTED_OR_FRAGMENT,
    UNMATCHED_UNKNOWN,
}

/**
 * Userspace L3 packet inspection, real-time firewall blocking, calibrated non-blocking Token Bucket
 * bandwidth shaper, experimental BPF NAT flow attribution, and packet-level diagnostic counter engine
 * interposed on the TestNetwork TUN file descriptor.
 *
 * Bandwidth & Pacing Semantics:
 * - [EnforcedClientPolicy.bandwidthLimitKbps] is defined in kilobits per second
 *   (1 Kbps = 1,000 bits/s = 125 bytes/s; 1 Mbps = 1,000 Kbps = 125,000 bytes/s).
 * - Burst capacity: `max(4500 bytes, 100ms of rate)`.
 * - Queue bounds per client per direction: max [MAX_QUEUED_PACKETS_PER_CLIENT] packets (32) and
 *   [MAX_QUEUED_BYTES_PER_CLIENT] bytes (48 KB), with max virtual queue delay `100ms`.
 * - Shared forwarding threads (`shizzi-tun-upload`, `shizzi-tun-download`) NEVER call `Thread.sleep()`.
 *   Paced packets are scheduled in bounded per-client queues so shaping Client A never stalls Client B.
 * - On policy change, queued packets for that client are immediately re-evaluated and dropped if the
 *   client became blocked.
 */
object TunTrafficEngine {

    private const val TAG = "TunTrafficEngine"
    private const val BUFFER_SIZE = 65536
    private const val SOCKET_BUFFER_BYTES = 2 * 1024 * 1024 // 2 MB

    const val TUN_LOCAL_V4 = "192.0.2.2"
    const val TUN_LOCAL_V6 = "2001:db8::2"
    val TUN_LOCAL_V6_NORMALIZED: String by lazy { normalizeIp(TUN_LOCAL_V6) }
    private const val TUN_PREFIX_V6 = "2001:db8:"

    private const val SAMPLE_LOG_INTERVAL_MS = 2_500L
    private const val COUNTER_LOG_INTERVAL_MS = 5_000L

    const val MAX_QUEUED_PACKETS_PER_CLIENT = 32
    const val MAX_QUEUED_BYTES_PER_CLIENT = 48 * 1024
    const val DEFAULT_MAX_QUEUE_DELAY_MS = 100L

    data class ClientTrafficCounters(
        val mac: String,
        val seenPackets: AtomicLong = AtomicLong(0L),
        val matchedPackets: AtomicLong = AtomicLong(0L),
        val directAttributedPackets: AtomicLong = AtomicLong(0L),
        val bpfAttributedPackets: AtomicLong = AtomicLong(0L),
        val conntrackAttributedPackets: AtomicLong = AtomicLong(0L),
        val forwardedPackets: AtomicLong = AtomicLong(0L),
        val uploadForwardedPackets: AtomicLong = AtomicLong(0L),
        val downloadForwardedPackets: AtomicLong = AtomicLong(0L),
        val droppedPackets: AtomicLong = AtomicLong(0L),
        val blockedDropPackets: AtomicLong = AtomicLong(0L),
        val shapingDropPackets: AtomicLong = AtomicLong(0L),
        val shapedPackets: AtomicLong = AtomicLong(0L),
        val rxBytes: AtomicLong = AtomicLong(0L),
        val txBytes: AtomicLong = AtomicLong(0L),
        val droppedBytes: AtomicLong = AtomicLong(0L),
        val shapedBytes: AtomicLong = AtomicLong(0L),
        val policyVersion: AtomicLong = AtomicLong(1L),
        val policyVersionBlockedDrops: AtomicLong = AtomicLong(0L),
        val policyVersionShapedPackets: AtomicLong = AtomicLong(0L),
        val quotaDropPackets: AtomicLong = AtomicLong(0L),
        val decisionsRecomputed: AtomicLong = AtomicLong(0L),
        val staleAllowCacheHitsPrevented: AtomicLong = AtomicLong(0L),
        val verifiedAllowedAfterBlockPackets: AtomicLong = AtomicLong(0L),
        val verifiedAllowedAfterBlockBytes: AtomicLong = AtomicLong(0L),
        val verifiedDroppedAfterBlockPackets: AtomicLong = AtomicLong(0L),
        val verifiedDroppedAfterBlockBytes: AtomicLong = AtomicLong(0L),
        val pinnedFlowEnforcedPackets: AtomicLong = AtomicLong(0L),
        val pinnedFlowEnforcedBytes: AtomicLong = AtomicLong(0L),
        @Volatile var lastTransitionType: String = "NONE",
        @Volatile var lastTransitionAtWallMs: Long = 0L,
        @Volatile var lastTransitionAtMonoMs: Long = 0L,
        @Volatile var verifiedFlowsAtTransition: Int = 0,
        @Volatile var policyBaselinePostNatUnmatched: Long = 0L,
        @Volatile var lastSeenAt: Long = 0L,
        @Volatile var lastLoggedPackets: Long = -1L,
        @Volatile var lastCounterLogAt: Long = 0L,
    )

    data class CounterSnapshot(
        val mac: String,
        val seenPackets: Long,
        val matchedPackets: Long,
        val forwardedPackets: Long,
        val droppedPackets: Long,
        val shapedPackets: Long,
        val rxBytes: Long,
        val txBytes: Long,
        val droppedBytes: Long,
        val shapedBytes: Long,
        val policyInstalled: Boolean,
        val blockedDropPackets: Long = droppedPackets,
        val shapingDropPackets: Long = 0L,
        val policyVersion: Long = 1L,
        val policyVersionBlockedDrops: Long = droppedPackets,
        val unattributedPostNatObserved: Boolean = false,
        val directAttributedPackets: Long = 0L,
        val bpfAttributedPackets: Long = 0L,
        val conntrackAttributedPackets: Long = 0L,
        val policyVersionShapedPackets: Long = shapedPackets,
        val quotaDropPackets: Long = 0L,
        val quotaUsedRxBytes: Long = 0L,
        val quotaUsedTxBytes: Long = 0L,
        val quotaWindowId: String = "",
        val quotaWindowStartEpochMs: Long = 0L,
        val quotaLastUpdatedEpochMs: Long = 0L,
        val quotaResetGeneration: Long = 0L,
        val quotaExceeded: Boolean = false,
    )

    data class ConntrackPathObservation(
        val path: String,
        val existsObserved: Boolean,
        val openReadStatus: String,
        val rawError: String,
        val bytesRead: Int,
        val totalLines: Int,
        val relevantParsedFlows: Int,
        val sampleTuples: List<String>,
    )

    data class EnforcedClientPolicy(
        val mac: String,
        val isBlocked: Boolean,
        val blockReason: String? = null,
        val bandwidthLimitKbps: Int = 0,
        val dataLimitBytes: Long = 0L,
        val quotaResetPeriod: QuotaResetPeriod = QuotaResetPeriod.MANUAL,
    ) {
        val isQuotaOnlyBlock: Boolean
            get() = isBlocked && blockReason == "Data limit reached"

        val isNonQuotaBlocked: Boolean
            get() = isBlocked && !isQuotaOnlyBlock
    }

    internal data class PacketMeta(
        val version: Int,
        val protocol: Int,
        val srcIp: String,
        val dstIp: String,
        val srcPort: Int,
        val dstPort: Int,
        val length: Int,
        val isSmallControlPacket: Boolean,
        val isNonInitialFragment: Boolean = false,
        val isTcpSyn: Boolean = false,
        val isTcpFinOrRst: Boolean = false,
        val isTcpAckOnly: Boolean = false,
    ) {
        @Volatile
        internal var resolvedAttribution: PacketAttribution? = null
    }

    internal data class PacketAttribution(
        val mac: String?,
        val source: AttributionSource,
        val unattributedReason: UnattributedReason? = null,
        val fallbackAttempted: Boolean = false,
        val refreshedSnapshotHit: Boolean = false,
        val pinnedFlowHit: Boolean = false,
    )

    internal data class EvaluationDetail(
        val decision: PacketDecision,
        val paceDelayMs: Long = 0L,
        val policyVersion: Long = 1L,
        val domainDecision: DomainPacketDecision? = null,
        val heldForDnsRetry: Boolean = false,
        val vpnGateDropped: Boolean = false,
    ) {
        val reason: String
            get() = when {
                vpnGateDropped -> "VPN_FAIL_CLOSED_GATE"
                heldForDnsRetry -> DomainDropOrSkipReason.DNS_RETRY_QUEUED.code
                domainDecision?.blocked == true -> domainDecision.reason.code
                decision == PacketDecision.DROP -> "BLOCKED_CLIENT_POLICY"
                decision == PacketDecision.DROP_AQM -> "AQM_SHAPING_DROP"
                decision == PacketDecision.RATE_LIMIT -> "RATE_LIMITED"
                domainDecision?.unknownOwnerClientRuleSkipped == true -> DomainDropOrSkipReason.DOMAIN_CLIENT_OWNER_UNKNOWN.code
                else -> "ALLOW"
            }

        val synthesizedDnsResponse: ByteArray?
            get() = domainDecision?.synthesizedDnsResponse
    }

    internal data class FlowKey(
        val version: Int = 4,
        val protocol: Int,
        val natPort: Int,
        val remoteIp: String,
        val remotePort: Int,
    )

    /**
     * Calibrated Token Bucket shaper for a single direction (Upload or Download) of a client.
     * - Rate: `limitKbps * 125.0` bytes/sec.
     * - Burst capacity: `max(4500 bytes, 100ms of rate)` so TCP initial windows pass cleanly.
     * - Non-blocking: computes the required pacing delay in milliseconds without sleeping.
     */
    internal class TokenBucket(limitKbps: Int) {
        @Volatile
        var currentKbps: Int = limitKbps
            private set

        @Volatile
        private var rateBytesPerSec: Double = maxOf(1000.0, (limitKbps * 1000.0) / 8.0)

        @Volatile
        private var maxBurstBytes: Double = maxOf(4500.0, rateBytesPerSec * 0.10)

        private var tokens: Double = maxBurstBytes
        private var lastRefillNs: Long = System.nanoTime()

        fun updateRate(newLimitKbps: Int) {
            if (currentKbps == newLimitKbps) return
            synchronized(this) {
                currentKbps = newLimitKbps
                rateBytesPerSec = maxOf(1000.0, (newLimitKbps * 1000.0) / 8.0)
                maxBurstBytes = maxOf(4500.0, rateBytesPerSec * 0.10)
                tokens = min(tokens, maxBurstBytes)
            }
        }

        /**
         * Returns:
         * - `0L` if packet passes immediately within burst tokens
         * - `> 0L` (milliseconds to pace in per-client queue) if packet was shaped
         * - `-1L` if virtual queue backlog exceeds [maxQueueDelayMs] and packet must be AQM-dropped
         */
        fun consume(
            packetBytes: Int,
            isSmallControlPacket: Boolean,
            maxQueueDelayMs: Long,
        ): Long {
            val waitMs: Long
            synchronized(this) {
                val nowNs = System.nanoTime()
                val elapsedSec = ((nowNs - lastRefillNs).coerceAtLeast(0L)) / 1_000_000_000.0
                lastRefillNs = nowNs

                tokens = min(maxBurstBytes, tokens + elapsedSec * rateBytesPerSec)
                if (tokens >= packetBytes) {
                    tokens -= packetBytes
                    return 0L
                }

                val deficitBytes = packetBytes - tokens
                waitMs = ((deficitBytes / rateBytesPerSec) * 1000.0).toLong()
                if (waitMs > maxQueueDelayMs && !isSmallControlPacket) {
                    // CoDel/Token-Bucket AQM drop: signals TCP sender to reduce cwnd immediately
                    return -1L
                }
                tokens -= packetBytes
            }
            return waitMs.coerceAtLeast(1L)
        }
    }

    /**
     * Bounded per-client packet queue for non-blocking pacing so shaping Client A never stalls Client B.
     */
    internal class QueuedPacedPacket(
        val mac: String,
        val isUpload: Boolean,
        val data: ByteArray,
        val length: Int,
        val releaseAtMonoNs: Long,
        val policyVersionAtEnqueue: Long,
        val targetFd: FileDescriptor?,
    )

    internal class ClientPacingQueue(val mac: String) {
        val packets = ConcurrentLinkedQueue<QueuedPacedPacket>()
        val queuedCount = AtomicInteger(0)
        val queuedBytes = AtomicInteger(0)

        fun tryEnqueue(pkt: QueuedPacedPacket): Boolean {
            while (true) {
                val curCount = queuedCount.get()
                val curBytes = queuedBytes.get()
                if (curCount >= MAX_QUEUED_PACKETS_PER_CLIENT ||
                    curBytes + pkt.length > MAX_QUEUED_BYTES_PER_CLIENT
                ) {
                    return false
                }
                if (queuedCount.compareAndSet(curCount, curCount + 1)) {
                    queuedBytes.addAndGet(pkt.length)
                    packets.add(pkt)
                    return true
                }
            }
        }

        fun pollIfDue(nowNs: Long): QueuedPacedPacket? {
            val head = packets.peek() ?: return null
            if (head.releaseAtMonoNs > nowNs) return null
            val removed = packets.poll() ?: return null
            queuedCount.decrementAndGet()
            queuedBytes.addAndGet(-removed.length)
            return removed
        }

        fun drainAll(): List<QueuedPacedPacket> {
            val drained = ArrayList<QueuedPacedPacket>()
            while (true) {
                val item = packets.poll() ?: break
                queuedCount.decrementAndGet()
                queuedBytes.addAndGet(-item.length)
                drained.add(item)
            }
            return drained
        }
    }

    private val running = AtomicBoolean(false)

    @Volatile
    var datapathMode: DatapathMode = DatapathMode.INACTIVE
        private set

    @Volatile
    var activeUpstreamName: String = ""
        private set

    @Volatile
    var activeDownstreamName: String = ""
        private set

    @Volatile
    var fallbackReason: String? = null
        private set

    private var engineEndPfd: ParcelFileDescriptor? = null
    private var datapathEndPfd: ParcelFileDescriptor? = null
    private var uploadThread: Thread? = null
    private var downloadThread: Thread? = null
    private var pacingExecutor: ScheduledExecutorService? = null

    private val countersByMac = ConcurrentHashMap<String, ClientTrafficCounters>()
    private val ipToMac = ConcurrentHashMap<String, String>()
    private val macToIps = ConcurrentHashMap<String, MutableSet<String>>()
    private val lastLoggedClientMap = ConcurrentHashMap<String, String>()

    private val policiesByMac = ConcurrentHashMap<String, EnforcedClientPolicy>()
    private val policiesByIp = ConcurrentHashMap<String, EnforcedClientPolicy>()
    private val activeConnectedMacs = ConcurrentHashMap.newKeySet<String>()

    private val uploadBucketsByMac = ConcurrentHashMap<String, TokenBucket>()
    private val downloadBucketsByMac = ConcurrentHashMap<String, TokenBucket>()
    private val pacingQueuesByMac = ConcurrentHashMap<String, ClientPacingQueue>()

    private val quotaRecordsByMac = ConcurrentHashMap<String, ClientQuotaRecord>()
    private val quotaLocksByMac = ConcurrentHashMap<String, Any>()
    private val quotaLoadedFromDisk = AtomicBoolean(false)
    private val lastQuotaCheckpointFlushMs = AtomicLong(0L)
    private val unflushedQuotaBytes = AtomicLong(0L)

    @Volatile
    var quotaCheckpointFile: File = File(DataQuota.DEFAULT_CHECKPOINT_FILE_PATH)

    @Volatile
    var quotaClockMillisProvider: () -> Long = { System.currentTimeMillis() }

    @Volatile
    var quotaZoneIdProvider: () -> java.time.ZoneId = { java.time.ZoneId.systemDefault() }

    private val flowToMacCache = ConcurrentHashMap<FlowKey, String>()
    private val flowTimestamps = ConcurrentHashMap<FlowKey, Long>()
    private const val FLOW_TTL_MS = 60_000L
    private val sampleLogTimestamps = ConcurrentHashMap<String, Long>()

    val totalUploadPackets = AtomicLong(0L)
    val totalDownloadPackets = AtomicLong(0L)
    val unmatchedPackets = AtomicLong(0L)
    val postNatUnmatchedPackets = AtomicLong(0L)
    val unknownForwardedBytes = AtomicLong(0L)

    val totalEligiblePackets = AtomicLong(0L)
    val totalEligibleBytes = AtomicLong(0L)
    val totalAttributedPackets = AtomicLong(0L)
    val totalAttributedBytes = AtomicLong(0L)

    val directAttributedPackets = AtomicLong(0L)
    val directAttributedBytes = AtomicLong(0L)
    val bpfAttributedPackets = AtomicLong(0L)
    val bpfAttributedBytes = AtomicLong(0L)
    val conntrackAttributedPackets = AtomicLong(0L)
    val conntrackAttributedBytes = AtomicLong(0L)

    val unattributedPacketsByReason = ConcurrentHashMap<UnattributedReason, AtomicLong>()
    val unattributedBytesByReason = ConcurrentHashMap<UnattributedReason, AtomicLong>()

    val ipv4EligiblePackets = AtomicLong(0L)
    val ipv4EligibleBytes = AtomicLong(0L)
    val ipv4AttributedPackets = AtomicLong(0L)
    val ipv4AttributedBytes = AtomicLong(0L)
    val ipv4UnattributedPackets = AtomicLong(0L)
    val ipv4UnattributedBytes = AtomicLong(0L)

    val ipv6EligiblePackets = AtomicLong(0L)
    val ipv6EligibleBytes = AtomicLong(0L)
    val ipv6AttributedPackets = AtomicLong(0L)
    val ipv6AttributedBytes = AtomicLong(0L)
    val ipv6UnattributedPackets = AtomicLong(0L)
    val ipv6UnattributedBytes = AtomicLong(0L)

    val tcpEligiblePackets = AtomicLong(0L)
    val tcpEligibleBytes = AtomicLong(0L)
    val tcpAttributedPackets = AtomicLong(0L)
    val tcpAttributedBytes = AtomicLong(0L)
    val tcpUnattributedPackets = AtomicLong(0L)
    val tcpUnattributedBytes = AtomicLong(0L)

    val udpEligiblePackets = AtomicLong(0L)
    val udpEligibleBytes = AtomicLong(0L)
    val udpAttributedPackets = AtomicLong(0L)
    val udpAttributedBytes = AtomicLong(0L)
    val udpUnattributedPackets = AtomicLong(0L)
    val udpUnattributedBytes = AtomicLong(0L)

    val icmpEligiblePackets = AtomicLong(0L)
    val icmpEligibleBytes = AtomicLong(0L)
    val icmpAttributedPackets = AtomicLong(0L)
    val icmpAttributedBytes = AtomicLong(0L)
    val icmpUnattributedPackets = AtomicLong(0L)
    val icmpUnattributedBytes = AtomicLong(0L)

    val otherProtoEligiblePackets = AtomicLong(0L)
    val otherProtoEligibleBytes = AtomicLong(0L)
    val otherProtoAttributedPackets = AtomicLong(0L)
    val otherProtoAttributedBytes = AtomicLong(0L)
    val otherProtoUnattributedPackets = AtomicLong(0L)
    val otherProtoUnattributedBytes = AtomicLong(0L)

    val uploadEligiblePackets = AtomicLong(0L)
    val uploadEligibleBytes = AtomicLong(0L)
    val uploadAttributedPackets = AtomicLong(0L)
    val uploadAttributedBytes = AtomicLong(0L)
    val uploadUnattributedPackets = AtomicLong(0L)
    val uploadUnattributedBytes = AtomicLong(0L)

    val downloadEligiblePackets = AtomicLong(0L)
    val downloadEligibleBytes = AtomicLong(0L)
    val downloadAttributedPackets = AtomicLong(0L)
    val downloadAttributedBytes = AtomicLong(0L)
    val downloadUnattributedPackets = AtomicLong(0L)
    val downloadUnattributedBytes = AtomicLong(0L)

    val conntrackFallbackAttemptedCount = AtomicLong(0L)
    val conntrackFallbackSucceededCount = AtomicLong(0L)
    val conntrackFallbackFailedCount = AtomicLong(0L)
    val conntrackPermissionDeniedCount = AtomicLong(0L)
    val conntrackBackoffSkippedCount = AtomicLong(0L)

    const val DEFAULT_CONNTRACK_UNAVAILABLE_BACKOFF_MS = 300_000L

    @Volatile
    var conntrackUnavailableBackoffMs: Long = DEFAULT_CONNTRACK_UNAVAILABLE_BACKOFF_MS

    @Volatile
    var conntrackClockMillisProvider: () -> Long = { System.currentTimeMillis() }

    @Volatile
    private var conntrackBackoffUntilMs: Long = 0L

    val postRefreshAttributedPackets = AtomicLong(0L)
    val postRefreshAttributedBytes = AtomicLong(0L)

    val ambiguousOrStaleLookups = AtomicLong(0L)
    val localControlPackets = AtomicLong(0L)
    val localControlBytes = AtomicLong(0L)
    val unsupportedOrFragmentPackets = AtomicLong(0L)

    // Phase D (`v0.10.5-debug`) state & diagnostics counters
    internal data class VerifiedFlowPin(
        val flowKey: TranslatedFlowKey,
        val verifiedMac: String,
        val originalClientIp: String,
        val sessionGeneration: Long,
        val bindingGeneration: Long,
        val pinnedAtMonoMs: Long,
        var lastSeenMonoMs: Long,
    )

    const val MAX_VERIFIED_FLOW_PINS = 2_048
    const val VERIFIED_FLOW_PIN_TTL_MS = 120_000L
    private const val MAX_PHASE_D_TRANSITION_EVENTS = 128
    private const val MAX_PHASE_D_LIFECYCLE_EVENTS = 64
    private const val MAX_PHASE_D_TEST_MARKERS = 64

    @Volatile
    var phaseDMode: PhaseDEnforcementMode = PhaseDEnforcementMode.DIAGNOSTIC
        private set

    private val verifiedFlowPinsLock = Any()
    private val verifiedFlowPins = object : LinkedHashMap<TranslatedFlowKey, VerifiedFlowPin>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<TranslatedFlowKey, VerifiedFlowPin>?): Boolean {
            return size > MAX_VERIFIED_FLOW_PINS
        }
    }

    private val phaseDEventsLock = Any()
    private val policyTransitionSequence = AtomicLong(0L)
    private val interfaceLifecycleSequence = AtomicLong(0L)
    private val deliveryTestMarkerSequence = AtomicLong(0L)
    private val policyTransitionEvents = ArrayDeque<PhaseDPolicyTransitionEvent>()
    private val interfaceLifecycleEvents = ArrayDeque<PhaseDInterfaceLifecycleEvent>()
    private val deliveryTestMarkers = ArrayDeque<PhaseDDeliveryTestMarker>()

    @Volatile
    private var lastObservedLifecycleState: PhaseDInterfaceLifecycleState =
        PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES

    val unknownForwardedAfterBlockPackets = AtomicLong(0L)
    val unknownForwardedAfterBlockBytes = AtomicLong(0L)
    val unknownPostBlockByProtocolAndDirection = ConcurrentHashMap<String, AtomicLong>()
    val unknownPostBlockBytesByProtocolAndDirection = ConcurrentHashMap<String, AtomicLong>()

    val establishedTcpMissingFromBpfPackets = AtomicLong(0L)
    val establishedTcpMissingFromBpfBytes = AtomicLong(0L)
    val establishedTcpPinnedMatchedPackets = AtomicLong(0L)
    val establishedTcpPinnedMatchedBytes = AtomicLong(0L)
    val tcpKeepaliveOrAckOnlyPackets = AtomicLong(0L)
    val tcpSynPacketsSeen = AtomicLong(0L)
    val tcpFinOrRstPacketsSeen = AtomicLong(0L)
    val udp443PostBlockUnattributedPackets = AtomicLong(0L)
    val udp443PostBlockUnattributedBytes = AtomicLong(0L)
    val udp53PostBlockUnattributedPackets = AtomicLong(0L)
    val udp53PostBlockUnattributedBytes = AtomicLong(0L)
    val pinnedFlowHitsInDiagnosticMode = AtomicLong(0L)
    val pinnedFlowEnforcedDropsInEnforcementMode = AtomicLong(0L)

    val bpfAttributor = NatFlowAttributor()
    val bpfReader = BpfMapReader(attributor = bpfAttributor)
    val deepTupleTracker = DeepTupleDiagnosticsTracker()

    /**
     * Exclusive Blocking Mode (`v0.10.8-debug`) enforcement gate:
     * - `true` when `effectiveMode == BlockingMode.BPF_NAT_VPN` and not in `RECOVERY_REQUIRED`.
     * - `false` when `effectiveMode == BlockingMode.SOFTAP_MAC_BLOCK` or `RECOVERY_REQUIRED` so
     *   two whole-client packet-blocking engines are NEVER active simultaneously, while read-only BPF telemetry
     *   and shared domain filtering continue.
     */
    @Volatile
    var bpfNatVpnEnforcementEnabled: Boolean = true

    // v0.10.9-debug Feature A2: Bounded DNS Attribution Retry Queue
    const val MAX_PENDING_DNS_RETRY_PACKETS = 128
    const val MAX_PENDING_DNS_RETRY_BYTES = 256 * 1024
    const val DEFAULT_DNS_RETRY_MAX_WAIT_MS = 200L
    const val MIN_DNS_RETRY_MAX_WAIT_MS = 150L
    const val MAX_DNS_RETRY_MAX_WAIT_MS = 300L

    @Volatile
    var dnsAttributionRetryEnabled: Boolean = false
        private set

    @Volatile
    var dnsRetryMaxWaitMs: Long = DEFAULT_DNS_RETRY_MAX_WAIT_MS
        private set

    internal class PendingDnsRetryPacket(
        val meta: PacketMeta,
        val packetBytes: ByteArray,
        val length: Int,
        val enqueuedAtMonoMs: Long,
        val deadlineMonoMs: Long,
        val sessionGeneration: Long,
        val bindingGeneration: Long,
        val tunFd: FileDescriptor? = null,
        val proxyFd: FileDescriptor? = null,
        val onResolvedAction: ((PacketDecision, DomainPacketDecision?, String?) -> Unit)? = null,
    )

    private val pendingDnsRetryLock = Any()
    private val pendingDnsRetryQueue = ArrayDeque<PendingDnsRetryPacket>()
    private val pendingDnsRetryBytes = AtomicInteger(0)

    // v0.10.9-debug Feature B2: Fail-Closed VPN Forwarding Gate
    @Volatile
    var vpnForwardingGateClosed: Boolean = false
        private set

    @Volatile
    var vpnFailClosedReason: String = ""
        private set

    val vpnFailClosedDroppedPackets = AtomicLong(0L)
    val vpnFailClosedDroppedBytes = AtomicLong(0L)

    init {
        bpfAttributor.onSnapshotPublished = { snap ->
            for ((ipv6Addr, verifiedMac) in snap.ipv6ClientBindings) {
                if (verifiedMac in activeConnectedMacs) {
                    bindClientIp(verifiedMac, ipv6Addr)
                }
            }
            if (deepTupleDiagnosticsEnabled || bpfRefreshOnMissEnabled) {
                deepTupleTracker.onSnapshotPublished(snap)
            }
            recordSnapshotFlowsInVerifiedPinCache(snap)
            val ready = (snap.collectionStatus == BpfCollectionStatus.OK || snap.collectionStatus == BpfCollectionStatus.EMPTY_VALID) &&
                snap.resolvedDownstreamIfIndex > 0 && snap.resolvedUpstreamIfIndex > 0
            if (ready) {
                maybeRecordInterfaceLifecycleState(
                    PhaseDInterfaceLifecycleState.ATTRIBUTION_READY,
                    "BPF snapshot seq=${snap.snapshotSequence} ready (downIfIndex=${snap.resolvedDownstreamIfIndex}, upIfIndex=${snap.resolvedUpstreamIfIndex})",
                )
            }
            if (dnsAttributionRetryEnabled) {
                val nowMono = if (snap.collectedAtMonotonicMs > 0L) snap.collectedAtMonotonicMs else bpfAttributor.monotonicClockMs()
                processPendingDnsAttributionRetries(nowMono)
            }
        }
    }

    internal fun recordSnapshotFlowsInVerifiedPinCache(snap: NatFlowSnapshot) {
        if (snap.flowsByTuple.isEmpty()) return
        val nowMono = if (snap.collectedAtMonotonicMs > 0L) snap.collectedAtMonotonicMs else bpfAttributor.monotonicClockMs()
        synchronized(verifiedFlowPinsLock) {
            for ((key, mapping) in snap.flowsByTuple) {
                if (mapping.verifiedMac.isBlank() || mapping.verifiedMac !in activeConnectedMacs) continue
                val existing = verifiedFlowPins[key]
                verifiedFlowPins[key] = VerifiedFlowPin(
                    flowKey = key,
                    verifiedMac = mapping.verifiedMac,
                    originalClientIp = mapping.origClientIp,
                    sessionGeneration = snap.sessionGeneration,
                    bindingGeneration = snap.bindingGeneration,
                    pinnedAtMonoMs = existing?.pinnedAtMonoMs ?: nowMono,
                    lastSeenMonoMs = nowMono,
                )
            }
        }
    }

    internal fun pinVerifiedBpfFlow(
        flowKey: TranslatedFlowKey,
        verifiedMac: String,
        originalClientIp: String,
        sessionGen: Long = bpfAttributor.currentSessionGeneration,
        bindingGen: Long = bpfAttributor.currentBindingGeneration,
        nowMonoMs: Long = bpfAttributor.monotonicClockMs(),
    ) {
        synchronized(verifiedFlowPinsLock) {
            val existing = verifiedFlowPins[flowKey]
            verifiedFlowPins[flowKey] = VerifiedFlowPin(
                flowKey = flowKey,
                verifiedMac = verifiedMac,
                originalClientIp = originalClientIp,
                sessionGeneration = sessionGen,
                bindingGeneration = bindingGen,
                pinnedAtMonoMs = existing?.pinnedAtMonoMs ?: nowMonoMs,
                lastSeenMonoMs = nowMonoMs,
            )
        }
    }

    internal fun invalidateVerifiedFlowPin(flowKey: TranslatedFlowKey) {
        synchronized(verifiedFlowPinsLock) {
            verifiedFlowPins.remove(flowKey)
        }
    }

    internal fun invalidateVerifiedFlowPinsForMac(mac: String): Int {
        val clean = mac.uppercase().trim()
        var removed = 0
        synchronized(verifiedFlowPinsLock) {
            val it = verifiedFlowPins.entries.iterator()
            while (it.hasNext()) {
                val entry = it.next()
                if (entry.value.verifiedMac == clean) {
                    it.remove()
                    removed++
                }
            }
        }
        return removed
    }

    internal fun lookupVerifiedFlowPin(
        flowKey: TranslatedFlowKey,
        nowMonoMs: Long = bpfAttributor.monotonicClockMs(),
    ): VerifiedFlowPin? {
        val curSessionGen = bpfAttributor.currentSessionGeneration
        synchronized(verifiedFlowPinsLock) {
            val pin = verifiedFlowPins[flowKey] ?: return null
            if (pin.sessionGeneration != curSessionGen ||
                (nowMonoMs - pin.lastSeenMonoMs) > VERIFIED_FLOW_PIN_TTL_MS ||
                pin.verifiedMac !in activeConnectedMacs
            ) {
                verifiedFlowPins.remove(flowKey)
                return null
            }
            val currentBoundMac = ipToMac[pin.originalClientIp]
            if (currentBoundMac != pin.verifiedMac) {
                verifiedFlowPins.remove(flowKey)
                return null
            }
            pin.lastSeenMonoMs = nowMonoMs
            return pin
        }
    }

    internal fun getVerifiedFlowPinCacheSize(): Int =
        synchronized(verifiedFlowPinsLock) { verifiedFlowPins.size }

    internal fun recordPolicyTransitionEvent(
        transitionType: String,
        mac: String,
        verifiedFlows: Int = getAttributedFlowCount(mac.takeIf { it.length == 17 }),
        queueInvalidated: Int = 0,
        detail: String = "",
    ): PhaseDPolicyTransitionEvent {
        val cleanMac = mac.uppercase().trim()
        val nowWall = conntrackClockMillisProvider()
        val nowMono = System.nanoTime() / 1_000_000L
        val counters = if (cleanMac.length == 17 && cleanMac != "00:00:00:00:00:00") {
            countersByMac.getOrPut(cleanMac) { ClientTrafficCounters(cleanMac) }
        } else {
            null
        }
        val policyGen = counters?.policyVersion?.get() ?: 1L
        if (counters != null) {
            counters.lastTransitionType = transitionType
            counters.lastTransitionAtWallMs = nowWall
            counters.lastTransitionAtMonoMs = nowMono
            counters.verifiedFlowsAtTransition = verifiedFlows
        }
        val event = PhaseDPolicyTransitionEvent(
            eventSequence = policyTransitionSequence.incrementAndGet(),
            timestampMonoMs = nowMono,
            timestampEpochMs = nowWall,
            transitionType = transitionType,
            clientMac = cleanMac.ifBlank { "GLOBAL" },
            clientIp = ipToMac.entries.firstOrNull { !it.key.contains(':') && it.value == cleanMac }?.key.orEmpty(),
            policyGeneration = policyGen,
            sessionGeneration = bpfAttributor.currentSessionGeneration,
            bindingGeneration = bpfAttributor.currentBindingGeneration,
            snapshotSequence = bpfAttributor.currentSnapshot().snapshotSequence,
            verifiedFlowsAtTransition = verifiedFlows,
            queuedPacketsPurged = queueInvalidated,
            detail = detail,
        )
        synchronized(phaseDEventsLock) {
            policyTransitionEvents.addLast(event)
            while (policyTransitionEvents.size > MAX_PHASE_D_TRANSITION_EVENTS) {
                policyTransitionEvents.removeFirst()
            }
        }
        if (transitionType == "ALLOW_TO_BLOCK" || transitionType == "QUOTA_EXHAUSTED") {
            recordDeliveryTestMarker(
                markerType = "POLICY_ACTIVATED",
                mac = cleanMac,
                note = "$transitionType ($detail)".trim(),
            )
        }
        return event
    }

    internal fun maybeRecordInterfaceLifecycleState(
        state: PhaseDInterfaceLifecycleState,
        reason: String,
        force: Boolean = false,
    ) {
        if (!force && lastObservedLifecycleState == state) return
        lastObservedLifecycleState = state
        val snap = bpfAttributor.currentSnapshot()
        val nowMono = System.nanoTime() / 1_000_000L
        val event = PhaseDInterfaceLifecycleEvent(
            eventSequence = interfaceLifecycleSequence.incrementAndGet(),
            timestampMonoMs = nowMono,
            state = state.name,
            downstreamIface = snap.downstreamIface.ifBlank { activeDownstreamName },
            upstreamIface = snap.upstreamIface.ifBlank { activeUpstreamName },
            osDownstreamIfIndex = snap.resolvedDownstreamIfIndex.takeIf { it > 0 } ?: snap.downstreamIfIndex.takeIf { it > 0 },
            osUpstreamIfIndex = snap.resolvedUpstreamIfIndex.takeIf { it > 0 } ?: snap.upstreamIfIndex.takeIf { it > 0 },
            inferredDownstreamIfIndex = snap.inferredDownstreamIfIndex,
            inferredUpstreamIfIndex = snap.inferredUpstreamIfIndex,
            sessionGeneration = bpfAttributor.currentSessionGeneration,
        )
        synchronized(phaseDEventsLock) {
            interfaceLifecycleEvents.addLast(event)
            while (interfaceLifecycleEvents.size > MAX_PHASE_D_LIFECYCLE_EVENTS) {
                interfaceLifecycleEvents.removeFirst()
            }
        }
    }

    fun recordDeliveryTestMarker(
        markerType: String,
        mac: String = "",
        note: String = "",
    ): PhaseDDeliveryTestMarker {
        val nowWall = conntrackClockMillisProvider()
        val nowMono = System.nanoTime() / 1_000_000L
        val cleanMac = mac.uppercase().trim()
        val marker = PhaseDDeliveryTestMarker(
            markerSequence = deliveryTestMarkerSequence.incrementAndGet(),
            markerType = markerType.uppercase().trim().ifBlank { "TEST_MARKER" },
            timestampMonoMs = nowMono,
            timestampEpochMs = nowWall,
            phaseDMode = phaseDMode.name,
            sessionGeneration = bpfAttributor.currentSessionGeneration,
            snapshotSequence = bpfAttributor.currentSnapshot().snapshotSequence,
            blockedClientsCount = policiesByMac.values.count { it.isNonQuotaBlocked },
            quotaExhaustedClientsCount = quotaRecordsByMac.values.count { it.isQuotaExceeded },
            note = if (cleanMac.isNotBlank()) "[$cleanMac] ${note.trim()}".trim() else note.trim(),
        )
        synchronized(phaseDEventsLock) {
            deliveryTestMarkers.addLast(marker)
            while (deliveryTestMarkers.size > MAX_PHASE_D_TEST_MARKERS) {
                deliveryTestMarkers.removeFirst()
            }
        }
        SessionLog.info(
            "PhaseDMarker: seq=${marker.markerSequence} type=${marker.markerType} mac=${cleanMac.ifBlank { "ALL" }} mode=${marker.phaseDMode} note=${marker.note}",
        )
        return marker
    }

    /**
     * Configures the Phase D operating mode (`DIAGNOSTIC` default vs `EXPERIMENTAL_ENFORCEMENT` opt-in)
     * at runtime without restarting the tethering service or rebuilding the APK.
     */
    @Synchronized
    fun configurePhaseDMode(mode: PhaseDEnforcementMode) {
        val previous = phaseDMode
        phaseDMode = mode
        if (previous != mode) {
            recordPolicyTransitionEvent(
                transitionType = "PHASE_D_MODE_CHANGED",
                mac = "GLOBAL",
                verifiedFlows = getAttributedFlowCount(null),
                queueInvalidated = 0,
                detail = "${previous.name} -> ${mode.name}",
            )
            if (mode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) {
                if (!bpfRefreshOnMissEnabled) {
                    bpfRefreshOnMissEnabled = true
                    bpfReader.refreshOnMissCooldownMs = 150L
                }
                for ((mac, pol) in policiesByMac) {
                    val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }
                    reconcileQueuedPacketsForPolicyChange(mac, pol, counters)
                }
            }
            SessionLog.info("PhaseD: mode changed ${previous.name} -> ${mode.name}")
        }
    }

    internal fun isAnyClientCurrentlyBlockedOrQuotaExhausted(): Boolean {
        for ((mac, pol) in policiesByMac) {
            if (pol.isBlocked) return true
            if (quotaRecordsByMac[mac]?.isQuotaExceeded == true) return true
        }
        for (q in quotaRecordsByMac.values) {
            if (q.isQuotaExceeded) return true
        }
        return false
    }

    @Volatile
    var isExperimentalBpfEnabled: Boolean = true
        private set

    @Volatile
    var bpfPollIntervalMs: Long = BpfMapReader.DEFAULT_POLL_INTERVAL_MS
        private set

    /**
     * Phase B controlled experiment toggle: OFF by default.
     * When enabled, an unattributed packet due to `TUPLE_NOT_PRESENT` or `SNAPSHOT_STALE`
     * triggers a non-blocking, single-flight, cooldown-bounded async BPF snapshot refresh.
     */
    @Volatile
    var bpfRefreshOnMissEnabled: Boolean = false
        private set

    /**
     * Phase C deep tuple & owner diagnostics toggle: OFF by default (`v0.10.4-debug`).
     */
    @Volatile
    var deepTupleDiagnosticsEnabled: Boolean = false
        private set

    @Volatile
    var unknownOwnerPacketPolicy: String = "ALLOW"
        private set

    @Volatile
    var isConntrackAvailable: Boolean = false
        private set

    @Volatile
    var lastConntrackReadStatus: String = "NOT_TESTED"
        private set

    @Volatile
    var lastConntrackPollLatencyMs: Long = 0L
        private set

    @Volatile
    var lastConntrackParsedFlows: Int = 0
        private set

    @Volatile
    var isMultiClientDegraded: Boolean = false
        private set

    @Volatile
    private var lastConntrackResolveMs: Long = 0L

    val isAttached: Boolean
        get() = running.get() && datapathMode == DatapathMode.USERSPACE_PROXY

    fun getVerifiedClientBindingsSnapshot(): Pair<Map<String, String>, Set<String>> {
        return HashMap(ipToMac) to HashSet(activeConnectedMacs)
    }

    fun getActiveConnectedMacsSnapshot(): Set<String> = HashSet(activeConnectedMacs)

    fun getBoundIpsForMac(mac: String): Set<String> =
        macToIps[mac.uppercase().trim()]?.toSet().orEmpty()

    fun getClientPolicy(mac: String): EnforcedClientPolicy? =
        policiesByMac[mac.uppercase().trim()]

    /**
     * Configures the experimental BPF NAT flow attribution reader.
     */
    @Synchronized
    fun configureExperimentalBpf(
        enabled: Boolean,
        pollIntervalMs: Long = BpfMapReader.DEFAULT_POLL_INTERVAL_MS,
        downstreamIface: String = activeDownstreamName,
        upstreamIface: String = activeUpstreamName,
    ) {
        isExperimentalBpfEnabled = enabled
        bpfPollIntervalMs = pollIntervalMs.coerceIn(
            BpfMapReader.MIN_POLL_INTERVAL_MS,
            BpfMapReader.MAX_POLL_INTERVAL_MS,
        )
        bpfAttributor.syncInterfaces(downstreamIface, upstreamIface)
        bpfReader.configure(
            enabled = enabled,
            intervalMs = bpfPollIntervalMs,
            sessionActive = running.get() && datapathMode == DatapathMode.USERSPACE_PROXY,
        )
        if (!enabled) {
            maybeRecordInterfaceLifecycleState(
                PhaseDInterfaceLifecycleState.DEGRADED_OR_STOPPED,
                "Experimental BPF disabled",
            )
        } else if (downstreamIface.isBlank() || upstreamIface.isBlank()) {
            maybeRecordInterfaceLifecycleState(
                PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES,
                "Waiting for downstream/upstream interface names",
            )
        } else {
            maybeRecordInterfaceLifecycleState(
                PhaseDInterfaceLifecycleState.BINDING_INTERFACES,
                "Binding interfaces down=$downstreamIface up=$upstreamIface",
            )
        }
    }

    /**
     * Configures the Phase B controlled async refresh-on-miss experiment (OFF by default).
     */
    @Synchronized
    fun configureBpfRefreshOnMiss(
        enabled: Boolean,
        cooldownMs: Long = BpfMapReader.DEFAULT_REFRESH_ON_MISS_COOLDOWN_MS,
    ) {
        bpfRefreshOnMissEnabled = enabled
        bpfReader.refreshOnMissCooldownMs = cooldownMs.coerceIn(100L, 10_000L)
        if (enabled) {
            bpfReader.resetDiagnosticCounters()
        }
    }

    /**
     * Configures the Phase C deep tuple & owner diagnostics tracker (OFF by default).
     */
    @Synchronized
    fun configureDeepTupleDiagnostics(
        enabled: Boolean,
        maxTrackedFlows: Int = DeepTupleDiagnosticsTracker.DEFAULT_MAX_TRACKED_FLOWS,
        maxSampleRecords: Int = DeepTupleDiagnosticsTracker.DEFAULT_MAX_SAMPLE_RECORDS,
        flowTtlMs: Long = DeepTupleDiagnosticsTracker.DEFAULT_FLOW_TTL_MS,
    ) {
        deepTupleDiagnosticsEnabled = enabled
        deepTupleTracker.maxTrackedFlows = maxTrackedFlows.coerceIn(16, 8_192)
        deepTupleTracker.maxSampleRecords = maxSampleRecords.coerceIn(16, 1_024)
        deepTupleTracker.flowTtlMs = flowTtlMs.coerceIn(1_000L, 600_000L)
        if (!enabled) {
            deepTupleTracker.reset()
        }
    }

    /**
     * Configures the v0.10.9-debug bounded DNS attribution retry queue (OFF by default).
     */
    @Synchronized
    fun configureDnsAttributionRetry(
        enabled: Boolean,
        maxWaitMs: Long = DEFAULT_DNS_RETRY_MAX_WAIT_MS,
    ) {
        val clampedWait = maxWaitMs.coerceIn(MIN_DNS_RETRY_MAX_WAIT_MS, MAX_DNS_RETRY_MAX_WAIT_MS)
        val wasEnabled = dnsAttributionRetryEnabled
        dnsAttributionRetryEnabled = enabled
        dnsRetryMaxWaitMs = clampedWait
        if (wasEnabled && !enabled) {
            cancelAllPendingDnsRetries("DNS_RETRY_DISABLED")
        }
    }

    /**
     * Sets the fail-closed VPN forwarding gate (`v0.10.9-debug` Feature B2).
     * While [closed] is true, outbound and inbound client data packets are dropped at the userspace
     * TUN gate so traffic can never silently bypass a disconnected VPN while the hotspot stays up.
     */
    fun setVpnForwardingGate(closed: Boolean, reason: String = "") {
        val prev = vpnForwardingGateClosed
        vpnForwardingGateClosed = closed
        vpnFailClosedReason = if (closed) reason.ifBlank { "VPN_WAITING_FOR_RECOVERY" } else ""
        if (closed) {
            clearPacingQueues()
            cancelAllPendingDnsRetries("VPN_FORWARDING_GATE_CLOSED")
            if (!prev) {
                SessionLog.warn(
                    "Datapath: VPN fail-closed forwarding gate CLOSED (reason=$vpnFailClosedReason) — client traffic blocked from bypassing VPN",
                )
            }
        } else if (prev) {
            SessionLog.info("Datapath: VPN fail-closed forwarding gate OPEN — forwarding resumed")
        }
    }

    /**
     * Invoked when the VPN upstream is rebound to [newHandle] after recovery (`v0.10.9-debug` Feature B2).
     * Clears stale NAT flow caches, bumps binding generation, and re-opens the fail-closed forwarding gate.
     */
    fun onVpnRebound(newHandle: Long) {
        clearFlowCache()
        cancelAllPendingDnsRetries("VPN_REBOUND")
        bpfAttributor.onClientBindingsUpdated()
        setVpnForwardingGate(closed = false, reason = "")
        SessionLog.info("Datapath: VPN rebound to network handle $newHandle; stale flow caches cleared and forwarding gate opened")
    }

    internal fun enqueuePendingDnsRetryPacket(
        meta: PacketMeta,
        rawPacket: ByteArray,
        rawLength: Int,
        tunFd: FileDescriptor? = null,
        proxyFd: FileDescriptor? = null,
        nowMonoMs: Long = bpfAttributor.monotonicClockMs(),
        onResolvedAction: ((PacketDecision, DomainPacketDecision?, String?) -> Unit)? = null,
    ): Boolean {
        val copy = rawPacket.copyOfRange(0, rawLength)
        synchronized(pendingDnsRetryLock) {
            if (pendingDnsRetryQueue.size >= MAX_PENDING_DNS_RETRY_PACKETS ||
                pendingDnsRetryBytes.get() + rawLength > MAX_PENDING_DNS_RETRY_BYTES
            ) {
                return false
            }
            val item = PendingDnsRetryPacket(
                meta = meta.copy(),
                packetBytes = copy,
                length = rawLength,
                enqueuedAtMonoMs = nowMonoMs,
                deadlineMonoMs = nowMonoMs + dnsRetryMaxWaitMs,
                sessionGeneration = bpfAttributor.currentSessionGeneration,
                bindingGeneration = bpfAttributor.currentBindingGeneration,
                tunFd = tunFd,
                proxyFd = proxyFd,
                onResolvedAction = onResolvedAction,
            )
            pendingDnsRetryQueue.addLast(item)
            pendingDnsRetryBytes.addAndGet(rawLength)
            return true
        }
    }

    fun getPendingDnsRetryQueueSize(): Int =
        synchronized(pendingDnsRetryLock) { pendingDnsRetryQueue.size }

    fun cancelAllPendingDnsRetries(reason: String = "SESSION_STOPPED"): Int {
        val drained: List<PendingDnsRetryPacket>
        synchronized(pendingDnsRetryLock) {
            if (pendingDnsRetryQueue.isEmpty()) return 0
            drained = pendingDnsRetryQueue.toList()
            pendingDnsRetryQueue.clear()
            pendingDnsRetryBytes.set(0)
        }
        for (pkt in drained) {
            DomainFilterEngine.dnsRetryCancelled.incrementAndGet()
            pkt.onResolvedAction?.invoke(PacketDecision.DROP, null, null)
        }
        return drained.size
    }

    /**
     * Re-evaluates held DNS queries after a fresh BPF snapshot publish or deadline tick (`D07`, `D08`).
     * Never blocks the TUN reader thread; each held DNS packet is resolved at most once.
     */
    fun processPendingDnsAttributionRetries(
        nowMonoMs: Long = bpfAttributor.monotonicClockMs(),
    ): Int {
        val snapshotToCheck: List<PendingDnsRetryPacket>
        synchronized(pendingDnsRetryLock) {
            if (pendingDnsRetryQueue.isEmpty()) return 0
            snapshotToCheck = pendingDnsRetryQueue.toList()
        }

        var processedCount = 0
        val currentSessionGen = bpfAttributor.currentSessionGeneration
        val currentBindingGen = bpfAttributor.currentBindingGeneration

        for (item in snapshotToCheck) {
            if (vpnForwardingGateClosed ||
                item.sessionGeneration != currentSessionGen ||
                item.bindingGeneration != currentBindingGen
            ) {
                val removed = synchronized(pendingDnsRetryLock) {
                    if (pendingDnsRetryQueue.remove(item)) {
                        pendingDnsRetryBytes.addAndGet(-item.length)
                        true
                    } else {
                        false
                    }
                }
                if (removed) {
                    DomainFilterEngine.dnsRetryCancelled.incrementAndGet()
                    if (vpnForwardingGateClosed) {
                        vpnFailClosedDroppedPackets.incrementAndGet()
                        vpnFailClosedDroppedBytes.addAndGet(item.length.toLong())
                    }
                    item.onResolvedAction?.invoke(PacketDecision.DROP, null, null)
                    processedCount++
                }
                continue
            }

            val retryAttr = resolveClientMacWithSource(item.meta, isUpload = true)
            val resolvedMac = retryAttr.mac
            val expired = nowMonoMs >= item.deadlineMonoMs

            if (resolvedMac == null && !expired) {
                // Still waiting within the bounded 150-300ms window
                continue
            }

            val removed = synchronized(pendingDnsRetryLock) {
                if (pendingDnsRetryQueue.remove(item)) {
                    pendingDnsRetryBytes.addAndGet(-item.length)
                    true
                } else {
                    false
                }
            }
            if (!removed) continue
            processedCount++

            if (resolvedMac != null) {
                DomainFilterEngine.dnsRetryResolved.incrementAndGet()
                val counters = countersByMac.getOrPut(resolvedMac) { ClientTrafficCounters(resolvedMac) }
                counters.lastSeenAt = System.currentTimeMillis()
                counters.seenPackets.incrementAndGet()
                counters.matchedPackets.incrementAndGet()
                when (retryAttr.source) {
                    AttributionSource.BPF_NAT -> {
                        bpfAttributedPackets.incrementAndGet()
                        bpfAttributedBytes.addAndGet(item.length.toLong())
                        counters.bpfAttributedPackets.incrementAndGet()
                        postRefreshAttributedPackets.incrementAndGet()
                        postRefreshAttributedBytes.addAndGet(item.length.toLong())
                    }
                    AttributionSource.DIRECT_IP -> {
                        directAttributedPackets.incrementAndGet()
                        directAttributedBytes.addAndGet(item.length.toLong())
                        counters.directAttributedPackets.incrementAndGet()
                    }
                    AttributionSource.CONNTRACK_PROCFS -> {
                        conntrackAttributedPackets.incrementAndGet()
                        conntrackAttributedBytes.addAndGet(item.length.toLong())
                        counters.conntrackAttributedPackets.incrementAndGet()
                    }
                    else -> {}
                }

                val policy = policiesByMac[resolvedMac]
                val quotaRecord = getQuotaRecord(resolvedMac)
                val wholeClientBlocked = bpfNatVpnEnforcementEnabled && (
                    policy?.isNonQuotaBlocked == true ||
                        (quotaRecord != null && quotaRecord.isQuotaExceeded) ||
                        (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT && policy?.isQuotaOnlyBlock == true)
                    )
                if (wholeClientBlocked) {
                    counters.droppedPackets.incrementAndGet()
                    counters.blockedDropPackets.incrementAndGet()
                    counters.policyVersionBlockedDrops.incrementAndGet()
                    counters.droppedBytes.addAndGet(item.length.toLong())
                    item.onResolvedAction?.invoke(PacketDecision.DROP, null, resolvedMac)
                    continue
                }

                val domainDecision = DomainFilterEngine.evaluateUploadPacket(
                    rawPacket = item.packetBytes,
                    length = item.length,
                    srcIp = item.meta.srcIp,
                    matchedMac = resolvedMac,
                    ownerVerified = true,
                    fromDedicatedHotspotTun = true,
                    isHostOriginated = false,
                    ownershipSource = retryAttr.source.name,
                )
                if (domainDecision.blocked) {
                    counters.droppedPackets.incrementAndGet()
                    counters.droppedBytes.addAndGet(item.length.toLong())
                    val synth = domainDecision.synthesizedDnsResponse
                    if (synth != null && synth.isNotEmpty() && item.tunFd != null) {
                        runCatching { writePacket(item.tunFd, synth, synth.size) }
                    }
                    item.onResolvedAction?.invoke(PacketDecision.DROP, domainDecision, resolvedMac)
                } else {
                    recordQuotaBytes(resolvedMac, item.length, isUpload = true, policy = policy)
                    counters.forwardedPackets.incrementAndGet()
                    counters.uploadForwardedPackets.incrementAndGet()
                    counters.txBytes.addAndGet(item.length.toLong())
                    if (item.proxyFd != null) {
                        runCatching { writePacket(item.proxyFd, item.packetBytes, item.length) }
                    }
                    item.onResolvedAction?.invoke(PacketDecision.ALLOW, domainDecision, resolvedMac)
                }
            } else {
                // Deadline expired and owner is still unknown/ambiguous -> fail-open for per-host rules (D08)
                DomainFilterEngine.dnsRetryTimeout.incrementAndGet()
                val fallbackDecision = DomainFilterEngine.evaluateUploadPacket(
                    rawPacket = item.packetBytes,
                    length = item.length,
                    srcIp = item.meta.srcIp,
                    matchedMac = null,
                    ownerVerified = false,
                    fromDedicatedHotspotTun = true,
                    isHostOriginated = false,
                    ownershipSource = "UNKNOWN_OWNER",
                    deferUnknownOwnerClientSkipForRetry = false,
                )
                if (fallbackDecision.blocked) {
                    val synth = fallbackDecision.synthesizedDnsResponse
                    if (synth != null && synth.isNotEmpty() && item.tunFd != null) {
                        runCatching { writePacket(item.tunFd, synth, synth.size) }
                    }
                    item.onResolvedAction?.invoke(PacketDecision.DROP, fallbackDecision, null)
                } else {
                    if (item.proxyFd != null) {
                        runCatching { writePacket(item.proxyFd, item.packetBytes, item.length) }
                    }
                    item.onResolvedAction?.invoke(PacketDecision.ALLOW, fallbackDecision, null)
                }
            }
        }
        return processedCount
    }

    /**
     * Resets ONLY the BPF/NAT attribution diagnostic counters while strictly preserving
     * all active client policies, connected bindings, token buckets, pacing queues,
     * per-client traffic counters, and persisted quota records.
     */
    fun resetAttributionDiagnosticsCounters() {
        unmatchedPackets.set(0L)
        postNatUnmatchedPackets.set(0L)
        unknownForwardedBytes.set(0L)
        totalEligiblePackets.set(0L)
        totalEligibleBytes.set(0L)
        totalAttributedPackets.set(0L)
        totalAttributedBytes.set(0L)
        directAttributedPackets.set(0L)
        directAttributedBytes.set(0L)
        bpfAttributedPackets.set(0L)
        bpfAttributedBytes.set(0L)
        conntrackAttributedPackets.set(0L)
        conntrackAttributedBytes.set(0L)
        unattributedPacketsByReason.clear()
        unattributedBytesByReason.clear()
        ipv4EligiblePackets.set(0L)
        ipv4EligibleBytes.set(0L)
        ipv4AttributedPackets.set(0L)
        ipv4AttributedBytes.set(0L)
        ipv4UnattributedPackets.set(0L)
        ipv4UnattributedBytes.set(0L)
        ipv6EligiblePackets.set(0L)
        ipv6EligibleBytes.set(0L)
        ipv6AttributedPackets.set(0L)
        ipv6AttributedBytes.set(0L)
        ipv6UnattributedPackets.set(0L)
        ipv6UnattributedBytes.set(0L)
        tcpEligiblePackets.set(0L)
        tcpEligibleBytes.set(0L)
        tcpAttributedPackets.set(0L)
        tcpAttributedBytes.set(0L)
        tcpUnattributedPackets.set(0L)
        tcpUnattributedBytes.set(0L)
        udpEligiblePackets.set(0L)
        udpEligibleBytes.set(0L)
        udpAttributedPackets.set(0L)
        udpAttributedBytes.set(0L)
        udpUnattributedPackets.set(0L)
        udpUnattributedBytes.set(0L)
        icmpEligiblePackets.set(0L)
        icmpEligibleBytes.set(0L)
        icmpAttributedPackets.set(0L)
        icmpAttributedBytes.set(0L)
        icmpUnattributedPackets.set(0L)
        icmpUnattributedBytes.set(0L)
        otherProtoEligiblePackets.set(0L)
        otherProtoEligibleBytes.set(0L)
        otherProtoAttributedPackets.set(0L)
        otherProtoAttributedBytes.set(0L)
        otherProtoUnattributedPackets.set(0L)
        otherProtoUnattributedBytes.set(0L)
        uploadEligiblePackets.set(0L)
        uploadEligibleBytes.set(0L)
        uploadAttributedPackets.set(0L)
        uploadAttributedBytes.set(0L)
        uploadUnattributedPackets.set(0L)
        uploadUnattributedBytes.set(0L)
        downloadEligiblePackets.set(0L)
        downloadEligibleBytes.set(0L)
        downloadAttributedPackets.set(0L)
        downloadAttributedBytes.set(0L)
        downloadUnattributedPackets.set(0L)
        downloadUnattributedBytes.set(0L)
        conntrackFallbackAttemptedCount.set(0L)
        conntrackFallbackSucceededCount.set(0L)
        conntrackFallbackFailedCount.set(0L)
        conntrackPermissionDeniedCount.set(0L)
        conntrackBackoffSkippedCount.set(0L)
        conntrackBackoffUntilMs = 0L
        lastConntrackResolveMs = 0L
        postRefreshAttributedPackets.set(0L)
        postRefreshAttributedBytes.set(0L)
        ambiguousOrStaleLookups.set(0L)
        localControlPackets.set(0L)
        localControlBytes.set(0L)
        unsupportedOrFragmentPackets.set(0L)
        unknownForwardedAfterBlockPackets.set(0L)
        unknownForwardedAfterBlockBytes.set(0L)
        unknownPostBlockByProtocolAndDirection.clear()
        unknownPostBlockBytesByProtocolAndDirection.clear()
        establishedTcpMissingFromBpfPackets.set(0L)
        establishedTcpMissingFromBpfBytes.set(0L)
        establishedTcpPinnedMatchedPackets.set(0L)
        establishedTcpPinnedMatchedBytes.set(0L)
        tcpKeepaliveOrAckOnlyPackets.set(0L)
        tcpSynPacketsSeen.set(0L)
        tcpFinOrRstPacketsSeen.set(0L)
        udp443PostBlockUnattributedPackets.set(0L)
        udp443PostBlockUnattributedBytes.set(0L)
        udp53PostBlockUnattributedPackets.set(0L)
        udp53PostBlockUnattributedBytes.set(0L)
        pinnedFlowHitsInDiagnosticMode.set(0L)
        pinnedFlowEnforcedDropsInEnforcementMode.set(0L)
        synchronized(phaseDEventsLock) {
            policyTransitionEvents.clear()
            interfaceLifecycleEvents.clear()
            deliveryTestMarkers.clear()
        }
        bpfAttributor.resetDiagnosticCounters()
        bpfReader.resetDiagnosticCounters()
        deepTupleTracker.reset()
        for (c in countersByMac.values) {
            c.policyBaselinePostNatUnmatched = 0L
            c.decisionsRecomputed.set(0L)
            c.staleAllowCacheHitsPrevented.set(0L)
            c.verifiedAllowedAfterBlockPackets.set(0L)
            c.verifiedAllowedAfterBlockBytes.set(0L)
            c.verifiedDroppedAfterBlockPackets.set(0L)
            c.verifiedDroppedAfterBlockBytes.set(0L)
            c.pinnedFlowEnforcedPackets.set(0L)
            c.pinnedFlowEnforcedBytes.set(0L)
        }
    }

    /**
     * Triggers an immediate on-demand BPF map collection cycle (off the packet path) and returns
     * the updated [BpfAttributionStatusReport].
     */
    fun collectBpfSnapshotNow(): BpfAttributionStatusReport {
        bpfReader.collectOnce(respectBackoff = false)
        return getBpfAttributionReport()
    }

    fun getBpfAttributionReport(): BpfAttributionStatusReport {
        val snap = bpfAttributor.currentSnapshot()
        val lastAttempt = bpfAttributor.lastAttemptDiagnostic()
        val nowMono = System.nanoTime() / 1_000_000L
        val ageMs = if (snap.collectedAtMonotonicMs > 0L) {
            (nowMono - snap.collectedAtMonotonicMs).coerceAtLeast(0L)
        } else {
            0L
        }
        val attemptAgeMs = if (lastAttempt.attemptAtMonotonicMs > 0L) {
            (nowMono - lastAttempt.attemptAtMonotonicMs).coerceAtLeast(0L)
        } else {
            0L
        }
        val hasRestrictivePolicy = policiesByMac.values.any {
            it.isBlocked || it.bandwidthLimitKbps > 0 || it.dataLimitBytes > 0L
        }
        val hasPublishedSnapshot = snap.collectedAtMonotonicMs > 0L &&
            (snap.collectionStatus == BpfCollectionStatus.OK || snap.collectionStatus == BpfCollectionStatus.EMPTY_VALID)
        val isStale = hasPublishedSnapshot && ageMs > bpfAttributor.maxFreshnessMs

        val state = when {
            !isExperimentalBpfEnabled -> ExperimentalBpfState.DISABLED
            !hasPublishedSnapshot && lastAttempt.attemptStatus == BpfCollectionStatus.IDLE -> ExperimentalBpfState.COLLECTING
            !hasPublishedSnapshot -> ExperimentalBpfState.STALE_OR_UNAVAILABLE
            isStale -> ExperimentalBpfState.STALE_OR_UNAVAILABLE
            hasRestrictivePolicy || snap.coverageIncomplete -> ExperimentalBpfState.PARTIAL_ENFORCEMENT
            else -> ExperimentalBpfState.MAPPINGS_AVAILABLE
        }

        val snapshotHealth = when {
            !isExperimentalBpfEnabled -> BpfSnapshotHealth.UNAVAILABLE
            lastAttempt.attemptStatus == BpfCollectionStatus.PARSE_FAILURE ||
                lastAttempt.attemptStatus == BpfCollectionStatus.TRUNCATED -> BpfSnapshotHealth.PARSE_FAILURE
            !hasPublishedSnapshot -> BpfSnapshotHealth.UNAVAILABLE
            isStale -> BpfSnapshotHealth.STALE
            else -> BpfSnapshotHealth.OK
        }

        var totalBlockedDrops = 0L
        var totalBlockedBytes = 0L
        var totalShapeDrops = 0L
        var totalShapedPkts = 0L
        for (c in countersByMac.values) {
            totalBlockedDrops += c.blockedDropPackets.get()
            totalBlockedBytes += c.droppedBytes.get()
            totalShapeDrops += c.shapingDropPackets.get()
            totalShapedPkts += c.shapedPackets.get()
        }

        val reasonPacketsMap = LinkedHashMap<String, Long>()
        val reasonBytesMap = LinkedHashMap<String, Long>()
        for (reason in UnattributedReason.entries) {
            val p = unattributedPacketsByReason[reason]?.get() ?: 0L
            val b = unattributedBytesByReason[reason]?.get() ?: 0L
            if (p > 0L || b > 0L) {
                reasonPacketsMap[reason.name] = p
                reasonBytesMap[reason.name] = b
            }
        }

        var blockedClients = 0
        var quotaExhaustedClients = 0
        var throttledClients = 0
        for ((mac, pol) in policiesByMac) {
            val q = quotaRecordsByMac[mac]
            val qExceeded = q?.isQuotaExceeded == true || pol.isQuotaOnlyBlock
            if (pol.isNonQuotaBlocked) blockedClients++
            if (qExceeded) quotaExhaustedClients++
            if (pol.bandwidthLimitKbps > 0) throttledClients++
        }

        val latencyPercentiles = bpfReader.getRefreshLatencyPercentiles()
        val deepSnap = deepTupleTracker.snapshot()
        val nowWall = conntrackClockMillisProvider()
        val backoffRemainingMs = (conntrackBackoffUntilMs - nowWall).coerceAtLeast(0L)

        val allKnownMacs = (activeConnectedMacs + countersByMac.keys + snap.perClientCounts.map { it.mac }).sorted()
        val perClientVerifiedSummaries = allKnownMacs.map { mac ->
            val c = countersByMac[mac]
            val pol = policiesByMac[mac]
            val q = quotaRecordsByMac[mac]
            val bpfIpv4 = snap.perClientCounts.find { it.mac == mac }?.originalIpv4.orEmpty()
            val boundIpv4 = macToIps[mac]?.firstOrNull { !it.contains(':') }.orEmpty()
            PerClientVerifiedTrafficSummary(
                mac = mac,
                originalIpv4 = bpfIpv4.ifBlank { boundIpv4 },
                activeFlows = getAttributedFlowCount(mac),
                verifiedUploadPackets = c?.uploadForwardedPackets?.get() ?: 0L,
                verifiedUploadBytes = c?.txBytes?.get() ?: 0L,
                verifiedDownloadPackets = c?.downloadForwardedPackets?.get() ?: 0L,
                verifiedDownloadBytes = c?.rxBytes?.get() ?: 0L,
                directIpPackets = c?.directAttributedPackets?.get() ?: 0L,
                bpfNatPackets = c?.bpfAttributedPackets?.get() ?: 0L,
                conntrackPackets = c?.conntrackAttributedPackets?.get() ?: 0L,
                blockedDropPackets = c?.blockedDropPackets?.get() ?: 0L,
                blockedDropBytes = c?.droppedBytes?.get() ?: 0L,
                isBlocked = pol?.isNonQuotaBlocked == true,
                isQuotaExhausted = q?.isQuotaExceeded == true || pol?.isQuotaOnlyBlock == true,
                isThrottled = (pol?.bandwidthLimitKbps ?: 0) > 0,
            )
        }

        val perClientPostTransitionSummaries = allKnownMacs.map { mac ->
            val c = countersByMac[mac]
            val pol = policiesByMac[mac]
            val q = quotaRecordsByMac[mac]
            val bpfIpv4 = snap.perClientCounts.find { it.mac == mac }?.originalIpv4.orEmpty()
            val boundIpv4 = macToIps[mac]?.firstOrNull { !it.contains(':') }.orEmpty()
            val isNonQuotaBlock = pol?.isNonQuotaBlocked == true
            val isQuotaExhausted = q?.isQuotaExceeded == true || pol?.isQuotaOnlyBlock == true
            val isThrottled = (pol?.bandwidthLimitKbps ?: 0) > 0
            val restrictionKind = when {
                isNonQuotaBlock && isQuotaExhausted -> "BLOCK+QUOTA_EXHAUSTED"
                isNonQuotaBlock -> "BLOCK"
                isQuotaExhausted -> "QUOTA_EXHAUSTED"
                isThrottled -> "THROTTLED"
                else -> "NONE"
            }
            PhaseDClientPostTransitionSummary(
                mac = mac,
                originalIpv4 = bpfIpv4.ifBlank { boundIpv4 },
                policyGeneration = c?.policyVersion?.get() ?: 1L,
                lastTransitionType = c?.lastTransitionType ?: "NONE",
                lastTransitionMonoMs = c?.lastTransitionAtMonoMs ?: 0L,
                verifiedFlowsAtTransition = c?.verifiedFlowsAtTransition ?: 0,
                decisionsRecomputed = c?.decisionsRecomputed?.get() ?: 0L,
                staleAllowCacheHitsPrevented = c?.staleAllowCacheHitsPrevented?.get() ?: 0L,
                verifiedAllowedAfterBlockPackets = c?.verifiedAllowedAfterBlockPackets?.get() ?: 0L,
                verifiedAllowedAfterBlockBytes = c?.verifiedAllowedAfterBlockBytes?.get() ?: 0L,
                verifiedDroppedAfterBlockPackets = c?.verifiedDroppedAfterBlockPackets?.get() ?: 0L,
                verifiedDroppedAfterBlockBytes = c?.verifiedDroppedAfterBlockBytes?.get() ?: 0L,
                pinnedFlowEnforcedPackets = c?.pinnedFlowEnforcedPackets?.get() ?: 0L,
                pinnedFlowEnforcedBytes = c?.pinnedFlowEnforcedBytes?.get() ?: 0L,
            )
        }

        val currentLifecycleState = when {
            !isExperimentalBpfEnabled || datapathMode == DatapathMode.DIRECT_TUN_FALLBACK || isMultiClientDegraded ->
                PhaseDInterfaceLifecycleState.DEGRADED_OR_STOPPED
            (snap.downstreamIface.ifBlank { activeDownstreamName }).isBlank() ||
                (snap.upstreamIface.ifBlank { activeUpstreamName }).isBlank() ->
                PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES
            hasPublishedSnapshot && !isStale && snap.resolvedDownstreamIfIndex > 0 && snap.resolvedUpstreamIfIndex > 0 ->
                PhaseDInterfaceLifecycleState.ATTRIBUTION_READY
            else ->
                PhaseDInterfaceLifecycleState.BINDING_INTERFACES
        }

        val evidenceConfidence = when {
            !isExperimentalBpfEnabled ||
                snapshotHealth == BpfSnapshotHealth.UNAVAILABLE ||
                snapshotHealth == BpfSnapshotHealth.PARSE_FAILURE ->
                PhaseDEvidenceConfidence.PATH_NOT_OBSERVABLE
            snapshotHealth == BpfSnapshotHealth.OK && unmatchedPackets.get() == 0L ->
                PhaseDEvidenceConfidence.VERIFIED_OWNER
            else ->
                PhaseDEvidenceConfidence.UNKNOWN_OWNER
        }

        val postBlockProtoPkts = LinkedHashMap<String, Long>()
        val postBlockProtoBytes = LinkedHashMap<String, Long>()
        for (key in unknownPostBlockByProtocolAndDirection.keys.sorted()) {
            val pkts = unknownPostBlockByProtocolAndDirection[key]?.get() ?: 0L
            val bytes = unknownPostBlockBytesByProtocolAndDirection[key]?.get() ?: 0L
            if (pkts > 0L || bytes > 0L) {
                postBlockProtoPkts[key] = pkts
                postBlockProtoBytes[key] = bytes
            }
        }
        val u443Pkts = udp443PostBlockUnattributedPackets.get()
        val u443Bytes = udp443PostBlockUnattributedBytes.get()
        if (u443Pkts > 0L || u443Bytes > 0L) {
            postBlockProtoPkts["UDP/443"] = u443Pkts
            postBlockProtoBytes["UDP/443"] = u443Bytes
        }
        val u53Pkts = udp53PostBlockUnattributedPackets.get()
        val u53Bytes = udp53PostBlockUnattributedBytes.get()
        if (u53Pkts > 0L || u53Bytes > 0L) {
            postBlockProtoPkts["UDP/53"] = u53Pkts
            postBlockProtoBytes["UDP/53"] = u53Bytes
        }

        val transitionsSnap: List<PhaseDPolicyTransitionEvent>
        val lifecycleSnap: List<PhaseDInterfaceLifecycleEvent>
        val markersSnap: List<PhaseDDeliveryTestMarker>
        synchronized(phaseDEventsLock) {
            transitionsSnap = policyTransitionEvents.toList()
            lifecycleSnap = interfaceLifecycleEvents.toList()
            markersSnap = deliveryTestMarkers.toList()
        }

        val phaseDReport = PhaseDStatusReport(
            phaseDMode = phaseDMode,
            evidenceConfidence = evidenceConfidence,
            interfaceLifecycleState = currentLifecycleState,
            policyTransitionEvents = transitionsSnap,
            postTransitionVerifiedClientTraffic = perClientPostTransitionSummaries,
            unknownForwardedAfterBlockPackets = unknownForwardedAfterBlockPackets.get(),
            unknownForwardedAfterBlockBytes = unknownForwardedAfterBlockBytes.get(),
            unknownPostBlockByProtocolAndDirection = postBlockProtoPkts,
            unknownPostBlockBytesByProtocolAndDirection = postBlockProtoBytes,
            verifiedFlowsAtTransitionTotal = perClientPostTransitionSummaries.sumOf { it.verifiedFlowsAtTransition.toLong() },
            staleAllowCacheHitsPreventedTotal = perClientPostTransitionSummaries.sumOf { it.staleAllowCacheHitsPrevented },
            decisionsRecomputedTotal = perClientPostTransitionSummaries.sumOf { it.decisionsRecomputed },
            verifiedAllowedAfterBlockPacketsTotal = perClientPostTransitionSummaries.sumOf { it.verifiedAllowedAfterBlockPackets },
            verifiedAllowedAfterBlockBytesTotal = perClientPostTransitionSummaries.sumOf { it.verifiedAllowedAfterBlockBytes },
            verifiedDroppedAfterBlockPacketsTotal = perClientPostTransitionSummaries.sumOf { it.verifiedDroppedAfterBlockPackets },
            verifiedDroppedAfterBlockBytesTotal = perClientPostTransitionSummaries.sumOf { it.verifiedDroppedAfterBlockBytes },
            activePinnedVerifiedFlowsCount = getVerifiedFlowPinCacheSize(),
            pinnedFlowHitsInDiagnosticMode = pinnedFlowHitsInDiagnosticMode.get(),
            pinnedFlowEnforcedDropsInEnforcementMode = pinnedFlowEnforcedDropsInEnforcementMode.get(),
            queuedPacketsPurgedOnTransitionTotal = transitionsSnap.sumOf { it.queuedPacketsPurged.toLong() },
            establishedTcpMissingFromBpfPackets = establishedTcpMissingFromBpfPackets.get(),
            establishedTcpMissingFromBpfBytes = establishedTcpMissingFromBpfBytes.get(),
            establishedTcpPinnedMatchedPackets = establishedTcpPinnedMatchedPackets.get(),
            establishedTcpPinnedMatchedBytes = establishedTcpPinnedMatchedBytes.get(),
            tcpKeepaliveOrAckOnlyPackets = tcpKeepaliveOrAckOnlyPackets.get(),
            tcpSynPacketsSeen = tcpSynPacketsSeen.get(),
            tcpFinOrRstPacketsSeen = tcpFinOrRstPacketsSeen.get(),
            udp443PostBlockUnattributedPackets = u443Pkts,
            udp443PostBlockUnattributedBytes = u443Bytes,
            udp53PostBlockUnattributedPackets = u53Pkts,
            udp53PostBlockUnattributedBytes = u53Bytes,
            interfaceLifecycleEvents = lifecycleSnap,
            deliveryTestMarkers = markersSnap,
            lastPolicyActivatedEpochMs = markersSnap.lastOrNull { it.markerType == "POLICY_ACTIVATED" }?.timestampEpochMs ?: 0L,
        )

        return BpfAttributionStatusReport(
            experimentalEnabled = isExperimentalBpfEnabled,
            state = state,
            snapshotHealth = snapshotHealth,
            collectionStatus = snap.collectionStatus,
            collectionError = snap.collectionError,
            parserVersion = BpfDumpParser.PARSER_VERSION,
            pollIntervalMs = bpfPollIntervalMs,
            snapshotSequence = snap.snapshotSequence,
            snapshotAgeMs = ageMs,
            lastSuccessfulRefreshEpochMs = snap.publishedAtEpochMs,
            lastCollectionDurationMs = snap.collectionDurationMs,
            totalCollectionsAttempted = bpfReader.totalCollectionsAttempted.get(),
            totalCollectionsSucceeded = bpfReader.totalCollectionsSucceeded.get(),
            totalCollectionsFailed = bpfReader.totalCollectionsFailed.get(),
            sessionGeneration = snap.sessionGeneration,
            bindingGeneration = snap.bindingGeneration,
            downstreamIface = snap.downstreamIface.ifBlank { activeDownstreamName },
            downstreamIfIndex = snap.downstreamIfIndex,
            upstreamIface = snap.upstreamIface.ifBlank { activeUpstreamName },
            upstreamIfIndex = snap.upstreamIfIndex,
            osDownstreamIfIndex = snap.osDownstreamIfIndex,
            osUpstreamIfIndex = snap.osUpstreamIfIndex,
            inferredDownstreamIfIndex = snap.inferredDownstreamIfIndex,
            inferredUpstreamIfIndex = snap.inferredUpstreamIfIndex,
            downstreamIfIndexSource = snap.downstreamIfIndexSource,
            upstreamIfIndexSource = snap.upstreamIfIndexSource,
            downstreamIfIndexError = snap.downstreamIfIndexError,
            upstreamIfIndexError = snap.upstreamIfIndexError,
            resolvedDownstreamIfIndex = snap.resolvedDownstreamIfIndex,
            resolvedUpstreamIfIndex = snap.resolvedUpstreamIfIndex,
            totalUpstreamEntries = snap.totalUpstreamEntries,
            totalDownstreamEntries = snap.totalDownstreamEntries,
            knownAgeEntries = snap.knownAgeEntries,
            unavailableAgeEntries = snap.unavailableAgeEntries,
            negativeDeltaAgeEntries = snap.negativeDeltaAgeEntries,
            reverseMatchedCount = snap.reverseMatchedCount,
            activeMappedFlows = snap.flowsByTuple.size,
            ambiguousTupleCount = snap.ambiguousTuples.size,
            unverifiedOwnerEntries = snap.unverifiedOwnerEntries,
            ifIndexMismatchCount = snap.ifIndexMismatchCount,
            rejectedLineCount = snap.rejectedLineCount,
            coverageIncomplete = snap.coverageIncomplete,
            perClientCounts = snap.perClientCounts,
            lastAttemptStatus = lastAttempt.attemptStatus,
            lastAttemptError = lastAttempt.attemptError,
            lastAttemptAgeMs = attemptAgeMs,
            lastAttemptDurationMs = lastAttempt.attemptDurationMs,
            lastAttemptRecognizedFormat = lastAttempt.recognizedFormat,
            lastAttemptSnapshotPublished = lastAttempt.snapshotPublished,
            lastAttemptDecisionReason = lastAttempt.decisionReason,
            lastAttemptUpstreamEntries = lastAttempt.upstreamEntries,
            lastAttemptDownstreamEntries = lastAttempt.downstreamEntries,
            lastAttemptKnownAgeEntries = lastAttempt.knownAgeEntries,
            lastAttemptUnavailableAgeEntries = lastAttempt.unavailableAgeEntries,
            lastAttemptNegativeDeltaAgeEntries = lastAttempt.negativeDeltaAgeEntries,
            lastAttemptRejectedLineCount = lastAttempt.rejectedLineCount,
            lastAttemptRejectedByReason = lastAttempt.rejectedByReason,
            lastAttemptRejectedLines = lastAttempt.rejectedLines,
            snapshotPublishRejectedByReason = bpfAttributor.getPublishRejectedByReasonSnapshot(),
            totalEligiblePackets = totalEligiblePackets.get(),
            totalEligibleBytes = totalEligibleBytes.get(),
            totalAttributedPackets = totalAttributedPackets.get(),
            totalAttributedBytes = totalAttributedBytes.get(),
            directAttributedPackets = directAttributedPackets.get(),
            directAttributedBytes = directAttributedBytes.get(),
            bpfAttributedPackets = bpfAttributedPackets.get(),
            bpfAttributedBytes = bpfAttributedBytes.get(),
            conntrackAttributedPackets = conntrackAttributedPackets.get(),
            conntrackAttributedBytes = conntrackAttributedBytes.get(),
            unknownForwardedPackets = unmatchedPackets.get(),
            unknownForwardedBytes = unknownForwardedBytes.get(),
            unattributedPacketsByReason = reasonPacketsMap,
            unattributedBytesByReason = reasonBytesMap,
            trafficSplit = BpfTrafficSplitCounters(
                ipv4EligiblePackets = ipv4EligiblePackets.get(),
                ipv4EligibleBytes = ipv4EligibleBytes.get(),
                ipv4AttributedPackets = ipv4AttributedPackets.get(),
                ipv4AttributedBytes = ipv4AttributedBytes.get(),
                ipv4UnattributedPackets = ipv4UnattributedPackets.get(),
                ipv4UnattributedBytes = ipv4UnattributedBytes.get(),
                ipv6EligiblePackets = ipv6EligiblePackets.get(),
                ipv6EligibleBytes = ipv6EligibleBytes.get(),
                ipv6AttributedPackets = ipv6AttributedPackets.get(),
                ipv6AttributedBytes = ipv6AttributedBytes.get(),
                ipv6UnattributedPackets = ipv6UnattributedPackets.get(),
                ipv6UnattributedBytes = ipv6UnattributedBytes.get(),
                tcpEligiblePackets = tcpEligiblePackets.get(),
                tcpEligibleBytes = tcpEligibleBytes.get(),
                tcpAttributedPackets = tcpAttributedPackets.get(),
                tcpAttributedBytes = tcpAttributedBytes.get(),
                tcpUnattributedPackets = tcpUnattributedPackets.get(),
                tcpUnattributedBytes = tcpUnattributedBytes.get(),
                udpEligiblePackets = udpEligiblePackets.get(),
                udpEligibleBytes = udpEligibleBytes.get(),
                udpAttributedPackets = udpAttributedPackets.get(),
                udpAttributedBytes = udpAttributedBytes.get(),
                udpUnattributedPackets = udpUnattributedPackets.get(),
                udpUnattributedBytes = udpUnattributedBytes.get(),
                icmpEligiblePackets = icmpEligiblePackets.get(),
                icmpEligibleBytes = icmpEligibleBytes.get(),
                icmpAttributedPackets = icmpAttributedPackets.get(),
                icmpAttributedBytes = icmpAttributedBytes.get(),
                icmpUnattributedPackets = icmpUnattributedPackets.get(),
                icmpUnattributedBytes = icmpUnattributedBytes.get(),
                otherProtoEligiblePackets = otherProtoEligiblePackets.get(),
                otherProtoEligibleBytes = otherProtoEligibleBytes.get(),
                otherProtoAttributedPackets = otherProtoAttributedPackets.get(),
                otherProtoAttributedBytes = otherProtoAttributedBytes.get(),
                otherProtoUnattributedPackets = otherProtoUnattributedPackets.get(),
                otherProtoUnattributedBytes = otherProtoUnattributedBytes.get(),
                uploadEligiblePackets = uploadEligiblePackets.get(),
                uploadEligibleBytes = uploadEligibleBytes.get(),
                uploadAttributedPackets = uploadAttributedPackets.get(),
                uploadAttributedBytes = uploadAttributedBytes.get(),
                uploadUnattributedPackets = uploadUnattributedPackets.get(),
                uploadUnattributedBytes = uploadUnattributedBytes.get(),
                downloadEligiblePackets = downloadEligiblePackets.get(),
                downloadEligibleBytes = downloadEligibleBytes.get(),
                downloadAttributedPackets = downloadAttributedPackets.get(),
                downloadAttributedBytes = downloadAttributedBytes.get(),
                downloadUnattributedPackets = downloadUnattributedPackets.get(),
                downloadUnattributedBytes = downloadUnattributedBytes.get(),
            ),
            conntrackFallbackAttemptedCount = conntrackFallbackAttemptedCount.get(),
            conntrackFallbackSucceededCount = conntrackFallbackSucceededCount.get(),
            conntrackFallbackFailedCount = conntrackFallbackFailedCount.get(),
            conntrackPermissionDeniedCount = conntrackPermissionDeniedCount.get(),
            conntrackBackoffActive = backoffRemainingMs > 0L,
            conntrackBackoffRemainingMs = backoffRemainingMs,
            conntrackBackoffSkippedCount = conntrackBackoffSkippedCount.get(),
            activeConnectedClientsCount = activeConnectedMacs.size,
            blockedClientsCount = blockedClients,
            quotaExhaustedClientsCount = quotaExhaustedClients,
            throttledClientsCount = throttledClients,
            bpfRefreshOnMissEnabled = bpfRefreshOnMissEnabled,
            refreshOnMissCooldownMs = bpfReader.refreshOnMissCooldownMs,
            refreshCircuitBreakerState = bpfReader.circuitBreakerState.name,
            refreshOnMissTriggeredCount = bpfReader.refreshOnMissTriggeredCount.get(),
            refreshOnMissCoalescedInFlightCount = bpfReader.refreshOnMissCoalescedInFlightCount.get(),
            refreshOnMissSuppressedCooldownCount = bpfReader.refreshOnMissSuppressedCooldownCount.get(),
            refreshOnMissCompletedCount = bpfReader.refreshOnMissCompletedCount.get(),
            missRefreshFailedCount = bpfReader.missRefreshFailedCount.get(),
            missRefreshSuppressedBreakerCount = bpfReader.missRefreshSuppressedBreakerCount.get(),
            missRefreshSuppressedIneligibleCount = bpfReader.missRefreshSuppressedIneligibleCount.get(),
            missRefreshQueueOverflowCount = bpfReader.missRefreshQueueOverflowCount.get(),
            refreshOnMissLastLatencyMs = bpfReader.refreshOnMissLastLatencyMs.get(),
            missRefreshLatency = latencyPercentiles,
            postRefreshAttributedPackets = postRefreshAttributedPackets.get(),
            postRefreshAttributedBytes = postRefreshAttributedBytes.get(),
            postRefreshFlowKeysResolved = deepSnap.postRefreshFlowKeysResolved,
            postRefreshFirstSubsequentAttributedPackets = deepSnap.postRefreshFirstSubsequentAttributedPackets,
            postRefreshFirstSubsequentAttributedBytes = deepSnap.postRefreshFirstSubsequentAttributedBytes,
            refreshOnMissAutoDisabled = bpfReader.refreshOnMissAutoDisabled,
            refreshOnMissAutoDisableReason = bpfReader.refreshOnMissAutoDisableReason,
            deepTupleDiagnosticsEnabled = deepTupleDiagnosticsEnabled,
            unknownOwnerPacketPolicy = unknownOwnerPacketPolicy,
            deepTupleDiagnostics = deepSnap,
            perClientVerifiedSummaries = perClientVerifiedSummaries,
            ambiguousOrStaleLookups = ambiguousOrStaleLookups.get(),
            localControlPackets = localControlPackets.get(),
            localControlBytes = localControlBytes.get(),
            unsupportedOrFragmentPackets = unsupportedOrFragmentPackets.get(),
            blockedDropPackets = totalBlockedDrops,
            blockedDropBytes = totalBlockedBytes,
            shapingDropPackets = totalShapeDrops,
            shapedPackets = totalShapedPkts,
            rejectedOldGenerationCount = bpfAttributor.rejectedOldGenerationCount.get(),
            tupleReuseGuardTriggeredCount = bpfAttributor.tupleReuseGuardTriggeredCount.get(),
            phaseD = phaseDReport,
            preNatDiagnostics = ExclusiveBlockingModeController.buildDiagnosticReport(),
            softApDiagnostics = ExclusiveBlockingModeController.buildSoftApDiagnosticReport(),
            domainDiagnostics = DomainFilterEngine.buildDiagnosticReport(
                legacyPreNatMigrated = true,
                legacyPreNatCleanupClean = ExclusiveBlockingModeController.legacyPreNatCleanupVerified,
            ),
        )
    }

    /**
     * Attaches the userspace proxy to [realTunPfd] and returns the proxy [ParcelFileDescriptor]
     * whose `.fd` is passed to `Datapath.start(fd, mtu)`.
     */
    @Synchronized
    fun attach(
        realTunPfd: ParcelFileDescriptor,
        mtu: Int,
        upstreamInterfaceName: String = "testtun",
    ): ParcelFileDescriptor? {
        stop()
        activeUpstreamName = upstreamInterfaceName
        synchronized(verifiedFlowPinsLock) {
            verifiedFlowPins.clear()
        }
        val newGen = bpfAttributor.onSessionOrUpstreamChanged(
            downstreamIface = activeDownstreamName,
            upstreamIface = upstreamInterfaceName,
        )
        ExclusiveBlockingModeController.onSessionOrInterfacesChanged(
            downstreamIface = activeDownstreamName,
            upstreamIface = upstreamInterfaceName,
            newSessionGeneration = newGen,
        )
        maybeRecordInterfaceLifecycleState(
            if (activeDownstreamName.isBlank()) PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES else PhaseDInterfaceLifecycleState.BINDING_INTERFACES,
            "Attach userspace proxy upstream=$upstreamInterfaceName downstream=$activeDownstreamName",
            force = true,
        )

        return runCatching {
            val engineSock = FileDescriptor()
            val datapathSock = FileDescriptor()
            try {
                Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_SEQPACKET, 0, engineSock, datapathSock)
            } catch (_: Throwable) {
                Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, engineSock, datapathSock)
            }

            runCatching {
                Os.setsockoptInt(engineSock, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, SOCKET_BUFFER_BYTES)
                Os.setsockoptInt(engineSock, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_BUFFER_BYTES)
                Os.setsockoptInt(datapathSock, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, SOCKET_BUFFER_BYTES)
                Os.setsockoptInt(datapathSock, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKET_BUFFER_BYTES)
            }

            val enginePfd = ParcelFileDescriptor.dup(engineSock)
            val datapathPfd = ParcelFileDescriptor.dup(datapathSock)
            runCatching { Os.close(engineSock) }
            runCatching { Os.close(datapathSock) }

            engineEndPfd = enginePfd
            datapathEndPfd = datapathPfd
            running.set(true)
            datapathMode = DatapathMode.USERSPACE_PROXY
            fallbackReason = null

            val tunFd = realTunPfd.fileDescriptor
            val proxyFd = enginePfd.fileDescriptor

            startPacingDispatcher()

            uploadThread = Thread(
                { relayUploadLoop(tunFd, proxyFd, maxOf(mtu + 128, BUFFER_SIZE)) },
                "shizzi-tun-upload",
            ).apply {
                isDaemon = true
                priority = Thread.MAX_PRIORITY
                start()
            }

            downloadThread = Thread(
                { relayDownloadLoop(proxyFd, tunFd, maxOf(mtu + 128, BUFFER_SIZE)) },
                "shizzi-tun-download",
            ).apply {
                isDaemon = true
                priority = Thread.MAX_PRIORITY
                start()
            }

            bpfReader.configure(
                enabled = isExperimentalBpfEnabled,
                intervalMs = bpfPollIntervalMs,
                sessionActive = true,
            )

            SessionLog.info(
                "Datapath: mode=USERSPACE_PROXY attached=true upstream=$upstreamInterfaceName mtu=$mtu bpfExperimental=$isExperimentalBpfEnabled",
            )
            datapathPfd
        }.onFailure { err ->
            val reason = "${err.javaClass.simpleName}: ${err.message}"
            Log.w(TAG, "Failed to attach userspace traffic proxy: $reason")
            markDirectTunFallback(upstreamInterfaceName, reason)
        }.getOrNull()
    }

    @Synchronized
    fun markDirectTunFallback(upstreamInterfaceName: String, reason: String) {
        stopInternal()
        activeUpstreamName = upstreamInterfaceName
        datapathMode = DatapathMode.DIRECT_TUN_FALLBACK
        fallbackReason = reason
        maybeRecordInterfaceLifecycleState(
            PhaseDInterfaceLifecycleState.DEGRADED_OR_STOPPED,
            "Direct TUN fallback: $reason",
            force = true,
        )
        SessionLog.warn(
            "Datapath: mode=DIRECT_TUN_FALLBACK attached=false upstream=$upstreamInterfaceName reason=$reason",
        )
    }

    @Synchronized
    fun stop() {
        stopInternal()
        datapathMode = DatapathMode.INACTIVE
        fallbackReason = null
        maybeRecordInterfaceLifecycleState(
            PhaseDInterfaceLifecycleState.DEGRADED_OR_STOPPED,
            "Userspace proxy stopped",
        )
    }

    private fun stopInternal() {
        running.set(false)
        bpfReader.stopWorker()
        stopPacingDispatcher()
        clearPacingQueues()
        cancelAllPendingDnsRetries("STOP_INTERNAL")
        flushQuotaCheckpointNow()
        runCatching { engineEndPfd?.close() }
        runCatching { datapathEndPfd?.close() }
        engineEndPfd = null
        datapathEndPfd = null

        uploadThread?.interrupt()
        downloadThread?.interrupt()
        uploadThread = null
        downloadThread = null
    }

    fun clearAll() {
        bpfReader.stopWorker()
        clearPacingQueues()
        cancelAllPendingDnsRetries("CLEAR_ALL")
        flushQuotaCheckpointNow()
        activeUpstreamName = ""
        activeDownstreamName = ""
        policiesByMac.clear()
        policiesByIp.clear()
        activeConnectedMacs.clear()
        ipToMac.clear()
        macToIps.clear()
        flowToMacCache.clear()
        flowTimestamps.clear()
        synchronized(verifiedFlowPinsLock) {
            verifiedFlowPins.clear()
        }
        lastLoggedClientMap.clear()
        uploadBucketsByMac.clear()
        downloadBucketsByMac.clear()
        countersByMac.clear()
        sampleLogTimestamps.clear()
        totalUploadPackets.set(0L)
        totalDownloadPackets.set(0L)
        bpfRefreshOnMissEnabled = false
        deepTupleDiagnosticsEnabled = false
        dnsAttributionRetryEnabled = false
        dnsRetryMaxWaitMs = DEFAULT_DNS_RETRY_MAX_WAIT_MS
        vpnForwardingGateClosed = false
        vpnFailClosedReason = ""
        vpnFailClosedDroppedPackets.set(0L)
        vpnFailClosedDroppedBytes.set(0L)
        phaseDMode = PhaseDEnforcementMode.DIAGNOSTIC
        bpfNatVpnEnforcementEnabled = true
        conntrackBackoffUntilMs = 0L
        lastConntrackResolveMs = 0L
        resetAttributionDiagnosticsCounters()
        bpfAttributor.onSessionOrUpstreamChanged("", "")
        isConntrackAvailable = false
        lastConntrackReadStatus = "NOT_TESTED"
        lastConntrackPollLatencyMs = 0L
        lastConntrackParsedFlows = 0
        isMultiClientDegraded = false
        DomainFilterEngine.replaceAllRules(emptyList())
        DomainFilterEngine.resetVolatileSessionState()
    }

    fun updateDomainRules(rules: List<DomainRule>): Long {
        DomainFilterEngine.replaceAllRules(rules)
        return DomainFilterEngine.currentRuleGeneration()
    }

    fun getBpfStatusReport(): BpfAttributionStatusReport = getBpfAttributionReport()

    fun resetClientDropCounters(mac: String) {
        val cleanMac = mac.uppercase().trim()
        countersByMac[cleanMac]?.let { counters ->
            counters.droppedPackets.set(0L)
            counters.blockedDropPackets.set(0L)
            counters.shapingDropPackets.set(0L)
            counters.quotaDropPackets.set(0L)
            counters.droppedBytes.set(0L)
            counters.matchedPackets.set(0L)
            counters.shapedPackets.set(0L)
            counters.shapedBytes.set(0L)
            counters.policyVersion.incrementAndGet()
            counters.policyVersionBlockedDrops.set(0L)
            counters.policyVersionShapedPackets.set(0L)
            counters.policyBaselinePostNatUnmatched = postNatUnmatchedPackets.get()
        }
    }

    private fun lockForMac(mac: String): Any =
        quotaLocksByMac.computeIfAbsent(mac.uppercase().trim()) { Any() }

    @Synchronized
    fun ensureQuotaLoaded() {
        if (!quotaLoadedFromDisk.compareAndSet(false, true)) return
        val loaded = DataQuota.loadFromFile(quotaCheckpointFile)
        val nowMs = quotaClockMillisProvider()
        val zoneId = quotaZoneIdProvider()
        for ((mac, record) in loaded) {
            synchronized(lockForMac(mac)) {
                if (!quotaRecordsByMac.containsKey(mac)) {
                    quotaRecordsByMac[mac] = DataQuota.evaluateWindowRollover(record, nowMs, zoneId)
                }
            }
        }
    }

    fun flushQuotaCheckpointNow(): Boolean {
        ensureQuotaLoaded()
        val records = quotaRecordsByMac.values.toList()
        unflushedQuotaBytes.set(0L)
        lastQuotaCheckpointFlushMs.set(quotaClockMillisProvider())
        if (records.isEmpty() && !quotaCheckpointFile.exists()) return true
        return DataQuota.saveToFile(quotaCheckpointFile, records)
    }

    private fun maybeFlushQuotaCheckpoint(nowMs: Long = quotaClockMillisProvider(), force: Boolean = false) {
        if (force) {
            flushQuotaCheckpointNow()
            return
        }
        val pendingBytes = unflushedQuotaBytes.get()
        val lastFlush = lastQuotaCheckpointFlushMs.get()
        if (pendingBytes >= DataQuota.CHECKPOINT_BYTE_DELTA_THRESHOLD &&
            nowMs - lastFlush >= DataQuota.CHECKPOINT_MIN_INTERVAL_MS
        ) {
            if (lastQuotaCheckpointFlushMs.compareAndSet(lastFlush, nowMs)) {
                unflushedQuotaBytes.set(0L)
                DataQuota.saveToFile(quotaCheckpointFile, quotaRecordsByMac.values.toList())
            }
        }
    }

    /**
     * Synchronizes configured [ClientRule] quota settings and persisted usage with the packet engine's
     * atomic per-MAC quota records.
     */
    fun syncQuotaRules(rules: List<ClientRule>) {
        ensureQuotaLoaded()
        val nowMs = quotaClockMillisProvider()
        val zoneId = quotaZoneIdProvider()
        var needsFlush = false

        for (rule in rules) {
            val mac = rule.cleanMac
            if (mac.length != 17 || mac == "00:00:00:00:00:00") continue
            synchronized(lockForMac(mac)) {
                val existing = quotaRecordsByMac[mac]
                val ruleRecord = rule.toQuotaRecord()
                val mergedBase = when {
                    existing == null -> ruleRecord
                    ruleRecord.resetGeneration > existing.resetGeneration -> {
                        needsFlush = true
                        ruleRecord
                    }
                    ruleRecord.resetGeneration < existing.resetGeneration -> {
                        existing.copy(
                            dataLimitBytes = ruleRecord.sanitizedLimitBytes,
                            resetPeriod = ruleRecord.resetPeriod,
                        )
                    }
                    else -> {
                        val sameWindow = existing.windowId.isEmpty() ||
                            ruleRecord.windowId.isEmpty() ||
                            existing.windowId == ruleRecord.windowId
                        val mergedRx = if (sameWindow) {
                            maxOf(existing.sanitizedRxBytes, ruleRecord.sanitizedRxBytes)
                        } else {
                            existing.sanitizedRxBytes
                        }
                        val mergedTx = if (sameWindow) {
                            maxOf(existing.sanitizedTxBytes, ruleRecord.sanitizedTxBytes)
                        } else {
                            existing.sanitizedTxBytes
                        }
                        existing.copy(
                            dataLimitBytes = ruleRecord.sanitizedLimitBytes,
                            resetPeriod = ruleRecord.resetPeriod,
                            usedRxBytes = mergedRx,
                            usedTxBytes = mergedTx,
                            windowId = existing.windowId.ifBlank { ruleRecord.windowId },
                            windowStartEpochMs = maxOf(existing.windowStartEpochMs, ruleRecord.windowStartEpochMs),
                            lastUpdatedEpochMs = maxOf(existing.lastUpdatedEpochMs, ruleRecord.lastUpdatedEpochMs),
                        )
                    }
                }

                val evaluated = DataQuota.evaluateWindowRollover(mergedBase, nowMs, zoneId)
                if (existing != evaluated) {
                    if (existing != null &&
                        (existing.windowId != evaluated.windowId ||
                            existing.dataLimitBytes != evaluated.dataLimitBytes ||
                            existing.resetPeriod != evaluated.resetPeriod ||
                            existing.resetGeneration != evaluated.resetGeneration)
                    ) {
                        needsFlush = true
                    }
                    val wasExceeded = existing?.isQuotaExceeded == true
                    quotaRecordsByMac[mac] = evaluated
                    if (wasExceeded && !evaluated.isQuotaExceeded) {
                        countersByMac[mac]?.let { c ->
                            c.quotaDropPackets.set(0L)
                            c.policyVersion.incrementAndGet()
                            c.policyVersionBlockedDrops.set(0L)
                        }
                    }
                }
            }
        }

        if (needsFlush) {
            flushQuotaCheckpointNow()
        }
    }

    /**
     * Evaluates and returns the current [ClientQuotaRecord] for [mac], lazily applying any
     * Daily/Weekly/Monthly calendar rollover at [quotaClockMillisProvider].
     */
    fun getQuotaRecord(mac: String): ClientQuotaRecord? {
        ensureQuotaLoaded()
        val cleanMac = mac.uppercase().trim()
        if (cleanMac.length != 17) return null
        val nowMs = quotaClockMillisProvider()
        val zoneId = quotaZoneIdProvider()
        synchronized(lockForMac(cleanMac)) {
            val existing = quotaRecordsByMac[cleanMac] ?: return null
            val rolled = DataQuota.evaluateWindowRollover(existing, nowMs, zoneId)
            if (rolled != existing) {
                val windowAdvanced = rolled.windowId != existing.windowId && rolled.usedTotalBytes == 0L
                quotaRecordsByMac[cleanMac] = rolled
                if (windowAdvanced) {
                    countersByMac[cleanMac]?.let { c ->
                        c.quotaDropPackets.set(0L)
                        c.policyVersion.incrementAndGet()
                        c.policyVersionBlockedDrops.set(0L)
                    }
                    policiesByMac[cleanMac]?.let { pol ->
                        if (pol.isQuotaOnlyBlock) {
                            val unblocked = pol.copy(isBlocked = false, blockReason = null)
                            policiesByMac[cleanMac] = unblocked
                            for (ip in macToIps[cleanMac].orEmpty()) {
                                policiesByIp[ip] = unblocked
                            }
                        }
                    }
                    SessionLog.info(
                        "Quota: mac=$cleanMac calendar period rolled over (${existing.windowId} -> ${rolled.windowId}); usage reset to 0 B",
                    )
                    ExclusiveBlockingModeController.softApEngine.removeClientBlockReasonOverride(
                        cleanMac,
                        SoftApClientBlockReason.QUOTA_EXHAUSTED,
                    )
                    flushQuotaCheckpointNow()
                    HostFirewall.reconcileSoftApFromQuotaChange()
                }
            }
            return rolled
        }
    }

    /**
     * Atomically resets only the quota usage counters (`usedRxBytes = 0`, `usedTxBytes = 0`) for [mac],
     * preserving `dataLimitBytes`, `resetPeriod`, and all non-quota rules.
     */
    fun resetClientQuota(mac: String): ClientQuotaRecord? {
        ensureQuotaLoaded()
        val cleanMac = mac.uppercase().trim()
        if (cleanMac.length != 17) return null
        val nowMs = quotaClockMillisProvider()
        val zoneId = quotaZoneIdProvider()
        val updated: ClientQuotaRecord
        synchronized(lockForMac(cleanMac)) {
            val existing = quotaRecordsByMac[cleanMac]
            val pol = policiesByMac[cleanMac]
            val period = existing?.resetPeriod ?: pol?.quotaResetPeriod ?: QuotaResetPeriod.MANUAL
            val limitBytes = existing?.dataLimitBytes ?: pol?.dataLimitBytes ?: 0L
            val window = DataQuota.computeWindow(period, nowMs, zoneId)
            updated = ClientQuotaRecord(
                mac = cleanMac,
                dataLimitBytes = limitBytes,
                resetPeriod = period,
                usedRxBytes = 0L,
                usedTxBytes = 0L,
                windowId = window.windowId,
                windowStartEpochMs = window.windowStartEpochMs.takeIf { it > 0L } ?: nowMs,
                lastUpdatedEpochMs = maxOf(nowMs, existing?.lastUpdatedEpochMs ?: 0L),
                resetGeneration = (existing?.resetGeneration ?: 0L) + 1L,
            )
            quotaRecordsByMac[cleanMac] = updated
        }

        countersByMac[cleanMac]?.let { counters ->
            counters.rxBytes.set(0L)
            counters.txBytes.set(0L)
            counters.uploadForwardedPackets.set(0L)
            counters.downloadForwardedPackets.set(0L)
            counters.quotaDropPackets.set(0L)
            counters.policyVersion.incrementAndGet()
            counters.policyVersionBlockedDrops.set(0L)
            if (policiesByMac[cleanMac]?.isNonQuotaBlocked != true) {
                counters.droppedPackets.set(0L)
                counters.blockedDropPackets.set(0L)
                counters.droppedBytes.set(0L)
                counters.verifiedDroppedAfterBlockPackets.set(0L)
                counters.verifiedDroppedAfterBlockBytes.set(0L)
                counters.verifiedAllowedAfterBlockPackets.set(0L)
                counters.verifiedAllowedAfterBlockBytes.set(0L)
            }
        }

        policiesByMac[cleanMac]?.let { pol ->
            if (pol.isQuotaOnlyBlock) {
                val unblocked = pol.copy(isBlocked = false, blockReason = null)
                policiesByMac[cleanMac] = unblocked
                for (ip in macToIps[cleanMac].orEmpty()) {
                    policiesByIp[ip] = unblocked
                }
            }
        }

        recordPolicyTransitionEvent(
            transitionType = "QUOTA_RESET",
            mac = cleanMac,
            verifiedFlows = getAttributedFlowCount(cleanMac),
            queueInvalidated = 0,
            detail = "resetGeneration=${updated.resetGeneration}",
        )
        ExclusiveBlockingModeController.softApEngine.removeClientBlockReasonOverride(
            cleanMac,
            SoftApClientBlockReason.QUOTA_EXHAUSTED,
        )
        flushQuotaCheckpointNow()
        HostFirewall.reconcileSoftApFromQuotaChange()
        SessionLog.info("Quota: mac=$cleanMac usage manually reset to 0 B (generation=${updated.resetGeneration})")
        return updated
    }

    /**
     * Simulates process death by clearing in-memory quota records while leaving the on-disk checkpoint intact.
     */
    internal fun simulateProcessRestartForQuotaTest() {
        quotaRecordsByMac.clear()
        quotaLoadedFromDisk.set(false)
    }

    internal fun resetAllQuotaStatesForTest(deleteCheckpointFile: Boolean = true) {
        clearAll()
        quotaRecordsByMac.clear()
        quotaLocksByMac.clear()
        unflushedQuotaBytes.set(0L)
        lastQuotaCheckpointFlushMs.set(0L)
        if (deleteCheckpointFile) {
            runCatching { quotaCheckpointFile.delete() }
        }
        quotaLoadedFromDisk.set(true)
    }

    private fun recordQuotaBytes(
        mac: String,
        packetBytes: Int,
        isUpload: Boolean,
        policy: EnforcedClientPolicy?,
    ): ClientQuotaRecord {
        ensureQuotaLoaded()
        val cleanMac = mac.uppercase().trim()
        val nowMs = quotaClockMillisProvider()
        val zoneId = quotaZoneIdProvider()
        var crossedLimit = false
        val updated: ClientQuotaRecord

        synchronized(lockForMac(cleanMac)) {
            val existing = quotaRecordsByMac[cleanMac]
            val limitBytes = policy?.dataLimitBytes?.takeIf { it > 0L }
                ?: existing?.dataLimitBytes
                ?: 0L
            val period = if (policy != null && (policy.dataLimitBytes > 0L || existing == null)) {
                policy.quotaResetPeriod
            } else {
                existing?.resetPeriod ?: QuotaResetPeriod.MANUAL
            }
            val base = existing?.copy(
                dataLimitBytes = limitBytes,
                resetPeriod = period,
            ) ?: ClientQuotaRecord(
                mac = cleanMac,
                dataLimitBytes = limitBytes,
                resetPeriod = period,
            )
            val rolled = DataQuota.evaluateWindowRollover(base, nowMs, zoneId)
            val wasExceeded = rolled.isQuotaExceeded
            val delta = packetBytes.coerceAtLeast(0).toLong()
            val newRx = if (isUpload) rolled.sanitizedRxBytes else DataQuota.safeAddBytes(rolled.sanitizedRxBytes, delta)
            val newTx = if (isUpload) DataQuota.safeAddBytes(rolled.sanitizedTxBytes, delta) else rolled.sanitizedTxBytes

            updated = rolled.copy(
                usedRxBytes = newRx,
                usedTxBytes = newTx,
                lastUpdatedEpochMs = maxOf(nowMs, rolled.lastUpdatedEpochMs),
            )
            quotaRecordsByMac[cleanMac] = updated
            crossedLimit = !wasExceeded && updated.isQuotaExceeded
        }

        if (crossedLimit) {
            val counters = countersByMac.getOrPut(cleanMac) { ClientTrafficCounters(cleanMac) }
            counters.policyVersion.incrementAndGet()
            counters.policyVersionBlockedDrops.set(0L)
            counters.policyBaselinePostNatUnmatched = postNatUnmatchedPackets.get()
            var queuePurged = 0
            if (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) {
                val effectivePol = policy ?: policiesByMac[cleanMac] ?: EnforcedClientPolicy(
                    mac = cleanMac,
                    isBlocked = true,
                    blockReason = "Data limit reached",
                    dataLimitBytes = updated.sanitizedLimitBytes,
                )
                queuePurged = reconcileQueuedPacketsForPolicyChange(cleanMac, effectivePol, counters)
            }
            recordPolicyTransitionEvent(
                transitionType = "QUOTA_EXHAUSTED",
                mac = cleanMac,
                verifiedFlows = getAttributedFlowCount(cleanMac),
                queueInvalidated = queuePurged,
                detail = DataQuota.formatUsageSummary(updated.usedTotalBytes, updated.sanitizedLimitBytes),
            )
            SessionLog.info(
                "Quota: mac=$cleanMac reached data limit (${DataQuota.formatUsageSummary(updated.usedTotalBytes, updated.sanitizedLimitBytes)}) period=${updated.resetPeriod.displayName}",
            )
            ExclusiveBlockingModeController.softApEngine.addClientBlockReasonOverride(
                cleanMac,
                SoftApClientBlockReason.QUOTA_EXHAUSTED,
            )
            maybeFlushQuotaCheckpoint(nowMs, force = true)
            HostFirewall.reconcileSoftApFromQuotaChange()
        } else {
            unflushedQuotaBytes.addAndGet(packetBytes.coerceAtLeast(0).toLong())
            maybeFlushQuotaCheckpoint(nowMs, force = false)
        }
        return updated
    }

    private fun refundQuotaBytes(mac: String, packetBytes: Int, isUpload: Boolean) {
        val cleanMac = mac.uppercase().trim()
        val delta = packetBytes.coerceAtLeast(0).toLong()
        if (delta <= 0L) return
        synchronized(lockForMac(cleanMac)) {
            val existing = quotaRecordsByMac[cleanMac] ?: return
            val newRx = if (isUpload) existing.sanitizedRxBytes else (existing.sanitizedRxBytes - delta).coerceAtLeast(0L)
            val newTx = if (isUpload) (existing.sanitizedTxBytes - delta).coerceAtLeast(0L) else existing.sanitizedTxBytes
            quotaRecordsByMac[cleanMac] = existing.copy(
                usedRxBytes = newRx,
                usedTxBytes = newTx,
            )
        }
    }

    fun purgeFlowsForMac(mac: String): Int {
        val cleanMac = mac.uppercase().trim()
        var removed = 0
        for ((flowKey, mappedMac) in flowToMacCache.entries.toList()) {
            if (mappedMac == cleanMac) {
                if (flowToMacCache.remove(flowKey, mappedMac)) {
                    removed++
                }
                flowTimestamps.remove(flowKey)
            }
        }
        removed += invalidateVerifiedFlowPinsForMac(cleanMac)
        countersByMac[cleanMac]?.let { counters ->
            counters.policyVersion.incrementAndGet()
            counters.policyVersionBlockedDrops.set(0L)
            counters.policyVersionShapedPackets.set(0L)
            counters.policyBaselinePostNatUnmatched = postNatUnmatchedPackets.get()
        }
        return removed
    }

    fun clearFlowCache() {
        flowToMacCache.clear()
        flowTimestamps.clear()
        synchronized(verifiedFlowPinsLock) {
            verifiedFlowPins.clear()
        }
    }

    fun getAttributedFlowCount(mac: String? = null): Int {
        val snap = bpfAttributor.currentSnapshot()
        if (mac.isNullOrBlank()) {
            return flowToMacCache.size + snap.flowsByTuple.size
        }
        val clean = mac.uppercase().trim()
        val cacheCount = flowToMacCache.values.count { it == clean }
        val bpfCount = snap.flowsByTuple.values.count { it.verifiedMac == clean }
        val pinCount = synchronized(verifiedFlowPinsLock) {
            verifiedFlowPins.values.count { it.verifiedMac == clean && it.flowKey !in snap.flowsByTuple }
        }
        return cacheCount + bpfCount + pinCount
    }

    /**
     * Synchronizes verified connected hosts and active client policies with the packet engine.
     * Evicts stale IP/flow mappings for disconnected clients or reassigned IPs immediately.
     */
    fun updatePolicies(
        macPolicies: Map<String, EnforcedClientPolicy>,
        connectedHosts: List<DiscoveredHost>,
    ) {
        val currentConnectedMacs = connectedHosts
            .map { it.mac.uppercase().trim() }
            .filter { it.length == 17 && it != "00:00:00:00:00:00" }
            .toSet()

        val previousConnectedMacs = HashSet(activeConnectedMacs)
        val previousIpToMac = HashMap(ipToMac)

        // 1. Evict disconnected MACs from active mappings, pacing queues, and flow cache
        for (disconnectedMac in previousConnectedMacs - currentConnectedMacs) {
            val drained = pacingQueuesByMac.remove(disconnectedMac)?.drainAll().orEmpty()
            for (pkt in drained) {
                refundQuotaBytes(disconnectedMac, pkt.length, pkt.isUpload)
            }
            invalidateVerifiedFlowPinsForMac(disconnectedMac)
            recordPolicyTransitionEvent(
                transitionType = "CLIENT_DISCONNECT",
                mac = disconnectedMac,
                verifiedFlows = 0,
                queueInvalidated = drained.size,
                detail = "Client disconnected from downstream interface",
            )
        }
        val newlyConnectedMacs = currentConnectedMacs - previousConnectedMacs
        activeConnectedMacs.retainAll(currentConnectedMacs)
        activeConnectedMacs.addAll(currentConnectedMacs)

        for ((ip, mappedMac) in ipToMac.entries.toList()) {
            if (mappedMac !in currentConnectedMacs) {
                ipToMac.remove(ip, mappedMac)
            }
        }
        macToIps.keys.retainAll(currentConnectedMacs)
        lastLoggedClientMap.keys.retainAll(currentConnectedMacs)

        for ((flowKey, mappedMac) in flowToMacCache.entries.toList()) {
            if (mappedMac !in currentConnectedMacs) {
                flowToMacCache.remove(flowKey, mappedMac)
                flowTimestamps.remove(flowKey)
            }
        }

        // 2. Bind verified downstream IPs for each currently connected host
        var detectedDownstreamIface = activeDownstreamName
        for (host in connectedHosts) {
            val mac = host.mac.uppercase().trim()
            if (mac !in currentConnectedMacs) continue
            if (host.interfaceName.isNotBlank() && host.interfaceName != "saved rule") {
                detectedDownstreamIface = host.interfaceName.trim()
            }

            val verifiedIps = LinkedHashSet<String>()
            fun addVerifiedIp(raw: String) {
                if (isUsableClientIp(raw)) {
                    val trimmed = raw.trim()
                    verifiedIps.add(trimmed)
                    val norm = normalizeIp(trimmed)
                    if (norm.isNotEmpty()) verifiedIps.add(norm)
                }
            }
            addVerifiedIp(host.ip)
            for (addr in host.allIps) {
                addVerifiedIp(addr)
            }

            val existingSet = macToIps.getOrPut(mac) { ConcurrentHashMap.newKeySet() }
            val previousIpsForMac = existingSet.toSet()
            existingSet.removeIf { oldIp ->
                if (oldIp !in verifiedIps) {
                    ipToMac.remove(oldIp, mac)
                    true
                } else false
            }
            for (ip in verifiedIps) {
                val previousMac = ipToMac.put(ip, mac)
                if (previousMac != null && previousMac != mac) {
                    macToIps[previousMac]?.remove(ip)
                    invalidateVerifiedFlowPinsForMac(previousMac)
                }
                existingSet.add(ip)
            }

            countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }

            val sortedIps = existingSet.sorted()
            if (mac in newlyConnectedMacs) {
                recordPolicyTransitionEvent(
                    transitionType = "CLIENT_RECONNECT",
                    mac = mac,
                    verifiedFlows = getAttributedFlowCount(mac),
                    queueInvalidated = 0,
                    detail = "ips=[${sortedIps.joinToString(",")}]",
                )
            } else if (previousIpsForMac.isNotEmpty() && previousIpsForMac != existingSet.toSet()) {
                invalidateVerifiedFlowPinsForMac(mac)
                recordPolicyTransitionEvent(
                    transitionType = "IP_MAC_BINDING_CHANGED",
                    mac = mac,
                    verifiedFlows = getAttributedFlowCount(mac),
                    queueInvalidated = 0,
                    detail = "ips=[${sortedIps.joinToString(",")}]",
                )
            }

            val mapSignature = "${host.interfaceName}:${sortedIps.joinToString(",")}"
            if (lastLoggedClientMap[mac] != mapSignature) {
                lastLoggedClientMap[mac] = mapSignature
                SessionLog.info(
                    "ClientMap: mac=$mac ips=[${sortedIps.joinToString(", ")}] interface=${host.interfaceName.ifBlank { "softap" }}",
                )
            }
        }

        if (detectedDownstreamIface.isNotBlank() && detectedDownstreamIface != activeDownstreamName) {
            val prevDown = activeDownstreamName
            activeDownstreamName = detectedDownstreamIface
            bpfAttributor.syncInterfaces(activeDownstreamName, activeUpstreamName)
            ExclusiveBlockingModeController.onSessionOrInterfacesChanged(
                downstreamIface = activeDownstreamName,
                upstreamIface = activeUpstreamName,
                newSessionGeneration = bpfAttributor.currentSessionGeneration,
            )
            recordPolicyTransitionEvent(
                transitionType = "INTERFACE_REBIND",
                mac = "GLOBAL",
                verifiedFlows = getAttributedFlowCount(null),
                queueInvalidated = 0,
                detail = "downstream=${prevDown.ifBlank { "none" }}->$activeDownstreamName upstream=$activeUpstreamName",
            )
            maybeRecordInterfaceLifecycleState(
                if (activeUpstreamName.isBlank()) PhaseDInterfaceLifecycleState.WAITING_FOR_INTERFACES else PhaseDInterfaceLifecycleState.BINDING_INTERFACES,
                "Downstream interface bound: $activeDownstreamName",
                force = true,
            )
        }
        if (previousConnectedMacs != currentConnectedMacs || previousIpToMac != ipToMac) {
            bpfAttributor.onClientBindingsUpdated()
        }

        // 3. Rebuild MAC and IP policy tables
        val newMacPolicies = HashMap<String, EnforcedClientPolicy>()
        val newIpPolicies = HashMap<String, EnforcedClientPolicy>()

        for ((rawMac, policy) in macPolicies) {
            val mac = rawMac.uppercase().trim()
            newMacPolicies[mac] = policy
            val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }

            synchronized(lockForMac(mac)) {
                val existingQuota = quotaRecordsByMac[mac]
                if (existingQuota != null || policy.dataLimitBytes > 0L) {
                    val base = existingQuota?.copy(
                        dataLimitBytes = policy.dataLimitBytes.coerceAtLeast(0L),
                        resetPeriod = policy.quotaResetPeriod,
                    ) ?: ClientQuotaRecord(
                        mac = mac,
                        dataLimitBytes = policy.dataLimitBytes.coerceAtLeast(0L),
                        resetPeriod = policy.quotaResetPeriod,
                    )
                    quotaRecordsByMac[mac] = DataQuota.evaluateWindowRollover(
                        record = base,
                        nowEpochMs = quotaClockMillisProvider(),
                        zoneId = quotaZoneIdProvider(),
                    )
                }
            }

            val oldPolicy = policiesByMac[mac]
            val policyChanged = oldPolicy == null ||
                oldPolicy.isBlocked != policy.isBlocked ||
                oldPolicy.blockReason != policy.blockReason ||
                oldPolicy.bandwidthLimitKbps != policy.bandwidthLimitKbps ||
                oldPolicy.dataLimitBytes != policy.dataLimitBytes ||
                oldPolicy.quotaResetPeriod != policy.quotaResetPeriod
            if (policyChanged) {
                counters.policyVersion.incrementAndGet()
                counters.policyVersionBlockedDrops.set(0L)
                counters.policyVersionShapedPackets.set(0L)
                counters.policyBaselinePostNatUnmatched = postNatUnmatchedPackets.get()
                val queueInvalidated = reconcileQueuedPacketsForPolicyChange(mac, policy, counters)
                val verifiedFlowsNow = getAttributedFlowCount(mac)
                val wasNonQuotaBlocked = oldPolicy?.isNonQuotaBlocked == true
                val wasQuotaBlocked = oldPolicy?.isQuotaOnlyBlock == true
                val wasAnyBlocked = oldPolicy?.isBlocked == true
                when {
                    !wasNonQuotaBlocked && policy.isNonQuotaBlocked -> {
                        counters.verifiedAllowedAfterBlockPackets.set(0L)
                        counters.verifiedAllowedAfterBlockBytes.set(0L)
                        counters.verifiedDroppedAfterBlockPackets.set(0L)
                        counters.verifiedDroppedAfterBlockBytes.set(0L)
                        if (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT && bpfRefreshOnMissEnabled) {
                            bpfReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT)
                        }
                        recordPolicyTransitionEvent(
                            transitionType = "ALLOW_TO_BLOCK",
                            mac = mac,
                            verifiedFlows = verifiedFlowsNow,
                            queueInvalidated = queueInvalidated,
                            detail = policy.blockReason ?: "Manually blocked",
                        )
                    }
                    !wasQuotaBlocked && policy.isQuotaOnlyBlock -> {
                        counters.verifiedAllowedAfterBlockPackets.set(0L)
                        counters.verifiedAllowedAfterBlockBytes.set(0L)
                        counters.verifiedDroppedAfterBlockPackets.set(0L)
                        counters.verifiedDroppedAfterBlockBytes.set(0L)
                        if (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT && bpfRefreshOnMissEnabled) {
                            bpfReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT)
                        }
                        recordPolicyTransitionEvent(
                            transitionType = "QUOTA_EXHAUSTED",
                            mac = mac,
                            verifiedFlows = verifiedFlowsNow,
                            queueInvalidated = queueInvalidated,
                            detail = policy.blockReason ?: "Data limit reached",
                        )
                    }
                    wasAnyBlocked && !policy.isBlocked -> {
                        recordPolicyTransitionEvent(
                            transitionType = "UNBLOCK",
                            mac = mac,
                            verifiedFlows = verifiedFlowsNow,
                            queueInvalidated = queueInvalidated,
                            detail = "Unblocked",
                        )
                    }
                }
            }
            if (oldPolicy != null && oldPolicy.isBlocked && !policy.isBlocked) {
                // Client transitioned from blocked to allowed: reset drop/match counters and purge cached flows
                counters.droppedPackets.set(0L)
                counters.blockedDropPackets.set(0L)
                counters.shapingDropPackets.set(0L)
                counters.quotaDropPackets.set(0L)
                counters.droppedBytes.set(0L)
                counters.matchedPackets.set(0L)
                counters.verifiedAllowedAfterBlockPackets.set(0L)
                counters.verifiedAllowedAfterBlockBytes.set(0L)
                counters.verifiedDroppedAfterBlockPackets.set(0L)
                counters.verifiedDroppedAfterBlockBytes.set(0L)
                for ((flowKey, mappedMac) in flowToMacCache.entries.toList()) {
                    if (mappedMac == mac) {
                        flowToMacCache.remove(flowKey, mappedMac)
                        flowTimestamps.remove(flowKey)
                    }
                }
            }

            val knownIps = macToIps[mac].orEmpty()
            for (ip in knownIps) {
                newIpPolicies[ip] = policy
            }

            if (policy.bandwidthLimitKbps > 0 && !policy.isBlocked) {
                uploadBucketsByMac.compute(mac) { _, existing ->
                    existing?.apply { updateRate(policy.bandwidthLimitKbps) }
                        ?: TokenBucket(policy.bandwidthLimitKbps)
                }
                downloadBucketsByMac.compute(mac) { _, existing ->
                    existing?.apply { updateRate(policy.bandwidthLimitKbps) }
                        ?: TokenBucket(policy.bandwidthLimitKbps)
                }
            } else {
                uploadBucketsByMac.remove(mac)
                downloadBucketsByMac.remove(mac)
            }
        }

        // For any MAC whose policy was removed entirely, flush its pacing queue immediately
        for (removedMac in policiesByMac.keys - newMacPolicies.keys) {
            countersByMac[removedMac]?.let { c ->
                c.policyVersion.incrementAndGet()
                c.policyVersionBlockedDrops.set(0L)
                c.policyVersionShapedPackets.set(0L)
            }
        }

        policiesByMac.keys.retainAll(newMacPolicies.keys)
        policiesByMac.putAll(newMacPolicies)

        policiesByIp.keys.retainAll(newIpPolicies.keys)
        policiesByIp.putAll(newIpPolicies)

        val allowedBucketMacs = newMacPolicies.filterValues { it.bandwidthLimitKbps > 0 && !it.isBlocked }.keys
        uploadBucketsByMac.keys.retainAll(allowedBucketMacs)
        downloadBucketsByMac.keys.retainAll(allowedBucketMacs)

        // 4. Expire old flow mappings to avoid port reuse collision
        val now = System.currentTimeMillis()
        val expiredThreshold = now - FLOW_TTL_MS
        for ((key, time) in flowTimestamps.entries.toList()) {
            if (time < expiredThreshold) {
                flowToMacCache.remove(key)
                flowTimestamps.remove(key)
            }
        }

        // 5. Update degraded multi-client state
        val hasRestricted = newMacPolicies.values.any {
            it.isBlocked || it.bandwidthLimitKbps > 0 || it.dataLimitBytes > 0L
        }
        val bpfHasFreshMappings = isExperimentalBpfEnabled &&
            bpfAttributor.currentSnapshot().let { snap ->
                (snap.collectionStatus == BpfCollectionStatus.OK || snap.collectionStatus == BpfCollectionStatus.EMPTY_VALID) &&
                    ((System.nanoTime() / 1_000_000L) - snap.collectedAtMonotonicMs) <= bpfAttributor.maxFreshnessMs
            }
        val degraded = currentConnectedMacs.size > 1 &&
            hasRestricted &&
            !isConntrackAvailable &&
            !HostFirewall.isKernelNetfilterAvailable &&
            !bpfHasFreshMappings
        if (degraded != isMultiClientDegraded) {
            isMultiClientDegraded = degraded
            if (degraded) {
                maybeRecordInterfaceLifecycleState(
                    PhaseDInterfaceLifecycleState.DEGRADED_OR_STOPPED,
                    "Multi-client NAT isolation degraded",
                )
                SessionLog.warn(
                    "Degraded: multi-client userspace NAT isolation degraded (conntrack, kernel netfilter, and fresh BPF mappings unavailable)",
                )
            }
        }

        // Log counter snapshots for connected clients that have active policies
        for (mac in currentConnectedMacs) {
            val counters = countersByMac[mac] ?: continue
            val policy = policiesByMac[mac]
            val hasRestriction = policy != null && (policy.isBlocked || policy.bandwidthLimitKbps > 0)
            val totalPkts = counters.seenPackets.get()
            if (hasRestriction && totalPkts > 0 && totalPkts != counters.lastLoggedPackets &&
                now - counters.lastCounterLogAt >= COUNTER_LOG_INTERVAL_MS
            ) {
                counters.lastLoggedPackets = totalPkts
                counters.lastCounterLogAt = now
                SessionLog.info(
                    "Counters: mac=$mac policyVer=${counters.policyVersion.get()} seenPackets=${counters.seenPackets.get()} " +
                        "matchedPackets=${counters.matchedPackets.get()} " +
                        "directPkts=${counters.directAttributedPackets.get()} " +
                        "bpfPkts=${counters.bpfAttributedPackets.get()} " +
                        "blockedDrops=${counters.blockedDropPackets.get()} " +
                        "shapeDrops=${counters.shapingDropPackets.get()} " +
                        "shapedBytes=${counters.shapedBytes.get()}",
                )
            }
        }
        ExclusiveBlockingModeController.onPoliciesUpdated()
    }

    /**
     * Cancels or re-evaluates queued paced packets when a client's policy changes so queued packets
     * can never escape using an outdated policy.
     */
    private fun reconcileQueuedPacketsForPolicyChange(
        mac: String,
        newPolicy: EnforcedClientPolicy,
        counters: ClientTrafficCounters,
    ): Int {
        val queue = pacingQueuesByMac[mac] ?: return 0
        val quotaExceeded = quotaRecordsByMac[mac]?.isQuotaExceeded == true || newPolicy.isQuotaOnlyBlock
        val shouldPurge = newPolicy.isNonQuotaBlocked ||
            (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT && (newPolicy.isBlocked || quotaExceeded))
        if (!shouldPurge) return 0
        val cancelled = queue.drainAll()
        for (pkt in cancelled) {
            if (newPolicy.isNonQuotaBlocked) {
                refundQuotaBytes(mac, pkt.length, pkt.isUpload)
            }
            counters.droppedPackets.incrementAndGet()
            counters.blockedDropPackets.incrementAndGet()
            counters.policyVersionBlockedDrops.incrementAndGet()
            if (quotaExceeded && !newPolicy.isNonQuotaBlocked) {
                counters.quotaDropPackets.incrementAndGet()
            }
            counters.droppedBytes.addAndGet(pkt.length.toLong())
            counters.decisionsRecomputed.incrementAndGet()
            counters.staleAllowCacheHitsPrevented.incrementAndGet()
            counters.verifiedDroppedAfterBlockPackets.incrementAndGet()
            counters.verifiedDroppedAfterBlockBytes.addAndGet(pkt.length.toLong())
        }
        return cancelled.size
    }

    fun getQueuedPacketCountForClient(mac: String): Int {
        return pacingQueuesByMac[mac.uppercase().trim()]?.queuedCount?.get() ?: 0
    }

    fun getCounterSnapshot(mac: String): CounterSnapshot {
        val cleanMac = mac.uppercase().trim()
        val c = countersByMac[cleanMac]
        val quota = getQuotaRecord(cleanMac)
        val policyInstalled = isAttached && policiesByMac.containsKey(cleanMac)
        return if (c == null) {
            CounterSnapshot(
                mac = cleanMac,
                seenPackets = 0L,
                matchedPackets = 0L,
                forwardedPackets = 0L,
                droppedPackets = 0L,
                shapedPackets = 0L,
                rxBytes = quota?.sanitizedRxBytes ?: 0L,
                txBytes = quota?.sanitizedTxBytes ?: 0L,
                droppedBytes = 0L,
                shapedBytes = 0L,
                policyInstalled = policyInstalled,
                blockedDropPackets = 0L,
                shapingDropPackets = 0L,
                policyVersion = 1L,
                policyVersionBlockedDrops = 0L,
                unattributedPostNatObserved = false,
                directAttributedPackets = 0L,
                bpfAttributedPackets = 0L,
                conntrackAttributedPackets = 0L,
                policyVersionShapedPackets = 0L,
                quotaDropPackets = 0L,
                quotaUsedRxBytes = quota?.sanitizedRxBytes ?: 0L,
                quotaUsedTxBytes = quota?.sanitizedTxBytes ?: 0L,
                quotaWindowId = quota?.windowId.orEmpty(),
                quotaWindowStartEpochMs = quota?.windowStartEpochMs ?: 0L,
                quotaLastUpdatedEpochMs = quota?.lastUpdatedEpochMs ?: 0L,
                quotaResetGeneration = quota?.resetGeneration ?: 0L,
                quotaExceeded = quota?.isQuotaExceeded == true,
            )
        } else {
            val unattributedSincePolicy =
                (postNatUnmatchedPackets.get() - c.policyBaselinePostNatUnmatched) > 0L &&
                    !HostFirewall.isKernelNetfilterAvailable
            val qRx = quota?.sanitizedRxBytes ?: c.rxBytes.get()
            val qTx = quota?.sanitizedTxBytes ?: c.txBytes.get()
            CounterSnapshot(
                mac = cleanMac,
                seenPackets = c.seenPackets.get(),
                matchedPackets = c.matchedPackets.get(),
                forwardedPackets = c.forwardedPackets.get(),
                droppedPackets = c.droppedPackets.get(),
                shapedPackets = c.shapedPackets.get(),
                rxBytes = maxOf(c.rxBytes.get(), qRx),
                txBytes = maxOf(c.txBytes.get(), qTx),
                droppedBytes = c.droppedBytes.get(),
                shapedBytes = c.shapedBytes.get(),
                policyInstalled = policyInstalled,
                blockedDropPackets = c.blockedDropPackets.get(),
                shapingDropPackets = c.shapingDropPackets.get(),
                policyVersion = c.policyVersion.get(),
                policyVersionBlockedDrops = c.policyVersionBlockedDrops.get(),
                unattributedPostNatObserved = unattributedSincePolicy,
                directAttributedPackets = c.directAttributedPackets.get(),
                bpfAttributedPackets = c.bpfAttributedPackets.get(),
                conntrackAttributedPackets = c.conntrackAttributedPackets.get(),
                policyVersionShapedPackets = c.policyVersionShapedPackets.get(),
                quotaDropPackets = c.quotaDropPackets.get(),
                quotaUsedRxBytes = qRx,
                quotaUsedTxBytes = qTx,
                quotaWindowId = quota?.windowId.orEmpty(),
                quotaWindowStartEpochMs = quota?.windowStartEpochMs ?: 0L,
                quotaLastUpdatedEpochMs = quota?.lastUpdatedEpochMs ?: 0L,
                quotaResetGeneration = quota?.resetGeneration ?: 0L,
                quotaExceeded = quota?.isQuotaExceeded == true,
            )
        }
    }

    fun getClientTraffic(mac: String, ips: Collection<String>): Pair<Long, Long> {
        val snapshot = getCounterSnapshot(mac)
        return snapshot.rxBytes to snapshot.txBytes
    }

    private fun startPacingDispatcher() {
        stopPacingDispatcher()
        val exec = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "shizzi-pacing-dispatcher").apply {
                isDaemon = true
                priority = Thread.MAX_PRIORITY
            }
        }
        pacingExecutor = exec
        exec.scheduleWithFixedDelay(
            { drainDuePacedPackets(System.nanoTime()) },
            2L,
            4L,
            java.util.concurrent.TimeUnit.MILLISECONDS,
        )
    }

    private fun stopPacingDispatcher() {
        pacingExecutor?.shutdownNow()
        pacingExecutor = null
    }

    private fun clearPacingQueues() {
        for ((mac, q) in pacingQueuesByMac) {
            val drained = q.drainAll()
            for (pkt in drained) {
                refundQuotaBytes(mac, pkt.length, pkt.isUpload)
            }
        }
        pacingQueuesByMac.clear()
    }

    internal fun drainDuePacedPackets(nowNs: Long = System.nanoTime()): Int {
        if (dnsAttributionRetryEnabled) {
            processPendingDnsAttributionRetries(nowNs / 1_000_000L)
        }
        if (vpnForwardingGateClosed) {
            clearPacingQueues()
            return 0
        }
        var sentCount = 0
        for ((mac, queue) in pacingQueuesByMac) {
            while (true) {
                val pkt = queue.pollIfDue(nowNs) ?: break
                val currentPolicy = policiesByMac[mac]
                val quotaRecord = quotaRecordsByMac[mac]
                val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }
                val isNonQuotaBlocked = currentPolicy != null && currentPolicy.isNonQuotaBlocked
                val isQuotaBlocked = (currentPolicy?.isQuotaOnlyBlock == true) || (quotaRecord?.isQuotaExceeded == true)
                val isVersionStale = pkt.policyVersionAtEnqueue != counters.policyVersion.get()
                val shouldDropInCurrentMode = bpfNatVpnEnforcementEnabled && (
                    isNonQuotaBlocked ||
                        (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT &&
                            (isQuotaBlocked || (isVersionStale && (currentPolicy?.isBlocked == true || isQuotaBlocked))))
                    )
                // Re-evaluate current policy before releasing a queued packet
                if (shouldDropInCurrentMode) {
                    if (isNonQuotaBlocked) {
                        refundQuotaBytes(mac, pkt.length, pkt.isUpload)
                    }
                    counters.droppedPackets.incrementAndGet()
                    counters.blockedDropPackets.incrementAndGet()
                    counters.policyVersionBlockedDrops.incrementAndGet()
                    if (isQuotaBlocked && !isNonQuotaBlocked) {
                        counters.quotaDropPackets.incrementAndGet()
                    }
                    counters.droppedBytes.addAndGet(pkt.length.toLong())
                    counters.decisionsRecomputed.incrementAndGet()
                    counters.staleAllowCacheHitsPrevented.incrementAndGet()
                    counters.verifiedDroppedAfterBlockPackets.incrementAndGet()
                    counters.verifiedDroppedAfterBlockBytes.addAndGet(pkt.length.toLong())
                    continue
                }
                if (isNonQuotaBlocked || isQuotaBlocked) {
                    counters.verifiedAllowedAfterBlockPackets.incrementAndGet()
                    counters.verifiedAllowedAfterBlockBytes.addAndGet(pkt.length.toLong())
                }
                counters.forwardedPackets.incrementAndGet()
                if (pkt.isUpload) {
                    counters.uploadForwardedPackets.incrementAndGet()
                    counters.txBytes.addAndGet(pkt.length.toLong())
                } else {
                    counters.downloadForwardedPackets.incrementAndGet()
                    counters.rxBytes.addAndGet(pkt.length.toLong())
                }
                pkt.targetFd?.let { fd ->
                    runCatching { writePacket(fd, pkt.data, pkt.length) }
                }
                sentCount++
            }
        }
        return sentCount
    }

    private fun relayUploadLoop(tunFd: FileDescriptor, proxyFd: FileDescriptor, bufSize: Int) {
        val buf = ByteArray(bufSize)
        val pollFds = arrayOf(
            StructPollfd().apply {
                fd = tunFd
                events = OsConstants.POLLIN.toShort()
            },
        )

        while (running.get()) {
            try {
                val n = readPacketWithPoll(tunFd, pollFds, buf)
                if (n <= 0) continue

                totalUploadPackets.incrementAndGet()
                val meta = parsePacketMeta(buf, n)
                if (meta != null) {
                    val attr = resolveClientMacWithSource(meta, isUpload = true)
                    val detail = evaluateAndShapeDetailed(
                        meta = meta,
                        matchedMac = attr.mac,
                        isUpload = true,
                        attributionSource = attr.source,
                        rawPacket = buf,
                        rawLength = n,
                        tunFd = tunFd,
                        proxyFd = proxyFd,
                    )
                    if (detail.heldForDnsRetry) {
                        continue
                    }
                    if (detail.decision == PacketDecision.DROP || detail.decision == PacketDecision.DROP_AQM) {
                        val synthResp = detail.domainDecision?.synthesizedDnsResponse
                        if (synthResp != null && synthResp.isNotEmpty()) {
                            writePacket(tunFd, synthResp, synthResp.size)
                        }
                        continue
                    }
                    if (detail.decision == PacketDecision.RATE_LIMIT && attr.mac != null && detail.paceDelayMs > 0L) {
                        val enqueued = enqueuePacedPacket(
                            mac = attr.mac,
                            isUpload = true,
                            buf = buf,
                            length = n,
                            paceDelayMs = detail.paceDelayMs,
                            policyVersion = detail.policyVersion,
                            targetFd = proxyFd,
                        )
                        if (!enqueued) {
                            recordQueueOverflowDrop(attr.mac, n)
                        }
                        continue
                    }
                }

                writePacket(proxyFd, buf, n)
            } catch (e: ErrnoException) {
                if (!running.get()) break
                if (e.errno == OsConstants.EINTR || e.errno == OsConstants.EAGAIN) continue
                if (e.errno == OsConstants.EBADF || e.errno == OsConstants.EPIPE || e.errno == OsConstants.ECONNRESET) break
            } catch (_: InterruptedException) {
                if (!running.get()) break
            } catch (_: Throwable) {
                if (!running.get()) break
            }
        }
    }

    private fun relayDownloadLoop(proxyFd: FileDescriptor, tunFd: FileDescriptor, bufSize: Int) {
        val buf = ByteArray(bufSize)
        val pollFds = arrayOf(
            StructPollfd().apply {
                fd = proxyFd
                events = OsConstants.POLLIN.toShort()
            },
        )

        while (running.get()) {
            try {
                val n = readPacketWithPoll(proxyFd, pollFds, buf)
                if (n <= 0) continue

                totalDownloadPackets.incrementAndGet()
                val meta = parsePacketMeta(buf, n)
                if (meta != null) {
                    val attr = resolveClientMacWithSource(meta, isUpload = false)
                    val detail = evaluateAndShapeDetailed(meta, attr.mac, isUpload = false, attributionSource = attr.source)
                    if (detail.decision == PacketDecision.DROP || detail.decision == PacketDecision.DROP_AQM) {
                        continue
                    }
                    if (detail.decision == PacketDecision.RATE_LIMIT && attr.mac != null && detail.paceDelayMs > 0L) {
                        val enqueued = enqueuePacedPacket(
                            mac = attr.mac,
                            isUpload = false,
                            buf = buf,
                            length = n,
                            paceDelayMs = detail.paceDelayMs,
                            policyVersion = detail.policyVersion,
                            targetFd = tunFd,
                        )
                        if (!enqueued) {
                            recordQueueOverflowDrop(attr.mac, n, isUpload = false)
                        }
                        continue
                    }
                }

                writePacket(tunFd, buf, n)
            } catch (e: ErrnoException) {
                if (!running.get()) break
                if (e.errno == OsConstants.EINTR || e.errno == OsConstants.EAGAIN) continue
                if (e.errno == OsConstants.EBADF || e.errno == OsConstants.EPIPE || e.errno == OsConstants.ECONNRESET) break
            } catch (_: InterruptedException) {
                if (!running.get()) break
            } catch (_: Throwable) {
                if (!running.get()) break
            }
        }
    }

    internal fun enqueuePacedPacket(
        mac: String,
        isUpload: Boolean,
        buf: ByteArray,
        length: Int,
        paceDelayMs: Long,
        policyVersion: Long,
        targetFd: FileDescriptor?,
        nowNs: Long = System.nanoTime(),
    ): Boolean {
        val cleanMac = mac.uppercase().trim()
        val queue = pacingQueuesByMac.getOrPut(cleanMac) { ClientPacingQueue(cleanMac) }
        val copy = buf.copyOfRange(0, length)
        val pkt = QueuedPacedPacket(
            mac = cleanMac,
            isUpload = isUpload,
            data = copy,
            length = length,
            releaseAtMonoNs = nowNs + paceDelayMs * 1_000_000L,
            policyVersionAtEnqueue = policyVersion,
            targetFd = targetFd,
        )
        return queue.tryEnqueue(pkt)
    }

    internal fun recordQueueOverflowDrop(mac: String, packetLength: Int, isUpload: Boolean = true) {
        refundQuotaBytes(mac, packetLength, isUpload)
        val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }
        counters.droppedPackets.incrementAndGet()
        counters.shapingDropPackets.incrementAndGet()
        counters.droppedBytes.addAndGet(packetLength.toLong())
    }

    private fun readPacketWithPoll(
        fd: FileDescriptor,
        pollFds: Array<StructPollfd>,
        buf: ByteArray,
    ): Int {
        return try {
            Os.read(fd, buf, 0, buf.size)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.EAGAIN && running.get()) {
                pollFds[0].revents = 0
                val ready = Os.poll(pollFds, 250)
                if (ready > 0 && running.get()) {
                    Os.read(fd, buf, 0, buf.size)
                } else {
                    0
                }
            } else {
                throw e
            }
        }
    }

    private fun writePacket(fd: FileDescriptor, buf: ByteArray, length: Int) {
        try {
            Os.write(fd, buf, 0, length)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.EAGAIN && running.get()) {
                val pollOut = arrayOf(
                    StructPollfd().apply {
                        this.fd = fd
                        this.events = OsConstants.POLLOUT.toShort()
                    },
                )
                if (Os.poll(pollOut, 25) > 0 && running.get()) {
                    runCatching { Os.write(fd, buf, 0, length) }
                }
            } else if (e.errno != OsConstants.ENOBUFS && e.errno != OsConstants.EINTR) {
                throw e
            }
        }
    }

    internal fun resolveClientMacForPacket(meta: PacketMeta, isUpload: Boolean): String? =
        resolveClientMacWithSource(meta, isUpload).mac

    /**
     * Resolves which verified connected client MAC owns [meta] and records the attribution source
     * and structured [UnattributedReason] without altering datapath forwarding decisions.
     */
    internal fun resolveClientMacWithSource(meta: PacketMeta, isUpload: Boolean): PacketAttribution {
        fun record(attr: PacketAttribution): PacketAttribution {
            meta.resolvedAttribution = attr
            return attr
        }

        if (isLinkLocalMulticastControl(meta)) {
            return record(PacketAttribution(null, AttributionSource.UNMATCHED_UNKNOWN, unattributedReason = null))
        }
        if (meta.isNonInitialFragment) {
            unsupportedOrFragmentPackets.incrementAndGet()
            return record(
                PacketAttribution(
                    mac = null,
                    source = AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT,
                    unattributedReason = UnattributedReason.NON_INITIAL_FRAGMENT,
                ),
            )
        }

        val tetherSideIp = if (isUpload) meta.srcIp else meta.dstIp
        val tetherSidePort = if (isUpload) meta.srcPort else meta.dstPort
        val remoteSideIp = if (isUpload) meta.dstIp else meta.srcIp
        val remoteSidePort = if (isUpload) meta.dstPort else meta.srcPort

        val normalizedTetherIp = normalizeIp(tetherSideIp)

        // 1. Direct lookup in verified IP -> MAC table
        ipToMac[tetherSideIp]?.let { mac ->
            if (mac in activeConnectedMacs) {
                return record(PacketAttribution(mac, AttributionSource.DIRECT_IP))
            }
        }
        if (normalizedTetherIp.isNotEmpty() && normalizedTetherIp != tetherSideIp) {
            ipToMac[normalizedTetherIp]?.let { mac ->
                if (mac in activeConnectedMacs) {
                    return record(PacketAttribution(mac, AttributionSource.DIRECT_IP))
                }
            }
        }

        // 2. Post-NAT MASQUERADE on testtun (`192.0.2.2` or `2001:db8::2`)
        if (tetherSideIp == TUN_LOCAL_V4 || tetherSideIp == TUN_LOCAL_V6 || normalizedTetherIp == TUN_LOCAL_V6_NORMALIZED) {
            // Non-TCP/UDP protocols on post-NAT cannot be disambiguated by transport ports
            if (meta.protocol != 6 && meta.protocol != 17) {
                unsupportedOrFragmentPackets.incrementAndGet()
                return record(
                    PacketAttribution(
                        mac = null,
                        source = AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT,
                        unattributedReason = UnattributedReason.UNSUPPORTED_PROTOCOL,
                    ),
                )
            }
            if (tetherSidePort !in 1..65535 || remoteSidePort !in 1..65535) {
                unsupportedOrFragmentPackets.incrementAndGet()
                return record(
                    PacketAttribution(
                        mac = null,
                        source = AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT,
                        unattributedReason = UnattributedReason.INVALID_OR_MISSING_PORTS,
                    ),
                )
            }

            var bpfFailureReason: UnattributedReason = if (meta.version == 6) {
                UnattributedReason.IPV6_NOT_SUPPORTED_BY_BPF_MAP
            } else {
                UnattributedReason.NO_ACTIVE_SNAPSHOT
            }

            // 2a. Experimental BPF NAT flow attribution (never caches ALLOW decisions; resolves owner per packet)
            if (isExperimentalBpfEnabled && meta.version == 4) {
                val translatedKey = TranslatedFlowKey(
                    family = 4,
                    protocol = meta.protocol,
                    translatedIp = tetherSideIp,
                    translatedPort = tetherSidePort,
                    remoteIp = remoteSideIp,
                    remotePort = remoteSidePort,
                )
                if (meta.isTcpSyn) {
                    invalidateVerifiedFlowPin(translatedKey)
                }
                val detailed = bpfAttributor.resolveTranslatedPacketDetailed(
                    family = meta.version,
                    protocol = meta.protocol,
                    packetSrcIp = meta.srcIp,
                    packetSrcPort = meta.srcPort,
                    packetDstIp = meta.dstIp,
                    packetDstPort = meta.dstPort,
                    isUpload = isUpload,
                    isTcpSyn = meta.isTcpSyn,
                    ipToMac = ipToMac,
                    activeConnectedMacs = activeConnectedMacs,
                )
                val pktBytesLong = meta.length.coerceAtLeast(0).toLong()
                when (val outcome = detailed.outcome) {
                    is AttributionOutcome.Matched -> {
                        if (meta.isTcpFinOrRst) {
                            invalidateVerifiedFlowPin(translatedKey)
                        } else {
                            pinVerifiedBpfFlow(
                                flowKey = translatedKey,
                                verifiedMac = outcome.mac,
                                originalClientIp = outcome.mapping.origClientIp,
                                sessionGen = outcome.mapping.sessionGeneration,
                                bindingGen = outcome.mapping.bindingGeneration,
                            )
                        }
                        val refreshedSnapMono = bpfReader.lastRefreshOnMissPublishedSnapshotMonoMs.get()
                        val isPostRefreshHit = bpfRefreshOnMissEnabled &&
                            refreshedSnapMono > 0L &&
                            outcome.mapping.collectedAtMonotonicMs == refreshedSnapMono
                        return record(
                            PacketAttribution(
                                mac = outcome.mac,
                                source = AttributionSource.BPF_NAT,
                                refreshedSnapshotHit = isPostRefreshHit,
                            ),
                        )
                    }
                    is AttributionOutcome.Ambiguous,
                    is AttributionOutcome.StaleSnapshot,
                    is AttributionOutcome.StaleOrInvalidated,
                    -> {
                        val reason = detailed.failureReason ?: UnattributedReason.OTHER_UNKNOWN
                        if (outcome is AttributionOutcome.StaleSnapshot && !meta.isTcpSyn) {
                            val pin = lookupVerifiedFlowPin(translatedKey)
                            if (meta.isTcpFinOrRst) {
                                invalidateVerifiedFlowPin(translatedKey)
                            }
                            if (pin != null) {
                                if (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) {
                                    if (meta.protocol == 6) {
                                        establishedTcpPinnedMatchedPackets.incrementAndGet()
                                        establishedTcpPinnedMatchedBytes.addAndGet(pktBytesLong)
                                    }
                                    if (bpfRefreshOnMissEnabled) {
                                        bpfReader.requestAsyncRefreshOnMiss(reason)
                                    }
                                    return record(
                                        PacketAttribution(
                                            mac = pin.verifiedMac,
                                            source = AttributionSource.BPF_NAT,
                                            pinnedFlowHit = true,
                                        ),
                                    )
                                } else {
                                    pinnedFlowHitsInDiagnosticMode.incrementAndGet()
                                }
                            }
                            if (meta.protocol == 6) {
                                establishedTcpMissingFromBpfPackets.incrementAndGet()
                                establishedTcpMissingFromBpfBytes.addAndGet(pktBytesLong)
                            }
                        } else if (meta.isTcpFinOrRst) {
                            invalidateVerifiedFlowPin(translatedKey)
                        }
                        ambiguousOrStaleLookups.incrementAndGet()
                        if (bpfRefreshOnMissEnabled && reason == UnattributedReason.SNAPSHOT_STALE) {
                            bpfReader.requestAsyncRefreshOnMiss(reason)
                        }
                        return record(
                            PacketAttribution(
                                mac = null,
                                source = AttributionSource.UNMATCHED_AMBIGUOUS_OR_STALE,
                                unattributedReason = reason,
                            ),
                        )
                    }
                    AttributionOutcome.Unknown -> {
                        bpfFailureReason = detailed.failureReason ?: UnattributedReason.TUPLE_NOT_PRESENT
                        if (!meta.isTcpSyn &&
                            (bpfFailureReason == UnattributedReason.TUPLE_NOT_PRESENT ||
                                bpfFailureReason == UnattributedReason.SNAPSHOT_STALE)
                        ) {
                            val pin = lookupVerifiedFlowPin(translatedKey)
                            if (meta.isTcpFinOrRst) {
                                invalidateVerifiedFlowPin(translatedKey)
                            }
                            if (pin != null) {
                                if (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) {
                                    if (meta.protocol == 6) {
                                        establishedTcpPinnedMatchedPackets.incrementAndGet()
                                        establishedTcpPinnedMatchedBytes.addAndGet(pktBytesLong)
                                    }
                                    if (bpfRefreshOnMissEnabled) {
                                        bpfReader.requestAsyncRefreshOnMiss(bpfFailureReason)
                                    }
                                    return record(
                                        PacketAttribution(
                                            mac = pin.verifiedMac,
                                            source = AttributionSource.BPF_NAT,
                                            pinnedFlowHit = true,
                                        ),
                                    )
                                } else {
                                    pinnedFlowHitsInDiagnosticMode.incrementAndGet()
                                }
                            }
                        } else if (meta.isTcpFinOrRst) {
                            invalidateVerifiedFlowPin(translatedKey)
                        }
                        if (meta.protocol == 6 && !meta.isTcpSyn) {
                            establishedTcpMissingFromBpfPackets.incrementAndGet()
                            establishedTcpMissingFromBpfBytes.addAndGet(pktBytesLong)
                        }
                        if (bpfRefreshOnMissEnabled &&
                            (bpfFailureReason == UnattributedReason.TUPLE_NOT_PRESENT ||
                                bpfFailureReason == UnattributedReason.SNAPSHOT_STALE)
                        ) {
                            bpfReader.requestAsyncRefreshOnMiss(bpfFailureReason)
                        }
                        // Fall through to check procfs conntrack if readable
                    }
                }
            }

            // 2b. Procfs conntrack fallback (when readable on the device)
            conntrackFallbackAttemptedCount.incrementAndGet()
            val normalizedRemoteIp = normalizeIp(remoteSideIp).ifEmpty { remoteSideIp }
            val flowKey = FlowKey(
                version = meta.version,
                protocol = meta.protocol,
                natPort = tetherSidePort,
                remoteIp = normalizedRemoteIp,
                remotePort = remoteSidePort,
            )

            flowToMacCache[flowKey]?.let { cachedMac ->
                if (cachedMac in activeConnectedMacs) {
                    flowTimestamps[flowKey] = System.currentTimeMillis()
                    conntrackFallbackSucceededCount.incrementAndGet()
                    return record(
                        PacketAttribution(
                            mac = cachedMac,
                            source = AttributionSource.CONNTRACK_PROCFS,
                            fallbackAttempted = true,
                        ),
                    )
                }
                flowToMacCache.remove(flowKey, cachedMac)
                flowTimestamps.remove(flowKey)
            }

            maybeResolveConntrackFlows()
            flowToMacCache[flowKey]?.let { resolvedMac ->
                if (resolvedMac in activeConnectedMacs) {
                    flowTimestamps[flowKey] = System.currentTimeMillis()
                    conntrackFallbackSucceededCount.incrementAndGet()
                    return record(
                        PacketAttribution(
                            mac = resolvedMac,
                            source = AttributionSource.CONNTRACK_PROCFS,
                            fallbackAttempted = true,
                        ),
                    )
                }
            }
            conntrackFallbackFailedCount.incrementAndGet()
            return record(
                PacketAttribution(
                    mac = null,
                    source = AttributionSource.UNMATCHED_UNKNOWN,
                    unattributedReason = bpfFailureReason,
                    fallbackAttempted = true,
                ),
            )
        }

        // 3. IPv6 SLAAC in testtun prefix (`2001:db8::/64`) or link-local (`fe80::/64`)
        if (meta.version == 6 && (tetherSideIp.lowercase().startsWith(TUN_PREFIX_V6) || tetherSideIp.lowercase().startsWith("fe80:"))) {
            extractMacFromIpv6Eui64(tetherSideIp)?.let { euiMac ->
                if (euiMac in activeConnectedMacs) {
                    bindClientIp(euiMac, tetherSideIp)
                    return record(PacketAttribution(euiMac, AttributionSource.DIRECT_IP))
                }
            }

            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) {
                    return record(PacketAttribution(neighborMac, AttributionSource.DIRECT_IP))
                }
            }
            if (normalizedTetherIp.isNotEmpty()) {
                ipToMac[normalizedTetherIp]?.let { neighborMac ->
                    if (neighborMac in activeConnectedMacs) {
                        return record(PacketAttribution(neighborMac, AttributionSource.DIRECT_IP))
                    }
                }
            }
            return record(
                PacketAttribution(
                    mac = null,
                    source = AttributionSource.UNMATCHED_UNKNOWN,
                    unattributedReason = UnattributedReason.IP_BINDING_MISSING_OR_CHANGED,
                ),
            )
        }

        // 4. Unmapped private IPv4 address lookup against control-plane neighbor table
        if (meta.version == 4 && isPrivateIpv4(tetherSideIp)) {
            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) {
                    return record(PacketAttribution(neighborMac, AttributionSource.DIRECT_IP))
                }
            }
            return record(
                PacketAttribution(
                    mac = null,
                    source = AttributionSource.UNMATCHED_UNKNOWN,
                    unattributedReason = UnattributedReason.IP_BINDING_MISSING_OR_CHANGED,
                ),
            )
        }

        val fallbackReason = if (meta.version == 6) {
            UnattributedReason.IPV6_NOT_SUPPORTED_BY_BPF_MAP
        } else {
            UnattributedReason.OTHER_UNKNOWN
        }
        return record(
            PacketAttribution(
                mac = null,
                source = AttributionSource.UNMATCHED_UNKNOWN,
                unattributedReason = fallbackReason,
            ),
        )
    }

    internal fun isLinkLocalMulticastControl(meta: PacketMeta): Boolean {
        if (meta.version != 6) return false
        val srcLower = meta.srcIp.lowercase()
        val dstLower = meta.dstIp.lowercase()
        return (srcLower.startsWith("fe80:") || srcLower == "::") && dstLower.startsWith("ff02:")
    }

    internal fun evaluateAndShape(
        meta: PacketMeta,
        matchedMac: String?,
        isUpload: Boolean,
        attributionSource: AttributionSource = AttributionSource.DIRECT_IP,
        rawPacket: ByteArray? = null,
        rawLength: Int = meta.length,
    ): PacketDecision = evaluateAndShapeDetailed(meta, matchedMac, isUpload, attributionSource, rawPacket, rawLength).decision

    internal fun evaluateAndShapeDetailed(
        meta: PacketMeta,
        matchedMac: String?,
        isUpload: Boolean,
        attributionSource: AttributionSource = AttributionSource.DIRECT_IP,
        rawPacket: ByteArray? = null,
        rawLength: Int = meta.length,
        tunFd: FileDescriptor? = null,
        proxyFd: FileDescriptor? = null,
        onDnsRetryResolvedAction: ((PacketDecision, DomainPacketDecision?, String?) -> Unit)? = null,
    ): EvaluationDetail {
        val pktBytes = meta.length.coerceAtLeast(0).toLong()

        // Local IPv6 multicast control frames (fe80:: -> ff02::2 RS/RA/MLD) are link-local
        // control traffic, not internet browsing traffic; excluded from eligible denominator.
        if (isLinkLocalMulticastControl(meta)) {
            localControlPackets.incrementAndGet()
            localControlBytes.addAndGet(pktBytes)
            return EvaluationDetail(PacketDecision.ALLOW)
        }

        // v0.10.9-debug Feature B2: Fail-closed VPN forwarding gate.
        // When a bound VPN disconnects and stopHotspotOnVpnDisconnect == false, drop all client
        // upstream/downstream data packets so traffic can NEVER silently bypass the VPN.
        if (vpnForwardingGateClosed) {
            vpnFailClosedDroppedPackets.incrementAndGet()
            vpnFailClosedDroppedBytes.addAndGet(pktBytes)
            return EvaluationDetail(
                decision = PacketDecision.DROP,
                vpnGateDropped = true,
            )
        }

        totalEligiblePackets.incrementAndGet()
        totalEligibleBytes.addAndGet(pktBytes)

        if (meta.version == 6) {
            ipv6EligiblePackets.incrementAndGet()
            ipv6EligibleBytes.addAndGet(pktBytes)
        } else {
            ipv4EligiblePackets.incrementAndGet()
            ipv4EligibleBytes.addAndGet(pktBytes)
        }

        when (meta.protocol) {
            6 -> {
                tcpEligiblePackets.incrementAndGet()
                tcpEligibleBytes.addAndGet(pktBytes)
                if (meta.isTcpSyn) tcpSynPacketsSeen.incrementAndGet()
                if (meta.isTcpFinOrRst) tcpFinOrRstPacketsSeen.incrementAndGet()
                if (meta.isTcpAckOnly) tcpKeepaliveOrAckOnlyPackets.incrementAndGet()
            }
            17 -> {
                udpEligiblePackets.incrementAndGet()
                udpEligibleBytes.addAndGet(pktBytes)
            }
            1, 58 -> {
                icmpEligiblePackets.incrementAndGet()
                icmpEligibleBytes.addAndGet(pktBytes)
            }
            else -> {
                otherProtoEligiblePackets.incrementAndGet()
                otherProtoEligibleBytes.addAndGet(pktBytes)
            }
        }

        if (isUpload) {
            uploadEligiblePackets.incrementAndGet()
            uploadEligibleBytes.addAndGet(pktBytes)
        } else {
            downloadEligiblePackets.incrementAndGet()
            downloadEligibleBytes.addAndGet(pktBytes)
        }

        if (matchedMac == null) {
            unmatchedPackets.incrementAndGet()
            unknownForwardedBytes.addAndGet(pktBytes)

            if (isAnyClientCurrentlyBlockedOrQuotaExhausted()) {
                unknownForwardedAfterBlockPackets.incrementAndGet()
                unknownForwardedAfterBlockBytes.addAndGet(pktBytes)
                val protoName = when (meta.protocol) {
                    6 -> "TCP"
                    17 -> "UDP"
                    1, 58 -> "ICMP"
                    else -> "OTHER"
                }
                val famName = if (meta.version == 6) "IPv6" else "IPv4"
                val dirName = if (isUpload) "UPLOAD" else "DOWNLOAD"
                val bucketKey = "${protoName}_${famName}_${dirName}"
                unknownPostBlockByProtocolAndDirection.computeIfAbsent(bucketKey) { AtomicLong(0L) }.incrementAndGet()
                unknownPostBlockBytesByProtocolAndDirection.computeIfAbsent(bucketKey) { AtomicLong(0L) }.addAndGet(pktBytes)
                if (meta.protocol == 17 && (meta.srcPort == 443 || meta.dstPort == 443)) {
                    udp443PostBlockUnattributedPackets.incrementAndGet()
                    udp443PostBlockUnattributedBytes.addAndGet(pktBytes)
                }
                if (meta.protocol == 17 && (meta.srcPort == 53 || meta.dstPort == 53)) {
                    udp53PostBlockUnattributedPackets.incrementAndGet()
                    udp53PostBlockUnattributedBytes.addAndGet(pktBytes)
                }
            }

            if (meta.version == 6) {
                ipv6UnattributedPackets.incrementAndGet()
                ipv6UnattributedBytes.addAndGet(pktBytes)
            } else {
                ipv4UnattributedPackets.incrementAndGet()
                ipv4UnattributedBytes.addAndGet(pktBytes)
            }

            when (meta.protocol) {
                6 -> {
                    tcpUnattributedPackets.incrementAndGet()
                    tcpUnattributedBytes.addAndGet(pktBytes)
                }
                17 -> {
                    udpUnattributedPackets.incrementAndGet()
                    udpUnattributedBytes.addAndGet(pktBytes)
                }
                1, 58 -> {
                    icmpUnattributedPackets.incrementAndGet()
                    icmpUnattributedBytes.addAndGet(pktBytes)
                }
                else -> {
                    otherProtoUnattributedPackets.incrementAndGet()
                    otherProtoUnattributedBytes.addAndGet(pktBytes)
                }
            }

            if (isUpload) {
                uploadUnattributedPackets.incrementAndGet()
                uploadUnattributedBytes.addAndGet(pktBytes)
            } else {
                downloadUnattributedPackets.incrementAndGet()
                downloadUnattributedBytes.addAndGet(pktBytes)
            }

            val reason = meta.resolvedAttribution?.unattributedReason ?: when {
                meta.isNonInitialFragment -> UnattributedReason.NON_INITIAL_FRAGMENT
                attributionSource == AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT -> {
                    if (meta.protocol != 6 && meta.protocol != 17) {
                        UnattributedReason.UNSUPPORTED_PROTOCOL
                    } else {
                        UnattributedReason.INVALID_OR_MISSING_PORTS
                    }
                }
                attributionSource == AttributionSource.UNMATCHED_AMBIGUOUS_OR_STALE ->
                    UnattributedReason.TUPLE_AMBIGUOUS
                meta.version == 6 -> UnattributedReason.IPV6_NOT_SUPPORTED_BY_BPF_MAP
                else -> UnattributedReason.TUPLE_NOT_PRESENT
            }
            unattributedPacketsByReason.computeIfAbsent(reason) { AtomicLong(0L) }.incrementAndGet()
            unattributedBytesByReason.computeIfAbsent(reason) { AtomicLong(0L) }.addAndGet(pktBytes)

            val srcNorm = normalizeIp(meta.srcIp)
            val dstNorm = normalizeIp(meta.dstIp)
            val isPostNat = meta.srcIp == TUN_LOCAL_V4 ||
                meta.dstIp == TUN_LOCAL_V4 ||
                meta.srcIp == TUN_LOCAL_V6 ||
                meta.dstIp == TUN_LOCAL_V6 ||
                srcNorm == TUN_LOCAL_V6_NORMALIZED ||
                dstNorm == TUN_LOCAL_V6_NORMALIZED
            if (isPostNat) {
                postNatUnmatchedPackets.incrementAndGet()
            }
            if (deepTupleDiagnosticsEnabled || bpfRefreshOnMissEnabled) {
                val snap = bpfAttributor.currentSnapshot()
                val isPrivateSide = meta.version == 4 && isPrivateIpv4(if (isUpload) meta.srcIp else meta.dstIp)
                val role = when {
                    isPostNat && isUpload -> PreNatOrPostNatRole.POST_NAT_UPSTREAM
                    isPostNat && !isUpload -> PreNatOrPostNatRole.POST_NAT_DOWNSTREAM
                    isPrivateSide -> PreNatOrPostNatRole.PRE_NAT_CLIENT
                    else -> PreNatOrPostNatRole.UNKNOWN
                }
                val origin = if (isPrivateSide) {
                    TupleRoleOrigin.TUN_PACKET_PRE_NAT
                } else {
                    TupleRoleOrigin.TUN_PACKET_POST_NAT
                }
                val canonicalTuple = CanonicalFlowTuple(
                    networkSessionGeneration = bpfAttributor.currentSessionGeneration,
                    bindingGeneration = bpfAttributor.currentBindingGeneration,
                    ipFamily = meta.version,
                    transportProtocol = meta.protocol,
                    direction = if (isUpload) "UPLOAD" else "DOWNLOAD",
                    srcIp = meta.srcIp,
                    srcPortOrIcmpId = meta.srcPort,
                    dstIp = meta.dstIp,
                    dstPortOrIcmpId = meta.dstPort,
                    preNatOrPostNatRole = role,
                )
                deepTupleTracker.onPacketMiss(
                    tuple = canonicalTuple,
                    packetBytes = meta.length,
                    missReason = reason,
                    snapshot = snap,
                    directionConfidence = DirectionConfidence.KNOWN,
                    tupleRoleOrigin = origin,
                )
            }
            var unknownOwnerDomainDecision: DomainPacketDecision? = null
            if (isUpload && rawPacket != null && rawLength > 0) {
                val canAttemptDnsRetry = isExperimentalBpfEnabled &&
                    meta.version == 4 &&
                    (meta.protocol == 17 || meta.protocol == 6) &&
                    meta.dstPort == 53 &&
                    (reason == UnattributedReason.TUPLE_NOT_PRESENT ||
                        reason == UnattributedReason.SNAPSHOT_STALE ||
                        reason == UnattributedReason.NO_ACTIVE_SNAPSHOT)

                unknownOwnerDomainDecision = DomainFilterEngine.evaluateUploadPacket(
                    rawPacket = rawPacket,
                    length = rawLength,
                    srcIp = meta.srcIp,
                    matchedMac = null,
                    ownerVerified = false,
                    fromDedicatedHotspotTun = true,
                    isHostOriginated = false,
                    ownershipSource = "UNKNOWN_OWNER",
                    deferUnknownOwnerClientSkipForRetry = dnsAttributionRetryEnabled && canAttemptDnsRetry,
                )
                if (unknownOwnerDomainDecision.blocked) {
                    maybeLogTrafficSample(
                        meta = meta,
                        isUpload = isUpload,
                        matchedMac = null,
                        decision = PacketDecision.DROP,
                        attributionSource = attributionSource,
                    )
                    return EvaluationDetail(
                        decision = PacketDecision.DROP,
                        domainDecision = unknownOwnerDomainDecision,
                    )
                }
                if (unknownOwnerDomainDecision.clientRuleMatchedDomainOnUnknownOwner && canAttemptDnsRetry) {
                    // Feature A2 (D07): Targeted async BPF refresh on DNS per-host rule miss
                    val refreshReason = if (reason == UnattributedReason.SNAPSHOT_STALE) {
                        UnattributedReason.SNAPSHOT_STALE
                    } else {
                        UnattributedReason.TUPLE_NOT_PRESENT
                    }
                    bpfReader.requestAsyncRefreshOnMiss(refreshReason)

                    if (dnsAttributionRetryEnabled) {
                        val enqueued = enqueuePendingDnsRetryPacket(
                            meta = meta,
                            rawPacket = rawPacket,
                            rawLength = rawLength,
                            tunFd = tunFd,
                            proxyFd = proxyFd,
                            onResolvedAction = onDnsRetryResolvedAction,
                        )
                        if (enqueued) {
                            DomainFilterEngine.dnsRetryQueued.incrementAndGet()
                            return EvaluationDetail(
                                decision = PacketDecision.ALLOW,
                                domainDecision = unknownOwnerDomainDecision,
                                heldForDnsRetry = true,
                            )
                        } else {
                            // Queue overflow -> fail-open immediately and record overflow + unknown owner skip
                            DomainFilterEngine.dnsRetryOverflow.incrementAndGet()
                            DomainFilterEngine.unknownOwnerClientRuleSkips.incrementAndGet()
                            DomainFilterEngine.dnsQueriesAllowed.incrementAndGet()
                        }
                    }
                }
            }
            maybeLogTrafficSample(
                meta = meta,
                isUpload = isUpload,
                matchedMac = null,
                decision = PacketDecision.ALLOW,
                attributionSource = attributionSource,
            )
            return EvaluationDetail(
                decision = PacketDecision.ALLOW,
                domainDecision = unknownOwnerDomainDecision,
            )
        }

        totalAttributedPackets.incrementAndGet()
        totalAttributedBytes.addAndGet(pktBytes)

        if (meta.version == 6) {
            ipv6AttributedPackets.incrementAndGet()
            ipv6AttributedBytes.addAndGet(pktBytes)
        } else {
            ipv4AttributedPackets.incrementAndGet()
            ipv4AttributedBytes.addAndGet(pktBytes)
        }

        when (meta.protocol) {
            6 -> {
                tcpAttributedPackets.incrementAndGet()
                tcpAttributedBytes.addAndGet(pktBytes)
            }
            17 -> {
                udpAttributedPackets.incrementAndGet()
                udpAttributedBytes.addAndGet(pktBytes)
            }
            1, 58 -> {
                icmpAttributedPackets.incrementAndGet()
                icmpAttributedBytes.addAndGet(pktBytes)
            }
            else -> {
                otherProtoAttributedPackets.incrementAndGet()
                otherProtoAttributedBytes.addAndGet(pktBytes)
            }
        }

        if (isUpload) {
            uploadAttributedPackets.incrementAndGet()
            uploadAttributedBytes.addAndGet(pktBytes)
        } else {
            downloadAttributedPackets.incrementAndGet()
            downloadAttributedBytes.addAndGet(pktBytes)
        }

        if (meta.resolvedAttribution?.refreshedSnapshotHit == true) {
            postRefreshAttributedPackets.incrementAndGet()
            postRefreshAttributedBytes.addAndGet(pktBytes)
        }

        val counters = countersByMac.getOrPut(matchedMac) { ClientTrafficCounters(matchedMac) }
        counters.lastSeenAt = System.currentTimeMillis()
        counters.seenPackets.incrementAndGet()
        val isPinnedHit = meta.resolvedAttribution?.pinnedFlowHit == true
        if (isPinnedHit) {
            counters.decisionsRecomputed.incrementAndGet()
            counters.staleAllowCacheHitsPrevented.incrementAndGet()
        }
        when (attributionSource) {
            AttributionSource.BPF_NAT -> {
                bpfAttributedPackets.incrementAndGet()
                bpfAttributedBytes.addAndGet(pktBytes)
                counters.bpfAttributedPackets.incrementAndGet()
                if ((deepTupleDiagnosticsEnabled || bpfRefreshOnMissEnabled) &&
                    meta.version == 4 &&
                    (meta.protocol == 6 || meta.protocol == 17)
                ) {
                    val tetherSideIp = if (isUpload) meta.srcIp else meta.dstIp
                    val tetherSidePort = if (isUpload) meta.srcPort else meta.dstPort
                    val remoteSideIp = if (isUpload) meta.dstIp else meta.srcIp
                    val remoteSidePort = if (isUpload) meta.dstPort else meta.srcPort
                    val flowKey = TranslatedFlowKey(
                        family = 4,
                        protocol = meta.protocol,
                        translatedIp = tetherSideIp,
                        translatedPort = tetherSidePort,
                        remoteIp = remoteSideIp,
                        remotePort = remoteSidePort,
                    )
                    val resolvedFirstAfterRefresh = deepTupleTracker.onPacketAttributedByBpf(
                        flowKey = flowKey,
                        packetBytes = meta.length,
                        snapshot = bpfAttributor.currentSnapshot(),
                    )
                    if (resolvedFirstAfterRefresh && meta.resolvedAttribution?.refreshedSnapshotHit != true) {
                        postRefreshAttributedPackets.incrementAndGet()
                        postRefreshAttributedBytes.addAndGet(pktBytes)
                    }
                }
            }
            AttributionSource.DIRECT_IP -> {
                directAttributedPackets.incrementAndGet()
                directAttributedBytes.addAndGet(pktBytes)
                counters.directAttributedPackets.incrementAndGet()
            }
            AttributionSource.CONNTRACK_PROCFS -> {
                conntrackAttributedPackets.incrementAndGet()
                conntrackAttributedBytes.addAndGet(pktBytes)
                counters.conntrackAttributedPackets.incrementAndGet()
            }
            else -> {}
        }

        val currentPolicyVersion = counters.policyVersion.get()
        val quotaRecordBefore = getQuotaRecord(matchedMac)
        val policy = policiesByMac[matchedMac]
        val hasConfiguredQuota = (policy?.dataLimitBytes ?: 0L) > 0L || (quotaRecordBefore?.isQuotaEnabled == true)
        val hasActivePolicy = policy != null &&
            (policy.isBlocked || policy.bandwidthLimitKbps > 0 || hasConfiguredQuota)

        counters.matchedPackets.incrementAndGet()

        if (bpfNatVpnEnforcementEnabled && (hasActivePolicy || hasConfiguredQuota)) {
            // 1a. Non-quota hard block enforcement (manual admin block, time limit, or schedule; evaluated freshly on every packet)
            if (policy != null && policy.isNonQuotaBlocked) {
                counters.droppedPackets.incrementAndGet()
                counters.blockedDropPackets.incrementAndGet()
                counters.policyVersionBlockedDrops.incrementAndGet()
                counters.droppedBytes.addAndGet(meta.length.toLong())
                counters.decisionsRecomputed.incrementAndGet()
                counters.verifiedDroppedAfterBlockPackets.incrementAndGet()
                counters.verifiedDroppedAfterBlockBytes.addAndGet(pktBytes)
                if (isPinnedHit) {
                    counters.pinnedFlowEnforcedPackets.incrementAndGet()
                    counters.pinnedFlowEnforcedBytes.addAndGet(pktBytes)
                    pinnedFlowEnforcedDropsInEnforcementMode.incrementAndGet()
                }
                maybeLogTrafficSample(
                    meta = meta,
                    isUpload = isUpload,
                    matchedMac = matchedMac,
                    decision = PacketDecision.DROP,
                    attributionSource = attributionSource,
                )
                maybeLogCountersOnMilestone(counters)
                return EvaluationDetail(PacketDecision.DROP, policyVersion = currentPolicyVersion)
            }

            // 1b. Atomic per-client data quota enforcement (usedTotalBytes >= dataLimitBytes)
            val effectiveLimitBytes = policy?.dataLimitBytes?.takeIf { it > 0L }
                ?: quotaRecordBefore?.sanitizedLimitBytes
                ?: 0L
            val currentUsedBytes = quotaRecordBefore?.usedTotalBytes ?: 0L
            val crossesQuotaInEnforcementMode = phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT &&
                effectiveLimitBytes > 0L &&
                !(quotaRecordBefore?.isQuotaExceeded == true) &&
                DataQuota.safeAddBytes(currentUsedBytes, pktBytes) >= effectiveLimitBytes
            if (crossesQuotaInEnforcementMode) {
                recordQuotaBytes(matchedMac, meta.length, isUpload, policy)
                counters.staleAllowCacheHitsPrevented.incrementAndGet()
            }
            if ((quotaRecordBefore != null && quotaRecordBefore.isQuotaExceeded) ||
                crossesQuotaInEnforcementMode ||
                (phaseDMode == PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT && policy?.isQuotaOnlyBlock == true)
            ) {
                counters.droppedPackets.incrementAndGet()
                counters.blockedDropPackets.incrementAndGet()
                counters.policyVersionBlockedDrops.incrementAndGet()
                counters.quotaDropPackets.incrementAndGet()
                counters.droppedBytes.addAndGet(meta.length.toLong())
                counters.decisionsRecomputed.incrementAndGet()
                counters.verifiedDroppedAfterBlockPackets.incrementAndGet()
                counters.verifiedDroppedAfterBlockBytes.addAndGet(pktBytes)
                if (isPinnedHit) {
                    counters.pinnedFlowEnforcedPackets.incrementAndGet()
                    counters.pinnedFlowEnforcedBytes.addAndGet(pktBytes)
                    pinnedFlowEnforcedDropsInEnforcementMode.incrementAndGet()
                }
                maybeLogTrafficSample(
                    meta = meta,
                    isUpload = isUpload,
                    matchedMac = matchedMac,
                    decision = PacketDecision.DROP,
                    attributionSource = attributionSource,
                )
                maybeLogCountersOnMilestone(counters)
                return EvaluationDetail(PacketDecision.DROP, policyVersion = counters.policyVersion.get())
            }
        }

        // 1c. Shared Domain Filtering policy layer (Global + Per-Host DNS/SNI/Host rules; active in both BPF_NAT_VPN and SOFTAP_MAC_BLOCK)
        var verifiedDomainDecision: DomainPacketDecision? = null
        if (isUpload && rawPacket != null && rawLength > 0) {
            verifiedDomainDecision = DomainFilterEngine.evaluateUploadPacket(
                rawPacket = rawPacket,
                length = rawLength,
                srcIp = meta.srcIp,
                matchedMac = matchedMac,
                ownerVerified = true,
                fromDedicatedHotspotTun = true,
                isHostOriginated = false,
                ownershipSource = attributionSource.name,
            )
            if (verifiedDomainDecision.blocked) {
                counters.droppedPackets.incrementAndGet()
                counters.droppedBytes.addAndGet(meta.length.toLong())
                maybeLogTrafficSample(
                    meta = meta,
                    isUpload = isUpload,
                    matchedMac = matchedMac,
                    decision = PacketDecision.DROP,
                    attributionSource = attributionSource,
                )
                return EvaluationDetail(
                    decision = PacketDecision.DROP,
                    policyVersion = currentPolicyVersion,
                    domainDecision = verifiedDomainDecision,
                )
            }
        }

        if (!bpfNatVpnEnforcementEnabled || (!hasActivePolicy && !hasConfiguredQuota)) {
            recordQuotaBytes(matchedMac, meta.length, isUpload, policy)
            counters.forwardedPackets.incrementAndGet()
            if (isUpload) {
                counters.uploadForwardedPackets.incrementAndGet()
                counters.txBytes.addAndGet(meta.length.toLong())
            } else {
                counters.downloadForwardedPackets.incrementAndGet()
                counters.rxBytes.addAndGet(meta.length.toLong())
            }
            return EvaluationDetail(
                decision = PacketDecision.ALLOW,
                policyVersion = currentPolicyVersion,
                domainDecision = verifiedDomainDecision,
            )
        }

        // 2. Non-blocking per-client calibrated Token Bucket bandwidth limiting
        val limitKbps = policy?.bandwidthLimitKbps ?: 0
        if (limitKbps > 0) {
            val bucketMap = if (isUpload) uploadBucketsByMac else downloadBucketsByMac
            val bucket = bucketMap.getOrPut(matchedMac) { TokenBucket(limitKbps) }
            bucket.updateRate(limitKbps)

            val waitMs = bucket.consume(
                packetBytes = meta.length,
                isSmallControlPacket = meta.isSmallControlPacket,
                maxQueueDelayMs = DEFAULT_MAX_QUEUE_DELAY_MS,
            )

            if (waitMs < 0L) {
                counters.droppedPackets.incrementAndGet()
                counters.shapingDropPackets.incrementAndGet()
                counters.droppedBytes.addAndGet(meta.length.toLong())
                counters.shapedPackets.incrementAndGet()
                counters.policyVersionShapedPackets.incrementAndGet()
                maybeLogTrafficSample(
                    meta = meta,
                    isUpload = isUpload,
                    matchedMac = matchedMac,
                    decision = PacketDecision.DROP_AQM,
                    attributionSource = attributionSource,
                )
                maybeLogCountersOnMilestone(counters)
                return EvaluationDetail(PacketDecision.DROP_AQM, policyVersion = currentPolicyVersion)
            }

            if (waitMs > 0L) {
                // Count each shaped/queued packet ONCE toward quota upon acceptance into the pacing pipeline;
                // if later dropped by queue overflow or admin block before transmission, bytes are refunded.
                recordQuotaBytes(matchedMac, meta.length, isUpload, policy)
                counters.shapedPackets.incrementAndGet()
                counters.policyVersionShapedPackets.incrementAndGet()
                counters.shapedBytes.addAndGet(meta.length.toLong())
                maybeLogTrafficSample(
                    meta = meta,
                    isUpload = isUpload,
                    matchedMac = matchedMac,
                    decision = PacketDecision.RATE_LIMIT,
                    attributionSource = attributionSource,
                )
                maybeLogCountersOnMilestone(counters)
                // Do NOT sleep on the shared forwarding thread; return paceDelayMs for per-client queue
                return EvaluationDetail(
                    decision = PacketDecision.RATE_LIMIT,
                    paceDelayMs = waitMs,
                    policyVersion = currentPolicyVersion,
                )
            } else {
                counters.shapedBytes.addAndGet(meta.length.toLong())
            }
        }

        // Count immediately forwarded packet ONCE toward quota and rx/tx counters
        val updatedQuota = recordQuotaBytes(matchedMac, meta.length, isUpload, policy)
        if ((quotaRecordBefore?.isQuotaExceeded != true && updatedQuota.isQuotaExceeded) ||
            policy?.isQuotaOnlyBlock == true
        ) {
            counters.verifiedAllowedAfterBlockPackets.incrementAndGet()
            counters.verifiedAllowedAfterBlockBytes.addAndGet(pktBytes)
        }
        counters.forwardedPackets.incrementAndGet()
        if (isUpload) {
            counters.uploadForwardedPackets.incrementAndGet()
            counters.txBytes.addAndGet(meta.length.toLong())
        } else {
            counters.downloadForwardedPackets.incrementAndGet()
            counters.rxBytes.addAndGet(meta.length.toLong())
        }
        maybeLogCountersOnMilestone(counters)
        return EvaluationDetail(PacketDecision.ALLOW, policyVersion = currentPolicyVersion)
    }

    private fun maybeLogTrafficSample(
        meta: PacketMeta,
        isUpload: Boolean,
        matchedMac: String?,
        decision: PacketDecision,
        attributionSource: AttributionSource = AttributionSource.UNMATCHED_UNKNOWN,
    ) {
        if (decision == PacketDecision.ALLOW && matchedMac != null) return
        val dir = if (isUpload) "UPLOAD" else "DOWNLOAD"
        val key = "$dir:${attributionSource.name}:${decision.name}"
        val now = System.currentTimeMillis()
        val last = sampleLogTimestamps[key] ?: 0L
        if (now - last < SAMPLE_LOG_INTERVAL_MS) return
        sampleLogTimestamps[key] = now

        val decisionLabel = when (decision) {
            PacketDecision.DROP -> "DROP"
            PacketDecision.RATE_LIMIT, PacketDecision.DROP_AQM -> "RATE_LIMIT"
            PacketDecision.ALLOW -> "ALLOW"
        }
        // Sensitive endpoints (IPs/ports/MACs) are omitted from default runtime logs
        SessionLog.info(
            "Traffic: direction=$dir family=IPv${meta.version} proto=${meta.protocol} " +
                "source=${attributionSource.name} datapath=${datapathMode.name} " +
                "matched=${matchedMac != null} decision=$decisionLabel",
        )
    }

    private fun maybeLogCountersOnMilestone(counters: ClientTrafficCounters) {
        val now = System.currentTimeMillis()
        val seen = counters.seenPackets.get()
        if (seen == 1L || (now - counters.lastCounterLogAt >= COUNTER_LOG_INTERVAL_MS && seen != counters.lastLoggedPackets)) {
            counters.lastLoggedPackets = seen
            counters.lastCounterLogAt = now
            SessionLog.info(
                "Counters: mac=${counters.mac} policyVer=${counters.policyVersion.get()} seenPackets=$seen " +
                    "matchedPackets=${counters.matchedPackets.get()} " +
                    "directPkts=${counters.directAttributedPackets.get()} " +
                    "bpfPkts=${counters.bpfAttributedPackets.get()} " +
                    "blockedDrops=${counters.blockedDropPackets.get()} " +
                    "shapeDrops=${counters.shapingDropPackets.get()} " +
                    "shapedBytes=${counters.shapedBytes.get()}",
            )
        }
    }

    internal fun normalizeIp(ip: String): String {
        val trimmed = ip.trim()
        if (trimmed.isEmpty()) return ""
        if (!trimmed.contains(':')) return trimmed
        return runCatching {
            InetAddress.getByName(trimmed).hostAddress.orEmpty()
        }.getOrDefault(trimmed.lowercase())
    }

    private fun bindClientIp(mac: String, ip: String) {
        val trimmed = ip.trim()
        if (trimmed.isEmpty()) return
        val norm = normalizeIp(trimmed)
        val aliases = if (norm.isNotEmpty() && norm != trimmed) listOf(trimmed, norm) else listOf(trimmed)
        for (addr in aliases) {
            ipToMac[addr] = mac
            macToIps.getOrPut(mac) { ConcurrentHashMap.newKeySet() }.add(addr)
            policiesByMac[mac]?.let { policy ->
                policiesByIp[addr] = policy
            }
        }
    }

    private fun isUsableClientIp(ip: String): Boolean {
        val clean = ip.trim()
        if (clean.isEmpty() || clean == TUN_LOCAL_V4 || clean == TUN_LOCAL_V6 || clean == TUN_LOCAL_V6_NORMALIZED) return false
        if (clean.startsWith("Assigning") || clean.startsWith("Dynamic") || clean.startsWith("Offline")) return false
        return true
    }

    private fun isPrivateIpv4(ip: String): Boolean {
        if (ip == TUN_LOCAL_V4) return false
        return ip.startsWith("192.168.") ||
            ip.startsWith("10.") ||
            ip.startsWith("172.16.") ||
            ip.startsWith("172.17.") ||
            ip.startsWith("172.18.") ||
            ip.startsWith("172.19.") ||
            ip.startsWith("172.2") ||
            ip.startsWith("172.30.") ||
            ip.startsWith("172.31.")
    }

    internal fun extractMacFromIpv6Eui64(ipv6: String): String? {
        return runCatching {
            val bytes = InetAddress.getByName(ipv6).address
            if (bytes.size != 16) return null
            if ((bytes[11].toInt() and 0xFF) != 0xFF || (bytes[12].toInt() and 0xFF) != 0xFE) {
                return null
            }
            val b0 = (bytes[8].toInt() and 0xFF) xor 0x02
            val b1 = bytes[9].toInt() and 0xFF
            val b2 = bytes[10].toInt() and 0xFF
            val b3 = bytes[13].toInt() and 0xFF
            val b4 = bytes[14].toInt() and 0xFF
            val b5 = bytes[15].toInt() and 0xFF
            "%02X:%02X:%02X:%02X:%02X:%02X".format(b0, b1, b2, b3, b4, b5)
        }.getOrNull()
    }

    val CONNTRACK_PATHS = listOf(
        "/proc/net/nf_conntrack",
        "/proc/self/net/nf_conntrack",
        "/proc/net/ip_conntrack",
        "/proc/self/net/ip_conntrack",
    )

    /**
     * Directly inspects all candidate conntrack procfs paths inside the current process
     * without spawning shell subprocesses or requesting `su`.
     */
    fun inspectConntrackPaths(maxBytesPerFile: Int = 65_536): List<ConntrackPathObservation> {
        val observations = ArrayList<ConntrackPathObservation>(CONNTRACK_PATHS.size)
        val startNs = System.nanoTime()
        var anyReadable = false
        var totalRelevantFlows = 0
        var primaryStatus = "UNAVAILABLE"

        for (path in CONNTRACK_PATHS) {
            val file = File(path)
            val exists = runCatching { file.exists() }.getOrDefault(false)
            var status = "FILE_MISSING"
            var rawErr = ""
            var bytesRead = 0
            var totalLines = 0
            var relevantFlows = 0
            val samples = mutableListOf<String>()

            try {
                file.inputStream().use { input ->
                    val buffer = ByteArray(maxBytesPerFile)
                    var offset = 0
                    while (offset < maxBytesPerFile) {
                        val n = input.read(buffer, offset, maxBytesPerFile - offset)
                        if (n <= 0) break
                        offset += n
                    }
                    bytesRead = offset
                    val content = String(buffer, 0, offset, Charsets.UTF_8)
                    val lines = if (content.isBlank()) emptyList() else content.lines().filter { it.isNotBlank() }
                    totalLines = lines.size
                    for (line in lines) {
                        if (parseConntrackLine(line)) {
                            relevantFlows++
                            if (samples.size < 5) {
                                samples.add(sanitizeConntrackTupleSummary(line))
                            }
                        }
                    }
                    status = if (bytesRead > 0) "READ_OK" else "EMPTY"
                    anyReadable = true
                    totalRelevantFlows += relevantFlows
                    if (primaryStatus == "UNAVAILABLE" || status == "READ_OK") {
                        primaryStatus = status
                    }
                }
            } catch (e: Throwable) {
                rawErr = "${e.javaClass.simpleName}: ${e.message ?: "unknown error"}"
                val msg = rawErr.lowercase()
                status = when {
                    msg.contains("eacces") || msg.contains("eperm") || msg.contains("permission denied") || msg.contains("operation not permitted") ->
                        "PERMISSION_DENIED"
                    msg.contains("enoent") || msg.contains("no such file") ->
                        "FILE_MISSING"
                    else -> "IO_ERROR"
                }
                if (primaryStatus == "UNAVAILABLE") {
                    primaryStatus = status
                }
            }

            observations.add(
                ConntrackPathObservation(
                    path = path,
                    existsObserved = exists,
                    openReadStatus = status,
                    rawError = rawErr,
                    bytesRead = bytesRead,
                    totalLines = totalLines,
                    relevantParsedFlows = relevantFlows,
                    sampleTuples = samples,
                ),
            )
        }

        lastConntrackPollLatencyMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(0L)
        lastConntrackReadStatus = primaryStatus
        lastConntrackParsedFlows = totalRelevantFlows
        isConntrackAvailable = anyReadable && totalRelevantFlows > 0
        if (anyReadable) {
            conntrackBackoffUntilMs = 0L
        } else {
            if (observations.any { it.openReadStatus == "PERMISSION_DENIED" }) {
                conntrackPermissionDeniedCount.incrementAndGet()
            }
            conntrackBackoffUntilMs = conntrackClockMillisProvider() + conntrackUnavailableBackoffMs
        }
        if (isConntrackAvailable) {
            isMultiClientDegraded = false
        }
        return observations
    }

    private fun sanitizeConntrackTupleSummary(line: String): String {
        val srcs = CONNTRACK_SRC_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val dsts = CONNTRACK_DST_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val sports = CONNTRACK_SPORT_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val dports = CONNTRACK_DPORT_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val proto = when {
            line.contains("tcp") -> "tcp"
            line.contains("udp") -> "udp"
            line.contains("icmp") -> "icmp"
            else -> "other"
        }
        return if (srcs.size >= 2 && dsts.size >= 2 && sports.size >= 2 && dports.size >= 2) {
            "$proto orig=${srcs[0]}:${sports[0]}->${dsts[0]}:${dports[0]} reply=${srcs[1]}:${sports[1]}->${dsts[1]}:${dports[1]}"
        } else {
            line.take(120)
        }
    }

    /**
     * Reads procfs conntrack directly in-process (never spawns shell subprocesses on packet threads).
     * Applies a 300s backoff when procfs conntrack is unavailable or permission-denied.
     */
    private fun maybeResolveConntrackFlows() {
        val now = conntrackClockMillisProvider()
        if (now < conntrackBackoffUntilMs) {
            conntrackBackoffSkippedCount.incrementAndGet()
            return
        }
        if (now - lastConntrackResolveMs < 500L) return
        lastConntrackResolveMs = now
        inspectConntrackPaths(maxBytesPerFile = 32_768)
    }

    internal fun parseConntrackLine(line: String): Boolean {
        if (!line.contains(TUN_LOCAL_V4) && !line.contains(TUN_LOCAL_V6) && !line.contains(TUN_LOCAL_V6_NORMALIZED)) return false
        val proto = when {
            line.contains("tcp") -> 6
            line.contains("udp") -> 17
            line.contains("icmpv6") -> 58
            line.contains("icmp") -> 1
            else -> return false
        }
        val srcs = CONNTRACK_SRC_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val dsts = CONNTRACK_DST_REGEX.findAll(line).map { it.groupValues[1] }.toList()
        val sports = CONNTRACK_SPORT_REGEX.findAll(line).mapNotNull { it.groupValues[1].toIntOrNull() }.toList()
        val dports = CONNTRACK_DPORT_REGEX.findAll(line).mapNotNull { it.groupValues[1].toIntOrNull() }.toList()

        if (srcs.size >= 2 && dsts.size >= 2 && sports.size >= 2 && dports.size >= 2) {
            val origSrcIp = srcs[0]
            val origDstIp = dsts[0]
            val origDstPort = dports[0]
            val replyDstIp = dsts[1]
            val replyDstPort = dports[1]

            val replyDstNorm = normalizeIp(replyDstIp)
            if (replyDstIp == TUN_LOCAL_V4 || replyDstIp == TUN_LOCAL_V6 || replyDstNorm == TUN_LOCAL_V6_NORMALIZED) {
                val origSrcNorm = normalizeIp(origSrcIp)
                val mac = ipToMac[origSrcIp] ?: (if (origSrcNorm.isNotEmpty()) ipToMac[origSrcNorm] else null) ?: return false
                if (mac in activeConnectedMacs) {
                    val ver = if (origSrcIp.contains(':') || line.trimStart().startsWith("ipv6")) 6 else 4
                    val normalizedRemoteIp = normalizeIp(origDstIp).ifEmpty { origDstIp }
                    val key = FlowKey(
                        version = ver,
                        protocol = proto,
                        natPort = replyDstPort,
                        remoteIp = normalizedRemoteIp,
                        remotePort = origDstPort,
                    )
                    flowToMacCache[key] = mac
                    flowTimestamps[key] = System.currentTimeMillis()
                    return true
                }
            }
        }
        return false
    }

    internal fun parsePacketMeta(packet: ByteArray, length: Int): PacketMeta? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> {
                val ihl = (packet[0].toInt() and 0x0F) * 4
                if (ihl < 20 || length < ihl) return null
                val flagsAndFragOffset = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
                val fragOffset = flagsAndFragOffset and 0x1FFF
                val isNonInitialFrag = fragOffset != 0

                val proto = packet[9].toInt() and 0xFF
                val srcIp = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
                val dstIp = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

                var srcPort = 0
                var dstPort = 0
                var isTcpSyn = false
                var isTcpFinOrRst = false
                var isTcpAckOnly = false
                if (!isNonInitialFrag && (proto == 6 || proto == 17) && length >= ihl + 4) {
                    srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                    if (proto == 6 && length >= ihl + 14) {
                        val tcpFlags = packet[ihl + 13].toInt() and 0xFF
                        isTcpSyn = (tcpFlags and 0x12) == 0x02 // SYN=1, ACK=0
                        isTcpFinOrRst = (tcpFlags and 0x05) != 0 // FIN=0x01 or RST=0x04
                        isTcpAckOnly = (tcpFlags and 0x10) != 0 && !isTcpSyn && !isTcpFinOrRst && length <= ihl + 32
                    }
                }
                val isControl = (proto == 6 && length <= ihl + 32) || srcPort == 53 || dstPort == 53 || proto == 1
                PacketMeta(
                    version = 4,
                    protocol = proto,
                    srcIp = srcIp,
                    dstIp = dstIp,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    length = length,
                    isSmallControlPacket = isControl,
                    isNonInitialFragment = isNonInitialFrag,
                    isTcpSyn = isTcpSyn,
                    isTcpFinOrRst = isTcpFinOrRst,
                    isTcpAckOnly = isTcpAckOnly,
                )
            }
            6 -> {
                if (length < 40) return null
                val nextHeader = packet[6].toInt() and 0xFF
                val srcBytes = packet.copyOfRange(8, 24)
                val dstBytes = packet.copyOfRange(24, 40)
                val srcIp = runCatching { InetAddress.getByAddress(srcBytes).hostAddress.orEmpty() }.getOrDefault("")
                val dstIp = runCatching { InetAddress.getByAddress(dstBytes).hostAddress.orEmpty() }.getOrDefault("")
                if (srcIp.isEmpty() || dstIp.isEmpty()) return null

                var isNonInitialFrag = false
                var effectiveHeader = nextHeader
                var transportOffset = 40
                if (nextHeader == 44) { // IPv6 Fragment Header
                    if (length < 48) return null
                    effectiveHeader = packet[40].toInt() and 0xFF
                    val fragOffAndFlags = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                    val fragOffset = (fragOffAndFlags ushr 3) and 0x1FFF
                    isNonInitialFrag = fragOffset != 0
                    transportOffset = 48
                }

                var srcPort = 0
                var dstPort = 0
                var isTcpSyn = false
                var isTcpFinOrRst = false
                var isTcpAckOnly = false
                if (!isNonInitialFrag && (effectiveHeader == 6 || effectiveHeader == 17) && length >= transportOffset + 4) {
                    srcPort = ((packet[transportOffset].toInt() and 0xFF) shl 8) or (packet[transportOffset + 1].toInt() and 0xFF)
                    dstPort = ((packet[transportOffset + 2].toInt() and 0xFF) shl 8) or (packet[transportOffset + 3].toInt() and 0xFF)
                    if (effectiveHeader == 6 && length >= transportOffset + 14) {
                        val tcpFlags = packet[transportOffset + 13].toInt() and 0xFF
                        isTcpSyn = (tcpFlags and 0x12) == 0x02
                        isTcpFinOrRst = (tcpFlags and 0x05) != 0
                        isTcpAckOnly = (tcpFlags and 0x10) != 0 && !isTcpSyn && !isTcpFinOrRst && length <= transportOffset + 32
                    }
                }
                val isControl = (effectiveHeader == 6 && length <= transportOffset + 32) ||
                    srcPort == 53 || dstPort == 53 || effectiveHeader == 58
                PacketMeta(
                    version = 6,
                    protocol = effectiveHeader,
                    srcIp = srcIp,
                    dstIp = dstIp,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    length = length,
                    isSmallControlPacket = isControl,
                    isNonInitialFragment = isNonInitialFrag,
                    isTcpSyn = isTcpSyn,
                    isTcpFinOrRst = isTcpFinOrRst,
                    isTcpAckOnly = isTcpAckOnly,
                )
            }
            else -> null
        }
    }

    private val CONNTRACK_SRC_REGEX = Regex("""\bsrc=([0-9a-fA-F.:]+)""")
    private val CONNTRACK_DST_REGEX = Regex("""\bdst=([0-9a-fA-F.:]+)""")
    private val CONNTRACK_SPORT_REGEX = Regex("""\bsport=(\d+)""")
    private val CONNTRACK_DPORT_REGEX = Regex("""\bdport=(\d+)""")
}
