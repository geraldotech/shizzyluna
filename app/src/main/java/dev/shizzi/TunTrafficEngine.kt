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
        val forwardedPackets: AtomicLong = AtomicLong(0L),
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
        val policyVersionShapedPackets: Long = shapedPackets,
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
    )

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
    )

    internal data class PacketAttribution(
        val mac: String?,
        val source: AttributionSource,
    )

    internal data class EvaluationDetail(
        val decision: PacketDecision,
        val paceDelayMs: Long = 0L,
        val policyVersion: Long = 1L,
    )

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

    private val flowToMacCache = ConcurrentHashMap<FlowKey, String>()
    private val flowTimestamps = ConcurrentHashMap<FlowKey, Long>()
    private const val FLOW_TTL_MS = 60_000L
    private val sampleLogTimestamps = ConcurrentHashMap<String, Long>()

    val totalUploadPackets = AtomicLong(0L)
    val totalDownloadPackets = AtomicLong(0L)
    val unmatchedPackets = AtomicLong(0L)
    val postNatUnmatchedPackets = AtomicLong(0L)
    val unknownForwardedBytes = AtomicLong(0L)
    val directAttributedPackets = AtomicLong(0L)
    val bpfAttributedPackets = AtomicLong(0L)
    val ambiguousOrStaleLookups = AtomicLong(0L)
    val localControlPackets = AtomicLong(0L)
    val unsupportedOrFragmentPackets = AtomicLong(0L)

    val bpfAttributor = NatFlowAttributor()
    val bpfReader = BpfMapReader(attributor = bpfAttributor)

    @Volatile
    var isExperimentalBpfEnabled: Boolean = false
        private set

    @Volatile
    var bpfPollIntervalMs: Long = BpfMapReader.DEFAULT_POLL_INTERVAL_MS
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
        val nowMono = System.nanoTime() / 1_000_000L
        val ageMs = if (snap.collectedAtMonotonicMs > 0L) {
            (nowMono - snap.collectedAtMonotonicMs).coerceAtLeast(0L)
        } else {
            0L
        }
        val hasRestrictivePolicy = policiesByMac.values.any { it.isBlocked || it.bandwidthLimitKbps > 0 }
        val isStale = snap.collectedAtMonotonicMs > 0L && ageMs > bpfAttributor.maxFreshnessMs

        val state = when {
            !isExperimentalBpfEnabled -> ExperimentalBpfState.DISABLED
            snap.collectionStatus == BpfCollectionStatus.IDLE -> ExperimentalBpfState.COLLECTING
            snap.collectionStatus != BpfCollectionStatus.OK &&
                snap.collectionStatus != BpfCollectionStatus.EMPTY_VALID -> ExperimentalBpfState.STALE_OR_UNAVAILABLE
            isStale -> ExperimentalBpfState.STALE_OR_UNAVAILABLE
            hasRestrictivePolicy -> ExperimentalBpfState.PARTIAL_ENFORCEMENT
            else -> ExperimentalBpfState.MAPPINGS_AVAILABLE
        }

        var totalBlockedDrops = 0L
        var totalShapeDrops = 0L
        var totalShapedPkts = 0L
        for (c in countersByMac.values) {
            totalBlockedDrops += c.blockedDropPackets.get()
            totalShapeDrops += c.shapingDropPackets.get()
            totalShapedPkts += c.shapedPackets.get()
        }

        return BpfAttributionStatusReport(
            experimentalEnabled = isExperimentalBpfEnabled,
            state = state,
            collectionStatus = snap.collectionStatus,
            collectionError = snap.collectionError,
            parserVersion = BpfDumpParser.PARSER_VERSION,
            pollIntervalMs = bpfPollIntervalMs,
            snapshotAgeMs = ageMs,
            lastCollectionDurationMs = snap.collectionDurationMs,
            sessionGeneration = snap.sessionGeneration,
            bindingGeneration = snap.bindingGeneration,
            downstreamIface = snap.downstreamIface.ifBlank { activeDownstreamName },
            downstreamIfIndex = snap.downstreamIfIndex,
            upstreamIface = snap.upstreamIface.ifBlank { activeUpstreamName },
            upstreamIfIndex = snap.upstreamIfIndex,
            totalUpstreamEntries = snap.totalUpstreamEntries,
            totalDownstreamEntries = snap.totalDownstreamEntries,
            reverseMatchedCount = snap.reverseMatchedCount,
            activeMappedFlows = snap.flowsByTuple.size,
            ambiguousTupleCount = snap.ambiguousTuples.size,
            unverifiedOwnerEntries = snap.unverifiedOwnerEntries,
            rejectedLineCount = snap.rejectedLineCount,
            coverageIncomplete = snap.coverageIncomplete,
            perClientCounts = snap.perClientCounts,
            directAttributedPackets = directAttributedPackets.get(),
            bpfAttributedPackets = bpfAttributedPackets.get(),
            unknownForwardedPackets = unmatchedPackets.get(),
            unknownForwardedBytes = unknownForwardedBytes.get(),
            ambiguousOrStaleLookups = ambiguousOrStaleLookups.get(),
            localControlPackets = localControlPackets.get(),
            unsupportedOrFragmentPackets = unsupportedOrFragmentPackets.get(),
            blockedDropPackets = totalBlockedDrops,
            shapingDropPackets = totalShapeDrops,
            shapedPackets = totalShapedPkts,
            rejectedOldGenerationCount = bpfAttributor.rejectedOldGenerationCount.get(),
            tupleReuseGuardTriggeredCount = bpfAttributor.tupleReuseGuardTriggeredCount.get(),
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
        bpfAttributor.onSessionOrUpstreamChanged(
            downstreamIface = activeDownstreamName,
            upstreamIface = upstreamInterfaceName,
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
        SessionLog.warn(
            "Datapath: mode=DIRECT_TUN_FALLBACK attached=false upstream=$upstreamInterfaceName reason=$reason",
        )
    }

    @Synchronized
    fun stop() {
        stopInternal()
        datapathMode = DatapathMode.INACTIVE
        fallbackReason = null
    }

    private fun stopInternal() {
        running.set(false)
        bpfReader.stopWorker()
        stopPacingDispatcher()
        clearPacingQueues()
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
        policiesByMac.clear()
        policiesByIp.clear()
        activeConnectedMacs.clear()
        ipToMac.clear()
        macToIps.clear()
        flowToMacCache.clear()
        flowTimestamps.clear()
        lastLoggedClientMap.clear()
        uploadBucketsByMac.clear()
        downloadBucketsByMac.clear()
        countersByMac.clear()
        sampleLogTimestamps.clear()
        totalUploadPackets.set(0L)
        totalDownloadPackets.set(0L)
        unmatchedPackets.set(0L)
        postNatUnmatchedPackets.set(0L)
        unknownForwardedBytes.set(0L)
        directAttributedPackets.set(0L)
        bpfAttributedPackets.set(0L)
        ambiguousOrStaleLookups.set(0L)
        localControlPackets.set(0L)
        unsupportedOrFragmentPackets.set(0L)
        bpfAttributor.onSessionOrUpstreamChanged("", "")
        isConntrackAvailable = false
        lastConntrackReadStatus = "NOT_TESTED"
        lastConntrackPollLatencyMs = 0L
        lastConntrackParsedFlows = 0
        isMultiClientDegraded = false
    }

    fun resetClientDropCounters(mac: String) {
        val cleanMac = mac.uppercase().trim()
        countersByMac[cleanMac]?.let { counters ->
            counters.droppedPackets.set(0L)
            counters.blockedDropPackets.set(0L)
            counters.shapingDropPackets.set(0L)
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
    }

    fun getAttributedFlowCount(mac: String? = null): Int {
        val snap = bpfAttributor.currentSnapshot()
        if (mac.isNullOrBlank()) {
            return flowToMacCache.size + snap.flowsByTuple.size
        }
        val clean = mac.uppercase().trim()
        val cacheCount = flowToMacCache.values.count { it == clean }
        val bpfCount = snap.flowsByTuple.values.count { it.verifiedMac == clean }
        return cacheCount + bpfCount
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
            pacingQueuesByMac.remove(disconnectedMac)?.drainAll()
        }
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
                }
                existingSet.add(ip)
            }

            countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }

            val sortedIps = existingSet.sorted()
            val mapSignature = "${host.interfaceName}:${sortedIps.joinToString(",")}"
            if (lastLoggedClientMap[mac] != mapSignature) {
                lastLoggedClientMap[mac] = mapSignature
                SessionLog.info(
                    "ClientMap: mac=$mac ips=[${sortedIps.joinToString(", ")}] interface=${host.interfaceName.ifBlank { "softap" }}",
                )
            }
        }

        if (detectedDownstreamIface.isNotBlank() && detectedDownstreamIface != activeDownstreamName) {
            activeDownstreamName = detectedDownstreamIface
            bpfAttributor.syncInterfaces(activeDownstreamName, activeUpstreamName)
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

            val oldPolicy = policiesByMac[mac]
            val policyChanged = oldPolicy == null ||
                oldPolicy.isBlocked != policy.isBlocked ||
                oldPolicy.bandwidthLimitKbps != policy.bandwidthLimitKbps
            if (policyChanged) {
                counters.policyVersion.incrementAndGet()
                counters.policyVersionBlockedDrops.set(0L)
                counters.policyVersionShapedPackets.set(0L)
                counters.policyBaselinePostNatUnmatched = postNatUnmatchedPackets.get()
                reconcileQueuedPacketsForPolicyChange(mac, policy, counters)
            }
            if (oldPolicy != null && oldPolicy.isBlocked && !policy.isBlocked) {
                // Client transitioned from blocked to allowed: reset drop/match counters and purge cached flows
                counters.droppedPackets.set(0L)
                counters.blockedDropPackets.set(0L)
                counters.shapingDropPackets.set(0L)
                counters.droppedBytes.set(0L)
                counters.matchedPackets.set(0L)
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
        val hasRestricted = newMacPolicies.values.any { it.isBlocked || it.bandwidthLimitKbps > 0 }
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
    }

    /**
     * Cancels or re-evaluates queued paced packets when a client's policy changes so queued packets
     * can never escape using an outdated policy.
     */
    private fun reconcileQueuedPacketsForPolicyChange(
        mac: String,
        newPolicy: EnforcedClientPolicy,
        counters: ClientTrafficCounters,
    ) {
        val queue = pacingQueuesByMac[mac] ?: return
        if (newPolicy.isBlocked) {
            val cancelled = queue.drainAll()
            for (pkt in cancelled) {
                counters.droppedPackets.incrementAndGet()
                counters.blockedDropPackets.incrementAndGet()
                counters.policyVersionBlockedDrops.incrementAndGet()
                counters.droppedBytes.addAndGet(pkt.length.toLong())
            }
        }
    }

    fun getQueuedPacketCountForClient(mac: String): Int {
        return pacingQueuesByMac[mac.uppercase().trim()]?.queuedCount?.get() ?: 0
    }

    fun getCounterSnapshot(mac: String): CounterSnapshot {
        val cleanMac = mac.uppercase().trim()
        val c = countersByMac[cleanMac]
        val policyInstalled = isAttached && policiesByMac.containsKey(cleanMac)
        return if (c == null) {
            CounterSnapshot(
                mac = cleanMac,
                seenPackets = 0L,
                matchedPackets = 0L,
                forwardedPackets = 0L,
                droppedPackets = 0L,
                shapedPackets = 0L,
                rxBytes = 0L,
                txBytes = 0L,
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
                policyVersionShapedPackets = 0L,
            )
        } else {
            val unattributedSincePolicy =
                (postNatUnmatchedPackets.get() - c.policyBaselinePostNatUnmatched) > 0L &&
                    !HostFirewall.isKernelNetfilterAvailable
            CounterSnapshot(
                mac = cleanMac,
                seenPackets = c.seenPackets.get(),
                matchedPackets = c.matchedPackets.get(),
                forwardedPackets = c.forwardedPackets.get(),
                droppedPackets = c.droppedPackets.get(),
                shapedPackets = c.shapedPackets.get(),
                rxBytes = c.rxBytes.get(),
                txBytes = c.txBytes.get(),
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
                policyVersionShapedPackets = c.policyVersionShapedPackets.get(),
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
        for (q in pacingQueuesByMac.values) {
            q.drainAll()
        }
        pacingQueuesByMac.clear()
    }

    internal fun drainDuePacedPackets(nowNs: Long = System.nanoTime()): Int {
        var sentCount = 0
        for ((mac, queue) in pacingQueuesByMac) {
            while (true) {
                val pkt = queue.pollIfDue(nowNs) ?: break
                val currentPolicy = policiesByMac[mac]
                val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }
                // Re-evaluate current policy before releasing a queued packet
                if (currentPolicy != null && currentPolicy.isBlocked) {
                    counters.droppedPackets.incrementAndGet()
                    counters.blockedDropPackets.incrementAndGet()
                    counters.policyVersionBlockedDrops.incrementAndGet()
                    counters.droppedBytes.addAndGet(pkt.length.toLong())
                    continue
                }
                counters.forwardedPackets.incrementAndGet()
                if (pkt.isUpload) {
                    counters.txBytes.addAndGet(pkt.length.toLong())
                } else {
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
                    val detail = evaluateAndShapeDetailed(meta, attr.mac, isUpload = true, attributionSource = attr.source)
                    if (detail.decision == PacketDecision.DROP || detail.decision == PacketDecision.DROP_AQM) {
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
                            recordQueueOverflowDrop(attr.mac, n)
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

    private fun recordQueueOverflowDrop(mac: String, packetLength: Int) {
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
     * Resolves which verified connected client MAC owns [meta] and records the attribution source.
     */
    internal fun resolveClientMacWithSource(meta: PacketMeta, isUpload: Boolean): PacketAttribution {
        if (isLinkLocalMulticastControl(meta)) {
            return PacketAttribution(null, AttributionSource.UNMATCHED_UNKNOWN)
        }
        if (meta.isNonInitialFragment) {
            unsupportedOrFragmentPackets.incrementAndGet()
            return PacketAttribution(null, AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT)
        }

        val tetherSideIp = if (isUpload) meta.srcIp else meta.dstIp
        val tetherSidePort = if (isUpload) meta.srcPort else meta.dstPort
        val remoteSideIp = if (isUpload) meta.dstIp else meta.srcIp
        val remoteSidePort = if (isUpload) meta.dstPort else meta.srcPort

        val normalizedTetherIp = normalizeIp(tetherSideIp)

        // 1. Direct lookup in verified IP -> MAC table
        ipToMac[tetherSideIp]?.let { mac ->
            if (mac in activeConnectedMacs) {
                return PacketAttribution(mac, AttributionSource.DIRECT_IP)
            }
        }
        if (normalizedTetherIp.isNotEmpty() && normalizedTetherIp != tetherSideIp) {
            ipToMac[normalizedTetherIp]?.let { mac ->
                if (mac in activeConnectedMacs) {
                    return PacketAttribution(mac, AttributionSource.DIRECT_IP)
                }
            }
        }

        // 2. Post-NAT MASQUERADE on testtun (`192.0.2.2` or `2001:db8::2`)
        if (tetherSideIp == TUN_LOCAL_V4 || tetherSideIp == TUN_LOCAL_V6 || normalizedTetherIp == TUN_LOCAL_V6_NORMALIZED) {
            // Non-TCP/UDP protocols on post-NAT cannot be disambiguated by transport ports
            if (meta.protocol != 6 && meta.protocol != 17) {
                unsupportedOrFragmentPackets.incrementAndGet()
                return PacketAttribution(null, AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT)
            }
            if (tetherSidePort !in 1..65535 || remoteSidePort !in 1..65535) {
                unsupportedOrFragmentPackets.incrementAndGet()
                return PacketAttribution(null, AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT)
            }

            // 2a. Experimental BPF NAT flow attribution (never caches ALLOW decisions; resolves owner per packet)
            if (isExperimentalBpfEnabled && meta.version == 4) {
                val outcome = bpfAttributor.resolveTranslatedPacket(
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
                when (outcome) {
                    is AttributionOutcome.Matched -> {
                        return PacketAttribution(outcome.mac, AttributionSource.BPF_NAT)
                    }
                    is AttributionOutcome.Ambiguous,
                    is AttributionOutcome.StaleSnapshot,
                    is AttributionOutcome.StaleOrInvalidated,
                    -> {
                        ambiguousOrStaleLookups.incrementAndGet()
                        return PacketAttribution(null, AttributionSource.UNMATCHED_AMBIGUOUS_OR_STALE)
                    }
                    AttributionOutcome.Unknown -> {
                        // Fall through to check procfs conntrack if readable
                    }
                }
            }

            // 2b. Procfs conntrack fallback (when readable on the device)
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
                    return PacketAttribution(cachedMac, AttributionSource.CONNTRACK_PROCFS)
                }
                flowToMacCache.remove(flowKey, cachedMac)
                flowTimestamps.remove(flowKey)
            }

            maybeResolveConntrackFlows()
            flowToMacCache[flowKey]?.let { resolvedMac ->
                if (resolvedMac in activeConnectedMacs) {
                    flowTimestamps[flowKey] = System.currentTimeMillis()
                    return PacketAttribution(resolvedMac, AttributionSource.CONNTRACK_PROCFS)
                }
            }
            return PacketAttribution(null, AttributionSource.UNMATCHED_UNKNOWN)
        }

        // 3. IPv6 SLAAC in testtun prefix (`2001:db8::/64`) or link-local (`fe80::/64`)
        if (meta.version == 6 && (tetherSideIp.lowercase().startsWith(TUN_PREFIX_V6) || tetherSideIp.lowercase().startsWith("fe80:"))) {
            extractMacFromIpv6Eui64(tetherSideIp)?.let { euiMac ->
                if (euiMac in activeConnectedMacs) {
                    bindClientIp(euiMac, tetherSideIp)
                    return PacketAttribution(euiMac, AttributionSource.DIRECT_IP)
                }
            }

            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) {
                    return PacketAttribution(neighborMac, AttributionSource.DIRECT_IP)
                }
            }
            if (normalizedTetherIp.isNotEmpty()) {
                ipToMac[normalizedTetherIp]?.let { neighborMac ->
                    if (neighborMac in activeConnectedMacs) {
                        return PacketAttribution(neighborMac, AttributionSource.DIRECT_IP)
                    }
                }
            }
        }

        // 4. Unmapped private IPv4 address lookup against control-plane neighbor table
        if (meta.version == 4 && isPrivateIpv4(tetherSideIp)) {
            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) {
                    return PacketAttribution(neighborMac, AttributionSource.DIRECT_IP)
                }
            }
        }

        return PacketAttribution(null, AttributionSource.UNMATCHED_UNKNOWN)
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
    ): PacketDecision = evaluateAndShapeDetailed(meta, matchedMac, isUpload, attributionSource).decision

    internal fun evaluateAndShapeDetailed(
        meta: PacketMeta,
        matchedMac: String?,
        isUpload: Boolean,
        attributionSource: AttributionSource = AttributionSource.DIRECT_IP,
    ): EvaluationDetail {
        // Local IPv6 multicast control frames (fe80:: -> ff02::2 RS/RA/MLD) are link-local
        // control traffic, not internet browsing traffic.
        if (isLinkLocalMulticastControl(meta)) {
            localControlPackets.incrementAndGet()
            return EvaluationDetail(PacketDecision.ALLOW)
        }

        if (matchedMac == null) {
            unmatchedPackets.incrementAndGet()
            unknownForwardedBytes.addAndGet(meta.length.toLong())
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
            maybeLogTrafficSample(meta, isUpload, matchedMac = null, decision = PacketDecision.ALLOW)
            return EvaluationDetail(PacketDecision.ALLOW)
        }

        val counters = countersByMac.getOrPut(matchedMac) { ClientTrafficCounters(matchedMac) }
        counters.lastSeenAt = System.currentTimeMillis()
        counters.seenPackets.incrementAndGet()
        when (attributionSource) {
            AttributionSource.BPF_NAT -> {
                bpfAttributedPackets.incrementAndGet()
                counters.bpfAttributedPackets.incrementAndGet()
            }
            AttributionSource.DIRECT_IP, AttributionSource.CONNTRACK_PROCFS -> {
                directAttributedPackets.incrementAndGet()
                counters.directAttributedPackets.incrementAndGet()
            }
            else -> {}
        }

        val currentPolicyVersion = counters.policyVersion.get()
        val policy = policiesByMac[matchedMac]
        if (policy == null || (!policy.isBlocked && policy.bandwidthLimitKbps <= 0)) {
            counters.forwardedPackets.incrementAndGet()
            if (isUpload) {
                counters.txBytes.addAndGet(meta.length.toLong())
            } else {
                counters.rxBytes.addAndGet(meta.length.toLong())
            }
            return EvaluationDetail(PacketDecision.ALLOW, policyVersion = currentPolicyVersion)
        }

        counters.matchedPackets.incrementAndGet()

        // 1. Hard block enforcement (evaluated freshly on every packet; never caches ALLOW)
        if (policy.isBlocked) {
            counters.droppedPackets.incrementAndGet()
            counters.blockedDropPackets.incrementAndGet()
            counters.policyVersionBlockedDrops.incrementAndGet()
            counters.droppedBytes.addAndGet(meta.length.toLong())
            maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.DROP)
            maybeLogCountersOnMilestone(counters)
            return EvaluationDetail(PacketDecision.DROP, policyVersion = currentPolicyVersion)
        }

        // 2. Non-blocking per-client calibrated Token Bucket bandwidth limiting
        val limitKbps = policy.bandwidthLimitKbps
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
                maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.DROP_AQM)
                maybeLogCountersOnMilestone(counters)
                return EvaluationDetail(PacketDecision.DROP_AQM, policyVersion = currentPolicyVersion)
            }

            if (waitMs > 0L) {
                counters.shapedPackets.incrementAndGet()
                counters.policyVersionShapedPackets.incrementAndGet()
                counters.shapedBytes.addAndGet(meta.length.toLong())
                maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.RATE_LIMIT)
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

        counters.forwardedPackets.incrementAndGet()
        if (isUpload) {
            counters.txBytes.addAndGet(meta.length.toLong())
        } else {
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
    ) {
        if (decision == PacketDecision.ALLOW && matchedMac != null) return
        val dir = if (isUpload) "UPLOAD" else "DOWNLOAD"
        val key = "$dir:${matchedMac ?: "NONE"}:${decision.name}"
        val now = System.currentTimeMillis()
        val last = sampleLogTimestamps[key] ?: 0L
        if (now - last < SAMPLE_LOG_INTERVAL_MS) return
        sampleLogTimestamps[key] = now

        val decisionLabel = when (decision) {
            PacketDecision.DROP -> "DROP"
            PacketDecision.RATE_LIMIT, PacketDecision.DROP_AQM -> "RATE_LIMIT"
            PacketDecision.ALLOW -> "ALLOW"
        }
        SessionLog.info(
            "Traffic: direction=$dir src=${meta.srcIp} dst=${meta.dstIp} " +
                "matchedMac=${matchedMac ?: "none"} decision=$decisionLabel",
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
     */
    private fun maybeResolveConntrackFlows() {
        val now = System.currentTimeMillis()
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
                if (!isNonInitialFrag && (proto == 6 || proto == 17) && length >= ihl + 4) {
                    srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                    if (proto == 6 && length >= ihl + 14) {
                        val tcpFlags = packet[ihl + 13].toInt() and 0xFF
                        isTcpSyn = (tcpFlags and 0x12) == 0x02 // SYN=1, ACK=0
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
                if (!isNonInitialFrag && (effectiveHeader == 6 || effectiveHeader == 17) && length >= transportOffset + 4) {
                    srcPort = ((packet[transportOffset].toInt() and 0xFF) shl 8) or (packet[transportOffset + 1].toInt() and 0xFF)
                    dstPort = ((packet[transportOffset + 2].toInt() and 0xFF) shl 8) or (packet[transportOffset + 3].toInt() and 0xFF)
                    if (effectiveHeader == 6 && length >= transportOffset + 14) {
                        val tcpFlags = packet[transportOffset + 13].toInt() and 0xFF
                        isTcpSyn = (tcpFlags and 0x12) == 0x02
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
