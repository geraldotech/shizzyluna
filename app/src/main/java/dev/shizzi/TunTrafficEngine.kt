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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
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

/**
 * Userspace L3 packet inspection, real-time firewall blocking, calibrated Token Bucket
 * bandwidth shaper, and packet-level diagnostic counter engine interposed on the
 * TestNetwork TUN file descriptor.
 *
 * Bandwidth semantics:
 * - [EnforcedClientPolicy.bandwidthLimitKbps] is defined in kilobits per second
 *   (1 Kbps = 1,000 bits/s = 125 bytes/s; 1 Mbps = 1,000 Kbps = 125,000 bytes/s).
 * - Each client receives an independent Download TokenBucket and an independent Upload
 *   TokenBucket at [bandwidthLimitKbps] so download saturation never starves upload TCP ACKs.
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

    data class ClientTrafficCounters(
        val mac: String,
        val seenPackets: AtomicLong = AtomicLong(0L),
        val matchedPackets: AtomicLong = AtomicLong(0L),
        val forwardedPackets: AtomicLong = AtomicLong(0L),
        val droppedPackets: AtomicLong = AtomicLong(0L),
        val shapedPackets: AtomicLong = AtomicLong(0L),
        val rxBytes: AtomicLong = AtomicLong(0L),
        val txBytes: AtomicLong = AtomicLong(0L),
        val droppedBytes: AtomicLong = AtomicLong(0L),
        val shapedBytes: AtomicLong = AtomicLong(0L),
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
    )

    private data class FlowKey(
        val protocol: Int,
        val natPort: Int,
        val remoteIp: String,
        val remotePort: Int,
    )

    /**
     * Calibrated Token Bucket shaper for a single direction (Upload or Download) of a client.
     * - Rate: `limitKbps * 125.0` bytes/sec.
     * - Burst capacity: `max(4500 bytes, 100ms of rate)` so TCP initial windows pass cleanly.
     * - Pacing: sleeps up to [maxPaceWaitMs] for smooth inter-packet spacing; drops excess data
     *   packets beyond the virtual queue threshold so TCP congestion control converges to the cap.
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
         * - `> 0L` (milliseconds to sleep) if packet was shaped/paced
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

    private val running = AtomicBoolean(false)

    @Volatile
    var datapathMode: DatapathMode = DatapathMode.INACTIVE
        private set

    @Volatile
    var activeUpstreamName: String = ""
        private set

    @Volatile
    var fallbackReason: String? = null
        private set

    private var engineEndPfd: ParcelFileDescriptor? = null
    private var datapathEndPfd: ParcelFileDescriptor? = null
    private var uploadThread: Thread? = null
    private var downloadThread: Thread? = null

    private val countersByMac = ConcurrentHashMap<String, ClientTrafficCounters>()
    private val ipToMac = ConcurrentHashMap<String, String>()
    private val macToIps = ConcurrentHashMap<String, MutableSet<String>>()
    private val lastLoggedClientMap = ConcurrentHashMap<String, String>()

    private val policiesByMac = ConcurrentHashMap<String, EnforcedClientPolicy>()
    private val policiesByIp = ConcurrentHashMap<String, EnforcedClientPolicy>()
    private val activeConnectedMacs = ConcurrentHashMap.newKeySet<String>()

    private val uploadBucketsByMac = ConcurrentHashMap<String, TokenBucket>()
    private val downloadBucketsByMac = ConcurrentHashMap<String, TokenBucket>()

    private val flowToMacCache = ConcurrentHashMap<FlowKey, String>()
    private val flowTimestamps = ConcurrentHashMap<FlowKey, Long>()
    private const val FLOW_TTL_MS = 60_000L
    private val sampleLogTimestamps = ConcurrentHashMap<String, Long>()

    val totalUploadPackets = AtomicLong(0L)
    val totalDownloadPackets = AtomicLong(0L)
    val unmatchedPackets = AtomicLong(0L)

    @Volatile
    var isConntrackAvailable: Boolean = false
        private set

    @Volatile
    var isMultiClientDegraded: Boolean = false
        private set

    @Volatile
    private var lastNeighborResolveMs: Long = 0L

    @Volatile
    private var lastConntrackResolveMs: Long = 0L

    val isAttached: Boolean
        get() = running.get() && datapathMode == DatapathMode.USERSPACE_PROXY

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

            SessionLog.info(
                "Datapath: mode=USERSPACE_PROXY attached=true upstream=$upstreamInterfaceName mtu=$mtu",
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
        isConntrackAvailable = false
        isMultiClientDegraded = false
    }

    fun resetClientDropCounters(mac: String) {
        val cleanMac = mac.uppercase().trim()
        countersByMac[cleanMac]?.let { counters ->
            counters.droppedPackets.set(0L)
            counters.droppedBytes.set(0L)
            counters.matchedPackets.set(0L)
            counters.shapedPackets.set(0L)
            counters.shapedBytes.set(0L)
        }
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

        // 1. Evict disconnected MACs from active mappings and flow cache
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
        for (host in connectedHosts) {
            val mac = host.mac.uppercase().trim()
            if (mac !in currentConnectedMacs) continue

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
            // Remove any IP that is no longer verified for this MAC (fixes stale IP leak across reassignments)
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

        // 3. Rebuild MAC and IP policy tables
        val newMacPolicies = HashMap<String, EnforcedClientPolicy>()
        val newIpPolicies = HashMap<String, EnforcedClientPolicy>()

        for ((rawMac, policy) in macPolicies) {
            val mac = rawMac.uppercase().trim()
            newMacPolicies[mac] = policy
            val counters = countersByMac.getOrPut(mac) { ClientTrafficCounters(mac) }

            val oldPolicy = policiesByMac[mac]
            if (oldPolicy != null && oldPolicy.isBlocked && !policy.isBlocked) {
                // Client transitioned from blocked to allowed: reset drop/match counters and purge cached flows
                counters.droppedPackets.set(0L)
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
        val degraded = currentConnectedMacs.size > 1 && hasRestricted && !isConntrackAvailable && !HostFirewall.isKernelNetfilterAvailable
        if (degraded != isMultiClientDegraded) {
            isMultiClientDegraded = degraded
            if (degraded) {
                SessionLog.warn("Degraded: multi-client userspace NAT isolation degraded (conntrack and kernel netfilter unavailable)")
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
                    "Counters: mac=$mac seenPackets=${counters.seenPackets.get()} " +
                        "matchedPackets=${counters.matchedPackets.get()} " +
                        "droppedPackets=${counters.droppedPackets.get()} " +
                        "shapedBytes=${counters.shapedBytes.get()}",
                )
            }
        }
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
            )
        } else {
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
            )
        }
    }

    fun getClientTraffic(mac: String, ips: Collection<String>): Pair<Long, Long> {
        val snapshot = getCounterSnapshot(mac)
        return snapshot.rxBytes to snapshot.txBytes
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
                    val matchedMac = resolveClientMacForPacket(meta, isUpload = true)
                    val decision = evaluateAndShape(meta, matchedMac, isUpload = true)
                    if (decision == PacketDecision.DROP || decision == PacketDecision.DROP_AQM) {
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
                    val matchedMac = resolveClientMacForPacket(meta, isUpload = false)
                    val decision = evaluateAndShape(meta, matchedMac, isUpload = false)
                    if (decision == PacketDecision.DROP || decision == PacketDecision.DROP_AQM) {
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

    /**
     * Resolves which verified connected client MAC owns [meta].
     *
     * Handles all three packet representations observed on Android TestNetwork tethering:
     * 1. Pre-NAT / directly routed IPv4 or IPv6 (`tetherSideIp` is in [ipToMac]).
     * 2. IPv6 SLAAC / EUI-64 or temporary addresses in `2001:db8::/64` or `fe80::/64`.
     * 3. Post-NAT MASQUERADE packets where Android Tethering rewrote the client's source IP
     *    to `192.0.2.2` (on upload) or destination IP to `192.0.2.2` (on download).
     */
    internal fun resolveClientMacForPacket(meta: PacketMeta, isUpload: Boolean): String? {
        val tetherSideIp = if (isUpload) meta.srcIp else meta.dstIp
        val tetherSidePort = if (isUpload) meta.srcPort else meta.dstPort
        val remoteSideIp = if (isUpload) meta.dstIp else meta.srcIp
        val remoteSidePort = if (isUpload) meta.dstPort else meta.srcPort

        val normalizedTetherIp = normalizeIp(tetherSideIp)

        // 1. Direct lookup in verified IP -> MAC table
        ipToMac[tetherSideIp]?.let { mac ->
            if (mac in activeConnectedMacs) return mac
        }
        if (normalizedTetherIp.isNotEmpty() && normalizedTetherIp != tetherSideIp) {
            ipToMac[normalizedTetherIp]?.let { mac ->
                if (mac in activeConnectedMacs) return mac
            }
        }

        // 2. Post-NAT MASQUERADE on testtun (`192.0.2.2` or `2001:db8::2`)
        if (tetherSideIp == TUN_LOCAL_V4 || tetherSideIp == TUN_LOCAL_V6 || normalizedTetherIp == TUN_LOCAL_V6_NORMALIZED) {
            val flowKey = FlowKey(
                protocol = meta.protocol,
                natPort = tetherSidePort,
                remoteIp = remoteSideIp,
                remotePort = remoteSidePort,
            )

            flowToMacCache[flowKey]?.let { cachedMac ->
                if (cachedMac in activeConnectedMacs) {
                    flowTimestamps[flowKey] = System.currentTimeMillis()
                    return cachedMac
                }
                flowToMacCache.remove(flowKey, cachedMac)
                flowTimestamps.remove(flowKey)
            }

            // Consult conntrack table for verified connection tracking
            maybeResolveConntrackFlows()
            flowToMacCache[flowKey]?.let { resolvedMac ->
                if (resolvedMac in activeConnectedMacs) {
                    flowTimestamps[flowKey] = System.currentTimeMillis()
                    return resolvedMac
                }
            }
            return null
        }

        // 3. IPv6 SLAAC in testtun prefix (`2001:db8::/64`) or link-local (`fe80::/64`)
        if (meta.version == 6 && (tetherSideIp.lowercase().startsWith(TUN_PREFIX_V6) || tetherSideIp.lowercase().startsWith("fe80:"))) {
            // 3a. Check if the IPv6 address embeds the client's EUI-64 MAC address
            extractMacFromIpv6Eui64(tetherSideIp)?.let { euiMac ->
                if (euiMac in activeConnectedMacs) {
                    bindClientIp(euiMac, tetherSideIp)
                    return euiMac
                }
            }

            // 3b. Refresh neighbor cache to see if `ip neigh` now lists this IPv6 address
            maybeRefreshNeighborCache()
            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) return neighborMac
            }
        }

        // 4. Unmapped private IPv4 address (e.g. DHCP just completed before neighbor poll)
        if (meta.version == 4 && isPrivateIpv4(tetherSideIp)) {
            maybeRefreshNeighborCache()
            ipToMac[tetherSideIp]?.let { neighborMac ->
                if (neighborMac in activeConnectedMacs) return neighborMac
            }
        }

        return null
    }

    internal fun evaluateAndShape(
        meta: PacketMeta,
        matchedMac: String?,
        isUpload: Boolean,
    ): PacketDecision {
        if (matchedMac == null) {
            unmatchedPackets.incrementAndGet()
            maybeLogTrafficSample(meta, isUpload, matchedMac = null, decision = PacketDecision.ALLOW)
            return PacketDecision.ALLOW
        }

        val counters = countersByMac.getOrPut(matchedMac) { ClientTrafficCounters(matchedMac) }
        counters.lastSeenAt = System.currentTimeMillis()
        counters.seenPackets.incrementAndGet()

        val policy = policiesByMac[matchedMac]
        if (policy == null || (!policy.isBlocked && policy.bandwidthLimitKbps <= 0)) {
            counters.forwardedPackets.incrementAndGet()
            if (isUpload) {
                counters.txBytes.addAndGet(meta.length.toLong())
            } else {
                counters.rxBytes.addAndGet(meta.length.toLong())
            }
            return PacketDecision.ALLOW
        }

        counters.matchedPackets.incrementAndGet()

        // 1. Hard block enforcement (manual block, schedule restriction, or connection time limit)
        if (policy.isBlocked) {
            counters.droppedPackets.incrementAndGet()
            counters.droppedBytes.addAndGet(meta.length.toLong())
            maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.DROP)
            maybeLogCountersOnMilestone(counters)
            return PacketDecision.DROP
        }

        // 2. Per-direction calibrated Token Bucket bandwidth limiting
        val limitKbps = policy.bandwidthLimitKbps
        if (limitKbps > 0) {
            val bucketMap = if (isUpload) uploadBucketsByMac else downloadBucketsByMac
            val bucket = bucketMap.getOrPut(matchedMac) { TokenBucket(limitKbps) }
            bucket.updateRate(limitKbps)

            // Keep pacing delay tight when multiple clients are active so one client never delays another
            val maxQueueDelayMs = if (activeConnectedMacs.size > 1) 35L else 150L
            val waitMs = bucket.consume(
                packetBytes = meta.length,
                isSmallControlPacket = meta.isSmallControlPacket,
                maxQueueDelayMs = maxQueueDelayMs,
            )

            if (waitMs < 0L) {
                counters.droppedPackets.incrementAndGet()
                counters.droppedBytes.addAndGet(meta.length.toLong())
                counters.shapedPackets.incrementAndGet()
                maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.DROP_AQM)
                maybeLogCountersOnMilestone(counters)
                return PacketDecision.DROP_AQM
            }

            if (waitMs > 0L) {
                counters.shapedPackets.incrementAndGet()
                counters.shapedBytes.addAndGet(meta.length.toLong())
                maybeLogTrafficSample(meta, isUpload, matchedMac = matchedMac, decision = PacketDecision.RATE_LIMIT)
                Thread.sleep(waitMs)
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
        return PacketDecision.ALLOW
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
                "Counters: mac=${counters.mac} seenPackets=$seen " +
                    "matchedPackets=${counters.matchedPackets.get()} " +
                    "droppedPackets=${counters.droppedPackets.get()} " +
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

    private fun maybeRefreshNeighborCache() {
        val now = System.currentTimeMillis()
        if (now - lastNeighborResolveMs < 1_000L) return
        lastNeighborResolveMs = now

        runCatching {
            val process = ProcessBuilder("ip", "neigh").start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(1, TimeUnit.SECONDS)) {
                process.destroyForcibly()
            }
            for (record in DownstreamInspector.parseIpNeighOutput(output)) {
                val mac = record.mac.uppercase()
                if (mac in activeConnectedMacs && isUsableClientIp(record.ip)) {
                    bindClientIp(mac, record.ip)
                }
            }
        }
    }

    /**
     * Parses `/proc/net/nf_conntrack`, `/proc/self/net/nf_conntrack`, or runs shell cat
     * to attribute post-NAT `192.0.2.2:natPort` flows to the exact downstream client IP/MAC.
     */
    private fun maybeResolveConntrackFlows() {
        val now = System.currentTimeMillis()
        if (now - lastConntrackResolveMs < 500L) return
        lastConntrackResolveMs = now

        var flowsParsed = 0
        val conntrackPaths = listOf(
            "/proc/net/nf_conntrack",
            "/proc/self/net/nf_conntrack",
            "/proc/net/ip_conntrack",
            "/proc/self/net/ip_conntrack",
        )

        for (path in conntrackPaths) {
            val file = File(path)
            if (!file.exists()) continue
            runCatching {
                file.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        if (parseConntrackLine(line)) {
                            flowsParsed++
                        }
                    }
                }
            }
            if (flowsParsed > 0) break
        }

        if (flowsParsed == 0) {
            // Try reading via process cat
            runCatching {
                val p = ProcessBuilder("cat", "/proc/net/nf_conntrack").start()
                val text = p.inputStream.bufferedReader().use { it.readText() }
                p.waitFor(500, TimeUnit.MILLISECONDS)
                if (text.isNotBlank()) {
                    text.lines().forEach { line ->
                        if (parseConntrackLine(line)) {
                            flowsParsed++
                        }
                    }
                }
            }
        }

        if (flowsParsed == 0 && HostFirewall.isSuAvailable) {
            runCatching {
                val res = HostFirewall.executePrivilegedCommand("cat", "/proc/net/nf_conntrack")
                if (res.isSuccess && res.stdout.isNotBlank()) {
                    res.stdout.lines().forEach { line ->
                        if (parseConntrackLine(line)) {
                            flowsParsed++
                        }
                    }
                }
            }
        }

        isConntrackAvailable = flowsParsed > 0
        if (flowsParsed > 0) {
            isMultiClientDegraded = false
        }
    }

    internal fun parseConntrackLine(line: String): Boolean {
        if (!line.contains(TUN_LOCAL_V4) && !line.contains(TUN_LOCAL_V6)) return false
        val proto = when {
            line.contains("tcp") -> 6
            line.contains("udp") -> 17
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
                    val key = FlowKey(
                        protocol = proto,
                        natPort = replyDstPort,
                        remoteIp = origDstIp,
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
                val proto = packet[9].toInt() and 0xFF
                val srcIp = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}.${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
                val dstIp = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}.${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

                var srcPort = 0
                var dstPort = 0
                if ((proto == 6 || proto == 17) && length >= ihl + 4) {
                    srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
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

                var srcPort = 0
                var dstPort = 0
                if ((nextHeader == 6 || nextHeader == 17) && length >= 44) {
                    srcPort = ((packet[40].toInt() and 0xFF) shl 8) or (packet[41].toInt() and 0xFF)
                    dstPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                }
                val isControl = (nextHeader == 6 && length <= 72) || srcPort == 53 || dstPort == 53 || nextHeader == 58
                PacketMeta(
                    version = 6,
                    protocol = nextHeader,
                    srcIp = srcIp,
                    dstIp = dstIp,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    length = length,
                    isSmallControlPacket = isControl,
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
