package dev.shizzi

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BpfFlowAttributionTest {

    // Exact device excerpts from Section 2 of the specification
    private val realDeviceExcerpt = """
        Tethering BPF Offload:
          Client Information:
            215(215) 2804:38a:a08a:c641:ecc7:78ff:fe6f:a0fb [00:00:00:00:00:00] -> [e2:15:cd:54:e4:9b] 1500
            215(215) 2804:38a:a08a:c641:70df:bf5c:e00c:5f9a [00:00:00:00:00:00] -> [e2:15:cd:54:e4:9b] 1500
            215(215) 2804:38a:a08a:c641:6a7a:f33f:a1d0:8159 [00:00:00:00:00:00] -> [f2:ff:8b:3d:b2:a6] 1500

          IPv4 Upstream:
            tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
            udp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:39398 -> 214(testtun46) 192.0.2.2:39398 -> 34.0.244.44:443 [00:00:00:00:00:00] 1500 183327ms
            tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:44056 -> 214(testtun46) 192.0.2.2:44056 -> 142.250.219.14:443 [00:00:00:00:00:00] 1500 227494ms

          IPv4 Downstream:
            tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
            udp [00:00:00:00:00:00] 214(testtun46) 34.0.244.44:443 -> 215(215) 192.0.2.2:39398 -> 192.168.167.151:39398 [e2:15:cd:54:e4:9b] 1500 184426ms
            tcp [00:00:00:00:00:00] 214(testtun46) 142.250.219.14:443 -> 215(215) 192.0.2.2:44056 -> 192.168.167.17:44056 [f2:ff:8b:3d:b2:a6] 1500 227494ms
    """.trimIndent()

    private val ipBindings = mapOf(
        "192.168.167.151" to "E2:15:CD:54:E4:9B",
        "192.168.167.17" to "F2:FF:8B:3D:B2:A6",
    )

    private val activeMacs = setOf(
        "E2:15:CD:54:E4:9B",
        "F2:FF:8B:3D:B2:A6",
    )

    @Before
    fun setUp() {
        TunTrafficEngine.stop()
        TunTrafficEngine.configureExperimentalBpf(enabled = false, pollIntervalMs = 1_000L)
    }

    @Test
    fun `1 real device excerpt parsing resolves TCP and UDP and numeric interface labels`() {
        val parsed = BpfDumpParser.parse(realDeviceExcerpt)
        assertTrue(parsed.recognizedFormat)
        assertEquals(3, parsed.ipv4UpstreamEntries.size)
        assertEquals(3, parsed.ipv4DownstreamEntries.size)
        assertFalse(parsed.hasRejections)

        // Verify numeric interface label 215(215) and named label 214(testtun46)
        val firstUp = parsed.ipv4UpstreamEntries[0]
        assertEquals(215, firstUp.inIfIndex)
        assertEquals("215", firstUp.inIfaceLabel)
        assertEquals(214, firstUp.outIfIndex)
        assertEquals("testtun46", firstUp.outIfaceLabel)
        assertEquals(6, firstUp.protocol)
        assertEquals("82:2D:00:30:5F:2D", firstUp.hotspotInDstMac)

        val secondUp = parsed.ipv4UpstreamEntries[1]
        assertEquals(17, secondUp.protocol)

        val clock = AtomicLong(1_000L)
        val attributor = NatFlowAttributor(monotonicClockMs = { clock.get() }, maxFreshnessMs = 4_500L)
        attributor.syncInterfaces(downstreamIface = "ap0", upstreamIface = "testtun46")

        val ingested = attributor.ingestParsedDump(
            parsed = parsed,
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 12L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertTrue(ingested)

        // Upload Client A TCP
        val upA = attributor.resolveTranslatedPacket(
            family = 4,
            protocol = 6,
            packetSrcIp = "192.0.2.2",
            packetSrcPort = 51006,
            packetDstIp = "108.158.147.26",
            packetDstPort = 443,
            isUpload = true,
            isTcpSyn = false,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertTrue(upA is AttributionOutcome.Matched)
        assertEquals("E2:15:CD:54:E4:9B", (upA as AttributionOutcome.Matched).mac)

        // Upload Client A UDP
        val upAUdp = attributor.resolveTranslatedPacket(
            family = 4,
            protocol = 17,
            packetSrcIp = "192.0.2.2",
            packetSrcPort = 39398,
            packetDstIp = "34.0.244.44",
            packetDstPort = 443,
            isUpload = true,
            isTcpSyn = false,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertTrue(upAUdp is AttributionOutcome.Matched)
        assertEquals("E2:15:CD:54:E4:9B", (upAUdp as AttributionOutcome.Matched).mac)

        // Upload Client B TCP
        val upB = attributor.resolveTranslatedPacket(
            family = 4,
            protocol = 6,
            packetSrcIp = "192.0.2.2",
            packetSrcPort = 44056,
            packetDstIp = "142.250.219.14",
            packetDstPort = 443,
            isUpload = true,
            isTcpSyn = false,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertTrue(upB is AttributionOutcome.Matched)
        assertEquals("F2:FF:8B:3D:B2:A6", (upB as AttributionOutcome.Matched).mac)
    }

    @Test
    fun `2 relationship-preserving 98-entry two-client fixture resolves all 88 Client A and 10 Client B flows`() {
        // Synthetic relationship-preserving fixture matching the exact 98-entry distribution from Section 2
        // (full raw capture file 22shizzi-poc-1793125251327.json is not stored in workspace).
        val sb = StringBuilder()
        sb.appendLine("IPv4 Upstream:")
        // 82 TCP + 6 UDP for Client A (192.168.167.151 -> E2:15:CD:54:E4:9B)
        for (i in 0 until 82) {
            val port = 50000 + i
            sb.appendLine("  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:$port -> 214(testtun46) 192.0.2.2:$port -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 200000ms")
        }
        for (i in 0 until 6) {
            val port = 39300 + i
            sb.appendLine("  udp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:$port -> 214(testtun46) 192.0.2.2:$port -> 34.0.244.44:443 [00:00:00:00:00:00] 1500 180000ms")
        }
        // 10 TCP for Client B (192.168.167.17 -> F2:FF:8B:3D:B2:A6)
        for (i in 0 until 10) {
            val port = 44000 + i
            sb.appendLine("  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:$port -> 214(testtun46) 192.0.2.2:$port -> 142.250.219.14:443 [00:00:00:00:00:00] 1500 220000ms")
        }
        sb.appendLine("IPv4 Downstream:")
        for (i in 0 until 82) {
            val port = 50000 + i
            sb.appendLine("  tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:$port -> 192.168.167.151:$port [e2:15:cd:54:e4:9b] 1500 200005ms")
        }
        for (i in 0 until 6) {
            val port = 39300 + i
            sb.appendLine("  udp [00:00:00:00:00:00] 214(testtun46) 34.0.244.44:443 -> 215(215) 192.0.2.2:$port -> 192.168.167.151:$port [e2:15:cd:54:e4:9b] 1500 180005ms")
        }
        for (i in 0 until 10) {
            val port = 44000 + i
            sb.appendLine("  tcp [00:00:00:00:00:00] 214(testtun46) 142.250.219.14:443 -> 215(215) 192.0.2.2:$port -> 192.168.167.17:$port [f2:ff:8b:3d:b2:a6] 1500 220005ms")
        }

        val parsed = BpfDumpParser.parse(sb.toString())
        assertEquals(98, parsed.ipv4UpstreamEntries.size)
        assertEquals(98, parsed.ipv4DownstreamEntries.size)

        val attributor = NatFlowAttributor(monotonicClockMs = { 2_000L }, maxFreshnessMs = 4_500L)
        attributor.syncInterfaces("ap0", "testtun46")
        assertTrue(
            attributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 15L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )

        val snap = attributor.currentSnapshot()
        assertEquals(98, snap.flowsByTuple.size)
        assertEquals(98, snap.reverseMatchedCount)
        assertEquals(88, snap.flowsByTuple.values.count { it.verifiedMac == "E2:15:CD:54:E4:9B" })
        assertEquals(10, snap.flowsByTuple.values.count { it.verifiedMac == "F2:FF:8B:3D:B2:A6" })

        val countsA = snap.perClientCounts.first { it.mac == "E2:15:CD:54:E4:9B" }
        assertEquals(82, countsA.tcpFlows)
        assertEquals(6, countsA.udpFlows)

        val countsB = snap.perClientCounts.first { it.mac == "F2:FF:8B:3D:B2:A6" }
        assertEquals(10, countsB.tcpFlows)
        assertEquals(0, countsB.udpFlows)
    }

    @Test
    fun `3 NAT disambiguation handles port rewriting equal ports different remotes TCP vs UDP and rejects ambiguous duplicates`() {
        val raw = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:50000 -> 214(testtun46) 192.0.2.2:61001 -> 35.186.224.25:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:55555 -> 214(testtun46) 192.0.2.2:55555 -> 1.1.1.1:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:55555 -> 214(testtun46) 192.0.2.2:55555 -> 8.8.8.8:443 [00:00:00:00:00:00] 1500 1000ms
              udp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:55555 -> 214(testtun46) 192.0.2.2:55555 -> 1.1.1.1:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:60000 -> 214(testtun46) 192.0.2.2:60000 -> 9.9.9.9:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:60001 -> 214(testtun46) 192.0.2.2:60000 -> 9.9.9.9:443 [00:00:00:00:00:00] 1500 1000ms
        """.trimIndent()
        val parsed = BpfDumpParser.parse(raw)
        val attributor = NatFlowAttributor(monotonicClockMs = { 1_000L }, maxFreshnessMs = 4_500L)
        attributor.ingestParsedDump(
            parsed = parsed,
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 5L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )

        // 1. Source-port rewriting (orig 50000 -> translated 61001)
        val rewritten = attributor.resolveTranslatedPacket(
            family = 4,
            protocol = 6,
            packetSrcIp = "192.0.2.2",
            packetSrcPort = 61001,
            packetDstIp = "35.186.224.25",
            packetDstPort = 443,
            isUpload = true,
            isTcpSyn = false,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertEquals("E2:15:CD:54:E4:9B", (rewritten as AttributionOutcome.Matched).mac)
        assertEquals(50000, rewritten.mapping.origClientPort)

        // 2. Equal ports (55555) with different remote destinations (1.1.1.1 vs 8.8.8.8)
        val dest1 = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 55555, "1.1.1.1", 443, true, false, ipBindings, activeMacs,
        )
        val dest2 = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 55555, "8.8.8.8", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals("E2:15:CD:54:E4:9B", (dest1 as AttributionOutcome.Matched).mac)
        assertEquals("F2:FF:8B:3D:B2:A6", (dest2 as AttributionOutcome.Matched).mac)

        // 3. TCP vs UDP with identical numeric endpoints (192.0.2.2:55555 -> 1.1.1.1:443)
        val udpDest1 = attributor.resolveTranslatedPacket(
            4, 17, "192.0.2.2", 55555, "1.1.1.1", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals("F2:FF:8B:3D:B2:A6", (udpDest1 as AttributionOutcome.Matched).mac)

        // 4. Ambiguous duplicate translated tuple (192.0.2.2:60000 -> 9.9.9.9:443 claimed by both clients)
        // Must NOT pick the first match; must return Ambiguous
        val ambiguous = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 60000, "9.9.9.9", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue(ambiguous is AttributionOutcome.Ambiguous)
    }

    @Test
    fun `4 reverse direction attribution never uses upstream inDstMac as client MAC and rejects contradictory downstream MAC`() {
        val parsed = BpfDumpParser.parse(realDeviceExcerpt)
        val attributor = NatFlowAttributor(monotonicClockMs = { 1_000L }, maxFreshnessMs = 4_500L)
        attributor.ingestParsedDump(
            parsed = parsed,
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 5L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )

        // Download lookup for Client A (packet src=108.158.147.26:443, dst=192.0.2.2:51006, isUpload=false)
        val dlA = attributor.resolveTranslatedPacket(
            4, 6, "108.158.147.26", 443, "192.0.2.2", 51006, false, false, ipBindings, activeMacs,
        )
        assertTrue(dlA is AttributionOutcome.Matched)
        assertEquals("E2:15:CD:54:E4:9B", (dlA as AttributionOutcome.Matched).mac)
        // Never equals upstream hotspotInDstMac (82:2D:00:30:5F:2D)
        assertFalse(dlA.mac.equals("82:2D:00:30:5F:2D", ignoreCase = true))

        // Download lookup for Client B
        val dlB = attributor.resolveTranslatedPacket(
            4, 6, "142.250.219.14", 443, "192.0.2.2", 44056, false, false, ipBindings, activeMacs,
        )
        assertTrue(dlB is AttributionOutcome.Matched)
        assertEquals("F2:FF:8B:3D:B2:A6", (dlB as AttributionOutcome.Matched).mac)

        // Contradictory downstream clientOutDstMac vs active neighbor binding -> rejected as Ambiguous
        val contradictoryRaw = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
            IPv4 Downstream:
              tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [f2:ff:8b:3d:b2:a6] 1500 230033ms
        """.trimIndent()
        attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(contradictoryRaw),
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 5L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        val conflictRes = attributor.resolveTranslatedPacket(
            4, 6, "108.158.147.26", 443, "192.0.2.2", 51006, false, false, ipBindings, activeMacs,
        )
        assertTrue(conflictRes is AttributionOutcome.Ambiguous)
    }

    @Test
    fun `5 parser and collector failures are distinguishable and do not overwrite valid snapshot`() {
        val malformedRaw = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006
              sctp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 999.999.1.1:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:99999 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 1000ms
        """.trimIndent()
        val parsedMalformed = BpfDumpParser.parse(malformedRaw)
        assertEquals(0, parsedMalformed.ipv4UpstreamEntries.size)
        assertEquals(4, parsedMalformed.rejectedLines.size)
        val reasons = parsedMalformed.rejectedLines.map { it.reason }.toSet()
        assertTrue(reasons.contains(BpfRejectionReason.TRUNCATED_LINE))
        assertTrue(reasons.contains(BpfRejectionReason.UNSUPPORTED_PROTOCOL))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_IP))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_PORT))

        // Verify valid snapshot is NOT overwritten by subsequent collector failures (TIMEOUT, TRUNCATED, PERMISSION_DENIED)
        val clock = AtomicLong(1_000L)
        val attributor = NatFlowAttributor(monotonicClockMs = { clock.get() }, maxFreshnessMs = 4_500L)
        assertTrue(
            attributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(realDeviceExcerpt),
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 10L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )
        assertEquals(3, attributor.currentSnapshot().flowsByTuple.size)

        // Simulate a timeout failure at t = 2_000L while previous snapshot is still fresh
        clock.set(2_000L)
        val failedIngest = attributor.ingestParsedDump(
            parsed = BpfParsedDump(recognizedFormat = false, ipv4UpstreamEntries = emptyList(), ipv4DownstreamEntries = emptyList(), ipv6Entries = emptyList(), rejectedLines = emptyList()),
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.TIMEOUT,
            collectionDurationMs = 1500L,
            collectionError = "Timed out after 1500ms",
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertFalse(failedIngest)
        // Fresh snapshot is preserved
        val stillValid = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue(stillValid is AttributionOutcome.Matched)

        // Valid empty dump IS distinguishable from parse failure and updates snapshot cleanly to EMPTY_VALID
        val emptyValidRaw = """
            IPv4 Upstream:
              none
            IPv4 Downstream:
              none
        """.trimIndent()
        val parsedEmpty = BpfDumpParser.parse(emptyValidRaw)
        assertTrue(parsedEmpty.isEmptyValid)
        clock.set(2_500L)
        assertTrue(
            attributor.ingestParsedDump(
                parsed = parsedEmpty,
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.EMPTY_VALID,
                collectionDurationMs = 6L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )
        assertEquals(BpfCollectionStatus.EMPTY_VALID, attributor.currentSnapshot().collectionStatus)
        assertEquals(0, attributor.currentSnapshot().flowsByTuple.size)
    }

    @Test
    fun `6 staleness session generation invalidation IP reassignment and TCP SYN tuple reuse guard`() {
        val clock = AtomicLong(1_000L)
        val attributor = NatFlowAttributor(monotonicClockMs = { clock.get() }, maxFreshnessMs = 4_500L)
        val gen1 = attributor.currentSessionGeneration
        attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(realDeviceExcerpt),
            collectionSessionGeneration = gen1,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 10L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )

        // 1. Expired snapshot data returns StaleSnapshot when clock advances past maxFreshnessMs (4_500ms)
        clock.set(6_000L)
        val staleLookup = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue(staleLookup is AttributionOutcome.StaleSnapshot)

        // Refresh snapshot at t = 6_000L
        attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(realDeviceExcerpt),
            collectionSessionGeneration = gen1,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 10L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )

        // 2. Upload TCP SYN on an already-mapped tuple triggers conservative tuple reuse guard
        clock.set(6_200L)
        val synReuse = attributor.resolveTranslatedPacket(
            family = 4,
            protocol = 6,
            packetSrcIp = "192.0.2.2",
            packetSrcPort = 51006,
            packetDstIp = "108.158.147.26",
            packetDstPort = 443,
            isUpload = true,
            isTcpSyn = true,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertTrue(synReuse is AttributionOutcome.StaleOrInvalidated)
        assertEquals(1L, attributor.tupleReuseGuardTriggeredCount.get())

        // 3. Client IP reassignment invalidates old owner attribution immediately (port 39398 is UDP = 17)
        val reassignedBindings = mapOf(
            "192.168.167.151" to "AA:BB:CC:DD:EE:FF",
            "192.168.167.17" to "F2:FF:8B:3D:B2:A6",
        )
        val reassignedLookup = attributor.resolveTranslatedPacket(
            4, 17, "192.0.2.2", 39398, "34.0.244.44", 443, true, false, reassignedBindings, activeMacs + "AA:BB:CC:DD:EE:FF",
        )
        assertTrue(reassignedLookup is AttributionOutcome.StaleOrInvalidated)

        // 4. Session / upstream change bumps session generation and rejects late old-generation dumps
        val gen2 = attributor.onSessionOrUpstreamChanged("ap0", "testtun47")
        assertTrue(gen2 > gen1)
        val lateAccepted = attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(realDeviceExcerpt),
            collectionSessionGeneration = gen1,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 10L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertFalse(lateAccepted)
        assertEquals(1L, attributor.rejectedOldGenerationCount.get())
    }

    @Test
    fun `7 policy changes immediately affect already-mapped flows in both directions without cached ALLOW`() {
        val hosts = listOf(
            DiscoveredHost(
                mac = "E2:15:CD:54:E4:9B",
                ip = "192.168.167.151",
                allIps = listOf("192.168.167.151"),
                interfaceName = "ap0",
            ),
            DiscoveredHost(
                mac = "F2:FF:8B:3D:B2:A6",
                ip = "192.168.167.17",
                allIps = listOf("192.168.167.17"),
                interfaceName = "ap0",
            ),
        )
        TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L)
        TunTrafficEngine.updatePolicies(emptyMap(), hosts)

        // Ingest real device BPF snapshot while both Client A and Client B are allowed
        assertTrue(
            TunTrafficEngine.bpfAttributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(realDeviceExcerpt),
                collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 8L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )

        val metaUpA = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "108.158.147.26",
            srcPort = 51006, dstPort = 443, length = 1200, isSmallControlPacket = false,
        )
        val metaDownA = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "108.158.147.26", dstIp = "192.0.2.2",
            srcPort = 443, dstPort = 51006, length = 1200, isSmallControlPacket = false,
        )
        val metaUpB = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "142.250.219.14",
            srcPort = 44056, dstPort = 443, length = 1200, isSmallControlPacket = false,
        )

        // Initially allowed
        val attrUpA = TunTrafficEngine.resolveClientMacWithSource(metaUpA, isUpload = true)
        assertEquals("E2:15:CD:54:E4:9B", attrUpA.mac)
        assertEquals(AttributionSource.BPF_NAT, attrUpA.source)
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(metaUpA, attrUpA.mac, isUpload = true, attributionSource = attrUpA.source),
        )

        // Dynamically block Client A -> existing mapped upload and download flows immediately DROP
        TunTrafficEngine.updatePolicies(
            mapOf(
                "E2:15:CD:54:E4:9B" to TunTrafficEngine.EnforcedClientPolicy(
                    mac = "E2:15:CD:54:E4:9B",
                    isBlocked = true,
                    bandwidthLimitKbps = 0,
                ),
            ),
            hosts,
        )

        val attrUpA2 = TunTrafficEngine.resolveClientMacWithSource(metaUpA, isUpload = true)
        val attrDownA2 = TunTrafficEngine.resolveClientMacWithSource(metaDownA, isUpload = false)
        val attrUpB2 = TunTrafficEngine.resolveClientMacWithSource(metaUpB, isUpload = true)

        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShape(metaUpA, attrUpA2.mac, isUpload = true, attributionSource = attrUpA2.source),
        )
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShape(metaDownA, attrDownA2.mac, isUpload = false, attributionSource = attrDownA2.source),
        )
        // Client B remains allowed
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(metaUpB, attrUpB2.mac, isUpload = true, attributionSource = attrUpB2.source),
        )

        val snapA = TunTrafficEngine.getCounterSnapshot("E2:15:CD:54:E4:9B")
        assertTrue(snapA.policyVersionBlockedDrops >= 2L)
        assertTrue(snapA.bpfAttributedPackets >= 3L)
        TunTrafficEngine.configureExperimentalBpf(enabled = false, pollIntervalMs = 1_000L)
        TunTrafficEngine.clearAll()
    }

    @Test
    fun `8 first-packet and cold-cache behavior keeps unknown flows unattributed until BPF evidence appears`() {
        val attributor = NatFlowAttributor(monotonicClockMs = { 1_000L }, maxFreshnessMs = 4_500L)

        // Cold cache before first BPF snapshot -> Unknown
        val coldRes = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, true, ipBindings, activeMacs,
        )
        assertTrue(coldRes is AttributionOutcome.Unknown)

        // After BPF snapshot, an unmapped new flow (port 62000) returns Unknown (never invents attribution)
        attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(realDeviceExcerpt),
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 8L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        val unmappedRes = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 62000, "108.158.147.26", 443, true, true, ipBindings, activeMacs,
        )
        assertTrue(unmappedRes is AttributionOutcome.Unknown)
    }

    @Test
    fun `9 IPv6 local control traffic multiple IPv6 addresses and non-initial IPv4 or IPv6 fragments are handled safely`() {
        // 1. Local IPv6 multicast router solicitation fe80::1 -> ff02::2 is classified as link-local control traffic
        val rsMeta = TunTrafficEngine.PacketMeta(
            version = 6, protocol = 58, srcIp = "fe80::1", dstIp = "ff02::2",
            srcPort = 0, dstPort = 0, length = 64, isSmallControlPacket = true,
        )
        assertTrue(TunTrafficEngine.isLinkLocalMulticastControl(rsMeta))
        val beforeLocal = TunTrafficEngine.localControlPackets.get()
        val rsDetail = TunTrafficEngine.evaluateAndShapeDetailed(rsMeta, matchedMac = null, isUpload = true)
        assertEquals(PacketDecision.ALLOW, rsDetail.decision)
        assertEquals(beforeLocal + 1L, TunTrafficEngine.localControlPackets.get())

        // 2. Non-initial IPv4 fragment detection (fragment offset > 0) does not read imaginary transport ports
        val ipv4Frag = ByteArray(28)
        ipv4Frag[0] = 0x45.toByte() // IPv4, IHL=20
        ipv4Frag[6] = 0x00.toByte()
        ipv4Frag[7] = 0x20.toByte() // Fragment offset = 32 (non-zero)
        ipv4Frag[9] = 6.toByte() // TCP
        ipv4Frag[12] = 192.toByte()
        ipv4Frag[13] = 0.toByte()
        ipv4Frag[14] = 2.toByte()
        ipv4Frag[15] = 2.toByte()
        ipv4Frag[16] = 1.toByte()
        ipv4Frag[17] = 1.toByte()
        ipv4Frag[18] = 1.toByte()
        ipv4Frag[19] = 1.toByte()
        // Write bogus bytes at offset 20..23 that would look like ports if fragment offset were ignored
        ipv4Frag[20] = 0xC7.toByte()
        ipv4Frag[21] = 0x3E.toByte()
        ipv4Frag[22] = 0x01.toByte()
        ipv4Frag[23] = 0xBB.toByte()

        val parsedV4Frag = TunTrafficEngine.parsePacketMeta(ipv4Frag, ipv4Frag.size)
        assertNotNull(parsedV4Frag)
        assertTrue(parsedV4Frag!!.isNonInitialFragment)
        assertEquals(0, parsedV4Frag.srcPort)
        assertEquals(0, parsedV4Frag.dstPort)

        val beforeFrag = TunTrafficEngine.unsupportedOrFragmentPackets.get()
        val fragAttr = TunTrafficEngine.resolveClientMacWithSource(parsedV4Frag, isUpload = true)
        assertNull(fragAttr.mac)
        assertEquals(AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT, fragAttr.source)
        assertEquals(beforeFrag + 1L, TunTrafficEngine.unsupportedOrFragmentPackets.get())

        // 3. Non-initial IPv6 fragment header (NextHeader = 44, fragOffset > 0)
        val ipv6Frag = ByteArray(56)
        ipv6Frag[0] = 0x60.toByte()
        ipv6Frag[6] = 44.toByte() // Fragment extension header
        val v6Src = InetAddress.getByName("2001:db8::2").address
        val v6Dst = InetAddress.getByName("2607:f8b0:4005:80a::200e").address
        System.arraycopy(v6Src, 0, ipv6Frag, 8, 16)
        System.arraycopy(v6Dst, 0, ipv6Frag, 24, 16)
        ipv6Frag[40] = 6.toByte() // Inner protocol = TCP
        ipv6Frag[42] = 0x00.toByte()
        ipv6Frag[43] = 0x18.toByte() // Non-zero fragment offset

        val parsedV6Frag = TunTrafficEngine.parsePacketMeta(ipv6Frag, ipv6Frag.size)
        assertNotNull(parsedV6Frag)
        assertTrue(parsedV6Frag!!.isNonInitialFragment)
        assertEquals(0, parsedV6Frag.srcPort)
        assertEquals(0, parsedV6Frag.dstPort)

        // 4. Multiple IPv6 addresses for the same client MAC
        val hostWithMultiV6 = DiscoveredHost(
            mac = "E2:15:CD:54:E4:9B",
            ip = "192.168.167.151",
            allIps = listOf(
                "192.168.167.151",
                "2804:38a:a08a:c641:ecc7:78ff:fe6f:a0fb",
                "2804:38a:a08a:c641:70df:bf5c:e00c:5f9a",
            ),
            interfaceName = "ap0",
        )
        TunTrafficEngine.updatePolicies(emptyMap(), listOf(hostWithMultiV6))
        val v6Meta1 = TunTrafficEngine.PacketMeta(
            version = 6, protocol = 6,
            srcIp = "2804:38a:a08a:c641:ecc7:78ff:fe6f:a0fb",
            dstIp = "2607:f8b0:4005:80a::200e",
            srcPort = 52000, dstPort = 443, length = 1280, isSmallControlPacket = false,
        )
        val v6Meta2 = TunTrafficEngine.PacketMeta(
            version = 6, protocol = 6,
            srcIp = "2804:38a:a08a:c641:70df:bf5c:e00c:5f9a",
            dstIp = "2607:f8b0:4005:80a::200e",
            srcPort = 52001, dstPort = 443, length = 1280, isSmallControlPacket = false,
        )
        assertEquals("E2:15:CD:54:E4:9B", TunTrafficEngine.resolveClientMacForPacket(v6Meta1, isUpload = true))
        assertEquals("E2:15:CD:54:E4:9B", TunTrafficEngine.resolveClientMacForPacket(v6Meta2, isUpload = true))
        TunTrafficEngine.clearAll()
    }

    @Test
    fun `10 non-blocking per-client shaping never sleeps on shared thread and drops queued packets on policy block`() {
        val macA = "E2:15:CD:54:E4:9B"
        val macB = "F2:FF:8B:3D:B2:A6"
        val hosts = listOf(
            DiscoveredHost(
                mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"),
                interfaceName = "ap0",
            ),
            DiscoveredHost(
                mac = macB, ip = "192.168.167.17", allIps = listOf("192.168.167.17"),
                interfaceName = "ap0",
            ),
        )

        // Configure Client A with a 500 Kbps bandwidth limit and Client B unrestricted
        TunTrafficEngine.updatePolicies(
            mapOf(
                macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = false, bandwidthLimitKbps = 500),
                macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false, bandwidthLimitKbps = 0),
            ),
            hosts,
        )

        val metaA = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.168.167.151", dstIp = "108.158.147.26",
            srcPort = 51006, dstPort = 443, length = 1400, isSmallControlPacket = false,
        )
        val metaB = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.168.167.17", dstIp = "142.250.219.14",
            srcPort = 44056, dstPort = 443, length = 1400, isSmallControlPacket = false,
        )

        val dummyPayload = ByteArray(1400)
        var rateLimitedCount = 0
        var totalScheduledPaceDelayMs = 0L
        for (i in 0 until 8) {
            val detailA = TunTrafficEngine.evaluateAndShapeDetailed(metaA, macA, isUpload = false)
            if (detailA.decision == PacketDecision.RATE_LIMIT && detailA.paceDelayMs > 0L) {
                rateLimitedCount++
                totalScheduledPaceDelayMs += detailA.paceDelayMs
                assertTrue(
                    TunTrafficEngine.enqueuePacedPacket(
                        mac = macA,
                        isUpload = false,
                        buf = dummyPayload,
                        length = dummyPayload.size,
                        paceDelayMs = detailA.paceDelayMs,
                        policyVersion = detailA.policyVersion,
                        targetFd = null,
                    ),
                )
            }
            // Client B evaluated on the same thread is immediately ALLOW with 0 delay
            val detailB = TunTrafficEngine.evaluateAndShapeDetailed(metaB, macB, isUpload = false)
            assertEquals(PacketDecision.ALLOW, detailB.decision)
            assertEquals(0L, detailB.paceDelayMs)
        }
        assertTrue("Expected Client A packets beyond burst to be RATE_LIMIT queued", rateLimitedCount > 0)
        assertTrue("Expected positive scheduled pacing delay in queue", totalScheduledPaceDelayMs >= 30L)
        assertEquals(rateLimitedCount, TunTrafficEngine.getQueuedPacketCountForClient(macA))

        // Transition Client A to blocked while packets are still sitting in Client A's pacing queue
        TunTrafficEngine.updatePolicies(
            mapOf(
                macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true, bandwidthLimitKbps = 500),
                macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false, bandwidthLimitKbps = 0),
            ),
            hosts,
        )

        // All queued packets for Client A must be purged and counted as blocked drops immediately
        assertEquals(0, TunTrafficEngine.getQueuedPacketCountForClient(macA))
        val snapA = TunTrafficEngine.getCounterSnapshot(macA)
        assertEquals(rateLimitedCount.toLong(), snapA.policyVersionBlockedDrops)
        TunTrafficEngine.clearAll()
    }
}
