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
        TunTrafficEngine.resetAllQuotaStatesForTest(deleteCheckpointFile = false)
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
              tcp [82:2d:00:30:5f:2d] 0(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 0 1000ms
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 -5s
        """.trimIndent()
        // When wasTruncatedByReader == false, incomplete flow syntax is INCOMPLETE_FLOW_LINE (never TRUNCATED_LINE)
        val parsedMalformed = BpfDumpParser.parse(malformedRaw, wasTruncatedByReader = false)
        assertEquals(0, parsedMalformed.ipv4UpstreamEntries.size)
        assertEquals(7, parsedMalformed.rejectedLines.size)
        val reasons = parsedMalformed.rejectedLines.map { it.reason }.toSet()
        assertFalse(reasons.contains(BpfRejectionReason.TRUNCATED_LINE))
        assertTrue(reasons.contains(BpfRejectionReason.INCOMPLETE_FLOW_LINE))
        assertTrue(reasons.contains(BpfRejectionReason.UNSUPPORTED_PROTOCOL))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_IP))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_PORT))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_IFINDEX))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_PMTU))
        assertTrue(reasons.contains(BpfRejectionReason.INVALID_AGE))

        // Authoritative reader truncation (wasTruncatedByReader == true) produces TRUNCATED_LINE
        val readerTruncatedRaw = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006
        """.trimIndent()
        val parsedReaderTruncated = BpfDumpParser.parse(readerTruncatedRaw, wasTruncatedByReader = true)
        assertTrue(parsedReaderTruncated.wasTruncatedByReader)
        assertEquals(1, parsedReaderTruncated.rejectedLines.size)
        assertEquals(BpfRejectionReason.TRUNCATED_LINE, parsedReaderTruncated.rejectedLines.first().reason)

        // Verify valid snapshot is NOT overwritten by subsequent collector failures (TIMEOUT, TRUNCATED, PARSE_FAILURE)
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
        assertTrue(attributor.lastAttemptDiagnostic().snapshotPublished)

        // Simulate a parse failure with 7 rejected lines at t = 1_500L while previous snapshot is fresh
        clock.set(1_500L)
        val failedParseIngest = attributor.ingestParsedDump(
            parsed = parsedMalformed,
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 14L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertFalse(failedParseIngest)
        // Published snapshot remains OK with 3 active flows and 0 rejected lines, while lastAttempt records the 7 rejected lines
        assertEquals(BpfCollectionStatus.OK, attributor.currentSnapshot().collectionStatus)
        assertEquals(3, attributor.currentSnapshot().flowsByTuple.size)
        assertEquals(0, attributor.currentSnapshot().rejectedLineCount)
        assertFalse(attributor.lastAttemptDiagnostic().snapshotPublished)
        assertEquals(BpfCollectionStatus.PARSE_FAILURE, attributor.lastAttemptDiagnostic().attemptStatus)
        assertEquals(7, attributor.lastAttemptDiagnostic().rejectedLineCount)
        assertEquals(7, attributor.lastAttemptDiagnostic().rejectedLines.size)

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
        TunTrafficEngine.clearAll()
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

    @Test
    fun `11 non-flow metadata is ignored without false-positive rejections and swapped ifindex is rejected`() {
        val dumpWithMetadataAndSwappedIfIndex = """
            Tethering BPF Offload:
              IPv4 Upstream:
                # Active upstream offload rules
                Total entries: 2
                tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
                tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:44056 -> 214(testtun46) 192.0.2.2:44056 -> 142.250.219.14:443 [00:00:00:00:00:00] 1500 227s
                ---
              IPv4 Downstream:
                Count: 2
                tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
                tcp [00:00:00:00:00:00] 215(215) 142.250.219.14:443 -> 214(testtun46) 192.0.2.2:44056 -> 192.168.167.17:44056 [f2:ff:8b:3d:b2:a6] 1500 227494ms
        """.trimIndent()

        val parsed = BpfDumpParser.parse(dumpWithMetadataAndSwappedIfIndex)
        assertTrue(parsed.recognizedFormat)
        assertFalse("Non-flow metadata must not be counted as rejected lines", parsed.hasRejections)
        assertEquals(2, parsed.ipv4UpstreamEntries.size)
        assertEquals(2, parsed.ipv4DownstreamEntries.size)
        // Verify "227s" age unit parsed as 227_000ms
        assertEquals(227_000L, parsed.ipv4UpstreamEntries[1].rawAgeMs)

        val attributor = NatFlowAttributor(
            monotonicClockMs = { 1_000L },
            maxFreshnessMs = 4_500L,
            interfaceIndexResolver = { iface ->
                when (iface) {
                    "ap0" -> 215
                    "testtun46" -> 214
                    else -> 0
                }
            },
        )
        attributor.syncInterfaces("ap0", "testtun46")

        assertTrue(
            attributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 9L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )

        val snap = attributor.currentSnapshot()
        assertEquals(215, snap.resolvedDownstreamIfIndex)
        assertEquals(214, snap.resolvedUpstreamIfIndex)
        // First flow has valid reverse ifindex parity (214 -> 215); second flow has swapped downstream ifindex (215 -> 214)
        assertEquals(1, snap.flowsByTuple.size)
        assertEquals(1, snap.ifIndexMismatchCount)

        val validRes = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue(validRes is AttributionOutcome.Matched)

        val swappedIfIndexRes = attributor.resolveTranslatedPacket(
            4, 6, "192.0.2.2", 44056, "142.250.219.14", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue("Swapped downstream ifindex must be rejected as Ambiguous", swappedIfIndexRes is AttributionOutcome.Ambiguous)
    }

    @Test
    fun `12 invalid IPv4 line among valid lines preserves BpfRejectedLine diagnostics masks sensitive previews by default and supports quarantine`() {
        val mixedDump = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
              tcp [82:2d:00:30:5f:2d] 215(215) 999.168.167.17:44056 -> 214(testtun46) 192.0.2.2:44056 -> 142.250.219.14:443 [e2:15:cd:54:e4:9b] 1500 227494ms
            IPv4 Downstream:
              tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
        """.trimIndent()

        val parsed = BpfDumpParser.parse(mixedDump)
        assertEquals(1, parsed.ipv4UpstreamEntries.size)
        assertEquals(1, parsed.ipv4DownstreamEntries.size)
        assertEquals(1, parsed.rejectedLines.size)
        val rej = parsed.rejectedLines.first()
        assertEquals(3, rej.lineNumber)
        assertEquals("IPv4 Upstream", rej.section)
        assertEquals(BpfRejectionReason.INVALID_IP, rej.reason)

        // Default conservative policy (allowSafePartialPublication = false) rejects snapshot publication
        // while preserving rejectedLines and counts in lastAttemptDiagnostic and BpfAttributionStatusReport
        TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L)
        val publishedConservative = TunTrafficEngine.bpfAttributor.ingestParsedDump(
            parsed = parsed,
            collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 11L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        assertFalse(publishedConservative)

        val report = TunTrafficEngine.getBpfAttributionReport()
        assertFalse(report.lastAttemptSnapshotPublished)
        assertEquals(BpfCollectionStatus.PARSE_FAILURE, report.lastAttemptStatus)
        assertEquals(1, report.lastAttemptUpstreamEntries)
        assertEquals(1, report.lastAttemptDownstreamEntries)
        assertEquals(1, report.lastAttemptRejectedLineCount)
        assertEquals(mapOf("INVALID_IP" to 1), report.lastAttemptRejectedByReason)
        assertEquals(1, report.lastAttemptRejectedLines.size)

        // Verify default Markdown & JSON reports mask IPs, ports, and MACs by default (includeSensitiveEndpoints = false)
        val defaultMd = report.toMarkdownReport(
            apkVersion = "0.4.0-rs-lua.8",
            sourceCommit = "test",
            serviceBuildId = 13,
        )
        assertTrue(defaultMd.contains("INVALID_IP"))
        assertTrue(defaultMd.contains("x.x.x.x:xxxx"))
        assertTrue(defaultMd.contains("xx:xx:xx:xx:xx:xx"))
        assertFalse("Default report must not expose raw public IP", defaultMd.contains("142.250.219.14"))
        assertFalse("Default report must not expose raw MAC", defaultMd.contains("e2:15:cd:54:e4:9b", ignoreCase = true))

        val rawMd = report.toMarkdownReport(
            apkVersion = "0.4.0-rs-lua.8",
            sourceCommit = "test",
            serviceBuildId = 13,
            includeSensitiveEndpoints = true,
        )
        assertTrue(rawMd.contains("142.250.219.14:443"))

        // Safe partial publication mode (allowSafePartialPublication = true):
        // Quarantines any flow touching an endpoint in a rejected line and marks coverageIncomplete = true
        val partialAttributor = NatFlowAttributor(
            monotonicClockMs = { 2_000L },
            maxFreshnessMs = 4_500L,
            allowSafePartialPublication = true,
        )
        val mixedForQuarantine = """
            IPv4 Upstream:
              tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
              tcp [82:2d:00:30:5f:2d] 215(215) 999.168.167.17:44056 -> 214(testtun46) 192.0.2.2:44056 -> 142.250.219.14:443 [00:00:00:00:00:00] 1500 227494ms
            IPv4 Downstream:
              tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
        """.trimIndent()
        assertTrue(
            partialAttributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(mixedForQuarantine),
                collectionSessionGeneration = partialAttributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 7L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )
        val partialSnap = partialAttributor.currentSnapshot()
        assertTrue(partialSnap.coverageIncomplete)
        assertEquals(1, partialSnap.rejectedLineCount)
        assertEquals(1, partialSnap.flowsByTuple.size)

        TunTrafficEngine.configureExperimentalBpf(enabled = false, pollIntervalMs = 1_000L)
        TunTrafficEngine.clearAll()
    }

    @Test
    fun `13 v2 and v3 age tokens handle unavailable dash age negative deltas and truly invalid age tokens`() {
        val dumpWithUnavailableAndNegativeAges = """
            Tethering:
              BPF offload:
                IPv4 Upstream:
                  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 -
                  udp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:39398 -> 214(testtun46) 192.0.2.2:39398 -> 34.0.244.44:443 [00:00:00:00:00:00] 1500 -15ms
                IPv4 Downstream:
                  tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 -
                  udp [00:00:00:00:00:00] 214(testtun46) 34.0.244.44:443 -> 215(215) 192.0.2.2:39398 -> 192.168.167.17:39398 [f2:ff:8b:3d:b2:a6] 1500 -3ms
        """.trimIndent()

        val parsed = BpfDumpParser.parse(dumpWithUnavailableAndNegativeAges)
        assertTrue(parsed.recognizedFormat)
        assertFalse("Valid '-' and '-15ms' age tokens must not be rejected", parsed.hasRejections)
        assertEquals(0, parsed.rejectedLines.size)
        assertEquals(2, parsed.ipv4UpstreamEntries.size)
        assertEquals(2, parsed.ipv4DownstreamEntries.size)

        assertTrue(parsed.ipv4UpstreamEntries[0].flowAge is BpfFlowAge.Unavailable)
        assertNull(parsed.ipv4UpstreamEntries[0].rawAgeMs)

        assertEquals(BpfFlowAge.NegativeDelta(-15L), parsed.ipv4UpstreamEntries[1].flowAge)
        assertEquals(-15L, parsed.ipv4UpstreamEntries[1].rawAgeMs)

        val attributor = NatFlowAttributor(monotonicClockMs = { 5_000L }, maxFreshnessMs = 4_500L)
        assertTrue(
            attributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 9L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )
        val snap = attributor.currentSnapshot()
        assertEquals(0, snap.knownAgeEntries)
        assertEquals(2, snap.unavailableAgeEntries)
        assertEquals(2, snap.negativeDeltaAgeEntries)
        assertEquals(2, snap.flowsByTuple.size)
        assertTrue(attributor.lastAttemptDiagnostic().snapshotPublished)

        // Truly invalid age tokens (abc, --, 12xyz, -abc) are still rejected as INVALID_AGE
        val invalidAgeTokens = listOf("abc", "--", "12xyz", "-abc")
        for (badAge in invalidAgeTokens) {
            val badDump = """
                IPv4 Upstream:
                  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 $badAge
            """.trimIndent()
            val badParsed = BpfDumpParser.parse(badDump)
            assertTrue("Expected $badAge to be rejected", badParsed.hasRejections)
            assertEquals(BpfRejectionReason.INVALID_AGE, badParsed.rejectedLines.first().reason)
        }
    }

    @Test
    fun `14 Fase 1 real Galaxy dumpsys tethering bpf interface mapping rows are ignored without INCOMPLETE_FLOW_LINE rejections`() {
        val realGalaxyDumpWithInterfaceMappings = """
            Tethering:
              BPF offload:
                IPv4 Upstream:
                  269 (testtun64) -> 269 (testtun64)
                  270 (270) -> 270 (270)
                  26 (rmnet_data0) -> 26 (rmnet_data0)
                  31 (rmnet_data5) -> 31 (rmnet_data5)
                  tcp [5e:96:66:b7:9d:2e] 270(swlan0) 192.168.50.145:51006 -> 269(testtun64) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
                  udp [5e:96:66:b7:9d:2e] 270(swlan0) 192.168.50.145:39398 -> 269(testtun64) 192.0.2.2:39398 -> 34.0.244.44:443 [00:00:00:00:00:00] 1500 -
                IPv4 Downstream:
                  269 (testtun64) -> 269 (testtun64)
                  270 (270) -> 270 (270)
                  26 (rmnet_data0) -> 26 (rmnet_data0)
                  31 (rmnet_data5) -> 31 (rmnet_data5)
                  tcp [00:00:00:00:00:00] 269(testtun64) 108.158.147.26:443 -> 270(swlan0) 192.0.2.2:51006 -> 192.168.50.145:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
                  udp [00:00:00:00:00:00] 269(testtun64) 34.0.244.44:443 -> 270(swlan0) 192.0.2.2:39398 -> 192.168.50.145:39398 [e2:15:cd:54:e4:9b] 1500 -
        """.trimIndent()

        val parsed = BpfDumpParser.parse(realGalaxyDumpWithInterfaceMappings)
        assertTrue(parsed.recognizedFormat)
        assertFalse("Interface mapping lines must not be rejected as INCOMPLETE_FLOW_LINE", parsed.hasRejections)
        assertEquals(0, parsed.rejectedLines.size)
        assertEquals(2, parsed.ipv4UpstreamEntries.size)
        assertEquals(2, parsed.ipv4DownstreamEntries.size)

        val singleClientMac = "E2:15:CD:54:E4:9B"
        val singleClientBindings = mapOf("192.168.50.145" to singleClientMac)
        val attributor = NatFlowAttributor(monotonicClockMs = { 2_000L }, maxFreshnessMs = 4_500L)
        attributor.syncInterfaces("swlan0", "testtun64")

        val published = attributor.ingestParsedDump(
            parsed = parsed,
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 12L,
            ipToMac = singleClientBindings,
            activeConnectedMacs = setOf(singleClientMac),
        )
        assertTrue("Snapshot must be published when interface mapping lines are present", published)
        assertTrue(attributor.lastAttemptDiagnostic().snapshotPublished)
        assertEquals(0, attributor.lastAttemptDiagnostic().rejectedLineCount)
        assertEquals(2, attributor.currentSnapshot().flowsByTuple.size)
        assertEquals(270, attributor.currentSnapshot().downstreamIfIndex)
        assertEquals(269, attributor.currentSnapshot().upstreamIfIndex)
        assertEquals(Integer.valueOf(270), attributor.currentSnapshot().inferredDownstreamIfIndex)
        assertEquals(Integer.valueOf(269), attributor.currentSnapshot().inferredUpstreamIfIndex)

        // Malformed lines starting with tcp/udp or partial '269 (testtun64) ->' MUST still be rejected
        val malformedPartialDump = """
            IPv4 Upstream:
              269 (testtun64) ->
              tcp 269 (testtun64) -> 269 (testtun64)
              269 (testtun64) -> 269 (testtun64) 192.0.2.2:51006
        """.trimIndent()
        val parsedMalformed = BpfDumpParser.parse(malformedPartialDump)
        assertEquals(3, parsedMalformed.rejectedLines.size)
        assertEquals(BpfRejectionReason.INCOMPLETE_FLOW_LINE, parsedMalformed.rejectedLines[0].reason)
        assertEquals(BpfRejectionReason.INCOMPLETE_FLOW_LINE, parsedMalformed.rejectedLines[1].reason)
        assertEquals(BpfRejectionReason.INCOMPLETE_FLOW_LINE, parsedMalformed.rejectedLines[2].reason)
    }

    @Test
    fun `15 Fase 3 single-client regression covers DIRECT_IP BPF_NAT UNMATCHED_UNKNOWN 1 Mbps shaping and IPv6-only neighbor table`() {
        val clientMac = "E2:15:CD:54:E4:9B"
        val clientIpv4 = "192.168.50.145"
        val clientIpv6 = "2804:38a:a08a:c641:ecc7:78ff:fe6f:a0fb"

        // Case A: Client discovered with IPv6 only in ipToMac (common when IPv4 ARP entry aged out under BPF offload),
        // while BPF downstream flow confirms clientMac via [e2:15:cd:54:e4:9b].
        val hostIpv6OnlyInNeigh = DiscoveredHost(
            mac = clientMac,
            ip = clientIpv6,
            allIps = listOf(clientIpv6),
            interfaceName = "swlan0",
        )
        TunTrafficEngine.clearAll()
        TunTrafficEngine.configureExperimentalBpf(
            enabled = true,
            pollIntervalMs = 1_000L,
            downstreamIface = "swlan0",
            upstreamIface = "testtun64",
        )
        TunTrafficEngine.updatePolicies(emptyMap(), listOf(hostIpv6OnlyInNeigh))

        val galaxySingleClientDump = """
            IPv4 Upstream:
              269 (testtun64) -> 269 (testtun64)
              270 (270) -> 270 (270)
              tcp [5e:96:66:b7:9d:2e] 270(270) $clientIpv4:51006 -> 269(testtun64) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 1200ms
            IPv4 Downstream:
              269 (testtun64) -> 269 (testtun64)
              270 (270) -> 270 (270)
              tcp [00:00:00:00:00:00] 269(testtun64) 108.158.147.26:443 -> 270(270) 192.0.2.2:51006 -> $clientIpv4:51006 [e2:15:cd:54:e4:9b] 1500 1205ms
        """.trimIndent()

        val (verifiedBindings, verifiedMacs) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
        assertTrue(
            TunTrafficEngine.bpfAttributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(galaxySingleClientDump),
                collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 8L,
                ipToMac = verifiedBindings,
                activeConnectedMacs = verifiedMacs,
            ),
        )

        // 1. Direct IPv6 packet -> DIRECT_IP
        val directV6Meta = TunTrafficEngine.PacketMeta(
            version = 6, protocol = 6, srcIp = clientIpv6, dstIp = "2607:f8b0:4005:80a::200e",
            srcPort = 54321, dstPort = 443, length = 1200, isSmallControlPacket = false,
        )
        val directAttr = TunTrafficEngine.resolveClientMacWithSource(directV6Meta, isUpload = true)
        assertEquals(clientMac, directAttr.mac)
        assertEquals(AttributionSource.DIRECT_IP, directAttr.source)
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(directV6Meta, directAttr.mac, isUpload = true, attributionSource = directAttr.source),
        )

        // 2. Post-NAT IPv4 packet on 192.0.2.2:51006 -> BPF_NAT (even when ipToMac only had IPv6 for this client!)
        val bpfUploadMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "108.158.147.26",
            srcPort = 51006, dstPort = 443, length = 1400, isSmallControlPacket = false,
        )
        val bpfDownloadMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "108.158.147.26", dstIp = "192.0.2.2",
            srcPort = 443, dstPort = 51006, length = 1400, isSmallControlPacket = false,
        )
        val bpfUpAttr = TunTrafficEngine.resolveClientMacWithSource(bpfUploadMeta, isUpload = true)
        assertEquals(clientMac, bpfUpAttr.mac)
        assertEquals(AttributionSource.BPF_NAT, bpfUpAttr.source)
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(bpfUploadMeta, bpfUpAttr.mac, isUpload = true, attributionSource = bpfUpAttr.source),
        )

        // 3. Unknown post-NAT flow (port 61234) -> UNMATCHED_UNKNOWN -> ALLOW (never invents MAC even with 1 client)
        val unknownPostNatMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "1.1.1.1",
            srcPort = 61234, dstPort = 443, length = 600, isSmallControlPacket = false,
        )
        val unknownAttr = TunTrafficEngine.resolveClientMacWithSource(unknownPostNatMeta, isUpload = true)
        assertNull("Single-client mode must NOT invent a MAC for an unmapped flow", unknownAttr.mac)
        assertEquals(AttributionSource.UNMATCHED_UNKNOWN, unknownAttr.source)
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(unknownPostNatMeta, unknownAttr.mac, isUpload = true, attributionSource = unknownAttr.source),
        )
        assertEquals(1L, TunTrafficEngine.unmatchedPackets.get())

        // 4. Block single client -> both DIRECT_IP and BPF_NAT drop immediately, while unknown flow still passes safely
        TunTrafficEngine.updatePolicies(
            mapOf(clientMac to TunTrafficEngine.EnforcedClientPolicy(mac = clientMac, isBlocked = true, bandwidthLimitKbps = 0)),
            listOf(hostIpv6OnlyInNeigh),
        )
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShape(directV6Meta, clientMac, isUpload = true, attributionSource = AttributionSource.DIRECT_IP),
        )
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShape(bpfUploadMeta, clientMac, isUpload = true, attributionSource = AttributionSource.BPF_NAT),
        )
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShape(bpfDownloadMeta, clientMac, isUpload = false, attributionSource = AttributionSource.BPF_NAT),
        )
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShape(unknownPostNatMeta, null, isUpload = true, attributionSource = AttributionSource.UNMATCHED_UNKNOWN),
        )

        val blockedSnap = TunTrafficEngine.getCounterSnapshot(clientMac)
        assertEquals(3L, blockedSnap.blockedDropPackets)
        assertEquals(2L, blockedSnap.directAttributedPackets)
        assertEquals(3L, blockedSnap.bpfAttributedPackets)

        // 5. Unblock and apply 1 Mbps (1000 Kbps) shaping -> packets pass burst and then schedule RATE_LIMIT pacing
        TunTrafficEngine.updatePolicies(
            mapOf(clientMac to TunTrafficEngine.EnforcedClientPolicy(mac = clientMac, isBlocked = false, bandwidthLimitKbps = 1000)),
            listOf(hostIpv6OnlyInNeigh),
        )
        var shapedCount = 0
        for (i in 0 until 20) {
            val detail = TunTrafficEngine.evaluateAndShapeDetailed(
                bpfDownloadMeta,
                clientMac,
                isUpload = false,
                attributionSource = AttributionSource.BPF_NAT,
            )
            if (detail.decision == PacketDecision.RATE_LIMIT || detail.decision == PacketDecision.DROP_AQM) {
                shapedCount++
            }
        }
        assertTrue("Expected 1 Mbps shaper to shape burst of 20 x 1400B packets", shapedCount > 0)
        val shapedSnap = TunTrafficEngine.getCounterSnapshot(clientMac)
        assertTrue(shapedSnap.shapedBytes > 0L)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `16 Fase 2 HostFirewall protects shared TUN NAT IPs and skips mutating write probes in rootless mode`() {
        // Shared NAT addresses 192.0.2.2 and 2001:db8::2 must NEVER be accepted as valid per-client target IPs
        val probeMatrix = HostFirewall.probeKernelCapabilities(force = true, allowWriteProbesInRootless = false)
        assertFalse("Rootless probe must not execute mutating write probes by default", probeMatrix.writeProbesExecuted)
        assertFalse(probeMatrix.canWriteBothFamiliesNetfilter)
        assertFalse(probeMatrix.canWriteBothFamiliesIpRule)
        assertEquals(
            FirewallBackend.USERSPACE,
            HostFirewall.currentBackend(userspaceAttached = true, kernelAvailable = false),
        )
        assertTrue(probeMatrix.capabilityNote.contains("rootless mode"))

        val clientMac = "E2:15:CD:54:E4:9B"
        val hostWithBogusSharedNatIp = DiscoveredHost(
            mac = clientMac,
            ip = TunTrafficEngine.TUN_LOCAL_V4,
            allIps = listOf(TunTrafficEngine.TUN_LOCAL_V4, TunTrafficEngine.TUN_LOCAL_V6, "192.168.50.145"),
            interfaceName = "swlan0",
        )
        HostFirewall.enforce(
            rules = listOf(
                ClientRule(
                    mac = clientMac,
                    isBlocked = true,
                    bandwidthLimitKbps = 1000,
                ),
            ),
            connectedHosts = listOf(hostWithBogusSharedNatIp),
            logSummary = false,
        )
        val (boundIps, _) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
        assertFalse("Shared TUN IPv4 192.0.2.2 must never be bound to a single client MAC", boundIps.containsKey(TunTrafficEngine.TUN_LOCAL_V4))
        assertFalse("Shared TUN IPv6 2001:db8::2 must never be bound to a single client MAC", boundIps.containsKey(TunTrafficEngine.TUN_LOCAL_V6))
        assertEquals(clientMac, boundIps["192.168.50.145"])
        HostFirewall.clearAll()
    }

    @Test
    fun `17 v0_10_3_debug classifies all structured UnattributedReason values accurately`() {
        val clock = AtomicLong(1_000L)
        val attributor = NatFlowAttributor(monotonicClockMs = { clock.get() }, maxFreshnessMs = 4_500L)

        // 1. Cold cache before any snapshot -> NO_ACTIVE_SNAPSHOT
        val coldDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.NO_ACTIVE_SNAPSHOT, coldDetail.failureReason)

        // 2. Failed collection when no prior snapshot exists -> SNAPSHOT_INVALID_OR_COLLECTION_FAILED
        attributor.ingestParsedDump(
            parsed = BpfParsedDump(
                recognizedFormat = false,
                ipv4UpstreamEntries = emptyList(),
                ipv4DownstreamEntries = emptyList(),
                ipv6Entries = emptyList(),
                rejectedLines = emptyList(),
            ),
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.COMMAND_FAILED,
            collectionDurationMs = 15L,
            collectionError = "dumpsys failed",
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        val failedSnapDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.SNAPSHOT_INVALID_OR_COLLECTION_FAILED, failedSnapDetail.failureReason)

        // 3. Unsupported protocol (GRE=47), invalid ports (0), and IPv6 on IPv4-only BPF map
        assertEquals(
            UnattributedReason.IPV6_NOT_SUPPORTED_BY_BPF_MAP,
            attributor.resolveTranslatedPacketDetailed(
                6, 6, "2001:db8::2", 51006, "2607:f8b0:4005:80a::200e", 443, true, false, ipBindings, activeMacs,
            ).failureReason,
        )
        assertEquals(
            UnattributedReason.UNSUPPORTED_PROTOCOL,
            attributor.resolveTranslatedPacketDetailed(
                4, 47, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
            ).failureReason,
        )
        assertEquals(
            UnattributedReason.INVALID_OR_MISSING_PORTS,
            attributor.resolveTranslatedPacketDetailed(
                4, 6, "192.0.2.2", 0, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
            ).failureReason,
        )

        // Publish valid snapshot at t = 1_000L
        assertTrue(
            attributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(realDeviceExcerpt),
                collectionSessionGeneration = attributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 9L,
                ipToMac = ipBindings,
                activeConnectedMacs = activeMacs,
            ),
        )

        // 4. Missing tuple in valid snapshot -> TUPLE_NOT_PRESENT
        val missingTupleDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 64999, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.TUPLE_NOT_PRESENT, missingTupleDetail.failureReason)

        // 5. Upload TCP SYN on already-mapped tuple -> TCP_TUPLE_REUSE_AWAITING_REFRESH
        val synReuseDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, true, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.TCP_TUPLE_REUSE_AWAITING_REFRESH, synReuseDetail.failureReason)

        // 6. Disconnected client -> CLIENT_DISCONNECTED
        val disconnectedDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, setOf("F2:FF:8B:3D:B2:A6"),
        )
        assertEquals(UnattributedReason.CLIENT_DISCONNECTED, disconnectedDetail.failureReason)

        // 7. Reassigned client IP -> CLIENT_IP_REASSIGNED
        val reassignedBindings = mapOf(
            "192.168.167.151" to "AA:BB:CC:DD:EE:FF",
            "192.168.167.17" to "F2:FF:8B:3D:B2:A6",
        )
        val reassignedDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, reassignedBindings, activeMacs + "AA:BB:CC:DD:EE:FF",
        )
        assertEquals(UnattributedReason.CLIENT_IP_REASSIGNED, reassignedDetail.failureReason)

        // 8. Stale snapshot -> SNAPSHOT_STALE
        clock.set(7_000L)
        val staleDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.SNAPSHOT_STALE, staleDetail.failureReason)

        // 9. Ambiguous tuple -> TUPLE_AMBIGUOUS
        clock.set(8_000L)
        val ambiguousRaw = """
            IPv4 Upstream:
              269 (testtun46) -> 269 (testtun46)
              270 (ap0) -> 270 (ap0)
              tcp [b6:f6:6c:df:e6:02] 270(ap0) 192.168.167.151:60000 -> 269(testtun46) 192.0.2.2:60000 -> 93.184.216.34:443 [00:00:00:00:00:00] 1500 50ms
              tcp [b6:f6:6c:df:e6:02] 270(ap0) 192.168.167.17:60000 -> 269(testtun46) 192.0.2.2:60000 -> 93.184.216.34:443 [00:00:00:00:00:00] 1500 50ms
            IPv4 Downstream:
              269 (testtun46) -> 269 (testtun46)
              270 (ap0) -> 270 (ap0)
              tcp [00:00:00:00:00:00] 269(testtun46) 93.184.216.34:443 -> 270(ap0) 192.0.2.2:60000 -> 192.168.167.151:60000 [e2:15:cd:54:e4:9b] 1500 55ms
              tcp [00:00:00:00:00:00] 269(testtun46) 93.184.216.34:443 -> 270(ap0) 192.0.2.2:60000 -> 192.168.167.17:60000 [f2:ff:8b:3d:b2:a6] 1500 55ms
        """.trimIndent()
        attributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(ambiguousRaw),
            collectionSessionGeneration = attributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 8L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )
        val ambigDetail = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 60000, "93.184.216.34", 443, true, false, ipBindings, activeMacs,
        )
        assertEquals(UnattributedReason.TUPLE_AMBIGUOUS, ambigDetail.failureReason)

        // 10. Non-initial fragment in TunTrafficEngine -> NON_INITIAL_FRAGMENT
        TunTrafficEngine.clearAll()
        val fragMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "108.158.147.26",
            srcPort = 0, dstPort = 0, length = 800, isSmallControlPacket = false,
            isNonInitialFragment = true,
        )
        val fragAttr = TunTrafficEngine.resolveClientMacWithSource(fragMeta, isUpload = true)
        assertEquals(AttributionSource.UNMATCHED_UNSUPPORTED_OR_FRAGMENT, fragAttr.source)
        assertEquals(UnattributedReason.NON_INITIAL_FRAGMENT, fragAttr.unattributedReason)
        TunTrafficEngine.clearAll()
    }

    @Test
    fun `18 v0_10_3_debug packet and byte denominators reconcile and reset preserves policies and quotas`() {
        val clientMac = "E2:15:CD:54:E4:9B"
        val clientIp = "192.168.167.151"
        val host = DiscoveredHost(
            mac = clientMac,
            ip = clientIp,
            allIps = listOf(clientIp),
            interfaceName = "ap0",
        )
        TunTrafficEngine.clearAll()
        TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L, downstreamIface = "ap0", upstreamIface = "testtun46")

        // Verify zero-denominator safety before any packets arrive
        val initialReport = TunTrafficEngine.getBpfAttributionReport()
        assertEquals(0L, initialReport.totalEligiblePackets)
        assertEquals(0L, initialReport.totalEligibleBytes)
        assertEquals("N/A", initialReport.formattedPacketCoverage())
        assertEquals("N/A", initialReport.formattedByteCoverage())

        // Install a blocked + quota rule for clientMac
        val quotaRules = listOf(
            ClientRule(
                mac = clientMac,
                isBlocked = true,
                bandwidthLimitKbps = 1000,
                dataLimitBytes = 500L * DataQuota.BYTES_PER_MB,
                quotaResetPeriod = QuotaResetPeriod.DAILY,
                quotaUsedRxBytes = 100L * DataQuota.BYTES_PER_MB,
                quotaUsedTxBytes = 50L * DataQuota.BYTES_PER_MB,
            ),
        )
        TunTrafficEngine.syncQuotaRules(quotaRules)
        TunTrafficEngine.updatePolicies(
            mapOf(
                clientMac to TunTrafficEngine.EnforcedClientPolicy(
                    mac = clientMac,
                    isBlocked = true,
                    bandwidthLimitKbps = 1000,
                    dataLimitBytes = 500L * DataQuota.BYTES_PER_MB,
                    quotaResetPeriod = QuotaResetPeriod.DAILY,
                ),
            ),
            listOf(host),
        )
        TunTrafficEngine.bpfAttributor.ingestParsedDump(
            parsed = BpfDumpParser.parse(realDeviceExcerpt),
            collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
            collectionStatus = BpfCollectionStatus.OK,
            collectionDurationMs = 7L,
            ipToMac = ipBindings,
            activeConnectedMacs = activeMacs,
        )

        // 1. Link-local multicast packet (excluded from eligible denominator, counted in localControl)
        val localCtrlMeta = TunTrafficEngine.PacketMeta(
            version = 6, protocol = 58, srcIp = "fe80::1", dstIp = "ff02::2",
            srcPort = 0, dstPort = 0, length = 72, isSmallControlPacket = true,
        )
        val localAttr = TunTrafficEngine.resolveClientMacWithSource(localCtrlMeta, isUpload = true)
        assertEquals(AttributionSource.UNMATCHED_UNKNOWN, localAttr.source)
        localCtrlMeta.resolvedAttribution = localAttr
        TunTrafficEngine.evaluateAndShapeDetailed(localCtrlMeta, localAttr.mac, isUpload = true, attributionSource = localAttr.source)

        // 2. Direct IP packet (1000 bytes)
        val directMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = clientIp, dstIp = "1.1.1.1",
            srcPort = 55000, dstPort = 443, length = 1000, isSmallControlPacket = false,
        )
        val directAttr = TunTrafficEngine.resolveClientMacWithSource(directMeta, isUpload = true)
        assertEquals(AttributionSource.DIRECT_IP, directAttr.source)
        directMeta.resolvedAttribution = directAttr
        TunTrafficEngine.evaluateAndShapeDetailed(directMeta, directAttr.mac, isUpload = true, attributionSource = directAttr.source)

        // 3. BPF NAT attributed packet (1400 bytes)
        val bpfMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "108.158.147.26",
            srcPort = 51006, dstPort = 443, length = 1400, isSmallControlPacket = false,
        )
        val bpfAttr = TunTrafficEngine.resolveClientMacWithSource(bpfMeta, isUpload = true)
        assertEquals(AttributionSource.BPF_NAT, bpfAttr.source)
        bpfMeta.resolvedAttribution = bpfAttr
        TunTrafficEngine.evaluateAndShapeDetailed(bpfMeta, bpfAttr.mac, isUpload = true, attributionSource = bpfAttr.source)

        // 4. Unattributed post-NAT packet (600 bytes, TUPLE_NOT_PRESENT) -> MUST still return PacketDecision.ALLOW
        val unknownMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 17, srcIp = "192.0.2.2", dstIp = "8.8.8.8",
            srcPort = 63111, dstPort = 53, length = 600, isSmallControlPacket = false,
        )
        val unknownAttr = TunTrafficEngine.resolveClientMacWithSource(unknownMeta, isUpload = true)
        assertNull(unknownAttr.mac)
        assertEquals(AttributionSource.UNMATCHED_UNKNOWN, unknownAttr.source)
        assertEquals(UnattributedReason.TUPLE_NOT_PRESENT, unknownAttr.unattributedReason)
        unknownMeta.resolvedAttribution = unknownAttr
        val unknownEval = TunTrafficEngine.evaluateAndShapeDetailed(unknownMeta, unknownAttr.mac, isUpload = true, attributionSource = unknownAttr.source)
        assertEquals(PacketDecision.ALLOW, unknownEval.decision)

        val rep = TunTrafficEngine.getBpfAttributionReport()
        // Denominator reconciliation
        assertEquals(1L, rep.localControlPackets)
        assertEquals(72L, rep.localControlBytes)
        assertEquals(3L, rep.totalEligiblePackets)
        assertEquals(3000L, rep.totalEligibleBytes)
        assertEquals(2L, rep.totalAttributedPackets)
        assertEquals(2400L, rep.totalAttributedBytes)
        assertEquals(1L, rep.directAttributedPackets)
        assertEquals(1000L, rep.directAttributedBytes)
        assertEquals(1L, rep.bpfAttributedPackets)
        assertEquals(1400L, rep.bpfAttributedBytes)
        assertEquals(0L, rep.conntrackAttributedPackets)
        assertEquals(1L, rep.unknownForwardedPackets)
        assertEquals(600L, rep.unknownForwardedBytes)
        assertEquals(1L, rep.unattributedPacketsByReason[UnattributedReason.TUPLE_NOT_PRESENT.name])
        assertEquals(600L, rep.unattributedBytesByReason[UnattributedReason.TUPLE_NOT_PRESENT.name])
        assertEquals("80.00%", rep.formattedByteCoverage())

        // Reset diagnostic counters -> zeroes counters while preserving blocked policy and quota record
        TunTrafficEngine.resetAttributionDiagnosticsCounters()
        val afterReset = TunTrafficEngine.getBpfAttributionReport()
        assertEquals(0L, afterReset.totalEligiblePackets)
        assertEquals(0L, afterReset.totalEligibleBytes)
        assertEquals(0L, afterReset.totalAttributedPackets)
        assertEquals(0L, afterReset.unknownForwardedPackets)
        assertEquals("N/A", afterReset.formattedPacketCoverage())
        assertEquals(1, afterReset.blockedClientsCount)

        // Blocked policy is still enforced immediately after counter reset
        bpfMeta.resolvedAttribution = bpfAttr
        val postResetEval = TunTrafficEngine.evaluateAndShapeDetailed(bpfMeta, bpfAttr.mac, isUpload = true, attributionSource = bpfAttr.source)
        assertEquals(PacketDecision.DROP, postResetEval.decision)
        val quotaSnap = TunTrafficEngine.getCounterSnapshot(clientMac)
        assertEquals(100L * DataQuota.BYTES_PER_MB, quotaSnap.quotaUsedRxBytes)
        assertEquals(50L * DataQuota.BYTES_PER_MB, quotaSnap.quotaUsedTxBytes)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `19 v0_10_3_debug Phase B async refresh-on-miss coalesces respects cooldown attributes subsequent packet and auto-disables on repeated failures`() {
        val clock = AtomicLong(10_000L)
        val attributor = NatFlowAttributor(monotonicClockMs = { clock.get() }, maxFreshnessMs = 4_500L)
        val readerCalls = AtomicLong(0L)
        var shouldFailCollection = false

        val mapReader = BpfMapReader(
            attributor = attributor,
            commandRunner = { _, _ ->
                readerCalls.incrementAndGet()
                if (shouldFailCollection) {
                    BpfRawCollectionResult(
                        status = BpfCollectionStatus.COMMAND_FAILED,
                        exitCode = 1,
                        durationMs = 5L,
                        stdout = "",
                        stderr = "Simulated failure",
                        timedOut = false,
                        wasTruncated = false,
                        errorSummary = "Simulated failure",
                    )
                } else {
                    BpfRawCollectionResult(
                        status = BpfCollectionStatus.OK,
                        exitCode = 0,
                        durationMs = 6L,
                        stdout = realDeviceExcerpt,
                        stderr = "",
                        timedOut = false,
                        wasTruncated = false,
                    )
                }
            },
            clientBindingsProvider = { ipBindings to activeMacs },
            monotonicClockMs = { clock.get() },
        )
        mapReader.synchronousRefreshOnMissForTesting = true
        mapReader.refreshOnMissCooldownMs = 500L
        mapReader.maxConsecutiveFailuresForAutoDisable = 3

        // Initially snapshot is empty -> miss on 192.0.2.2:51006 triggers refresh #1 at t = 10_000L
        assertTrue(mapReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT))
        assertEquals(1L, mapReader.refreshOnMissTriggeredCount.get())
        assertEquals(1L, mapReader.refreshOnMissCompletedCount.get())
        assertEquals(10_000L, mapReader.lastRefreshOnMissPublishedSnapshotMonoMs.get())

        // Subsequent miss within 500ms cooldown (t = 10_200L) is suppressed by cooldown
        clock.set(10_200L)
        assertFalse(mapReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT))
        assertEquals(1L, mapReader.refreshOnMissSuppressedCooldownCount.get())

        // Subsequent packet on 192.0.2.2:51006 now matches the refreshed snapshot
        val resolvedAfterRefresh = attributor.resolveTranslatedPacketDetailed(
            4, 6, "192.0.2.2", 51006, "108.158.147.26", 443, true, false, ipBindings, activeMacs,
        )
        assertTrue(resolvedAfterRefresh.outcome is AttributionOutcome.Matched)

        // Simulate 3 consecutive collection failures -> circuit breaker transitions CLOSED -> OPEN
        shouldFailCollection = true
        for (i in 1..3) {
            clock.addAndGet(35_000L)
            mapReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT)
        }
        assertTrue("Expected circuit breaker to open after 3 consecutive failures", mapReader.refreshOnMissAutoDisabled)
        assertEquals(RefreshCircuitBreakerState.OPEN, mapReader.circuitBreakerState)
        assertEquals(3L, mapReader.missRefreshFailedCount.get())

        // Within 30_000ms breaker cooldown (e.g., +15_000ms), new triggers are suppressed by breaker
        clock.addAndGet(15_000L)
        assertFalse("OPEN circuit breaker must reject triggers within 30s cooldown", mapReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT))
        assertEquals(1L, mapReader.missRefreshSuppressedBreakerCount.get())

        // After 30_000ms breaker cooldown (+20_000ms -> +35_000ms total), breaker transitions OPEN -> HALF_OPEN for a single probe.
        // If that probe succeeds, breaker transitions HALF_OPEN -> CLOSED!
        shouldFailCollection = false
        clock.addAndGet(20_000L)
        assertTrue("HALF_OPEN probe after 30s cooldown should execute and recover to CLOSED", mapReader.requestAsyncRefreshOnMiss(UnattributedReason.TUPLE_NOT_PRESENT))
        assertEquals(RefreshCircuitBreakerState.CLOSED, mapReader.circuitBreakerState)
        assertFalse(mapReader.refreshOnMissAutoDisabled)

        val lat = mapReader.getRefreshLatencyPercentiles()
        assertTrue(lat.sampleCount >= 2)
        assertTrue(lat.maxMs >= lat.p50Ms)
    }

    @Test
    fun `20 v0_10_3_debug diagnostic report redacts PII by default and supports salted SHA-256 pseudonymous IDs`() {
        val report = BpfAttributionStatusReport(
            experimentalEnabled = true,
            state = ExperimentalBpfState.MAPPINGS_AVAILABLE,
            collectionStatus = BpfCollectionStatus.OK,
            snapshotHealth = BpfSnapshotHealth.OK,
            totalEligiblePackets = 100L,
            totalEligibleBytes = 120_000L,
            totalAttributedPackets = 95L,
            totalAttributedBytes = 114_000L,
            directAttributedPackets = 20L,
            directAttributedBytes = 24_000L,
            bpfAttributedPackets = 75L,
            bpfAttributedBytes = 90_000L,
            unknownForwardedPackets = 5L,
            unknownForwardedBytes = 6_000L,
            unattributedPacketsByReason = mapOf(UnattributedReason.TUPLE_NOT_PRESENT.name to 5L),
            unattributedBytesByReason = mapOf(UnattributedReason.TUPLE_NOT_PRESENT.name to 6_000L),
            perClientCounts = listOf(
                ClientProtocolFlowCounts(
                    mac = "E2:15:CD:54:E4:9B",
                    originalIpv4 = "192.168.167.151",
                    tcpFlows = 4,
                    udpFlows = 2,
                ),
            ),
            lastAttemptRejectedLineCount = 1,
            lastAttemptRejectedLines = listOf(
                BpfRejectedLine(
                    lineNumber = 12,
                    section = "IPv4 Upstream",
                    reason = BpfRejectionReason.INVALID_IP,
                    linePreview = "tcp [e2:15:cd:54:e4:9b] 270(ap0) 192.168.167.151:51006 -> 269(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443",
                ),
            ),
        )

        // Default export (redacted)
        val defaultMd = report.toMarkdownReport(
            apkVersion = "0.10.4-debug",
            sourceCommit = "test-commit",
            serviceBuildId = 19,
            includeSensitiveEndpoints = false,
            includePseudonymousIds = false,
        )
        val defaultJson = report.toJson(
            includeSensitiveEndpoints = false,
            includePseudonymousIds = false,
        ).toString()

        assertFalse("Default Markdown report must not contain raw MAC/IP PII", DiagnosticRedactor.containsUnredactedPii(defaultMd))
        assertFalse("Default JSON report must not contain raw MAC/IP PII", DiagnosticRedactor.containsUnredactedPii(defaultJson))
        assertFalse(defaultMd.contains("E2:15:CD:54:E4:9B", ignoreCase = true))
        assertFalse(defaultMd.contains("192.168.167.151"))

        // Opt-in pseudonymous export (salted SHA-256 hashes Client#xxxxxx / IP#xxxxxx)
        val pseudoMd = report.toMarkdownReport(
            apkVersion = "0.10.4-debug",
            sourceCommit = "test-commit",
            serviceBuildId = 19,
            includeSensitiveEndpoints = false,
            includePseudonymousIds = true,
        )
        val pseudoJson = report.toJson(
            includeSensitiveEndpoints = false,
            includePseudonymousIds = true,
        ).toString()

        assertTrue(pseudoMd.contains("Client#"))
        assertTrue(pseudoMd.contains("IP#"))
        assertFalse("Pseudonymous Markdown report must not contain raw MAC/IP PII", DiagnosticRedactor.containsUnredactedPii(pseudoMd))
        assertFalse("Pseudonymous JSON report must not contain raw MAC/IP PII", DiagnosticRedactor.containsUnredactedPii(pseudoJson))
    }

    @Test
    fun `21 v0_10_8_debug build identity and file paths isolate debug APK from production baseline`() {
        assertEquals("dev.shizzyluna.proxy.debug", BuildConfig.APPLICATION_ID)
        assertEquals("0.10.8-debug", BuildConfig.VERSION_NAME)
        assertEquals(23, BuildConfig.VERSION_CODE)
        assertEquals(23, BuildConfig.SERVICE_BUILD_ID)
        assertTrue(BuildConfig.DEBUG_DIAGNOSTICS_ENABLED)
        assertFalse("applicationId must not have duplicate .debug.debug suffix", BuildConfig.APPLICATION_ID.endsWith(".debug.debug"))
        assertEquals("/data/local/tmp/shizzyluna-debug-quota-state.json", DataQuota.DEFAULT_CHECKPOINT_FILE_PATH)
        assertEquals("/data/local/tmp/shizzi-debug-probe-report.json", TetherService.REPORT_PATH)
        assertEquals("/data/local/tmp/shizzi-debug-firewall-diagnostic.json", TetherService.FIREWALL_DIAG_REPORT_PATH)
        assertEquals("/data/local/tmp/shizzyluna-debug-softap-journal.json", SoftApOwnershipJournal.DEFAULT_JOURNAL_PATH)
    }

    private fun buildIpv4TcpPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        syn: Boolean = false,
        ack: Boolean = true,
        payloadBytes: Int = 64,
    ): ByteArray {
        val totalLen = 20 + 20 + payloadBytes
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45.toByte() // IPv4, IHL = 5 (20 bytes)
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64.toByte() // TTL
        pkt[9] = 6.toByte() // TCP
        val srcIpBytes = CanonicalFlowTuple.ipv4ToNetworkOrderBytes(srcIp)
        val dstIpBytes = CanonicalFlowTuple.ipv4ToNetworkOrderBytes(dstIp)
        System.arraycopy(srcIpBytes, 0, pkt, 12, 4)
        System.arraycopy(dstIpBytes, 0, pkt, 16, 4)
        // TCP header at offset 20
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[32] = 0x50.toByte() // Data offset = 5 (20 bytes)
        var flags = 0
        if (syn) flags = flags or 0x02
        if (ack) flags = flags or 0x10
        pkt[33] = flags.toByte()
        return pkt
    }

    @Test
    fun `22 v0_10_4_debug CanonicalFlowTuple network-order IPv4 packet bytes match BpfDumpParser upstream entry`() {
        val parsed = BpfDumpParser.parse(realDeviceExcerpt)
        val bpfEntry = parsed.ipv4UpstreamEntries.first { it.translatedPort == 51006 }

        val fromBpf = CanonicalFlowTuple.fromBpfUpstreamEntry(bpfEntry)
        val rawUploadPacket = buildIpv4TcpPacket(
            srcIp = "192.0.2.2",
            dstIp = "108.158.147.26",
            srcPort = 51006,
            dstPort = 443,
            syn = false,
            ack = true,
            payloadBytes = 64,
        )
        val fromPacketUpload = CanonicalFlowTuple.fromRawIpv4Packet(rawUploadPacket, rawUploadPacket.size, isUpload = true)
        assertNotNull(fromPacketUpload)

        // Both must produce identical 14-byte network-order representation and identical TranslatedFlowKey
        assertTrue(fromBpf.toNetworkByteOrderBytes().contentEquals(fromPacketUpload!!.toNetworkByteOrderBytes()))
        assertEquals(fromBpf.toTranslatedFlowKey(), fromPacketUpload.toTranslatedFlowKey())

        // Download reply packet (108.158.147.26:443 -> 192.0.2.2:51006) must also normalize to the exact same TranslatedFlowKey
        val rawDownloadPacket = buildIpv4TcpPacket(
            srcIp = "108.158.147.26",
            dstIp = "192.0.2.2",
            srcPort = 443,
            dstPort = 51006,
            syn = false,
            ack = true,
            payloadBytes = 120,
        )
        val fromPacketDownload = CanonicalFlowTuple.fromRawIpv4Packet(rawDownloadPacket, rawDownloadPacket.size, isUpload = false)
        assertNotNull(fromPacketDownload)
        assertEquals(fromBpf.toTranslatedFlowKey(), fromPacketDownload!!.toTranslatedFlowKey())
    }

    @Test
    fun `23 v0_10_4_debug DeepTupleDiagnosticsTracker state machine transitions LRU eviction TTL expiration and generation invalidation`() {
        val clock = java.util.concurrent.atomic.AtomicLong(100_000L)
        val tracker = DeepTupleDiagnosticsTracker(
            monotonicClockMs = { clock.get() },
            maxTrackedFlows = 4,
            maxSampleRecords = 16,
            flowTtlMs = 60_000L,
        )

        val emptySnap = NatFlowSnapshot(
            snapshotSequence = 0L,
            sessionGeneration = 1L,
            bindingGeneration = 1L,
            collectedAtMonotonicMs = clock.get(),
            publishedAtEpochMs = clock.get(),
            upstreamIface = "testtun46",
            downstreamIface = "ap0",
        )

        val quicTuple = CanonicalFlowTuple(
            networkSessionGeneration = 1L,
            bindingGeneration = 1L,
            ipFamily = 4,
            transportProtocol = 17,
            direction = "UPLOAD",
            srcIp = "192.0.2.2",
            srcPortOrIcmpId = 55111,
            dstIp = "142.250.190.46",
            dstPortOrIcmpId = 443,
            preNatOrPostNatRole = PreNatOrPostNatRole.POST_NAT_UPSTREAM,
        )

        // 1. First miss -> NEW_MISS, UDP/443 QUIC counter incremented
        val state1 = tracker.onPacketMiss(
            tuple = quicTuple,
            packetBytes = 1200,
            missReason = UnattributedReason.TUPLE_NOT_PRESENT,
            snapshot = emptySnap,
            directionConfidence = DirectionConfidence.KNOWN,
            tupleRoleOrigin = TupleRoleOrigin.TUN_PACKET_POST_NAT,
        )
        assertEquals(FlowMissState.NEW_MISS, state1)

        // 2. Second miss before any snapshot -> REPEATED_MISS
        clock.addAndGet(50L)
        val state2 = tracker.onPacketMiss(
            tuple = quicTuple,
            packetBytes = 1200,
            missReason = UnattributedReason.TUPLE_NOT_PRESENT,
            snapshot = emptySnap,
            directionConfidence = DirectionConfidence.KNOWN,
            tupleRoleOrigin = TupleRoleOrigin.TUN_PACKET_POST_NAT,
        )
        assertEquals(FlowMissState.REPEATED_MISS, state2)

        // 3. Snapshot #1 published without this flow -> PERSISTENT_AFTER_REFRESH
        clock.addAndGet(600L)
        val snap1 = emptySnap.copy(
            snapshotSequence = 1L,
            collectedAtMonotonicMs = clock.get(),
            publishedAtEpochMs = clock.get(),
        )
        tracker.onSnapshotPublished(snap1)
        var snapDiag = tracker.snapshot()
        assertEquals(1L, snapDiag.persistentAfterRefreshFlowsCount)
        assertEquals(1, snapDiag.survived1SnapshotCount)

        // 4. Snapshots #2 and #3 published after >= 2,000ms total age without this flow -> NOT_OFFLOADED_OR_NOT_OBSERVABLE
        clock.addAndGet(800L)
        tracker.onSnapshotPublished(snap1.copy(snapshotSequence = 2L, collectedAtMonotonicMs = clock.get()))
        clock.addAndGet(1_000L)
        tracker.onSnapshotPublished(snap1.copy(snapshotSequence = 3L, collectedAtMonotonicMs = clock.get()))
        snapDiag = tracker.snapshot()
        assertEquals(1L, snapDiag.notOffloadedOrNotObservableFlowsCount)
        assertEquals(1, snapDiag.survived3PlusSnapshotsCount)
        assertEquals(2L, snapDiag.udp443MissingPacketsCount)

        // 5. Key mismatch suspicion: add a flow where the BPF snapshot has the reversed direction key
        val reversedTuple = CanonicalFlowTuple(
            networkSessionGeneration = 1L,
            bindingGeneration = 1L,
            ipFamily = 4,
            transportProtocol = 6,
            direction = "UPLOAD",
            srcIp = "108.158.147.26",
            srcPortOrIcmpId = 443,
            dstIp = "192.0.2.2",
            dstPortOrIcmpId = 51006,
            preNatOrPostNatRole = PreNatOrPostNatRole.POST_NAT_UPSTREAM,
        )
        tracker.onPacketMiss(reversedTuple, 60, UnattributedReason.TUPLE_NOT_PRESENT, snap1)
        val realFlowKey = TranslatedFlowKey(4, 6, "192.0.2.2", 51006, "108.158.147.26", 443)
        val snapWithRealFlow = snap1.copy(
            snapshotSequence = 4L,
            collectedAtMonotonicMs = clock.addAndGet(200L),
            flowsByTuple = mapOf(
                realFlowKey to NatFlowMapping(
                    sessionGeneration = 1L,
                    bindingGeneration = 1L,
                    downstreamIfIndex = 270,
                    downstreamIfaceLabel = "ap0",
                    upstreamIfIndex = 269,
                    upstreamIfaceLabel = "testtun46",
                    family = 4,
                    protocol = 6,
                    origClientIp = "192.168.167.151",
                    origClientPort = 51006,
                    translatedIp = "192.0.2.2",
                    translatedPort = 51006,
                    remoteIp = "108.158.147.26",
                    remotePort = 443,
                    verifiedMac = "E2:15:CD:54:E4:9B",
                    reverseMapConfirmed = true,
                    boundInIpToMacAtIngest = true,
                    collectedAtMonotonicMs = clock.get(),
                    rawDumpAgeMs = 10L,
                ),
            ),
        )
        tracker.onSnapshotPublished(snapWithRealFlow)
        assertEquals(1L, tracker.snapshot().keyMismatchSuspectedFlowsCount)

        // 6. Resolved after refresh: miss on a new TCP flow, then snapshot includes it, then subsequent packet attributed
        val tcpMissTuple = CanonicalFlowTuple(
            networkSessionGeneration = 1L,
            bindingGeneration = 1L,
            ipFamily = 4,
            transportProtocol = 6,
            direction = "UPLOAD",
            srcIp = "192.0.2.2",
            srcPortOrIcmpId = 61000,
            dstIp = "1.1.1.1",
            dstPortOrIcmpId = 443,
            preNatOrPostNatRole = PreNatOrPostNatRole.POST_NAT_UPSTREAM,
        )
        tracker.onPacketMiss(tcpMissTuple, 64, UnattributedReason.TUPLE_NOT_PRESENT, snapWithRealFlow)
        val resolvedKey = tcpMissTuple.toTranslatedFlowKey()
        val snap5 = snapWithRealFlow.copy(
            snapshotSequence = 5L,
            collectedAtMonotonicMs = clock.addAndGet(200L),
            flowsByTuple = snapWithRealFlow.flowsByTuple + (
                resolvedKey to NatFlowMapping(
                    sessionGeneration = 1L,
                    bindingGeneration = 1L,
                    downstreamIfIndex = 270,
                    downstreamIfaceLabel = "ap0",
                    upstreamIfIndex = 269,
                    upstreamIfaceLabel = "testtun46",
                    family = 4,
                    protocol = 6,
                    origClientIp = "192.168.167.151",
                    origClientPort = 61000,
                    translatedIp = "192.0.2.2",
                    translatedPort = 61000,
                    remoteIp = "1.1.1.1",
                    remotePort = 443,
                    verifiedMac = "E2:15:CD:54:E4:9B",
                    reverseMapConfirmed = true,
                    boundInIpToMacAtIngest = true,
                    collectedAtMonotonicMs = clock.get(),
                    rawDumpAgeMs = 10L,
                )
            ),
        )
        tracker.onSnapshotPublished(snap5)
        assertEquals(1L, tracker.snapshot().postRefreshFlowKeysResolved)
        assertTrue(tracker.onPacketAttributedByBpf(resolvedKey, 500, snap5))
        val snapAfterAttr = tracker.snapshot()
        assertEquals(1L, snapAfterAttr.postRefreshFirstSubsequentAttributedPackets)
        assertEquals(500L, snapAfterAttr.postRefreshFirstSubsequentAttributedBytes)

        // 7. Generation bump invalidates tracked flows
        tracker.onGenerationChanged(sessionGeneration = 2L, bindingGeneration = 1L)
        assertEquals(0, tracker.snapshot().activeTrackedFlowsCount)
    }

    @Test
    fun `24 v0_10_4_debug conntrack procfs permission-denied backoff skips repeated procfs reads for 300s`() {
        val conntrackClock = java.util.concurrent.atomic.AtomicLong(50_000L)
        TunTrafficEngine.conntrackClockMillisProvider = { conntrackClock.get() }
        try {
            TunTrafficEngine.clearAll()
            val host = DiscoveredHost(
                mac = "E2:15:CD:54:E4:9B",
                ip = "192.168.167.151",
                allIps = listOf("192.168.167.151"),
                interfaceName = "ap0",
            )
            TunTrafficEngine.updatePolicies(emptyMap(), listOf(host))
            TunTrafficEngine.configureExperimentalBpf(
                enabled = true,
                pollIntervalMs = 1000L,
                downstreamIface = "ap0",
                upstreamIface = "testtun46",
            )

            // First unknown post-NAT packet triggers inspectConntrackPaths(), which sets 300_000ms backoff when procfs is unreadable/empty
            val meta1 = TunTrafficEngine.PacketMeta(
                version = 4,
                protocol = 6,
                srcIp = "192.0.2.2",
                dstIp = "198.51.100.99",
                srcPort = 62001,
                dstPort = 443,
                length = 120,
                isSmallControlPacket = false,
            )
            val attr1 = TunTrafficEngine.resolveClientMacWithSource(meta1, isUpload = true)
            assertNull(attr1.mac)
            assertTrue("Expected conntrack backoff to be active after unreadable procfs check", TunTrafficEngine.getBpfAttributionReport().conntrackBackoffActive)

            // Advance clock by 10s (still within 300s backoff) and send 5 more unknown packets -> skipped by conntrack backoff
            for (i in 1..5) {
                conntrackClock.addAndGet(2_000L)
                val m = meta1.copy(srcPort = 62001 + i)
                TunTrafficEngine.resolveClientMacWithSource(m, isUpload = true)
            }
            val report = TunTrafficEngine.getBpfAttributionReport()
            assertTrue("Expected conntrackBackoffActive=true during 300s window", report.conntrackBackoffActive)
            assertEquals(5L, report.conntrackBackoffSkippedCount)
        } finally {
            TunTrafficEngine.conntrackClockMillisProvider = { System.currentTimeMillis() }
            TunTrafficEngine.clearAll()
        }
    }

    @Test
    fun `25 v0_10_4_debug multi-client safety keeps UNKNOWN_OWNER as ALLOW while enforcing blocked client and separating verified summary`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B" // Blocked client
        val macB = "F2:FF:8B:3D:B2:A6" // Allowed client (matches realDeviceExcerpt flow 44056)
        val hosts = listOf(
            DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "ap0"),
            DiscoveredHost(mac = macB, ip = "192.168.167.17", allIps = listOf("192.168.167.17"), interfaceName = "ap0"),
        )
        TunTrafficEngine.updatePolicies(
            mapOf(
                macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true),
                macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
            ),
            hosts,
        )
        TunTrafficEngine.configureExperimentalBpf(
            enabled = true,
            pollIntervalMs = 1000L,
            downstreamIface = "ap0",
            upstreamIface = "testtun46",
        )
        TunTrafficEngine.configureDeepTupleDiagnostics(enabled = true)
        val (verifiedBindings, verifiedMacs) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
        assertTrue(
            TunTrafficEngine.bpfAttributor.ingestParsedDump(
                parsed = BpfDumpParser.parse(realDeviceExcerpt),
                collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 5L,
                ipToMac = verifiedBindings,
                activeConnectedMacs = verifiedMacs,
            ),
        )

        // 1. Blocked Client A mapped flow (51006 -> 108.158.147.26:443) -> DROPPED
        val metaA = TunTrafficEngine.PacketMeta(
            version = 4,
            protocol = 6,
            srcIp = "192.0.2.2",
            dstIp = "108.158.147.26",
            srcPort = 51006,
            dstPort = 443,
            length = 120,
            isSmallControlPacket = false,
        )
        val attrA = TunTrafficEngine.resolveClientMacWithSource(metaA, isUpload = true)
        assertEquals(macA, attrA.mac)
        assertEquals(PacketDecision.DROP, TunTrafficEngine.evaluateAndShape(metaA, attrA.mac, isUpload = true, attributionSource = attrA.source))

        // 2. Allowed Client B mapped flow (44056 -> 142.250.219.14:443) -> ALLOWED and counted in Client B's verified summary
        val metaB = TunTrafficEngine.PacketMeta(
            version = 4,
            protocol = 6,
            srcIp = "192.0.2.2",
            dstIp = "142.250.219.14",
            srcPort = 44056,
            dstPort = 443,
            length = 240,
            isSmallControlPacket = false,
        )
        val attrB = TunTrafficEngine.resolveClientMacWithSource(metaB, isUpload = true)
        assertEquals(macB, attrB.mac)
        assertEquals(PacketDecision.ALLOW, TunTrafficEngine.evaluateAndShape(metaB, attrB.mac, isUpload = true, attributionSource = attrB.source))

        // 3. Unmapped post-NAT packet (port 59999) -> UNKNOWN_OWNER -> MUST remain ALLOW (never attributed to Blocked Client A)
        val metaUnknown = TunTrafficEngine.PacketMeta(
            version = 4,
            protocol = 6,
            srcIp = "192.0.2.2",
            dstIp = "93.184.216.34",
            srcPort = 59999,
            dstPort = 443,
            length = 300,
            isSmallControlPacket = false,
        )
        val attrUnknown = TunTrafficEngine.resolveClientMacWithSource(metaUnknown, isUpload = true)
        assertNull(attrUnknown.mac)
        assertEquals(PacketDecision.ALLOW, TunTrafficEngine.evaluateAndShape(metaUnknown, attrUnknown.mac, isUpload = true, attributionSource = attrUnknown.source))

        val report = TunTrafficEngine.getBpfAttributionReport()
        assertEquals("ALLOW", report.unknownOwnerPacketPolicy)
        assertEquals(1L, report.unknownForwardedPackets)

        val summaryA = report.perClientVerifiedSummaries.first { it.mac == macA }
        val summaryB = report.perClientVerifiedSummaries.first { it.mac == macB }
        assertEquals(1L, summaryA.blockedDropPackets)
        assertEquals(0L, summaryA.verifiedUploadPackets)
        assertEquals(1L, summaryB.verifiedUploadPackets)
        assertEquals(240L, summaryB.verifiedUploadBytes)
        TunTrafficEngine.clearAll()
    }

    @Test
    fun `26 v0_10_5_debug schema v3 JSON and 8-section Markdown report export with zero PII leakage`() {
        val sampleRecord = TupleDiagnosticSampleRecord(
            schemaVersion = 3,
            featureVersion = "0.10.5-debug",
            sessionGeneration = 1L,
            bindingGeneration = 1L,
            snapshotSequence = 7L,
            snapshotAgeMs = 180L,
            flowHash = "ephemeral:a1b2c3d4e5f60123",
            ipFamily = "IPV4",
            protocol = "UDP",
            direction = "UPLOAD",
            directionConfidence = DirectionConfidence.KNOWN.name,
            tupleRoleOrigin = TupleRoleOrigin.TUN_PACKET_POST_NAT.name,
            missReason = UnattributedReason.TUPLE_NOT_PRESENT.name,
            flowMissState = FlowMissState.PERSISTENT_AFTER_REFRESH.name,
            snapshotsSurvived = 2,
            packetsSeenOnFlow = 5L,
            bytesSeenOnFlow = 6_000L,
            firstSeenRelativeMs = 0L,
            lastSeenRelativeMs = 1_200L,
            ownerConfidence = OwnerConfidence.UNKNOWN_OWNER.name,
            decision = "ALLOW",
            enforcementGuarantee = "NONE_FOR_UNKNOWN_OWNER",
        )
        val report = BpfAttributionStatusReport(
            experimentalEnabled = true,
            state = ExperimentalBpfState.MAPPINGS_AVAILABLE,
            collectionStatus = BpfCollectionStatus.OK,
            snapshotHealth = BpfSnapshotHealth.OK,
            totalEligiblePackets = 200L,
            totalEligibleBytes = 250_000L,
            totalAttributedPackets = 185L,
            totalAttributedBytes = 230_000L,
            bpfAttributedPackets = 165L,
            bpfAttributedBytes = 210_000L,
            directAttributedPackets = 20L,
            directAttributedBytes = 20_000L,
            unknownForwardedPackets = 15L,
            unknownForwardedBytes = 20_000L,
            bpfRefreshOnMissEnabled = true,
            refreshOnMissTriggeredCount = 4L,
            refreshOnMissCompletedCount = 4L,
            refreshCircuitBreakerState = RefreshCircuitBreakerState.CLOSED.name,
            missRefreshLatency = RefreshLatencyPercentiles(
                sampleCount = 4,
                p50Ms = 6L,
                p95Ms = 11L,
                p99Ms = 14L,
                maxMs = 14L,
            ),
            postRefreshFlowKeysResolved = 3L,
            postRefreshFirstSubsequentAttributedPackets = 3L,
            postRefreshFirstSubsequentAttributedBytes = 3_600L,
            deepTupleDiagnosticsEnabled = true,
            deepTupleDiagnostics = DeepTupleDiagnosticsSnapshot(
                activeTrackedFlowsCount = 2,
                resolvedAfterRefreshFlowsCount = 3L,
                persistentAfterRefreshFlowsCount = 1L,
                notOffloadedOrNotObservableFlowsCount = 1L,
                udp443MissingPacketsCount = 8L,
                udp443MissingBytesCount = 9_600L,
                sampleRecords = listOf(sampleRecord),
            ),
            perClientVerifiedSummaries = listOf(
                PerClientVerifiedTrafficSummary(
                    mac = "E2:15:CD:54:E4:9B",
                    originalIpv4 = "192.168.167.151",
                    activeFlows = 4,
                    verifiedUploadPackets = 80L,
                    verifiedUploadBytes = 90_000L,
                    verifiedDownloadPackets = 85L,
                    verifiedDownloadBytes = 140_000L,
                    directIpPackets = 10L,
                    bpfNatPackets = 155L,
                    conntrackPackets = 0L,
                    blockedDropPackets = 0L,
                    blockedDropBytes = 0L,
                ),
            ),
            phaseD = PhaseDStatusReport(
                phaseDMode = PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT,
                interfaceLifecycleState = PhaseDInterfaceLifecycleState.ATTRIBUTION_READY,
                verifiedFlowsAtTransitionTotal = 3L,
                staleAllowCacheHitsPreventedTotal = 2L,
                decisionsRecomputedTotal = 12L,
                verifiedDroppedAfterBlockPacketsTotal = 10L,
                verifiedDroppedAfterBlockBytesTotal = 12_000L,
                unknownForwardedAfterBlockPackets = 4L,
                unknownForwardedAfterBlockBytes = 2_400L,
                unknownPostBlockByProtocolAndDirection = mapOf("UDP_IPv4_UPLOAD" to 4L),
                activePinnedVerifiedFlowsCount = 2,
                establishedTcpPinnedMatchedPackets = 6L,
                establishedTcpPinnedMatchedBytes = 7_200L,
            ),
        )

        val md = report.toMarkdownReport(
            apkVersion = "0.10.5-debug",
            sourceCommit = "ab2e16dcef1590fe09358fc462cf3a3561439602+v0.10.5-debug",
            serviceBuildId = 20,
            includeSensitiveEndpoints = false,
            includePseudonymousIds = false,
        )
        val jsonObj = report.toJson(
            includeSensitiveEndpoints = false,
            includePseudonymousIds = false,
        )
        val jsonStr = jsonObj.toString()

        // Verify all mandatory sections in Markdown report + Phase D section 7 + v0.10.8 sections 10, 11 & 12
        assertTrue(md.contains("## 1. Build & Session Metadata"))
        assertTrue(md.contains("## 2. Global Attribution Summary"))
        assertTrue(md.contains("## 3. Unattributed Traffic by Structured Reason"))
        assertTrue(md.contains("## 4. Phase B: Refresh-on-Miss Telemetry"))
        assertTrue(md.contains("## 5. Phase C: Deep Tuple & Survival Diagnostics"))
        assertTrue(md.contains("## 6. Multi-Client Verified Traffic Summary"))
        assertTrue(md.contains("## 7. Phase D: Persistent Connection Leak Investigation & Experimental Enforcement"))
        assertTrue(md.contains("## 8. Snapshot & Parser Health"))
        assertTrue(md.contains("## 9. Explicit Limitations & Enforcement Status"))
        assertTrue(md.contains("## 10. Exclusive Blocking Mode & Legacy Pre-NAT Retirement (`v0.10.8-debug`, Schema v6)"))
        assertTrue(md.contains("## 11. Native SoftAP MAC Blocklist Engine & Ownership Journal (`v0.10.8-debug`, Schema v6)"))
        assertTrue(md.contains("## 12. Domain Blocking & Shared DNS/Hostname Policy Layer (`v0.10.8-debug`, Schema v6)"))
        assertTrue(md.contains("PARTIAL_ENFORCEMENT"))

        // Verify schemaVersion = 6 in JSON and roundtrip deserialization
        assertEquals(6, jsonObj.getInt("schemaVersion"))
        assertEquals("0.10.8-debug", jsonObj.getString("featureVersion"))
        val roundTrip = BpfAttributionStatusReport.fromJson(jsonObj)
        assertEquals(RefreshCircuitBreakerState.CLOSED.name, roundTrip.refreshCircuitBreakerState)
        assertEquals(3L, roundTrip.postRefreshFlowKeysResolved)
        assertEquals(8L, roundTrip.udp443MissingPacketsCount)
        assertEquals(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT, roundTrip.phaseDMode)
        assertEquals(2L, roundTrip.staleAllowCacheHitsPrevented)
        assertEquals(12L, roundTrip.decisionsRecomputed)
        assertEquals(6L, roundTrip.pinnedVerifiedFlowHitsPackets)
        assertEquals(4L, roundTrip.unknownPostBlockByProtocolAndDirection["UDP_IPv4_UPLOAD"])
        assertEquals(BlockingMode.BPF_NAT_VPN, roundTrip.preNatDiagnostics.effectiveMode)
        assertTrue(roundTrip.preNatDiagnostics.exclusiveEngineInvariant)
        assertEquals(SoftApEngineState.PROBE_REQUIRED, roundTrip.softApDiagnostics.engineState)
        assertEquals(6, roundTrip.domainDiagnostics.schemaVersion)

        // Verify zero unredacted PII
        assertFalse(DiagnosticRedactor.containsUnredactedPii(md))
        assertFalse(DiagnosticRedactor.containsUnredactedPii(jsonStr))
    }

    @Test
    fun `27 v0_10_5_debug Phase D DIAGNOSTIC vs EXPERIMENTAL_ENFORCEMENT mode comparison on quota exhaustion pacing queue and pinned verified flows`() {
        val macA = "E2:15:CD:54:E4:9B"
        val macB = "F2:FF:8B:3D:B2:A6"
        val hosts = listOf(
            DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "ap0"),
            DiscoveredHost(mac = macB, ip = "192.168.167.17", allIps = listOf("192.168.167.17"), interfaceName = "ap0"),
        )

        // --- PART 1: Mid-stream quota-crossing boundary packet & pacing queue reconciliation ---
        // Run identical sequence in DIAGNOSTIC mode vs EXPERIMENTAL_ENFORCEMENT mode
        fun runMidStreamQuotaCrossingScenario(mode: PhaseDEnforcementMode): Pair<PacketDecision, Int> {
            TunTrafficEngine.clearAll()
            TunTrafficEngine.configurePhaseDMode(mode)
            TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L, downstreamIface = "ap0", upstreamIface = "testtun46")

            // Client A has 2,000-byte data quota and 500 Kbps bandwidth limit; already used 1,500 bytes
            val nextResetGen = (TunTrafficEngine.getQuotaRecord(macA)?.resetGeneration ?: 0L) + 1L
            val ruleA = ClientRule(
                mac = macA,
                isBlocked = false,
                bandwidthLimitKbps = 500,
                dataLimitBytes = 2_000L,
                quotaResetPeriod = QuotaResetPeriod.DAILY,
                quotaUsedRxBytes = 1_000L,
                quotaUsedTxBytes = 500L,
                quotaResetGeneration = nextResetGen,
            )
            TunTrafficEngine.syncQuotaRules(listOf(ruleA))
            TunTrafficEngine.updatePolicies(
                mapOf(
                    macA to TunTrafficEngine.EnforcedClientPolicy(
                        mac = macA,
                        isBlocked = false,
                        bandwidthLimitKbps = 500,
                        dataLimitBytes = 2_000L,
                        quotaResetPeriod = QuotaResetPeriod.DAILY,
                    ),
                ),
                hosts,
            )

            // Enqueue a paced packet for Client A BEFORE quota is crossed
            val dummyBuf = ByteArray(400)
            val snapBefore = TunTrafficEngine.getCounterSnapshot(macA)
            assertTrue(
                TunTrafficEngine.enqueuePacedPacket(
                    mac = macA,
                    isUpload = false,
                    buf = dummyBuf,
                    length = dummyBuf.size,
                    paceDelayMs = 50L,
                    policyVersion = snapBefore.policyVersion,
                    targetFd = null,
                ),
            )
            assertEquals(1, TunTrafficEngine.getQueuedPacketCountForClient(macA))

            // Send a 1,000-byte packet that crosses the 2,000-byte quota (1,500 + 1,000 = 2,500 >= 2,000)
            val boundaryMeta = TunTrafficEngine.PacketMeta(
                version = 4,
                protocol = 6,
                srcIp = "192.168.167.151",
                dstIp = "108.158.147.26",
                srcPort = 51006,
                dstPort = 443,
                length = 1_000,
                isSmallControlPacket = false,
            )
            val attr = TunTrafficEngine.resolveClientMacWithSource(boundaryMeta, isUpload = true)
            boundaryMeta.resolvedAttribution = attr
            val eval = TunTrafficEngine.evaluateAndShapeDetailed(
                boundaryMeta,
                attr.mac,
                isUpload = true,
                attributionSource = attr.source,
            )
            val remainingQueued = TunTrafficEngine.getQueuedPacketCountForClient(macA)
            return eval.decision to remainingQueued
        }

        val (diagDecision, diagRemainingQueue) = runMidStreamQuotaCrossingScenario(PhaseDEnforcementMode.DIAGNOSTIC)
        // In DIAGNOSTIC mode (0.10.4-debug baseline), boundary packet passes and queued packet remains until drained
        assertEquals(PacketDecision.ALLOW, diagDecision)
        assertEquals(1, diagRemainingQueue)
        val diagRep = TunTrafficEngine.getBpfAttributionReport()
        assertEquals(1L, diagRep.verifiedAllowedAfterBlockPackets)

        val (enfDecision, enfRemainingQueue) = runMidStreamQuotaCrossingScenario(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT)
        // In EXPERIMENTAL_ENFORCEMENT mode, boundary packet is immediately dropped and queued paced packets are purged
        assertEquals(PacketDecision.DROP, enfDecision)
        assertEquals(0, enfRemainingQueue)
        val enfRep = TunTrafficEngine.getBpfAttributionReport()
        assertTrue(enfRep.staleAllowCacheHitsPrevented >= 1L)
        assertTrue(enfRep.decisionsRecomputed >= 1L)
        assertTrue(enfRep.verifiedDroppedAfterBlockPackets >= 2L)

        // --- PART 2: Long-lived TCP connection across stale BPF snapshot (pinned verified flow ownership) ---
        val clock = AtomicLong(10_000L)
        val originalClock = TunTrafficEngine.bpfAttributor.monotonicClockMs
        val originalMaxFreshness = TunTrafficEngine.bpfAttributor.maxFreshnessMs
        TunTrafficEngine.bpfAttributor.monotonicClockMs = { clock.get() }
        TunTrafficEngine.bpfAttributor.maxFreshnessMs = 4_500L
        try {
            fun runLongLivedTcpAfterSnapshotExpiry(mode: PhaseDEnforcementMode): Pair<TunTrafficEngine.PacketAttribution, PacketDecision> {
                TunTrafficEngine.clearAll()
                clock.set(10_000L)
                TunTrafficEngine.configurePhaseDMode(mode)
                TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L, downstreamIface = "ap0", upstreamIface = "testtun46")
                TunTrafficEngine.updatePolicies(
                    mapOf(
                        macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = false),
                        macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
                    ),
                    hosts,
                )

                val (verifiedBindings, verifiedMacs) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
                assertTrue(
                    TunTrafficEngine.bpfAttributor.ingestParsedDump(
                        parsed = BpfDumpParser.parse(realDeviceExcerpt),
                        collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                        collectionStatus = BpfCollectionStatus.OK,
                        collectionDurationMs = 5L,
                        ipToMac = verifiedBindings,
                        activeConnectedMacs = verifiedMacs,
                    ),
                )

                val longLivedTcpMeta = TunTrafficEngine.PacketMeta(
                    version = 4,
                    protocol = 6,
                    srcIp = "192.0.2.2",
                    dstIp = "108.158.147.26",
                    srcPort = 51006,
                    dstPort = 443,
                    length = 520,
                    isSmallControlPacket = false,
                )
                // First packet while snapshot is fresh -> attributed via BPF_NAT and pins verified flow
                val freshAttr = TunTrafficEngine.resolveClientMacWithSource(longLivedTcpMeta, isUpload = true)
                assertEquals(macA, freshAttr.mac)
                assertEquals(AttributionSource.BPF_NAT, freshAttr.source)
                longLivedTcpMeta.resolvedAttribution = freshAttr
                assertEquals(
                    PacketDecision.ALLOW,
                    TunTrafficEngine.evaluateAndShapeDetailed(longLivedTcpMeta, freshAttr.mac, isUpload = true, attributionSource = freshAttr.source).decision,
                )

                // Now block Client A
                TunTrafficEngine.updatePolicies(
                    mapOf(
                        macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true),
                        macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
                    ),
                    hosts,
                )

                // Advance clock past maxFreshnessMs (10_000 + 6_000 = 16_000 -> snapshot is STALE)
                clock.set(16_000L)
                val postExpiryMeta = longLivedTcpMeta.copy()
                val postExpiryAttr = TunTrafficEngine.resolveClientMacWithSource(postExpiryMeta, isUpload = true)
                postExpiryMeta.resolvedAttribution = postExpiryAttr
                val postExpiryEval = TunTrafficEngine.evaluateAndShapeDetailed(
                    postExpiryMeta,
                    postExpiryAttr.mac,
                    isUpload = true,
                    attributionSource = postExpiryAttr.source,
                )
                return postExpiryAttr to postExpiryEval.decision
            }

            val (diagAttr, diagDec) = runLongLivedTcpAfterSnapshotExpiry(PhaseDEnforcementMode.DIAGNOSTIC)
            // In DIAGNOSTIC mode, stale snapshot falls back to UNKNOWN_OWNER -> ALLOW, but records pinnedFlowHitsInDiagnosticMode
            assertNull(diagAttr.mac)
            assertEquals(UnattributedReason.SNAPSHOT_STALE, diagAttr.unattributedReason)
            assertEquals(PacketDecision.ALLOW, diagDec)
            val diagSnapRep = TunTrafficEngine.getBpfAttributionReport()
            assertEquals(1L, diagSnapRep.pinnedFlowHitsInDiagnosticMode)
            assertEquals(1L, diagSnapRep.unknownForwardedAfterBlockPackets)

            val (enfAttr, enfDec) = runLongLivedTcpAfterSnapshotExpiry(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT)
            // In EXPERIMENTAL_ENFORCEMENT mode, pinned verified flow retains ownership for Client A -> DROPPED!
            assertEquals(macA, enfAttr.mac)
            assertTrue(enfAttr.pinnedFlowHit)
            assertEquals(PacketDecision.DROP, enfDec)
            val enfSnapRep = TunTrafficEngine.getBpfAttributionReport()
            assertEquals(1L, enfSnapRep.pinnedVerifiedFlowHitsPackets)
            assertEquals(520L, enfSnapRep.pinnedVerifiedFlowHitsBytes)
            assertEquals(1L, enfSnapRep.verifiedDroppedAfterBlockPackets)
            assertEquals(0L, enfSnapRep.unknownForwardedAfterBlockPackets)
        } finally {
            TunTrafficEngine.bpfAttributor.monotonicClockMs = originalClock
            TunTrafficEngine.bpfAttributor.maxFreshnessMs = originalMaxFreshness
            TunTrafficEngine.clearAll()
        }
    }

    @Test
    fun `28 v0_10_5_debug Phase D verified flow pins invalidate on TCP SYN FIN RST client disconnect IP reassignment and session generation change`() {
        val clock = AtomicLong(20_000L)
        val originalClock = TunTrafficEngine.bpfAttributor.monotonicClockMs
        val originalMaxFreshness = TunTrafficEngine.bpfAttributor.maxFreshnessMs
        TunTrafficEngine.bpfAttributor.monotonicClockMs = { clock.get() }
        TunTrafficEngine.bpfAttributor.maxFreshnessMs = 4_500L
        try {
            val macA = "E2:15:CD:54:E4:9B"
            val macB = "F2:FF:8B:3D:B2:A6"
            val hosts = listOf(
                DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "ap0"),
                DiscoveredHost(mac = macB, ip = "192.168.167.17", allIps = listOf("192.168.167.17"), interfaceName = "ap0"),
            )
            TunTrafficEngine.clearAll()
            TunTrafficEngine.configurePhaseDMode(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT)
            TunTrafficEngine.configureExperimentalBpf(enabled = true, pollIntervalMs = 1_000L, downstreamIface = "ap0", upstreamIface = "testtun46")
            TunTrafficEngine.updatePolicies(
                mapOf(macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true)),
                hosts,
            )

            val (verifiedBindings, verifiedMacs) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
            assertTrue(
                TunTrafficEngine.bpfAttributor.ingestParsedDump(
                    parsed = BpfDumpParser.parse(realDeviceExcerpt),
                    collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                    collectionStatus = BpfCollectionStatus.OK,
                    collectionDurationMs = 5L,
                    ipToMac = verifiedBindings,
                    activeConnectedMacs = verifiedMacs,
                ),
            )
            assertTrue(TunTrafficEngine.getBpfAttributionReport().activePinnedVerifiedFlowsCount >= 2)

            // Advance clock so snapshot is stale -> pin still attributes normal TCP data packet
            clock.set(26_000L)
            val normalMeta = TunTrafficEngine.PacketMeta(
                version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "108.158.147.26",
                srcPort = 51006, dstPort = 443, length = 400, isSmallControlPacket = false,
            )
            val pinnedAttr = TunTrafficEngine.resolveClientMacWithSource(normalMeta, isUpload = true)
            assertEquals(macA, pinnedAttr.mac)
            assertTrue(pinnedAttr.pinnedFlowHit)

            // TCP FIN/RST invalidates the pin after attributing the closing packet
            val finMeta = normalMeta.copy(isTcpFinOrRst = true)
            val finAttr = TunTrafficEngine.resolveClientMacWithSource(finMeta, isUpload = true)
            assertEquals(macA, finAttr.mac)
            val afterFinAttr = TunTrafficEngine.resolveClientMacWithSource(normalMeta.copy(), isUpload = true)
            assertNull("Expected pin for 51006 to be invalidated after TCP FIN/RST", afterFinAttr.mac)

            // Client B flow (44056) is still pinned while Client B is connected, but if Client B disconnects, pin is invalidated
            val metaB = TunTrafficEngine.PacketMeta(
                version = 4, protocol = 6, srcIp = "192.0.2.2", dstIp = "142.250.219.14",
                srcPort = 44056, dstPort = 443, length = 400, isSmallControlPacket = false,
            )
            assertEquals(macB, TunTrafficEngine.resolveClientMacWithSource(metaB, isUpload = true).mac)

            // Disconnect Client B -> pin for Client B is purged and cannot match
            TunTrafficEngine.updatePolicies(
                mapOf(macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true)),
                listOf(hosts[0]), // Only Client A remains connected
            )
            assertNull("Disconnected client pin must be purged immediately", TunTrafficEngine.resolveClientMacWithSource(metaB.copy(), isUpload = true).mac)
        } finally {
            TunTrafficEngine.bpfAttributor.monotonicClockMs = originalClock
            TunTrafficEngine.bpfAttributor.maxFreshnessMs = originalMaxFreshness
            TunTrafficEngine.clearAll()
        }
    }

    @Test
    fun `29 v0_10_5_debug Phase D UNKNOWN_OWNER remains ALLOW in both modes and tracks post-block protocol direction and delivery test markers`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B"
        val hostA = DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "ap0")

        TunTrafficEngine.configurePhaseDMode(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT)
        TunTrafficEngine.recordDeliveryTestMarker("TEST_SESSION_START", macA, "Start WhatsApp block test")

        // Block Client A
        TunTrafficEngine.updatePolicies(
            mapOf(macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true)),
            listOf(hostA),
        )

        // Send unattributed UDP/443 (QUIC) and UDP/53 (DNS) post-NAT packets while Client A is blocked
        val quicMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 17, srcIp = "192.0.2.2", dstIp = "157.240.22.53",
            srcPort = 58111, dstPort = 443, length = 1200, isSmallControlPacket = false,
        )
        val dnsMeta = TunTrafficEngine.PacketMeta(
            version = 4, protocol = 17, srcIp = "192.0.2.2", dstIp = "8.8.8.8",
            srcPort = 58112, dstPort = 53, length = 90, isSmallControlPacket = true,
        )

        val quicAttr = TunTrafficEngine.resolveClientMacWithSource(quicMeta, isUpload = true)
        assertNull(quicAttr.mac)
        quicMeta.resolvedAttribution = quicAttr
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShapeDetailed(quicMeta, quicAttr.mac, isUpload = true, attributionSource = quicAttr.source).decision,
        )

        val dnsAttr = TunTrafficEngine.resolveClientMacWithSource(dnsMeta, isUpload = true)
        assertNull(dnsAttr.mac)
        dnsMeta.resolvedAttribution = dnsAttr
        assertEquals(
            PacketDecision.ALLOW,
            TunTrafficEngine.evaluateAndShapeDetailed(dnsMeta, dnsAttr.mac, isUpload = true, attributionSource = dnsAttr.source).decision,
        )

        TunTrafficEngine.recordDeliveryTestMarker("TEST_SESSION_STOP", macA, "Stop WhatsApp block test")

        val rep = TunTrafficEngine.getBpfAttributionReport()
        assertEquals(2L, rep.unknownForwardedAfterBlockPackets)
        assertEquals(1290L, rep.unknownForwardedAfterBlockBytes)
        assertEquals(2L, rep.unknownPostBlockByProtocolAndDirection["UDP_IPv4_UPLOAD"])
        assertEquals(1L, rep.unknownPostBlockByProtocolAndDirection["UDP/443"])
        assertEquals(1L, rep.unknownPostBlockByProtocolAndDirection["UDP/53"])
        assertTrue(rep.policyTransitionEvents.any { it.transitionType == "ALLOW_TO_BLOCK" })
        assertTrue(rep.deliveryTestMarkers.any { it.markerType == "TEST_SESSION_START" })
        assertTrue(rep.deliveryTestMarkers.any { it.markerType == "POLICY_ACTIVATED" })
        assertTrue(rep.deliveryTestMarkers.any { it.markerType == "TEST_SESSION_STOP" })

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `30 v0_10_6_debug Pre-NAT capability state machine in rootless UID 2000 vs privileged CAP_NET_ADMIN zero read-only mutations and user-approved scoped probe`() {
        val originalExecutor = ExclusiveBlockingModeController.preNatEngine.shellExecutor
        try {
            TunTrafficEngine.clearAll()
            ExclusiveBlockingModeController.resetForTesting()

            val macA = "E2:15:CD:54:E4:9B"
            val hostA = DiscoveredHost(
                mac = macA,
                ip = "192.168.167.151",
                allIps = listOf("192.168.167.151", "2804:38a:a08a:c641::55"),
                interfaceName = "ap0",
            )
            TunTrafficEngine.updatePolicies(
                mapOf(macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true)),
                listOf(hostA),
            )
            TunTrafficEngine.configureExperimentalBpf(
                enabled = true,
                pollIntervalMs = 1_000L,
                downstreamIface = "ap0",
                upstreamIface = "testtun46",
            )

            // 1. Rootless UID 2000 shell executor (CapEff = 0, iptables denied)
            val executedRootlessCmds = mutableListOf<String>()
            val rootlessExecutor = object : PreNatShellExecutor {
                override fun resolveUid(): Int = 2000
                override fun resolveGid(): Int = 2000
                override fun resolveShizukuUid(): Int = 2000
                override fun resolveShizukuRunning(): Boolean = true
                override fun resolveSeLinuxContext(): String = "u:r:shell:s0"
                override fun resolveEffectiveCapabilitiesHex(): String = "0000000000000000"
                override fun execute(vararg args: String, timeoutMs: Long): HostFirewall.CommandResult {
                    val cmd = args.joinToString(" ")
                    executedRootlessCmds.add(cmd)
                    return when {
                        cmd.startsWith("iptables") || cmd.startsWith("ip6tables") ->
                            HostFirewall.CommandResult(
                                command = cmd,
                                exitCode = 3,
                                stdout = "",
                                stderr = "iptables v1.8.7 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)",
                                timedOut = false,
                                errorKind = ProbeErrorKind.PERMISSION_DENIED,
                            )
                        cmd.startsWith("nft") ->
                            HostFirewall.CommandResult(cmd, 0, "nftables v1.0.2", "", false, ProbeErrorKind.NONE)
                        cmd.startsWith("tc") ->
                            HostFirewall.CommandResult(cmd, 0, "tc utility, iproute2", "", false, ProbeErrorKind.NONE)
                        cmd.startsWith("ip ") ->
                            HostFirewall.CommandResult(cmd, 0, "0:\tfrom all lookup local", "", false, ProbeErrorKind.NONE)
                        else ->
                            HostFirewall.CommandResult(cmd, 0, "", "", false, ProbeErrorKind.NONE)
                    }
                }
            }
            ExclusiveBlockingModeController.resetForTesting(rootlessExecutor)

            // DB01: Migrating legacy "PRE_NAT_FIREWALL" in rootless UID 2000 migrates to BPF_NAT_VPN cleanly
            val (parsedMode, migratedFromLegacyPreNat) = BlockingMode.parseWithMigration("PRE_NAT_FIREWALL")
            assertEquals(BlockingMode.BPF_NAT_VPN, parsedMode)
            assertTrue(migratedFromLegacyPreNat)

            val rootlessReport = ExclusiveBlockingModeController.migrateAndReconcilePersistedMode("PRE_NAT_FIREWALL")
            assertEquals(BlockingMode.BPF_NAT_VPN, rootlessReport.requestedMode)
            assertEquals(BlockingMode.BPF_NAT_VPN, rootlessReport.effectiveMode)
            assertTrue(rootlessReport.legacyPreNatMigrated)
            assertTrue(rootlessReport.legacyPreNatCleanupVerified)
            assertTrue(rootlessReport.exclusiveEngineInvariant)
            assertTrue(TunTrafficEngine.bpfNatVpnEnforcementEnabled)
        } finally {
            ExclusiveBlockingModeController.resetForTesting(originalExecutor)
            TunTrafficEngine.clearAll()
        }
    }

    @Test
    fun `31 v0_10_8_debug ExclusiveBlockingModeController cleans up lingering legacy Pre-NAT chains and enters RECOVERY_REQUIRED on unverified cleanup`() {
        val originalExecutor = ExclusiveBlockingModeController.preNatEngine.shellExecutor
        try {
            TunTrafficEngine.clearAll()
            ExclusiveBlockingModeController.resetForTesting()

            val activeChains = mutableSetOf("SHIZZI_PN4")
            val activeJumps = mutableSetOf("SHIZZI_PN4")
            var simulateStuckChainOnCleanup = false

            val mockPrivilegedExecutor = object : PreNatShellExecutor {
                override fun resolveUid(): Int = 0
                override fun resolveGid(): Int = 0
                override fun resolveShizukuUid(): Int = 0
                override fun resolveShizukuRunning(): Boolean = true
                override fun resolveSeLinuxContext(): String = "u:r:su:s0"
                override fun resolveEffectiveCapabilitiesHex(): String = "0000003fffffffff"
                override fun execute(vararg args: String, timeoutMs: Long): HostFirewall.CommandResult {
                    val command = args.joinToString(" ")
                    if (command.contains(" -X ")) {
                        val chain = command.substringAfter(" -X ").trim()
                        if (!simulateStuckChainOnCleanup) {
                            activeChains.remove(chain)
                        }
                        return HostFirewall.CommandResult(command, if (simulateStuckChainOnCleanup) 1 else 0, "", "", false, ProbeErrorKind.NONE)
                    }
                    if (command.contains(" -D FORWARD ") && command.contains(" -j ")) {
                        val chain = command.substringAfter(" -j ").trim()
                        if (!simulateStuckChainOnCleanup) {
                            activeJumps.remove(chain)
                        }
                        return HostFirewall.CommandResult(command, if (simulateStuckChainOnCleanup) 1 else 0, "", "", false, ProbeErrorKind.NONE)
                    }
                    if (command.contains(" -S ")) {
                        val token = command.substringAfter(" -S ").trim()
                        if (token == "FORWARD") {
                            val fwdLines = buildString {
                                append("-P FORWARD ACCEPT")
                                for (jmp in activeJumps) {
                                    append("\n-A FORWARD -j $jmp")
                                }
                            }
                            return HostFirewall.CommandResult(command, 0, fwdLines, "", false, ProbeErrorKind.NONE)
                        }
                        val exists = activeChains.contains(token)
                        return HostFirewall.CommandResult(
                            command = command,
                            exitCode = if (exists) 0 else 1,
                            stdout = if (exists) "-N $token" else "",
                            stderr = if (exists) "" else "No chain",
                            timedOut = false,
                            errorKind = if (exists) ProbeErrorKind.NONE else ProbeErrorKind.EXECUTION_FAILED,
                        )
                    }
                    return HostFirewall.CommandResult(command, 0, "ok", "", false, ProbeErrorKind.NONE)
                }
            }
            ExclusiveBlockingModeController.resetForTesting(mockPrivilegedExecutor)

            // Seed a lingering legacy Pre-NAT chain in the journal and simulate stuck cleanup -> RECOVERY_REQUIRED (DB02)
            ExclusiveBlockingModeController.preNatEngine.seedLegacyJournalForTests(chainV4 = "SHIZZI_PN4")
            simulateStuckChainOnCleanup = true

            val stuckReport = ExclusiveBlockingModeController.migrateAndReconcilePersistedMode("PRE_NAT_FIREWALL")
            assertEquals(PreNatRuntimeState.RECOVERY_REQUIRED, stuckReport.runtimeState)
            assertFalse(stuckReport.legacyPreNatCleanupVerified)
            assertNull("effectiveModeOrNull must be null during RECOVERY_REQUIRED", ExclusiveBlockingModeController.effectiveModeOrNull)
            assertFalse("BPF_NAT_VPN must NOT be re-enabled while legacy pre-NAT cleanup is unverified", TunTrafficEngine.bpfNatVpnEnforcementEnabled)
            assertTrue(stuckReport.exclusiveEngineInvariant)

            // Once stuck chain clears, restoreBpfNatVpnMode recovers cleanly
            simulateStuckChainOnCleanup = false
            val recoveredReport = ExclusiveBlockingModeController.restoreBpfNatVpnMode("Recover after legacy Pre-NAT cleanup fixed")
            assertEquals(BlockingMode.BPF_NAT_VPN, recoveredReport.effectiveMode)
            assertEquals(PreNatRuntimeState.CURRENT_ACTIVE, recoveredReport.runtimeState)
            assertTrue(recoveredReport.legacyPreNatCleanupVerified)
            assertTrue(TunTrafficEngine.bpfNatVpnEnforcementEnabled)
            assertTrue(activeChains.isEmpty())
        } finally {
            ExclusiveBlockingModeController.resetForTesting(originalExecutor)
            TunTrafficEngine.clearAll()
        }
    }

    @Test
    fun `32 v0_10_6_debug BPF_NAT_VPN host-blocking improvements ingest IPv4 downstream-only flows and bind IPv6 downstream client addresses`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B" // Blocked client
        val macB = "F2:FF:8B:3D:B2:A6" // Allowed client
        val hosts = listOf(
            DiscoveredHost(
                mac = macA,
                ip = "192.168.167.151",
                allIps = listOf("192.168.167.151"),
                interfaceName = "ap0",
            ),
            DiscoveredHost(
                mac = macB,
                ip = "192.168.167.17",
                allIps = listOf("192.168.167.17"),
                interfaceName = "ap0",
            ),
        )
        TunTrafficEngine.configurePhaseDMode(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT)
        TunTrafficEngine.configureExperimentalBpf(
            enabled = true,
            pollIntervalMs = 1_000L,
            downstreamIface = "ap0",
            upstreamIface = "testtun46",
        )
        TunTrafficEngine.updatePolicies(
            mapOf(
                macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true),
                macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
            ),
            hosts,
        )

        // Verify EXPERIMENTAL_ENFORCEMENT auto-enables fast bpfRefreshOnMiss (150ms cooldown)
        assertTrue(TunTrafficEngine.bpfRefreshOnMissEnabled)
        assertEquals(150L, TunTrafficEngine.bpfReader.refreshOnMissCooldownMs)

        // Dump containing:
        // 1) An IPv4 Downstream-only flow (e.g., server-pushed WhatsApp notification socket on port 52222)
        // 2) An IPv6 Downstream entry for a new RFC 4941 privacy IPv6 address (2804:38a:a08a:c641:9999:8888:7777:6666)
        val downstreamAndIpv6Dump = """
            Tethering:
              BPF offload:
                IPv4 Upstream:
                  269 (testtun46) -> 269 (testtun46)
                  270 (ap0) -> 270 (ap0)
                IPv4 Downstream:
                  269 (testtun46) -> 269 (testtun46)
                  270 (ap0) -> 270 (ap0)
                  tcp [00:00:00:00:00:00] 269(testtun46) 157.240.22.53:443 -> 270(ap0) 192.0.2.2:52222 -> 192.168.167.151:52222 [e2:15:cd:54:e4:9b] 1500 45ms
                IPv6 Downstream:
                  269(testtun46) 270(ap0) 2804:38a:a08a:c641:9999:8888:7777:6666 [00:00:00:00:00:00] [e2:15:cd:54:e4:9b] 1500
        """.trimIndent()

        val parsed = BpfDumpParser.parse(downstreamAndIpv6Dump)
        assertEquals(0, parsed.ipv4UpstreamEntries.size)
        assertEquals(1, parsed.ipv4DownstreamEntries.size)
        assertEquals(1, parsed.ipv6Entries.size)

        val (verifiedBindings, verifiedMacs) = TunTrafficEngine.getVerifiedClientBindingsSnapshot()
        assertTrue(
            TunTrafficEngine.bpfAttributor.ingestParsedDump(
                parsed = parsed,
                collectionSessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                collectionStatus = BpfCollectionStatus.OK,
                collectionDurationMs = 4L,
                ipToMac = verifiedBindings,
                activeConnectedMacs = verifiedMacs,
            ),
        )

        // 1. Verify IPv4 Downstream-only flow for blocked Client A is attributed and DROPPED
        val serverPushMeta = TunTrafficEngine.PacketMeta(
            version = 4,
            protocol = 6,
            srcIp = "157.240.22.53",
            dstIp = "192.0.2.2",
            srcPort = 443,
            dstPort = 52222,
            length = 640,
            isSmallControlPacket = false,
        )
        val pushAttr = TunTrafficEngine.resolveClientMacWithSource(serverPushMeta, isUpload = false)
        assertEquals(macA, pushAttr.mac)
        assertEquals(AttributionSource.BPF_NAT, pushAttr.source)
        serverPushMeta.resolvedAttribution = pushAttr
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShapeDetailed(serverPushMeta, pushAttr.mac, isUpload = false, attributionSource = pushAttr.source).decision,
        )

        // 2. Verify IPv6 Downstream entry bound the new privacy IPv6 address to Client A and drops its packets via DIRECT_IP
        val privacyIpv6Meta = TunTrafficEngine.PacketMeta(
            version = 6,
            protocol = 17,
            srcIp = "2804:38a:a08a:c641:9999:8888:7777:6666",
            dstIp = "2606:4700:4700::1111",
            srcPort = 53111,
            dstPort = 443,
            length = 900,
            isSmallControlPacket = false,
        )
        val v6Attr = TunTrafficEngine.resolveClientMacWithSource(privacyIpv6Meta, isUpload = true)
        assertEquals(macA, v6Attr.mac)
        assertEquals(AttributionSource.DIRECT_IP, v6Attr.source)
        privacyIpv6Meta.resolvedAttribution = v6Attr
        assertEquals(
            PacketDecision.DROP,
            TunTrafficEngine.evaluateAndShapeDetailed(privacyIpv6Meta, v6Attr.mac, isUpload = true, attributionSource = v6Attr.source).decision,
        )

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `33 v0_10_7_debug Shizuku offline and unpermitted states report NOT_TESTED_SHIZUKU_UNAVAILABLE and SHIZUKU_NOT_RUNNING with UNKNOWN identity without fabricating UID 2000`() {
        val originalExecutor = ExclusiveBlockingModeController.preNatEngine.shellExecutor
        val originalAdapter = ExclusiveBlockingModeController.softApEngine.platformAdapter
        try {
            // 1. Shizuku offline PreNatShellExecutor (simulates DefaultPreNatShellExecutor when Shizuku is not running)
            val shizukuOfflineExecutor = object : PreNatShellExecutor {
                override fun resolveUid(): Int = -1
                override fun resolveGid(): Int = -1
                override fun resolveShizukuUid(): Int = -1
                override fun resolveShizukuRunning(): Boolean = false
                override fun resolveShizukuPermissionGranted(): Boolean = false
                override fun resolveSeLinuxContext(): String = "UNKNOWN"
                override fun resolveEffectiveCapabilitiesHex(): String = "UNKNOWN"
                override fun execute(vararg args: String, timeoutMs: Long): HostFirewall.CommandResult =
                    HostFirewall.CommandResult(args.joinToString(" "), -1, "", "Shizuku not running", false, ProbeErrorKind.EXECUTION_FAILED)
            }
            val shizukuOfflineAdapter = object : SoftApPlatformAdapter {
                override fun inspectExecutionIdentity(): SoftApExecutionIdentity = SoftApExecutionIdentity(
                    shizukuState = "SHIZUKU_NOT_RUNNING",
                    shizukuRunning = false,
                    shizukuPermissionGranted = false,
                    uid = "UNKNOWN",
                    gid = "UNKNOWN",
                    selinuxContext = "UNKNOWN",
                    capEff = "UNKNOWN",
                    provenance = "SHIZUKU_BINDER_DEAD",
                )
                override fun isHotspotActive(): Boolean = false
                override fun resolveTetherInterface(): String = "wlan1"
                override fun querySoftApCapability(): SoftApPlatformCapabilitySnapshot = SoftApPlatformCapabilitySnapshot(
                    callbackRegistered = false,
                    capabilityReceived = false,
                    forceDisconnectSupported = false,
                )
                override fun readSoftApConfiguration(): SoftApConfigSnapshot = SoftApConfigSnapshot(readable = false)
                override fun writeBlockedClientList(updatedBlockedMacs: List<String>): SoftApWriteOutcome =
                    SoftApWriteOutcome(invoked = false, returnedTrue = false, readbackSnapshot = SoftApConfigSnapshot(readable = false))
                override fun queryConnectedClientMacs(): List<String> = emptyList()
            }
            ExclusiveBlockingModeController.resetForTesting(shizukuOfflineExecutor, shizukuOfflineAdapter)

            val preNatOffline = ExclusiveBlockingModeController.checkCapabilityReadOnly()
            assertEquals(PreNatCapabilityStatus.NOT_TESTED_SHIZUKU_UNAVAILABLE, preNatOffline.capability.capabilityStatus)
            assertEquals(-1, preNatOffline.capability.uid)
            assertEquals(-1, preNatOffline.capability.gid)
            assertEquals("UNKNOWN", preNatOffline.capability.shizukuPrivilegeMode)
            assertEquals("UNKNOWN", preNatOffline.capability.selinuxContext)
            assertEquals("UNKNOWN", preNatOffline.capability.capEffHex)
            assertTrue("Must not run any shell commands when Shizuku is offline", preNatOffline.capability.auditedCommands.isEmpty())

            val softApOffline = ExclusiveBlockingModeController.checkSoftApCapability()
            assertEquals(SoftApEngineState.SHIZUKU_NOT_RUNNING, softApOffline.engineState)
            assertEquals("SHIZUKU_NOT_RUNNING", softApOffline.shizukuState)
            assertEquals("UNKNOWN", softApOffline.executionIdentity.uid)
            assertEquals("UNKNOWN", softApOffline.executionIdentity.gid)
            assertEquals("UNKNOWN", softApOffline.executionIdentity.selinuxContext)
            assertEquals("UNKNOWN", softApOffline.executionIdentity.capEffHex)
            assertEquals("SHIZUKU_BINDER_DEAD", softApOffline.executionIdentity.provenance)

            // 2. Shizuku running, but permission not granted -> SHIZUKU_PERMISSION_REQUIRED
            val shizukuUnpermittedAdapter = object : SoftApPlatformAdapter by shizukuOfflineAdapter {
                override fun inspectExecutionIdentity(): SoftApExecutionIdentity = SoftApExecutionIdentity(
                    shizukuState = "SHIZUKU_PERMISSION_REQUIRED",
                    shizukuRunning = true,
                    shizukuPermissionGranted = false,
                    uid = "UNKNOWN",
                    gid = "UNKNOWN",
                    selinuxContext = "UNKNOWN",
                    capEff = "UNKNOWN",
                    provenance = "SHIZUKU_PERMISSION_NOT_GRANTED",
                )
            }
            ExclusiveBlockingModeController.resetForTesting(shizukuOfflineExecutor, shizukuUnpermittedAdapter)
            val softApUnpermitted = ExclusiveBlockingModeController.checkSoftApCapability()
            assertEquals(SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED, softApUnpermitted.engineState)
            assertEquals("SHIZUKU_PERMISSION_REQUIRED", softApUnpermitted.shizukuState)
        } finally {
            ExclusiveBlockingModeController.resetForTesting(originalExecutor, originalAdapter)
        }
    }

    @Test
    fun `34 v0_10_7_debug SoftApPolicyReducer enforces multi-reason OR semantics and strict unicast MAC validation`() {
        val mac = "E2:15:CD:54:E4:9B"

        // 1. Validate unicast MAC address rules (SA19)
        assertTrue(SoftApPolicyReducer.isValidUnicastMac(mac))
        assertFalse("Broadcast MAC must be rejected", SoftApPolicyReducer.isValidUnicastMac("FF:FF:FF:FF:FF:FF"))
        assertFalse("Zero MAC must be rejected", SoftApPolicyReducer.isValidUnicastMac("00:00:00:00:00:00"))
        assertFalse("Multicast MAC (least-significant bit of first octet = 1) must be rejected", SoftApPolicyReducer.isValidUnicastMac("01:00:5E:00:00:01"))
        assertFalse("Locally administered multicast MAC must be rejected", SoftApPolicyReducer.isValidUnicastMac("03:15:CD:54:E4:9B"))

        // 2. Multi-reason OR semantics (SA10, SA11, SA12, AC09):
        // Apply both MANUAL_BLOCK (via rule.isBlocked = true) and QUOTA_EXHAUSTED (via extraReasons / quota exceeded)
        val bothReasons = SoftApPolicyReducer.evaluateRuleReasons(
            rule = ClientRule(mac = mac, isBlocked = true),
            extraReasons = setOf(SoftApClientBlockReason.QUOTA_EXHAUSTED),
        )
        assertEquals(
            setOf(SoftApClientBlockReason.MANUAL_BLOCK, SoftApClientBlockReason.QUOTA_EXHAUSTED),
            bothReasons,
        )
        assertTrue(SoftApPolicyReducer.shouldBlock(bothReasons))

        // Resetting quota removes QUOTA_EXHAUSTED, but MANUAL_BLOCK keeps client blocked!
        val afterQuotaReset = SoftApPolicyReducer.evaluateRuleReasons(
            rule = ClientRule(mac = mac, isBlocked = true),
            extraReasons = emptySet(),
        )
        assertEquals(setOf(SoftApClientBlockReason.MANUAL_BLOCK), afterQuotaReset)
        assertTrue("Client must remain blocked while MANUAL_BLOCK is still active", SoftApPolicyReducer.shouldBlock(afterQuotaReset))

        // Unblocking MANUAL_BLOCK while QUOTA_EXHAUSTED is active -> QUOTA_EXHAUSTED keeps client blocked!
        val afterManualUnblock = SoftApPolicyReducer.evaluateRuleReasons(
            rule = ClientRule(mac = mac, isBlocked = false),
            extraReasons = setOf(SoftApClientBlockReason.QUOTA_EXHAUSTED),
        )
        assertEquals(setOf(SoftApClientBlockReason.QUOTA_EXHAUSTED), afterManualUnblock)
        assertTrue("Client must remain blocked while QUOTA_EXHAUSTED is still active", SoftApPolicyReducer.shouldBlock(afterManualUnblock))

        // Clearing the final active reason unblocks the client
        val allCleared = SoftApPolicyReducer.evaluateRuleReasons(
            rule = ClientRule(mac = mac, isBlocked = false),
            extraReasons = emptySet(),
        )
        assertTrue(allCleared.isEmpty())
        assertFalse("Client must transition to unblocked once all reasons are cleared", SoftApPolicyReducer.shouldBlock(allCleared))
    }

    @Test
    fun `35 v0_10_7_debug SoftApMacBlockEngine and SoftApOwnershipJournal preserve priorBlockedMacs detect allowlist conflicts run 2-client live probe and handle crash recovery`() {
        val tempJournalFile = java.io.File.createTempFile("shizzyluna-softap-journal-test", ".json")
        val originalExecutor = ExclusiveBlockingModeController.preNatEngine.shellExecutor
        val originalAdapter = ExclusiveBlockingModeController.softApEngine.platformAdapter
        try {
            val priorUserMac = "AA:AA:AA:AA:AA:01"
            val allowlistedMac = "CC:CC:CC:CC:CC:03"
            val clientAMac = "E2:15:CD:54:E4:9B"
            val clientBMac = "F2:FF:8B:3D:B2:A6"

            val currentBlockedList = mutableListOf(priorUserMac)
            val currentAllowedList = mutableListOf(allowlistedMac)
            val connectedHotspotMacs = mutableSetOf(clientAMac, clientBMac)
            var shizukuAlive = true
            var disconnectClientAOnBlock = true
            var disconnectClientBCollateral = false
            var setConfigSucceeds = true

            val mockAdapter = object : SoftApPlatformAdapter {
                override fun inspectExecutionIdentity(): SoftApExecutionIdentity =
                    if (shizukuAlive) {
                        SoftApExecutionIdentity(
                            shizukuState = "SHIZUKU_RUNNING",
                            shizukuRunning = true,
                            shizukuPermissionGranted = true,
                            uid = "2000",
                            gid = "2000",
                            selinuxContext = "u:r:shell:s0",
                            capEff = "0000000000000000",
                            provenance = "LIVE_SHIZUKU_USERSERVICE_PROCESS",
                        )
                    } else {
                        SoftApExecutionIdentity(
                            shizukuState = "SHIZUKU_NOT_RUNNING",
                            shizukuRunning = false,
                            shizukuPermissionGranted = false,
                            uid = "UNKNOWN",
                            gid = "UNKNOWN",
                            selinuxContext = "UNKNOWN",
                            capEff = "UNKNOWN",
                            provenance = "SHIZUKU_BINDER_DEAD",
                        )
                    }

                override fun isHotspotActive(): Boolean = shizukuAlive
                override fun resolveTetherInterface(): String = "ap0"
                override fun querySoftApCapability(): SoftApPlatformCapabilitySnapshot = SoftApPlatformCapabilitySnapshot(
                    callbackRegistered = true,
                    capabilityReceived = true,
                    forceDisconnectSupported = true,
                )

                override fun readSoftApConfiguration(): SoftApConfigSnapshot {
                    if (!shizukuAlive) return SoftApConfigSnapshot(readable = false, errorDetail = "Shizuku dead")
                    val blockedSorted = currentBlockedList.map { it.uppercase() }.distinct()
                    val allowedSorted = currentAllowedList.map { it.uppercase() }.distinct()
                    return SoftApConfigSnapshot(
                        readable = true,
                        ssidPresent = true,
                        ssidLength = 10,
                        securityType = 1,
                        bandsSummary = "1,2",
                        maxNumberOfClients = 10,
                        clientControlByUserEnabled = true,
                        blockedClientMacs = blockedSorted,
                        allowedClientMacs = allowedSorted,
                        configFingerprint = "fp1234567890",
                    )
                }

                override fun writeBlockedClientList(updatedBlockedMacs: List<String>): SoftApWriteOutcome {
                    if (!shizukuAlive || !setConfigSucceeds) {
                        return SoftApWriteOutcome(
                            invoked = false,
                            returnedTrue = false,
                            readbackSnapshot = readSoftApConfiguration(),
                            errorDetail = "Write rejected",
                        )
                    }
                    currentBlockedList.clear()
                    currentBlockedList.addAll(updatedBlockedMacs.map { it.uppercase() }.distinct())
                    if (disconnectClientAOnBlock && clientAMac in currentBlockedList) {
                        connectedHotspotMacs.remove(clientAMac)
                    } else if (clientAMac !in currentBlockedList) {
                        connectedHotspotMacs.add(clientAMac)
                    }
                    if (disconnectClientBCollateral && clientAMac in currentBlockedList) {
                        connectedHotspotMacs.remove(clientBMac)
                    }
                    return SoftApWriteOutcome(
                        invoked = true,
                        returnedTrue = true,
                        readbackSnapshot = readSoftApConfiguration(),
                    )
                }

                override fun queryConnectedClientMacs(): List<String> = connectedHotspotMacs.toList()
            }

            val journal = SoftApOwnershipJournal(journalFile = tempJournalFile)
            val engine = SoftApMacBlockEngine(
                platformAdapter = mockAdapter,
                journal = journal,
            )

            // 1. Read-only capability inspection -> PROBE_REQUIRED, captures priorUserMac
            val cap = engine.inspectCapability()
            assertEquals(SoftApEngineState.PROBE_REQUIRED, engine.currentState())
            assertTrue(cap.getSoftApConfigSupported)
            assertTrue(cap.setSoftApConfigSupported)
            assertEquals(listOf(priorUserMac), journal.currentSnapshot().priorBlockedMacs)

            // 2. Unconfirmed live probe must not mutate
            val unconfirmed = engine.runControlledLiveProbe(clientAMac, clientBMac, userConfirmed = false)
            assertFalse(unconfirmed.probePassed)
            assertEquals(SoftApEngineState.PROBE_REQUIRED, unconfirmed.resultingState)

            // 3. Live probe where Client A fails to disconnect within timeout -> LIVE_UPDATE_UNSUPPORTED & restores config
            disconnectClientAOnBlock = false
            val noLiveDisconnect = engine.runControlledLiveProbe(
                clientAMac = clientAMac,
                clientBMac = clientBMac,
                userConfirmed = true,
                disconnectTimeoutMs = 300L,
                pollIntervalMs = 50L,
            )
            assertEquals(SoftApEngineState.LIVE_UPDATE_UNSUPPORTED, engine.currentState())
            assertFalse(noLiveDisconnect.clientADisconnected)
            assertTrue(noLiveDisconnect.restoredVerified)
            assertEquals(listOf(priorUserMac), currentBlockedList.toList())
            disconnectClientAOnBlock = true

            // 4. Live probe where Client B also disconnects (collateral hotspot restart) -> fails probe
            disconnectClientBCollateral = true
            connectedHotspotMacs.add(clientAMac)
            connectedHotspotMacs.add(clientBMac)
            val collateralFail = engine.runControlledLiveProbe(
                clientAMac = clientAMac,
                clientBMac = clientBMac,
                userConfirmed = true,
                disconnectTimeoutMs = 300L,
                pollIntervalMs = 50L,
            )
            assertFalse(collateralFail.probePassed)
            assertFalse(collateralFail.clientBRemainedConnected)
            assertTrue(collateralFail.restoredVerified)
            disconnectClientBCollateral = false
            connectedHotspotMacs.add(clientAMac)
            connectedHotspotMacs.add(clientBMac)

            // 5. Successful 2-client live probe -> transitions to READY and preserves priorBlockedMacs
            val probePass = engine.runControlledLiveProbe(
                clientAMac = clientAMac,
                clientBMac = clientBMac,
                userConfirmed = true,
                disconnectTimeoutMs = 600L,
                pollIntervalMs = 40L,
            )
            assertTrue(probePass.probePassed)
            assertEquals("READY", probePass.verdict)
            assertEquals(SoftApEngineState.READY, engine.currentState())
            assertTrue(probePass.clientADisconnected)
            assertTrue(probePass.clientBRemainedConnected)
            assertTrue(probePass.restoredVerified)
            assertEquals(listOf(priorUserMac), currentBlockedList.toList())

            // 6. Activate mode and enforce rules:
            // - clientAMac is manually blocked -> BLOCK_CONFIRMED, added to SoftAP blocked list alongside priorUserMac
            // - allowlistedMac is manually blocked -> CONFLICT_ALLOWLIST, never added to SoftAP blocked list
            connectedHotspotMacs.add(clientAMac)
            val (activated, _) = engine.activateEngine(
                rules = listOf(
                    ClientRule(mac = clientAMac, isBlocked = true),
                    ClientRule(mac = allowlistedMac, isBlocked = true),
                ),
            )
            assertTrue(activated)
            assertEquals(SoftApEngineState.ACTIVE, engine.currentState())
            assertEquals(setOf(priorUserMac, clientAMac), currentBlockedList.toSet())
            assertEquals(listOf(priorUserMac), journal.currentSnapshot().priorBlockedMacs)
            assertEquals(listOf(clientAMac), journal.currentSnapshot().appOwnedMacs)

            val recordsByMac = engine.getClientRecords().associateBy { it.mac }
            assertEquals(SoftApAppliedState.BLOCK_CONFIRMED, recordsByMac[clientAMac]?.appliedState)
            assertEquals(SoftApAppliedState.CONFLICT_ALLOWLIST, recordsByMac[allowlistedMac]?.appliedState)

            // 7. Simulate Shizuku dying before teardown -> ROLLBACK_REQUIRED
            shizukuAlive = false
            val (deactivatedWhileDead, _) = engine.deactivateAndRollbackAllAppOwnedBlocks()
            assertFalse(deactivatedWhileDead)
            assertEquals(SoftApEngineState.ROLLBACK_REQUIRED, engine.currentState())
            assertTrue(journal.currentSnapshot().rollbackRequired)

            // When Shizuku comes back, deactivateAndRollbackAllAppOwnedBlocks succeeds and restores only priorUserMac
            shizukuAlive = true
            val (recovered, _) = engine.deactivateAndRollbackAllAppOwnedBlocks()
            assertTrue(recovered)
            assertEquals(SoftApEngineState.READY, engine.currentState())
            assertFalse(journal.currentSnapshot().rollbackRequired)
            assertEquals(listOf(priorUserMac), currentBlockedList.toList())
        } finally {
            tempJournalFile.delete()
            ExclusiveBlockingModeController.resetForTesting(originalExecutor, originalAdapter)
        }
    }

    @Test
    fun `36 v0_10_7_debug ExclusiveBlockingModeController coordinates all 3 engines with exclusiveEngineInvariant and enforces SoftAP quota exhaustion without duplicate TUN drops`() {
        val originalExecutor = ExclusiveBlockingModeController.preNatEngine.shellExecutor
        val originalAdapter = ExclusiveBlockingModeController.softApEngine.platformAdapter
        try {
            TunTrafficEngine.clearAll()
            val clientAMac = "E2:15:CD:54:E4:9B"
            val clientBMac = "F2:FF:8B:3D:B2:A6"
            val currentBlockedList = mutableListOf<String>()
            val connectedHotspotMacs = mutableSetOf(clientAMac, clientBMac)

            val mockAdapter = object : SoftApPlatformAdapter {
                override fun inspectExecutionIdentity(): SoftApExecutionIdentity = SoftApExecutionIdentity(
                    shizukuState = "SHIZUKU_RUNNING",
                    shizukuRunning = true,
                    shizukuPermissionGranted = true,
                    uid = "2000",
                    gid = "2000",
                    selinuxContext = "u:r:shell:s0",
                    capEff = "0000000000000000",
                    provenance = "LIVE_SHIZUKU_USERSERVICE_PROCESS",
                )
                override fun isHotspotActive(): Boolean = true
                override fun resolveTetherInterface(): String = "ap0"
                override fun querySoftApCapability(): SoftApPlatformCapabilitySnapshot = SoftApPlatformCapabilitySnapshot(
                    callbackRegistered = true,
                    capabilityReceived = true,
                    forceDisconnectSupported = true,
                )
                override fun readSoftApConfiguration(): SoftApConfigSnapshot = SoftApConfigSnapshot(
                    readable = true,
                    clientControlByUserEnabled = true,
                    blockedClientMacs = currentBlockedList.toList(),
                    allowedClientMacs = emptyList(),
                    configFingerprint = "abc1234567890def",
                )
                override fun writeBlockedClientList(updatedBlockedMacs: List<String>): SoftApWriteOutcome {
                    currentBlockedList.clear()
                    currentBlockedList.addAll(updatedBlockedMacs.map { it.uppercase() }.distinct())
                    if (clientAMac in currentBlockedList) connectedHotspotMacs.remove(clientAMac) else connectedHotspotMacs.add(clientAMac)
                    return SoftApWriteOutcome(
                        invoked = true,
                        returnedTrue = true,
                        readbackSnapshot = readSoftApConfiguration(),
                    )
                }
                override fun queryConnectedClientMacs(): List<String> = connectedHotspotMacs.toList()
            }

            ExclusiveBlockingModeController.resetForTesting(originalExecutor, mockAdapter)
            ExclusiveBlockingModeController.checkSoftApCapability()
            val probeRep = ExclusiveBlockingModeController.runSoftApLiveProbe(
                clientAMac = clientAMac,
                clientBMac = clientBMac,
                userConfirmed = true,
                disconnectTimeoutMs = 600L,
                pollIntervalMs = 40L,
            )
            assertEquals(SoftApEngineState.READY, probeRep.engineState)
            connectedHotspotMacs.add(clientAMac)

            // Configure Client A with a 1,000-byte quota and 500 Kbps bandwidth limit (not manually blocked yet)
            val hostA = DiscoveredHost(mac = clientAMac, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "ap0")
            val ruleA = ClientRule(
                mac = clientAMac,
                isBlocked = false,
                bandwidthLimitKbps = 500,
                dataLimitBytes = 1_000L,
                quotaResetPeriod = QuotaResetPeriod.DAILY,
            )
            TunTrafficEngine.syncQuotaRules(listOf(ruleA))

            // Activate SOFTAP_MAC_BLOCK mode
            val softApRep = ExclusiveBlockingModeController.activateSoftApBlockingMode(rules = listOf(ruleA), discoveredHosts = listOf(hostA))
            assertEquals(BlockingMode.SOFTAP_MAC_BLOCK, ExclusiveBlockingModeController.effectiveModeOrNull)
            assertEquals(SoftApEngineState.ACTIVE, softApRep.engineState)
            assertTrue(softApRep.exclusiveEngineInvariant)
            assertFalse("TUN packet drop/throttle enforcement must be disabled when SOFTAP_MAC_BLOCK is active", TunTrafficEngine.bpfNatVpnEnforcementEnabled)

            // HostFirewall.enforce in SOFTAP_MAC_BLOCK mode must keep TunTrafficEngine.bpfNatVpnEnforcementEnabled == false
            HostFirewall.enforce(rules = listOf(ruleA), connectedHosts = listOf(hostA), logSummary = false)
            assertFalse(TunTrafficEngine.bpfNatVpnEnforcementEnabled)
            assertTrue(currentBlockedList.isEmpty())

            // Send a 1,200-byte packet from Client A through TunTrafficEngine:
            // Because bpfNatVpnEnforcementEnabled == false, TUN does NOT drop or throttle the packet,
            // BUT recordQuotaBytes accounts the 1,200 bytes, crosses the 1,000-byte quota, and triggers SoftAP MAC block!
            val pktMeta = TunTrafficEngine.PacketMeta(
                version = 4,
                protocol = 6,
                srcIp = "192.168.167.151",
                dstIp = "1.1.1.1",
                srcPort = 55000,
                dstPort = 443,
                length = 1_200,
                isSmallControlPacket = false,
            )
            val attr = TunTrafficEngine.resolveClientMacWithSource(pktMeta, isUpload = true)
            pktMeta.resolvedAttribution = attr
            val eval = TunTrafficEngine.evaluateAndShapeDetailed(pktMeta, attr.mac, isUpload = true, attributionSource = attr.source)
            assertEquals("TUN engine must not drop packets while SOFTAP_MAC_BLOCK is the active enforcement engine", PacketDecision.ALLOW, eval.decision)
            assertTrue("Crossing data quota must automatically add Client A to SoftAP MAC blocklist", clientAMac in currentBlockedList)

            // Resetting Client A's quota removes QUOTA_EXHAUSTED and unblocks Client A in SoftAP
            TunTrafficEngine.resetClientQuota(clientAMac)
            assertFalse("Resetting Client A quota with no other block reasons must remove Client A from SoftAP MAC blocklist", clientAMac in currentBlockedList)

            // Restore BPF_NAT_VPN mode -> deactivates SoftAP engine and re-enables TUN enforcement
            val restoredBpf = ExclusiveBlockingModeController.restoreBpfNatVpnMode("Switch back to BPF_NAT_VPN")
            assertEquals(BlockingMode.BPF_NAT_VPN, restoredBpf.effectiveMode)
            assertTrue(restoredBpf.exclusiveEngineInvariant)
            assertTrue(TunTrafficEngine.bpfNatVpnEnforcementEnabled)
        } finally {
            ExclusiveBlockingModeController.resetForTesting(originalExecutor, originalAdapter)
            TunTrafficEngine.resetAllQuotaStatesForTest(deleteCheckpointFile = false)
        }
    }

    @Test
    fun `37 v0_10_8_debug DomainNormalizer and DomainRule validate normalize match and deduplicate DB04 DB05 DB13`() {
        // 1. Valid normalization (DB04)
        val normBasic = DomainNormalizer.validateAndNormalize("  *.Example.COM. ")
        assertTrue(normBasic.isValid)
        assertEquals("example.com", normBasic.normalizedDomain)
        assertTrue(normBasic.hadLeadingWildcard)

        // IDNA Punycode normalization
        val normIdna = DomainNormalizer.validateAndNormalize("münchen.de")
        assertTrue(normIdna.isValid)
        assertEquals("xn--mnchen-3ya.de", normIdna.normalizedDomain)

        // 2. Reject invalid inputs (DB04)
        assertFalse("Blank input must be rejected", DomainNormalizer.validateAndNormalize("   ").isValid)
        assertFalse("URL with scheme must be rejected", DomainNormalizer.validateAndNormalize("https://example.com").isValid)
        assertFalse("URL with path must be rejected", DomainNormalizer.validateAndNormalize("example.com/path").isValid)
        assertFalse("Host with port must be rejected", DomainNormalizer.validateAndNormalize("example.com:443").isValid)
        assertFalse("Raw IPv4 literal must be rejected", DomainNormalizer.validateAndNormalize("192.168.1.1").isValid)
        assertFalse("Raw IPv6 literal must be rejected", DomainNormalizer.validateAndNormalize("[2001:db8::1]").isValid)
        assertFalse("Single-label hostname must be rejected", DomainNormalizer.validateAndNormalize("localhost").isValid)
        assertFalse("Mid-string wildcard must be rejected", DomainNormalizer.validateAndNormalize("a.*.example.com").isValid)
        assertFalse("Leading hyphen label must be rejected", DomainNormalizer.validateAndNormalize("-bad.example.com").isValid)

        // 3. INCLUDE_SUBDOMAINS vs EXACT_HOSTNAME matching (DB05)
        assertTrue(DomainNormalizer.matchesDomain("example.com", "example.com", DomainMatchMode.INCLUDE_SUBDOMAINS))
        assertTrue(DomainNormalizer.matchesDomain("a.b.example.com", "example.com", DomainMatchMode.INCLUDE_SUBDOMAINS))
        assertFalse(DomainNormalizer.matchesDomain("notexample.com", "example.com", DomainMatchMode.INCLUDE_SUBDOMAINS))
        assertFalse(DomainNormalizer.matchesDomain("example.org", "example.com", DomainMatchMode.INCLUDE_SUBDOMAINS))

        assertTrue(DomainNormalizer.matchesDomain("example.com", "example.com", DomainMatchMode.EXACT_HOSTNAME))
        assertFalse(DomainNormalizer.matchesDomain("sub.example.com", "example.com", DomainMatchMode.EXACT_HOSTNAME))

        // 4. DomainRule persistence & per-scope deduplication round-trip (DB13)
        val rules = listOf(
            DomainRule(
                id = "r1",
                scope = DomainRuleScope.GLOBAL,
                normalizedDomain = "example.com",
                matchMode = DomainMatchMode.EXACT_HOSTNAME,
                enabled = true,
            ),
            DomainRule(
                id = "r2",
                scope = DomainRuleScope.GLOBAL,
                normalizedDomain = "EXAMPLE.COM.",
                matchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
                enabled = true,
            ),
            DomainRule(
                id = "r3",
                scope = DomainRuleScope.CLIENT,
                clientMac = "e2:15:cd:54:e4:9b",
                normalizedDomain = "tiktok.com",
                matchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
                enabled = true,
            ),
        )
        val encoded = DomainRule.toJsonArrayString(rules)
        val decoded = DomainRule.fromJsonArrayString(encoded)
        assertEquals("Duplicate GLOBAL rules for example.com must deduplicate", 2, decoded.size)
        val globalExample = decoded.first { it.scope == DomainRuleScope.GLOBAL }
        assertEquals(DomainMatchMode.INCLUDE_SUBDOMAINS, globalExample.matchMode)
        val clientTiktok = decoded.first { it.scope == DomainRuleScope.CLIENT }
        assertEquals("E2:15:CD:54:E4:9B", clientTiktok.clientMac)
    }

    @Test
    fun `38 v0_10_8_debug DnsWirePacketParser DnsRefusedResponseBuilder and ConnectionHostnameClassifier handle IPv4 IPv6 DNS RCODE 5 REFUSED malformed packets and TLS SNI HTTP Host DB14 DB15 DB19`() {
        // 1. Build a valid IPv4 UDP/53 query for "ads.example.com" (txId = 0x1234)
        val ipv4DnsQuery = buildIpv4UdpDnsQueryPacket(
            srcIp = "192.168.43.101",
            dstIp = "8.8.8.8",
            srcPort = 54321,
            dstPort = 53,
            txId = 0x1234,
            qname = "Ads.Example.COM",
            qtype = 1,
        )
        val parsedV4 = DnsWirePacketParser.parsePacket(ipv4DnsQuery, ipv4DnsQuery.size)
        assertNotNull(parsedV4)
        assertEquals(4, parsedV4!!.ipVersion)
        assertEquals(17, parsedV4.protocol)
        assertEquals(0x1234, parsedV4.transactionId)
        assertEquals("ads.example.com", parsedV4.qname)
        assertEquals(1, parsedV4.qtype)

        // Synthesize RCODE=5 (REFUSED) response and verify wire fields
        val refusedV4 = DnsRefusedResponseBuilder.buildRefusedResponse(ipv4DnsQuery, ipv4DnsQuery.size, parsedV4)
        assertNotNull(refusedV4)
        // Verify swapped IPv4 src/dst and UDP ports, QR=1, RCODE=5
        val respUdpOffset = 20
        val respDnsOffset = 28
        val respSrcPort = ((refusedV4!![respUdpOffset].toInt() and 0xFF) shl 8) or (refusedV4[respUdpOffset + 1].toInt() and 0xFF)
        val respDstPort = ((refusedV4[respUdpOffset + 2].toInt() and 0xFF) shl 8) or (refusedV4[respUdpOffset + 3].toInt() and 0xFF)
        assertEquals(53, respSrcPort)
        assertEquals(54321, respDstPort)
        val respTxId = ((refusedV4[respDnsOffset].toInt() and 0xFF) shl 8) or (refusedV4[respDnsOffset + 1].toInt() and 0xFF)
        val respFlags = ((refusedV4[respDnsOffset + 2].toInt() and 0xFF) shl 8) or (refusedV4[respDnsOffset + 3].toInt() and 0xFF)
        assertEquals(0x1234, respTxId)
        assertTrue("QR bit must be 1 (response)", (respFlags and 0x8000) != 0)
        assertEquals("RCODE must be 5 (REFUSED)", 5, respFlags and 0x000F)

        // 2. Build an IPv6 UDP/53 query and synthesize RCODE=5 response (DB14)
        val ipv6DnsQuery = buildIpv6UdpDnsQueryPacket(
            srcPort = 51111,
            dstPort = 53,
            txId = 0xABCD,
            qname = "video.tiktok.com",
            qtype = 28,
        )
        val parsedV6 = DnsWirePacketParser.parsePacket(ipv6DnsQuery, ipv6DnsQuery.size)
        assertNotNull(parsedV6)
        assertEquals(6, parsedV6!!.ipVersion)
        assertEquals("video.tiktok.com", parsedV6.qname)
        assertEquals(28, parsedV6.qtype)
        val refusedV6 = DnsRefusedResponseBuilder.buildRefusedResponse(ipv6DnsQuery, ipv6DnsQuery.size, parsedV6)
        assertNotNull(refusedV6)
        val v6RespFlags = ((refusedV6!![48 + 2].toInt() and 0xFF) shl 8) or (refusedV6[48 + 3].toInt() and 0xFF)
        assertEquals(5, v6RespFlags and 0x000F)

        // 3. Malformed / truncated / compression pointer loop safety (DB15)
        val loopPacket = ipv4DnsQuery.copyOf()
        // Replace QNAME first byte with self-referencing compression pointer 0xC0 0x0C
        loopPacket[28 + 12] = 0xC0.toByte()
        loopPacket[28 + 13] = 0x0C.toByte()
        assertNull("Self-referencing DNS compression pointer must return null safely without infinite loop", DnsWirePacketParser.parsePacket(loopPacket, loopPacket.size))
        assertNull("Truncated packet must return null safely", DnsWirePacketParser.parsePacket(ipv4DnsQuery, 15))

        // 4. Bounded TLS ClientHello SNI and HTTP Host extraction (DB19)
        val httpPkt = buildIpv4TcpPayloadPacket(
            srcIp = "192.168.43.101",
            dstIp = "93.184.216.34",
            srcPort = 52000,
            dstPort = 80,
            payload = "GET /index.html HTTP/1.1\r\nHost: Sub.BlockedExample.com:8080\r\nUser-Agent: curl\r\n\r\n".toByteArray(Charsets.US_ASCII),
        )
        val extractedHttp = ConnectionHostnameClassifier.extractHostnameFromPacket(httpPkt, httpPkt.size)
        assertNotNull(extractedHttp)
        assertEquals("sub.blockedexample.com", extractedHttp!!.hostname)
        assertFalse(extractedHttp.isTlsSni)

        val tlsClientHelloPayload = buildTlsClientHelloWithSni("sni.blockedexample.com")
        val tlsPkt = buildIpv4TcpPayloadPacket(
            srcIp = "192.168.43.101",
            dstIp = "93.184.216.34",
            srcPort = 52001,
            dstPort = 443,
            payload = tlsClientHelloPayload,
        )
        val extractedSni = ConnectionHostnameClassifier.extractHostnameFromPacket(tlsPkt, tlsPkt.size)
        assertNotNull(extractedSni)
        assertEquals("sni.blockedexample.com", extractedSni!!.hostname)
        assertTrue(extractedSni.isTlsSni)
    }

    @Test
    fun `39 v0_10_8_debug TunTrafficEngine and DomainFilterEngine enforce GLOBAL and CLIENT domain rules host provenance unknown-owner skip and rule precedence DB06 DB07 DB08 DB09 DB10 DB11 DB12 DB16 DB17 DB20`() {
        try {
            TunTrafficEngine.clearAll()
            ExclusiveBlockingModeController.resetForTesting()

            val macA = "E2:15:CD:54:E4:9B"
            val macB = "F2:FF:8B:3D:B2:A6"
            val hosts = listOf(
                DiscoveredHost(mac = macA, ip = "192.168.43.101", allIps = listOf("192.168.43.101"), interfaceName = "ap0"),
                DiscoveredHost(mac = macB, ip = "192.168.43.102", allIps = listOf("192.168.43.102"), interfaceName = "ap0"),
            )
            TunTrafficEngine.updatePolicies(
                mapOf(
                    macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = false),
                    macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
                ),
                hosts,
            )

            // Configure 1 GLOBAL rule (globalblock.com) and 1 CLIENT rule for macA (clientablock.com)
            val rules = listOf(
                DomainRule(
                    id = "g1",
                    scope = DomainRuleScope.GLOBAL,
                    normalizedDomain = "globalblock.com",
                    matchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
                    enabled = true,
                ),
                DomainRule(
                    id = "c1",
                    scope = DomainRuleScope.CLIENT,
                    clientMac = macA,
                    normalizedDomain = "clientablock.com",
                    matchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
                    enabled = true,
                ),
            )
            val gen1 = TunTrafficEngine.updateDomainRules(rules)
            assertTrue(gen1 > 0L)

            // 1. GLOBAL rule blocks DNS query even when matchedMac == null (post-NAT hotspot TUN packet) (DB06)
            val globalDnsPkt = buildIpv4UdpDnsQueryPacket(
                srcIp = "192.0.2.2",
                dstIp = "8.8.8.8",
                srcPort = 53001,
                dstPort = 53,
                txId = 0x2222,
                qname = "sub.globalblock.com",
            )
            val globalMeta = TunTrafficEngine.parsePacketMeta(globalDnsPkt, globalDnsPkt.size)!!
            val globalEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = globalMeta,
                matchedMac = null,
                isUpload = true,
                attributionSource = AttributionSource.UNMATCHED_UNKNOWN,
                rawPacket = globalDnsPkt,
                rawLength = globalDnsPkt.size,
            )
            assertEquals(PacketDecision.DROP, globalEval.decision)
            assertEquals("DOMAIN_BLOCK_GLOBAL_DNS", globalEval.reason)
            assertNotNull("Blocked UDP/53 query must synthesize RCODE=5 REFUSED response", globalEval.synthesizedDnsResponse)

            // 2. Host-phone local/loopback traffic (127.0.0.1) is NEVER blocked by GLOBAL rules (DB09)
            val loopbackDnsPkt = buildIpv4UdpDnsQueryPacket(
                srcIp = "127.0.0.1",
                dstIp = "8.8.8.8",
                srcPort = 53002,
                dstPort = 53,
                txId = 0x2223,
                qname = "sub.globalblock.com",
            )
            val loopbackMeta = TunTrafficEngine.parsePacketMeta(loopbackDnsPkt, loopbackDnsPkt.size)!!
            val loopbackEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = loopbackMeta,
                matchedMac = null,
                isUpload = true,
                attributionSource = AttributionSource.UNMATCHED_UNKNOWN,
                rawPacket = loopbackDnsPkt,
                rawLength = loopbackDnsPkt.size,
            )
            assertEquals("Host-phone local traffic without hotspot provenance must not be blocked", PacketDecision.ALLOW, loopbackEval.decision)

            // 3. CLIENT rule blocks Client A (DB07) while Client B is allowed (DB08)
            val clientADnsPkt = buildIpv4UdpDnsQueryPacket(
                srcIp = "192.168.43.101",
                dstIp = "8.8.8.8",
                srcPort = 53003,
                dstPort = 53,
                txId = 0x3333,
                qname = "api.clientablock.com",
            )
            val clientAMeta = TunTrafficEngine.parsePacketMeta(clientADnsPkt, clientADnsPkt.size)!!
            val clientAEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = clientAMeta,
                matchedMac = macA,
                isUpload = true,
                attributionSource = AttributionSource.DIRECT_IP,
                rawPacket = clientADnsPkt,
                rawLength = clientADnsPkt.size,
            )
            assertEquals(PacketDecision.DROP, clientAEval.decision)
            assertEquals("DOMAIN_BLOCK_CLIENT_DNS", clientAEval.reason)
            assertNotNull(clientAEval.synthesizedDnsResponse)

            val clientBDnsPkt = buildIpv4UdpDnsQueryPacket(
                srcIp = "192.168.43.102",
                dstIp = "8.8.8.8",
                srcPort = 53004,
                dstPort = 53,
                txId = 0x3334,
                qname = "api.clientablock.com",
            )
            val clientBMeta = TunTrafficEngine.parsePacketMeta(clientBDnsPkt, clientBDnsPkt.size)!!
            val clientBEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = clientBMeta,
                matchedMac = macB,
                isUpload = true,
                attributionSource = AttributionSource.DIRECT_IP,
                rawPacket = clientBDnsPkt,
                rawLength = clientBDnsPkt.size,
            )
            assertEquals("Client B must not be blocked by Client A's per-host domain rule", PacketDecision.ALLOW, clientBEval.decision)

            // 4. Unknown owner (matchedMac == null) skips CLIENT rules and increments DOMAIN_CLIENT_OWNER_UNKNOWN (DB10, DB16)
            val unknownOwnerEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = clientAMeta,
                matchedMac = null,
                isUpload = true,
                attributionSource = AttributionSource.UNMATCHED_UNKNOWN,
                rawPacket = clientADnsPkt,
                rawLength = clientADnsPkt.size,
            )
            assertEquals("Per-client domain rules must not guess packet ownership when matchedMac == null", PacketDecision.ALLOW, unknownOwnerEval.decision)

            val diagReport = TunTrafficEngine.getBpfStatusReport()
            assertTrue(diagReport.domainDiagnostics.unknownOwnerClientRuleSkips >= 1L)
            assertEquals(
                DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.name,
                diagReport.domainDiagnostics.capabilityStatus,
            )

            // 5. Whole-client block takes priority over domain rules (DB11)
            TunTrafficEngine.updatePolicies(
                mapOf(
                    macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true),
                    macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
                ),
                hosts,
            )
            val wholeClientBlockedEval = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = clientAMeta,
                matchedMac = macA,
                isUpload = true,
                attributionSource = AttributionSource.DIRECT_IP,
                rawPacket = clientADnsPkt,
                rawLength = clientADnsPkt.size,
            )
            assertEquals(PacketDecision.DROP, wholeClientBlockedEval.decision)
            assertEquals("BLOCKED_CLIENT_POLICY", wholeClientBlockedEval.reason)

            // Unblock Client A whole-client policy -> Client A domain rule is still active
            TunTrafficEngine.updatePolicies(
                mapOf(
                    macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = false),
                    macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
                ),
                hosts,
            )

            // 6. Removing Client A's domain rule increments ruleGeneration and immediately allows clientablock.com while GLOBAL rule remains active (DB11, DB12)
            val gen2 = TunTrafficEngine.updateDomainRules(rules.filter { it.scope == DomainRuleScope.GLOBAL })
            assertTrue(gen2 > gen1)
            val afterClientRuleRemoved = TunTrafficEngine.evaluateAndShapeDetailed(
                meta = clientAMeta,
                matchedMac = macA,
                isUpload = true,
                attributionSource = AttributionSource.DIRECT_IP,
                rawPacket = clientADnsPkt,
                rawLength = clientADnsPkt.size,
            )
            assertEquals(PacketDecision.ALLOW, afterClientRuleRemoved.decision)

            // 7. Verify Schema v6 export redacts domains and MACs by default (DB20)
            val fullReport = TunTrafficEngine.getBpfStatusReport()
            val redactedJson = fullReport.toJson(includeSensitiveEndpoints = false, includePseudonymousIds = false).toString()
            val redactedMd = fullReport.toMarkdownReport(includeSensitiveEndpoints = false, includePseudonymousIds = false)
            assertFalse("Redacted JSON must not contain raw blocked domain name", redactedJson.contains("globalblock.com"))
            assertFalse("Redacted Markdown must not contain raw blocked domain name", redactedMd.contains("globalblock.com"))
            assertTrue("Redacted export must use Domain# hash token", redactedJson.contains("Domain#"))
            assertFalse(DiagnosticRedactor.containsUnredactedPii(redactedJson))
            assertFalse(DiagnosticRedactor.containsUnredactedPii(redactedMd))
        } finally {
            TunTrafficEngine.clearAll()
        }
    }

    private fun buildIpv4UdpDnsQueryPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        txId: Int,
        qname: String,
        qtype: Int = 1,
    ): ByteArray {
        val qnameBytes = encodeDnsQname(qname)
        val dnsLen = 12 + qnameBytes.size + 4
        val udpLen = 8 + dnsLen
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45.toByte()
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64.toByte()
        pkt[9] = 17.toByte() // UDP
        val srcParts = srcIp.split(".").map { it.toInt() }
        val dstParts = dstIp.split(".").map { it.toInt() }
        for (i in 0..3) {
            pkt[12 + i] = srcParts[i].toByte()
            pkt[16 + i] = dstParts[i].toByte()
        }
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()

        val dnsOffset = 28
        pkt[dnsOffset] = ((txId ushr 8) and 0xFF).toByte()
        pkt[dnsOffset + 1] = (txId and 0xFF).toByte()
        pkt[dnsOffset + 2] = 0x01.toByte() // RD = 1, QR = 0
        pkt[dnsOffset + 3] = 0x00.toByte()
        pkt[dnsOffset + 4] = 0x00.toByte()
        pkt[dnsOffset + 5] = 0x01.toByte() // QDCOUNT = 1
        System.arraycopy(qnameBytes, 0, pkt, dnsOffset + 12, qnameBytes.size)
        val qtypeOffset = dnsOffset + 12 + qnameBytes.size
        pkt[qtypeOffset] = ((qtype ushr 8) and 0xFF).toByte()
        pkt[qtypeOffset + 1] = (qtype and 0xFF).toByte()
        pkt[qtypeOffset + 2] = 0x00.toByte()
        pkt[qtypeOffset + 3] = 0x01.toByte() // QCLASS = IN
        return pkt
    }

    private fun buildIpv6UdpDnsQueryPacket(
        srcPort: Int,
        dstPort: Int,
        txId: Int,
        qname: String,
        qtype: Int = 28,
    ): ByteArray {
        val qnameBytes = encodeDnsQname(qname)
        val dnsLen = 12 + qnameBytes.size + 4
        val udpLen = 8 + dnsLen
        val totalLen = 40 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x60.toByte() // IPv6
        pkt[4] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[5] = (udpLen and 0xFF).toByte()
        pkt[6] = 17.toByte() // Next Header = UDP
        pkt[7] = 64.toByte() // Hop Limit
        // Src IP: 2001:db8::1, Dst IP: 2001:4860:4860::8888
        pkt[8] = 0x20.toByte()
        pkt[9] = 0x01.toByte()
        pkt[23] = 0x01.toByte()
        pkt[24] = 0x20.toByte()
        pkt[25] = 0x01.toByte()
        pkt[38] = 0x88.toByte()
        pkt[39] = 0x88.toByte()

        val udpOffset = 40
        pkt[udpOffset] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[udpOffset + 1] = (srcPort and 0xFF).toByte()
        pkt[udpOffset + 2] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[udpOffset + 3] = (dstPort and 0xFF).toByte()
        pkt[udpOffset + 4] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[udpOffset + 5] = (udpLen and 0xFF).toByte()

        val dnsOffset = 48
        pkt[dnsOffset] = ((txId ushr 8) and 0xFF).toByte()
        pkt[dnsOffset + 1] = (txId and 0xFF).toByte()
        pkt[dnsOffset + 2] = 0x01.toByte()
        pkt[dnsOffset + 5] = 0x01.toByte() // QDCOUNT = 1
        System.arraycopy(qnameBytes, 0, pkt, dnsOffset + 12, qnameBytes.size)
        val qtypeOffset = dnsOffset + 12 + qnameBytes.size
        pkt[qtypeOffset] = ((qtype ushr 8) and 0xFF).toByte()
        pkt[qtypeOffset + 1] = (qtype and 0xFF).toByte()
        pkt[qtypeOffset + 3] = 0x01.toByte()
        return pkt
    }

    private fun encodeDnsQname(domain: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (label in domain.trim('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun buildIpv4TcpPayloadPacket(
        srcIp: String,
        dstIp: String,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val totalLen = 20 + 20 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45.toByte()
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64.toByte()
        pkt[9] = 6.toByte() // TCP
        val srcParts = srcIp.split(".").map { it.toInt() }
        val dstParts = dstIp.split(".").map { it.toInt() }
        for (i in 0..3) {
            pkt[12 + i] = srcParts[i].toByte()
            pkt[16 + i] = dstParts[i].toByte()
        }
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[32] = 0x50.toByte() // Data offset = 5 (20 bytes)
        pkt[33] = 0x18.toByte() // PSH + ACK
        System.arraycopy(payload, 0, pkt, 40, payload.size)
        return pkt
    }

    private fun buildTlsClientHelloWithSni(hostname: String): ByteArray {
        val hostBytes = hostname.toByteArray(Charsets.US_ASCII)
        val sniEntryLen = 1 + 2 + hostBytes.size
        val sniListLen = sniEntryLen
        val extDataLen = 2 + sniListLen
        val extTotalLen = 2 + 2 + extDataLen
        // Handshake body: version(2) + random(32) + session_id_len(1) + cipher_suites_len(2)+suite(2) + comp_len(1)+comp(1) + extensions_len(2) + ext
        val bodyLen = 2 + 32 + 1 + 4 + 2 + 2 + extTotalLen
        val recordLen = 4 + bodyLen
        val out = ByteArray(5 + recordLen)
        var p = 0
        out[p++] = 0x16.toByte() // Handshake
        out[p++] = 0x03.toByte()
        out[p++] = 0x01.toByte()
        out[p++] = ((recordLen ushr 8) and 0xFF).toByte()
        out[p++] = (recordLen and 0xFF).toByte()
        out[p++] = 0x01.toByte() // ClientHello
        out[p++] = 0x00.toByte()
        out[p++] = ((bodyLen ushr 8) and 0xFF).toByte()
        out[p++] = (bodyLen and 0xFF).toByte()
        out[p++] = 0x03.toByte()
        out[p++] = 0x03.toByte() // TLS 1.2
        p += 32 // Random
        out[p++] = 0x00.toByte() // Session ID len = 0
        out[p++] = 0x00.toByte()
        out[p++] = 0x02.toByte() // Cipher suites len = 2
        out[p++] = 0x13.toByte()
        out[p++] = 0x01.toByte()
        out[p++] = 0x01.toByte() // Compression methods len = 1
        out[p++] = 0x00.toByte()
        out[p++] = ((extTotalLen ushr 8) and 0xFF).toByte()
        out[p++] = (extTotalLen and 0xFF).toByte()
        // Extension: server_name (0x0000)
        out[p++] = 0x00.toByte()
        out[p++] = 0x00.toByte()
        out[p++] = ((extDataLen ushr 8) and 0xFF).toByte()
        out[p++] = (extDataLen and 0xFF).toByte()
        out[p++] = ((sniListLen ushr 8) and 0xFF).toByte()
        out[p++] = (sniListLen and 0xFF).toByte()
        out[p++] = 0x00.toByte() // host_name (0)
        out[p++] = ((hostBytes.size ushr 8) and 0xFF).toByte()
        out[p++] = (hostBytes.size and 0xFF).toByte()
        System.arraycopy(hostBytes, 0, out, p, hostBytes.size)
        return out
    }
}



