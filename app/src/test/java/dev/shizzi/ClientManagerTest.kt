package dev.shizzi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientManagerTest {

    @Test
    fun `blocked client reports restriction`() {
        val client = ConnectedClient(
            mac = "AA:BB:CC:DD:EE:FF",
            ip = "192.168.43.50",
            isBlocked = true,
        )
        val (isRestricted, reason) = client.isRestricted()
        assertTrue(isRestricted)
        assertTrue(reason!!.contains("Blocked"))
    }

    @Test
    fun `unrestricted client reports access permitted`() {
        val client = ConnectedClient(
            mac = "AA:BB:CC:DD:EE:FF",
            ip = "192.168.43.50",
            isBlocked = false,
            bandwidthLimitKbps = 1000,
            connectionTimeLimitMinutes = 0,
        )
        val (isRestricted, reason) = client.isRestricted()
        assertFalse(isRestricted)
        assertEquals(null, reason)
    }

    @Test
    fun `connection time limit triggers restriction when elapsed`() {
        val pastTime = System.currentTimeMillis() - 40 * 60_000 // 40 minutes ago
        val client = ConnectedClient(
            mac = "AA:BB:CC:DD:EE:FF",
            ip = "192.168.43.50",
            firstSeenAt = pastTime,
            isBlocked = false,
            connectionTimeLimitMinutes = 30, // 30 minutes limit
        )
        val (isRestricted, reason) = client.isRestricted()
        assertTrue(isRestricted)
        assertTrue(reason!!.contains("Time limit reached"))
    }

    @Test
    fun `client rule serialization and deserialization roundtrip`() {
        val rules = listOf(
            ClientRule(
                mac = "11:22:33:44:55:66",
                alias = "Work Laptop",
                isBlocked = false,
                bandwidthLimitKbps = 5000,
                connectionTimeLimitMinutes = 60,
                scheduleEnabled = true,
                scheduleStartHour = 9,
                scheduleEndHour = 18,
            ),
            ClientRule(
                mac = "AA:BB:CC:DD:EE:FF",
                alias = "Guest Tablet",
                isBlocked = true,
            ),
        )

        val serialized = ClientRule.serializeList(rules)
        val parsed = ClientRule.parseList(serialized)

        assertEquals(2, parsed.size)
        assertEquals("11:22:33:44:55:66", parsed[0].mac)
        assertEquals("Work Laptop", parsed[0].alias)
        assertEquals(5000, parsed[0].bandwidthLimitKbps)
        assertEquals(60, parsed[0].connectionTimeLimitMinutes)
        assertTrue(parsed[0].scheduleEnabled)

        assertEquals("AA:BB:CC:DD:EE:FF", parsed[1].mac)
        assertTrue(parsed[1].isBlocked)
    }

    @Test
    fun `bandwidth limit formatting works across ranges`() {
        val unlimited = ConnectedClient(mac = "AA:BB:CC:DD:EE:FF", ip = "1.1.1.1", bandwidthLimitKbps = 0)
        assertEquals("Unlimited", unlimited.formattedBandwidthLimit())

        val kbps = ConnectedClient(mac = "AA:BB:CC:DD:EE:FF", ip = "1.1.1.1", bandwidthLimitKbps = 512)
        assertEquals("512 Kbps", kbps.formattedBandwidthLimit())

        val mbps = ConnectedClient(mac = "AA:BB:CC:DD:EE:FF", ip = "1.1.1.1", bandwidthLimitKbps = 10000)
        assertEquals("10 Mbps", mbps.formattedBandwidthLimit())
    }

    @Test
    fun `scenario 1 and 10 - 0 connected clients with 295 wifi scan BSSIDs returns 0 connected devices`() {
        val scanBssids = (1..295).joinToString("\n") { idx ->
            val b1 = (idx / 100).toString(16).padStart(2, '0')
            val b2 = (idx % 100).toString(16).padStart(2, '0')
            "  ScanResult: BSSID=02:11:22:33:$b1:$b2 SSID=NeighborWifi_$idx"
        }
        val dumpsysWifi = """
            Dump of WifiService:
            SoftApManager:
              mApInterfaceName: wlan1
              getConnectedClientList().size(): 0
            WifiScanner:
            $scanBssids
        """.trimIndent()

        val wifiDump = DownstreamInspector.parseWifiSoftApDump(dumpsysWifi)
        assertEquals(0, wifiDump.reportedCount)
        assertTrue(wifiDump.connectedMacs.isEmpty())

        val neighbors = DownstreamInspector.parseIpNeighOutput(
            """
            192.168.1.1 dev wlan0 lladdr 88:99:aa:bb:cc:dd REACHABLE
            192.168.43.55 dev wlan1 lladdr aa:bb:cc:dd:ee:01 STALE
            """.trimIndent(),
        )

        val verified = DownstreamInspector.buildVerifiedConnectedClients(
            wifiDump = wifiDump,
            tetheredInterfaces = setOf("wlan1"),
            neighbors = neighbors,
        )
        assertEquals(0, verified.size)

        // Saved rules for offline devices must never inflate connected client count
        val savedRules = listOf(ClientRule(mac = "AA:BB:CC:DD:EE:01", isBlocked = true))
        val uiClients = ClientDiscovery.discoverClients(
            savedRules = savedRules,
            discoveredHosts = verified,
            activeClientCount = verified.size,
        )
        assertEquals(0, uiClients.size)
    }

    @Test
    fun `scenario 2 - 1 connected client with 295 scan BSSIDs returns exactly 1 connected device with IPv4 and IPv6`() {
        val scanBssids = (1..294).joinToString("\n") { idx ->
            val b1 = (idx / 100).toString(16).padStart(2, '0')
            val b2 = (idx % 100).toString(16).padStart(2, '0')
            "  ScanResult: BSSID=02:aa:bb:cc:$b1:$b2 SSID=AP_$idx"
        }
        val dumpsysWifi = """
            SoftApManager:
              mApInterfaceName: wlan1
              getConnectedClientList().size(): 1
              WifiClient{mMacAddress=d4:6a:6a:12:34:56 mApInstanceIdentifier=wlan1}
            WifiScanningService:
            $scanBssids
        """.trimIndent()

        val wifiDump = DownstreamInspector.parseWifiSoftApDump(dumpsysWifi)
        assertEquals(1, wifiDump.reportedCount)
        assertEquals(listOf("D4:6A:6A:12:34:56"), wifiDump.connectedMacs)

        // Even when IPv6 link-local appears before IPv4 in `ip neigh`, primary ip must be IPv4
        val neighbors = DownstreamInspector.parseIpNeighOutput(
            """
            fe80::d66a:6aff:fe12:3456 dev wlan1 lladdr d4:6a:6a:12:34:56 STALE
            192.168.43.105 dev wlan1 lladdr d4:6a:6a:12:34:56 REACHABLE
            192.168.1.1 dev wlan0 lladdr 10:20:30:40:50:60 REACHABLE
            """.trimIndent(),
        )

        val verified = DownstreamInspector.buildVerifiedConnectedClients(
            wifiDump = wifiDump,
            tetheredInterfaces = setOf("wlan1"),
            neighbors = neighbors,
        )
        assertEquals(1, verified.size)
        assertEquals("D4:6A:6A:12:34:56", verified[0].mac)
        assertEquals("192.168.43.105", verified[0].ip)
        assertEquals(2, verified[0].allIps.size)
        assertTrue(verified[0].allIps.contains("192.168.43.105"))
        assertTrue(verified[0].allIps.contains("fe80::d66a:6aff:fe12:3456"))
    }

    @Test
    fun `scenario 3, 4, 5 - multiple clients connect, disconnect, and reconnect restoring rules`() {
        val dumpsysTwoClients = """
            SoftApManager:
              mApInterfaceName: ap0
              getConnectedClientList().size(): 2
              WifiClient{mMacAddress=aa:bb:cc:00:00:01 mApInstanceIdentifier=ap0}
              WifiClient{mMacAddress=aa:bb:cc:00:00:02 mApInstanceIdentifier=ap0}
        """.trimIndent()

        val neighbors = DownstreamInspector.parseIpNeighOutput(
            """
            192.168.43.10 dev ap0 lladdr aa:bb:cc:00:00:01 REACHABLE
            192.168.43.11 dev ap0 lladdr aa:bb:cc:00:00:02 REACHABLE
            """.trimIndent(),
        )

        val rules = listOf(
            ClientRule(mac = "AA:BB:CC:00:00:01", alias = "Phone 1", bandwidthLimitKbps = 1000),
            ClientRule(mac = "AA:BB:CC:00:00:02", alias = "Laptop 2", isBlocked = true),
        )

        val twoVerified = DownstreamInspector.buildVerifiedConnectedClients(
            wifiDump = DownstreamInspector.parseWifiSoftApDump(dumpsysTwoClients),
            tetheredInterfaces = setOf("ap0"),
            neighbors = neighbors,
        )
        val uiTwo = ClientDiscovery.discoverClients(rules, twoVerified, twoVerified.size)
        assertEquals(2, uiTwo.size)
        assertEquals(1000, uiTwo[0].bandwidthLimitKbps)
        assertTrue(uiTwo[1].isBlocked)

        // Client 2 disconnects -> count drops to 1 automatically
        val dumpsysOneClient = """
            SoftApManager:
              mApInterfaceName: ap0
              getConnectedClientList().size(): 1
              WifiClient{mMacAddress=aa:bb:cc:00:00:01 mApInstanceIdentifier=ap0}
        """.trimIndent()
        val oneVerified = DownstreamInspector.buildVerifiedConnectedClients(
            wifiDump = DownstreamInspector.parseWifiSoftApDump(dumpsysOneClient),
            tetheredInterfaces = setOf("ap0"),
            neighbors = neighbors,
        )
        val uiOne = ClientDiscovery.discoverClients(rules, oneVerified, oneVerified.size)
        assertEquals(1, uiOne.size)
        assertEquals("AA:BB:CC:00:00:01", uiOne[0].cleanMac)

        // Client 2 reconnects -> rule is automatically restored
        val reconnected = ClientDiscovery.discoverClients(rules, twoVerified, twoVerified.size)
        assertEquals(2, reconnected.size)
        assertTrue(reconnected.first { it.cleanMac == "AA:BB:CC:00:00:02" }.isBlocked)
    }

    @Test
    fun `scenario 6, 7, 8 - real-time bandwidth limit and block enforcement summary with honest state`() {
        val connected = listOf(
            DiscoveredHost(
                mac = "AA:BB:CC:DD:EE:FF",
                ip = "192.168.43.20",
                allIps = listOf("192.168.43.20", "fe80::1"),
                interfaceName = "wlan1",
            ),
        )

        // 1. Enforce 1 Mbps (1000 Kbps) limit
        val throttleRule = listOf(ClientRule(mac = "AA:BB:CC:DD:EE:FF", bandwidthLimitKbps = 1000))
        val summary1 = HostFirewall.enforce(throttleRule, connected)
        assertEquals(1, summary1.connectedClientsCount)
        assertEquals(0, summary1.blockedConnectedCount)
        assertEquals(1, summary1.throttledConnectedCount)

        // 2. Block device in real time
        val blockRule = listOf(ClientRule(mac = "AA:BB:CC:DD:EE:FF", isBlocked = true, bandwidthLimitKbps = 1000))
        val summary2 = HostFirewall.enforce(blockRule, connected)
        assertEquals(1, summary2.blockedConnectedCount)
        assertEquals(0, summary2.throttledConnectedCount)

        // 3. Unblock device and remove bandwidth limit
        val unrestrictedRule = listOf(ClientRule(mac = "AA:BB:CC:DD:EE:FF", isBlocked = false, bandwidthLimitKbps = 0))
        val summary3 = HostFirewall.enforce(unrestrictedRule, connected)
        assertEquals(0, summary3.policyInstalledOnConnectedCount)
        assertEquals(0, summary3.verifiedEnforcedOnConnectedCount)
        assertEquals(0, summary3.blockedConnectedCount)
        assertEquals(0, summary3.throttledConnectedCount)

        HostFirewall.clearAll()
    }

    @Test
    fun `post-NAT 192_0_2_2 upload and download packets match connected S25 client and drop when blocked`() {
        TunTrafficEngine.clearAll()
        val s25Mac = "E2:15:CD:54:E4:9B"
        val s25Host = DiscoveredHost(
            mac = s25Mac,
            ip = "192.168.167.151",
            allIps = listOf("192.168.167.151"),
            interfaceName = "swlan0",
        )
        val blockPolicy = TunTrafficEngine.EnforcedClientPolicy(
            mac = s25Mac,
            isBlocked = true,
            blockReason = "Blocked by administrator",
            bandwidthLimitKbps = 1000,
        )
        TunTrafficEngine.updatePolicies(mapOf(s25Mac to blockPolicy), listOf(s25Host))

        // Parse conntrack entry for flow (deterministic NAT attribution without single-client heuristic)
        val conntrackLine =
            "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.167.151 dst=142.250.190.46 sport=54321 dport=443 src=142.250.190.46 dst=192.0.2.2 sport=443 dport=54321 [ASSURED] mark=0 use=2"
        assertTrue(TunTrafficEngine.parseConntrackLine(conntrackLine))

        // Build IPv4 TCP upload packet after Android Tethering MASQUERADE:
        // src = 192.0.2.2 (TUN_LOCAL_V4), dst = 142.250.190.46 (remote server), sport = 54321, dport = 443
        val uploadPkt = buildIpv4TcpPacket(
            srcIp = intArrayOf(192, 0, 2, 2),
            dstIp = intArrayOf(142, 250, 190, 46),
            srcPort = 54321,
            dstPort = 443,
            totalLength = 120,
        )
        val uploadMeta = TunTrafficEngine.parsePacketMeta(uploadPkt, uploadPkt.size)!!
        val uploadMatchedMac = TunTrafficEngine.resolveClientMacForPacket(uploadMeta, isUpload = true)
        assertEquals(s25Mac, uploadMatchedMac)
        val uploadDecision = TunTrafficEngine.evaluateAndShape(uploadMeta, uploadMatchedMac, isUpload = true)
        assertEquals(PacketDecision.DROP, uploadDecision)

        // Build IPv4 TCP download packet heading back to 192.0.2.2:
        // src = 142.250.190.46, dst = 192.0.2.2, sport = 443, dport = 54321
        val downloadPkt = buildIpv4TcpPacket(
            srcIp = intArrayOf(142, 250, 190, 46),
            dstIp = intArrayOf(192, 0, 2, 2),
            srcPort = 443,
            dstPort = 54321,
            totalLength = 1400,
        )
        val downloadMeta = TunTrafficEngine.parsePacketMeta(downloadPkt, downloadPkt.size)!!
        val downloadMatchedMac = TunTrafficEngine.resolveClientMacForPacket(downloadMeta, isUpload = false)
        assertEquals(s25Mac, downloadMatchedMac)
        val downloadDecision = TunTrafficEngine.evaluateAndShape(downloadMeta, downloadMatchedMac, isUpload = false)
        assertEquals(PacketDecision.DROP, downloadDecision)

        val stats = TunTrafficEngine.getCounterSnapshot(s25Mac)
        assertEquals(2L, stats.seenPackets)
        assertEquals(2L, stats.matchedPackets)
        assertEquals(2L, stats.droppedPackets)

        // Unblock and verify 1 Mbps (1000 Kbps) rate-limiting allows packets and records shapedBytes
        val throttleOnlyPolicy = blockPolicy.copy(isBlocked = false, bandwidthLimitKbps = 1000)
        TunTrafficEngine.updatePolicies(mapOf(s25Mac to throttleOnlyPolicy), listOf(s25Host))

        val shapedDecision = TunTrafficEngine.evaluateAndShape(downloadMeta, downloadMatchedMac, isUpload = false)
        assertEquals(PacketDecision.ALLOW, shapedDecision)

        val updatedStats = TunTrafficEngine.getCounterSnapshot(s25Mac)
        assertEquals(1L, updatedStats.matchedPackets)
        assertEquals(0L, updatedStats.droppedPackets)
        assertTrue(updatedStats.shapedBytes >= 1400L)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `multi-client isolation - Client A blocked and Client B allowed never leaks drops to Client B`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B"
        val macB = "00:A5:54:56:D0:D3"
        val hostA = DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "swlan0")
        val hostB = DiscoveredHost(mac = macB, ip = "192.168.167.242", allIps = listOf("192.168.167.242"), interfaceName = "swlan0")

        val policyA = TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true, blockReason = "Admin block")
        val policyB = TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false, bandwidthLimitKbps = 0)
        TunTrafficEngine.updatePolicies(mapOf(macA to policyA, macB to policyB), listOf(hostA, hostB))

        // Attribute flows via conntrack for both clients
        val conntrackA = "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.167.151 dst=142.250.190.46 sport=50001 dport=443 src=142.250.190.46 dst=192.0.2.2 sport=443 dport=50001 [ASSURED] mark=0 use=2"
        val conntrackB = "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.167.242 dst=142.250.190.46 sport=50002 dport=443 src=142.250.190.46 dst=192.0.2.2 sport=443 dport=50002 [ASSURED] mark=0 use=2"
        assertTrue(TunTrafficEngine.parseConntrackLine(conntrackA))
        assertTrue(TunTrafficEngine.parseConntrackLine(conntrackB))

        // Packet from Client A (port 50001) -> DROP
        val pktA = buildIpv4TcpPacket(intArrayOf(192, 0, 2, 2), intArrayOf(142, 250, 190, 46), 50001, 443, 100)
        val metaA = TunTrafficEngine.parsePacketMeta(pktA, pktA.size)!!
        val matchedA = TunTrafficEngine.resolveClientMacForPacket(metaA, isUpload = true)
        assertEquals(macA, matchedA)
        assertEquals(PacketDecision.DROP, TunTrafficEngine.evaluateAndShape(metaA, matchedA, isUpload = true))

        // Packet from Client B (port 50002) -> ALLOW
        val pktB = buildIpv4TcpPacket(intArrayOf(192, 0, 2, 2), intArrayOf(142, 250, 190, 46), 50002, 443, 100)
        val metaB = TunTrafficEngine.parsePacketMeta(pktB, pktB.size)!!
        val matchedB = TunTrafficEngine.resolveClientMacForPacket(metaB, isUpload = true)
        assertEquals(macB, matchedB)
        assertEquals(PacketDecision.ALLOW, TunTrafficEngine.evaluateAndShape(metaB, matchedB, isUpload = true))

        // Verify statistics: Client A has 1 drop, Client B has 0 drops
        val snapshotA = TunTrafficEngine.getCounterSnapshot(macA)
        val snapshotB = TunTrafficEngine.getCounterSnapshot(macB)
        assertEquals(1L, snapshotA.droppedPackets)
        assertEquals(0L, snapshotB.droppedPackets)
        assertEquals(1L, snapshotB.forwardedPackets)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `strict IP pruning removes old IP when client reassigns address`() {
        TunTrafficEngine.clearAll()
        val mac = "AA:BB:CC:11:22:33"
        val host1 = DiscoveredHost(mac = mac, ip = "192.168.167.10", allIps = listOf("192.168.167.10"), interfaceName = "swlan0")
        val policy = TunTrafficEngine.EnforcedClientPolicy(mac = mac, isBlocked = true)
        TunTrafficEngine.updatePolicies(mapOf(mac to policy), listOf(host1))

        // Client reassigns to 192.168.167.20
        val host2 = DiscoveredHost(mac = mac, ip = "192.168.167.20", allIps = listOf("192.168.167.20"), interfaceName = "swlan0")
        TunTrafficEngine.updatePolicies(mapOf(mac to policy), listOf(host2))

        // Packet for old IP (192.168.167.10) must NOT resolve to this client
        val oldPkt = buildIpv4TcpPacket(intArrayOf(192, 168, 167, 10), intArrayOf(8, 8, 8, 8), 12345, 53, 60)
        val metaOld = TunTrafficEngine.parsePacketMeta(oldPkt, oldPkt.size)!!
        assertEquals(null, TunTrafficEngine.resolveClientMacForPacket(metaOld, isUpload = true))

        // Packet for new IP (192.168.167.20) must resolve to this client
        val newPkt = buildIpv4TcpPacket(intArrayOf(192, 168, 167, 20), intArrayOf(8, 8, 8, 8), 12345, 53, 60)
        val metaNew = TunTrafficEngine.parsePacketMeta(newPkt, newPkt.size)!!
        assertEquals(mac, TunTrafficEngine.resolveClientMacForPacket(metaNew, isUpload = true))

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `IPv6 2001_db8 prefix EUI-64 and temporary addresses match connected client`() {
        TunTrafficEngine.clearAll()
        val mac = "E2:15:CD:54:E4:9B"
        // EUI-64 for E2:15:CD:54:E4:9B flips bit 1 of 0xE2 -> 0xE0: 2001:db8::e015:cdff:fe54:e49b
        val extracted = TunTrafficEngine.extractMacFromIpv6Eui64("2001:db8:0:0:e015:cdff:fe54:e49b")
        assertEquals(mac, extracted)

        val host = DiscoveredHost(
            mac = mac,
            ip = "192.168.167.151",
            allIps = listOf("192.168.167.151"),
            interfaceName = "swlan0",
        )
        val blockPolicy = TunTrafficEngine.EnforcedClientPolicy(mac = mac, isBlocked = true)
        TunTrafficEngine.updatePolicies(mapOf(mac to blockPolicy), listOf(host))

        // Privacy/temporary IPv6 address in 2001:db8::/64 subnet (2001:db8::9999)
        val ipv6Upload = buildIpv6UdpPacket(
            srcWords = intArrayOf(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x9999),
            dstWords = intArrayOf(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            srcPort = 51000,
            dstPort = 443,
        )
        val meta = TunTrafficEngine.parsePacketMeta(ipv6Upload, ipv6Upload.size)!!
        // Pre-bind temporary address via neighbor list
        val hostWithIpv6 = host.copy(allIps = listOf("192.168.167.151", "2001:db8::9999"))
        TunTrafficEngine.updatePolicies(mapOf(mac to blockPolicy), listOf(hostWithIpv6))

        val matchedMac = TunTrafficEngine.resolveClientMacForPacket(meta, isUpload = true)
        assertEquals(mac, matchedMac)
        val decision = TunTrafficEngine.evaluateAndShape(meta, matchedMac, isUpload = true)
        assertEquals(PacketDecision.DROP, decision)
        assertEquals(1L, TunTrafficEngine.getCounterSnapshot(mac).droppedPackets)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `SYNTHETIC FIXTURE - conntrack parser resolves post-NAT 192_0_2_2 flow to original downstream client IP across two clients`() {
        // NOTE: This test uses a SYNTHETIC conntrack line to verify parser and 5-tuple lookup logic only.
        // It does NOT prove that /proc/net/nf_conntrack is readable under Shizuku UID 2000 on a physical phone.
        TunTrafficEngine.clearAll()
        val clientAMac = "AA:BB:CC:00:00:01"
        val clientBMac = "AA:BB:CC:00:00:02"
        val hosts = listOf(
            DiscoveredHost(mac = clientAMac, ip = "192.168.167.10", allIps = listOf("192.168.167.10"), interfaceName = "swlan0"),
            DiscoveredHost(mac = clientBMac, ip = "192.168.167.20", allIps = listOf("192.168.167.20"), interfaceName = "swlan0"),
        )
        val policies = mapOf(
            clientAMac to TunTrafficEngine.EnforcedClientPolicy(mac = clientAMac, isBlocked = true),
            clientBMac to TunTrafficEngine.EnforcedClientPolicy(mac = clientBMac, isBlocked = false, bandwidthLimitKbps = 0),
        )
        TunTrafficEngine.updatePolicies(policies, hosts)

        val syntheticConntrack =
            "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.167.10 dst=142.250.190.46 sport=41000 dport=443 src=142.250.190.46 dst=192.0.2.2 sport=443 dport=41000 [ASSURED] mark=0 use=2"
        assertTrue(TunTrafficEngine.parseConntrackLine(syntheticConntrack))

        val pkt = buildIpv4TcpPacket(
            srcIp = intArrayOf(192, 0, 2, 2),
            dstIp = intArrayOf(142, 250, 190, 46),
            srcPort = 41000,
            dstPort = 443,
            totalLength = 100,
        )
        val meta = TunTrafficEngine.parsePacketMeta(pkt, pkt.size)!!
        val matchedMac = TunTrafficEngine.resolveClientMacForPacket(meta, isUpload = true)
        assertEquals(clientAMac, matchedMac)
        val decision = TunTrafficEngine.evaluateAndShape(meta, matchedMac, isUpload = true)
        assertEquals(PacketDecision.DROP, decision)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `honest EnforcementState never claims verified enforcement on DIRECT_TUN_FALLBACK, stale counters, or post-NAT leak`() {
        val emptySnapshot = TunTrafficEngine.CounterSnapshot(
            mac = "E2:15:CD:54:E4:9B",
            seenPackets = 0L,
            matchedPackets = 0L,
            forwardedPackets = 0L,
            droppedPackets = 0L,
            blockedDropPackets = 0L,
            shapingDropPackets = 0L,
            shapedPackets = 0L,
            rxBytes = 0L,
            txBytes = 0L,
            droppedBytes = 0L,
            shapedBytes = 0L,
            policyInstalled = false,
            policyVersion = 1L,
            policyVersionBlockedDrops = 0L,
            unattributedPostNatObserved = false,
        )

        // 1. Direct-TUN fallback without kernel netfilter -> ENFORCEMENT_UNAVAILABLE
        TunTrafficEngine.markDirectTunFallback("testtun0", "Simulated socketpair failure")
        val unavailableState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 1000,
            counters = emptySnapshot,
            datapathMode = DatapathMode.DIRECT_TUN_FALLBACK,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.ENFORCEMENT_UNAVAILABLE, unavailableState)

        // 2. Inactive datapath -> CONFIGURED (saved intent, not active datapath)
        TunTrafficEngine.stop()
        val configuredState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot,
            datapathMode = DatapathMode.INACTIVE,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.CONFIGURED, configuredState)

        // 3. Stale cumulative droppedPackets (1082) with policyVersionBlockedDrops == 0 must NOT report PACKETS_DROPPED
        val staleCounterState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(
                policyInstalled = true,
                droppedPackets = 1082L,
                shapingDropPackets = 1082L,
                policyVersionBlockedDrops = 0L,
            ),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.POLICY_INSTALLED, staleCounterState)

        // 4. Current policy version has drops (41), BUT unattributed post-NAT packets are escaping -> DEGRADED_MULTI_CLIENT
        val leakWithPartialDropsState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(
                policyInstalled = true,
                matchedPackets = 41L,
                droppedPackets = 41L,
                blockedDropPackets = 41L,
                policyVersionBlockedDrops = 41L,
                unattributedPostNatObserved = true,
            ),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.DEGRADED_MULTI_CLIENT, leakWithPartialDropsState)

        // 5. Userspace proxy active + policyVersionBlockedDrops > 0 + no post-NAT leak -> PACKETS_DROPPED
        val verifiedDropState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(
                policyInstalled = true,
                matchedPackets = 5L,
                droppedPackets = 5L,
                blockedDropPackets = 5L,
                policyVersionBlockedDrops = 5L,
                unattributedPostNatObserved = false,
            ),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.PACKETS_DROPPED, verifiedDropState)

        // 6. Unrestricted client must always report UNRESTRICTED even with non-zero past drops
        val unrestrictedState = HostFirewall.computeClientEnforcementState(
            isRestricted = false,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(droppedPackets = 358L, policyVersionBlockedDrops = 358L),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.UNRESTRICTED, unrestrictedState)
    }

    @Test
    fun `empty flow cache post-NAT packet leak marks unattributedPostNatObserved and degrades blocked client state`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B"
        val hostA = DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "swlan0")
        val policyA = TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true, blockReason = "Manual block")
        TunTrafficEngine.updatePolicies(mapOf(macA to policyA), listOf(hostA))

        // Flow cache is empty (no synthetic conntrack pre-loaded).
        // Send a post-NAT packet (src=192.0.2.2 -> dst=8.8.8.8) as observed on the user's phone:
        val postNatDnsPkt = buildIpv4TcpPacket(intArrayOf(192, 0, 2, 2), intArrayOf(8, 8, 8, 8), 55111, 53, 80)
        val meta = TunTrafficEngine.parsePacketMeta(postNatDnsPkt, postNatDnsPkt.size)!!
        val matchedMac = TunTrafficEngine.resolveClientMacForPacket(meta, isUpload = true)
        assertEquals(null, matchedMac)

        val decision = TunTrafficEngine.evaluateAndShape(meta, matchedMac, isUpload = true)
        // Engine does not globally drop unknown traffic (which would break Client B),
        // but MUST record postNatUnmatchedPackets and mark the blocked client as unattributedPostNatObserved!
        assertEquals(PacketDecision.ALLOW, decision)
        assertTrue(TunTrafficEngine.postNatUnmatchedPackets.get() > 0L)

        val snapA = TunTrafficEngine.getCounterSnapshot(macA)
        assertTrue(snapA.unattributedPostNatObserved)

        val uiClients = ClientDiscovery.discoverClients(
            savedRules = listOf(ClientRule(mac = macA, isBlocked = true)),
            discoveredHosts = listOf(
                hostA.copy(
                    droppedPackets = 41L,
                    blockedDropPackets = 41L,
                    policyVersionBlockedDrops = 41L,
                    unattributedPostNatObserved = snapA.unattributedPostNatObserved,
                ),
            ),
            activeClientCount = 1,
            datapathMode = DatapathMode.USERSPACE_PROXY,
            firewallBackend = FirewallBackend.USERSPACE,
            kernelNetfilterAvailable = false,
        )
        assertEquals(EnforcementState.DEGRADED_MULTI_CLIENT, uiClients[0].enforcementState)
        assertTrue(uiClients[0].formattedBlockStatusLabel().contains("degraded"))

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `IPv6 link-local multicast control traffic fe80 to ff02_2 is not treated as post-NAT internet leak`() {
        TunTrafficEngine.clearAll()
        val macA = "E2:15:CD:54:E4:9B"
        val hostA = DiscoveredHost(mac = macA, ip = "192.168.167.151", allIps = listOf("192.168.167.151"), interfaceName = "swlan0")
        val policyA = TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true)
        TunTrafficEngine.updatePolicies(mapOf(macA to policyA), listOf(hostA))

        // fe80::1234 -> ff02::2 (All Routers multicast)
        val rsPkt = buildIpv6UdpPacket(
            srcWords = intArrayOf(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234),
            dstWords = intArrayOf(0xff02, 0, 0, 0, 0, 0, 0, 0x0002),
            srcPort = 0,
            dstPort = 0,
        )
        val meta = TunTrafficEngine.parsePacketMeta(rsPkt, rsPkt.size)!!
        assertTrue(TunTrafficEngine.isLinkLocalMulticastControl(meta))

        val decision = TunTrafficEngine.evaluateAndShape(meta, matchedMac = null, isUpload = true)
        assertEquals(PacketDecision.ALLOW, decision)
        assertEquals(1L, TunTrafficEngine.localControlPackets.get())
        assertEquals(0L, TunTrafficEngine.postNatUnmatchedPackets.get())
        assertFalse(TunTrafficEngine.getCounterSnapshot(macA).unattributedPostNatObserved)

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `flow reuse and purgeFlowsForMac invalidates stale NAT port mapping when client changes or cache is cleared`() {
        TunTrafficEngine.clearAll()
        val macA = "AA:BB:CC:00:00:01"
        val macB = "AA:BB:CC:00:00:02"
        val hostA = DiscoveredHost(mac = macA, ip = "192.168.167.10", allIps = listOf("192.168.167.10"), interfaceName = "swlan0")
        val hostB = DiscoveredHost(mac = macB, ip = "192.168.167.20", allIps = listOf("192.168.167.20"), interfaceName = "swlan0")
        TunTrafficEngine.updatePolicies(
            mapOf(
                macA to TunTrafficEngine.EnforcedClientPolicy(mac = macA, isBlocked = true),
                macB to TunTrafficEngine.EnforcedClientPolicy(mac = macB, isBlocked = false),
            ),
            listOf(hostA, hostB),
        )

        // SYNTHETIC conntrack entry attributing port 60000 -> 1.1.1.1:443 to Client A
        val ctLineA =
            "ipv4 2 udp 17 30 src=192.168.167.10 dst=1.1.1.1 sport=60000 dport=443 src=1.1.1.1 dst=192.0.2.2 sport=443 dport=60000 mark=0 use=1"
        assertTrue(TunTrafficEngine.parseConntrackLine(ctLineA))
        assertEquals(1, TunTrafficEngine.getAttributedFlowCount(macA))

        // Purge Client A flows (e.g. for empty-cache test or reconnect)
        val removed = TunTrafficEngine.purgeFlowsForMac(macA)
        assertEquals(1, removed)
        assertEquals(0, TunTrafficEngine.getAttributedFlowCount(macA))

        // Now Client B reuses NAT port 60000 to 1.1.1.1:443
        val ctLineB =
            "ipv4 2 udp 17 30 src=192.168.167.20 dst=1.1.1.1 sport=60000 dport=443 src=1.1.1.1 dst=192.0.2.2 sport=443 dport=60000 mark=0 use=1"
        assertTrue(TunTrafficEngine.parseConntrackLine(ctLineB))
        assertEquals(1, TunTrafficEngine.getAttributedFlowCount(macB))

        TunTrafficEngine.clearAll()
    }

    @Test
    fun `error classification separates PERMISSION_DENIED, COMMAND_MISSING, FILE_MISSING, and TIMEOUT`() {
        assertEquals(
            ProbeErrorKind.PERMISSION_DENIED,
            HostFirewall.classifyError(
                exitCode = 4,
                stdout = "",
                stderr = "iptables v1.8.7 (nf_tables): can't initialize iptables table `filter': Permission denied (you must be root)",
                timedOut = false,
            ),
        )
        assertEquals(
            ProbeErrorKind.PERMISSION_DENIED,
            HostFirewall.classifyError(
                exitCode = 2,
                stdout = "",
                stderr = "RTNETLINK answers: Operation not permitted",
                timedOut = false,
            ),
        )
        assertEquals(
            ProbeErrorKind.COMMAND_MISSING,
            HostFirewall.classifyError(
                exitCode = 127,
                stdout = "",
                stderr = "/system/bin/sh: nft: inaccessible or not found",
                timedOut = false,
            ),
        )
        assertEquals(
            ProbeErrorKind.FILE_MISSING,
            HostFirewall.classifyError(
                exitCode = 1,
                stdout = "",
                stderr = "cat: /proc/net/nf_conntrack: No such file or directory",
                timedOut = false,
            ),
        )
        assertEquals(
            ProbeErrorKind.TIMEOUT,
            HostFirewall.classifyError(
                exitCode = -1,
                stdout = "",
                stderr = "Command timed out after 2000ms",
                timedOut = true,
            ),
        )
    }

    @Test
    fun `iptables chain counter parser sums rule packet counts and diagnostic report serializes cleanly`() {
        val sampleIptablesOut = """
            Chain SHIZZI_TEST_1A2B3C (2 references)
                pkts      bytes target     prot opt in     out     source               destination
                  18     1420 DROP       0    --  *      *       192.168.167.151      0.0.0.0/0
                   7      840 DROP       0    --  *      *       0.0.0.0/0            192.168.167.151
        """.trimIndent()
        assertEquals(25L, FirewallDiagnosticRunner.parseIptablesChainPacketSum(sampleIptablesOut))

        val report = FirewallDiagnosticReport(
            testId = "DIAG-TEST01",
            timestamp = "2026-10-26T18:00:00.000-0700",
            apkVersion = "0.4.0-rs-lua5",
            versionCode = 10,
            sourceCommit = "0b0d7595ffc5605b3582bd639c3f7ff14cbd10e2+lua5",
            serviceBuildId = 10,
            device = "samsung SM-S918B",
            androidApi = 34,
            androidRelease = "14",
            vendorBuild = "UP1A.231005.007",
            tetheringModuleVersion = "com.google.android.tethering:341510000",
            uid = 2000,
            pid = 12345,
            shizukuUid = 2000,
            shizukuMode = "ADB_SHELL (uid=2000, rootless)",
            selinuxContext = "u:r:shell:s0",
            effectiveCapabilitiesHex = "CapEff=0000000000000000 CapPrm=0000000000000000",
            downstreamInterface = "swlan0",
            upstreamInterface = "testtun38",
            datapathMode = "USERSPACE_PROXY",
            vpnState = "NO_VPN",
            softApCallbackStatus = "ACTIVE_CLIENTS_2",
            tetheringCallbackStatus = "ACTIVE_CLIENTS_2",
            clients = listOf(
                ClientIdentityRecord(
                    clientId = "E2:15:CD:54:E4:9B",
                    currentAddresses = listOf("192.168.167.151"),
                    ipv4Addresses = listOf("192.168.167.151"),
                    ipv6Addresses = emptyList(),
                    downstreamInterface = "swlan0",
                    mappingSource = "softap_callback+tethering_callback+downstream_neigh",
                ),
            ),
            probes = listOf(
                ReadOnlyProbeResult(
                    probeName = "ip_rule_show",
                    command = "ip rule show",
                    exitCode = 0,
                    timedOut = false,
                    errorKind = ProbeErrorKind.NONE,
                    boundedStdout = "0: from all lookup local",
                    boundedStderr = "",
                ),
            ),
            mechanismCapabilities = listOf(
                MechanismCapability(
                    mechanism = "policy_routing_ip_rule",
                    family = "IPv4",
                    canReadRules = true,
                    canWriteOwnedRules = false,
                    selectiveEnforcementObserved = false,
                    status = FirewallDiagnosticStatus.READ_ONLY,
                    detail = "canRead=true (ip rule show is read-only); write denied: RTNETLINK answers: Operation not permitted",
                ),
            ),
            conntrackObservations = listOf(
                TunTrafficEngine.ConntrackPathObservation(
                    path = "/proc/net/nf_conntrack",
                    existsObserved = false,
                    openReadStatus = "FILE_MISSING_OR_HIDDEN",
                    rawError = "exists=false",
                    bytesRead = 0,
                    totalLines = 0,
                    relevantParsedFlows = 0,
                    sampleTuples = emptyList(),
                ),
            ),
            conntrackReadStatus = "FILE_MISSING_OR_UNEXPOSED",
            parsedFlows = 0,
            attributedFlows = 0,
            unmatchedDelta = 12L,
            temporaryRuleTest = TemporaryRuleTestResult(executed = false),
            validationMatrix = emptyList(),
            overallStatus = FirewallDiagnosticStatus.ENFORCEMENT_UNAVAILABLE,
            finalDecision = "INDISPONÍVEL EM ADB_SHELL",
            factsConfirmed = listOf("ip rule show é apenas leitura"),
            hypothesesToVerify = listOf("Testar com 2 clientes"),
        )

        val json = report.toJsonString()
        val roundtrip = FirewallDiagnosticReport.fromJsonString(json)
        assertEquals("DIAG-TEST01", roundtrip.testId)
        assertEquals("0.4.0-rs-lua5", roundtrip.apkVersion)
        assertEquals(10, roundtrip.serviceBuildId)
        assertEquals(FirewallDiagnosticStatus.ENFORCEMENT_UNAVAILABLE, roundtrip.overallStatus)
        assertTrue(roundtrip.mechanismCapabilities[0].canReadRules)
        assertFalse(roundtrip.mechanismCapabilities[0].canWriteOwnedRules)
        assertEquals(FirewallDiagnosticStatus.READ_ONLY, roundtrip.mechanismCapabilities[0].status)
        assertTrue(report.toMarkdownReport().contains("ShizziLuna — Relatório de Capacidade do Firewall por Cliente"))
    }

    private fun buildIpv4TcpPacket(
        srcIp: IntArray,
        dstIp: IntArray,
        srcPort: Int,
        dstPort: Int,
        totalLength: Int,
    ): ByteArray {
        val buf = ByteArray(totalLength.coerceAtLeast(40))
        buf[0] = 0x45.toByte() // IPv4, IHL=5 (20 bytes)
        buf[2] = ((buf.size ushr 8) and 0xFF).toByte()
        buf[3] = (buf.size and 0xFF).toByte()
        buf[9] = 6.toByte() // TCP
        for (i in 0..3) {
            buf[12 + i] = srcIp[i].toByte()
            buf[16 + i] = dstIp[i].toByte()
        }
        buf[20] = ((srcPort ushr 8) and 0xFF).toByte()
        buf[21] = (srcPort and 0xFF).toByte()
        buf[22] = ((dstPort ushr 8) and 0xFF).toByte()
        buf[23] = (dstPort and 0xFF).toByte()
        buf[32] = 0x50.toByte() // TCP data offset = 20 bytes
        return buf
    }

    private fun buildIpv6UdpPacket(
        srcWords: IntArray,
        dstWords: IntArray,
        srcPort: Int,
        dstPort: Int,
    ): ByteArray {
        val buf = ByteArray(64)
        buf[0] = 0x60.toByte() // IPv6
        buf[4] = 0
        buf[5] = 24 // Payload length
        buf[6] = 17 // Next Header = UDP
        buf[7] = 64 // Hop limit
        for (i in 0..7) {
            buf[8 + i * 2] = ((srcWords[i] ushr 8) and 0xFF).toByte()
            buf[8 + i * 2 + 1] = (srcWords[i] and 0xFF).toByte()
            buf[24 + i * 2] = ((dstWords[i] ushr 8) and 0xFF).toByte()
            buf[24 + i * 2 + 1] = (dstWords[i] and 0xFF).toByte()
        }
        buf[40] = ((srcPort ushr 8) and 0xFF).toByte()
        buf[41] = (srcPort and 0xFF).toByte()
        buf[42] = ((dstPort ushr 8) and 0xFF).toByte()
        buf[43] = (dstPort and 0xFF).toByte()
        return buf
    }
}


