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
    fun `conntrack parser resolves post-NAT 192_0_2_2 flow to original downstream client IP across two clients`() {
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

        val sampleConntrack =
            "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.167.10 dst=142.250.190.46 sport=41000 dport=443 src=142.250.190.46 dst=192.0.2.2 sport=443 dport=41000 [ASSURED] mark=0 use=2"
        assertTrue(TunTrafficEngine.parseConntrackLine(sampleConntrack))

        // Verify post-NAT packet for port 41000 resolves to Client A (blocked) and not Client B
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
    fun `honest EnforcementState never claims verified enforcement on DIRECT_TUN_FALLBACK or before packets match`() {
        val emptySnapshot = TunTrafficEngine.CounterSnapshot(
            mac = "E2:15:CD:54:E4:9B",
            seenPackets = 0L,
            matchedPackets = 0L,
            forwardedPackets = 0L,
            droppedPackets = 0L,
            shapedPackets = 0L,
            rxBytes = 0L,
            txBytes = 0L,
            droppedBytes = 0L,
            shapedBytes = 0L,
            policyInstalled = false,
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

        // 3. Multi-client degraded state (userspace active, 0 drops, degraded = true) -> DEGRADED_MULTI_CLIENT
        val degradedState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(policyInstalled = true),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = true,
        )
        assertEquals(EnforcementState.DEGRADED_MULTI_CLIENT, degradedState)

        // 4. Userspace proxy active + policy installed + 0 packets -> POLICY_INSTALLED (not yet PACKETS_DROPPED)
        val installedState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(policyInstalled = true),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.POLICY_INSTALLED, installedState)

        // 5. Userspace proxy active + droppedPackets > 0 -> PACKETS_DROPPED (verified)
        val verifiedDropState = HostFirewall.computeClientEnforcementState(
            isRestricted = true,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(policyInstalled = true, matchedPackets = 5L, droppedPackets = 5L),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.PACKETS_DROPPED, verifiedDropState)

        // 6. Unrestricted client must always report UNRESTRICTED even with non-zero past drops
        val unrestrictedState = HostFirewall.computeClientEnforcementState(
            isRestricted = false,
            bandwidthLimitKbps = 0,
            counters = emptySnapshot.copy(droppedPackets = 358L),
            datapathMode = DatapathMode.USERSPACE_PROXY,
            kernelAvailable = false,
            isDegradedMultiClient = false,
        )
        assertEquals(EnforcementState.UNRESTRICTED, unrestrictedState)
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

