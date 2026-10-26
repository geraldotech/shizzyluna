package dev.shizzi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsConfigTest {

    @Test
    fun `preset resolution returns expected IP addresses`() {
        val google = DnsSettings(preset = DnsPreset.GOOGLE)
        val addrs = google.resolveAddresses()
        assertTrue(addrs.contains("8.8.8.8"))
        assertTrue(addrs.contains("8.8.4.4"))

        val cloudflare = DnsSettings(preset = DnsPreset.CLOUDFLARE)
        val cfAddrs = cloudflare.resolveAddresses()
        assertTrue(cfAddrs.contains("1.1.1.1"))
        assertTrue(cfAddrs.contains("1.0.0.1"))
    }

    @Test
    fun `custom DNS preset uses user defined servers`() {
        val custom = DnsSettings(
            preset = DnsPreset.CUSTOM,
            customPrimary = "192.168.1.1",
            customSecondary = "192.168.1.254",
        )
        val addrs = custom.resolveAddresses()
        assertEquals(listOf("192.168.1.1", "192.168.1.254"), addrs)
    }

    @Test
    fun `custom DNS ignores empty secondary`() {
        val custom = DnsSettings(
            preset = DnsPreset.CUSTOM,
            customPrimary = "10.0.0.1",
            customSecondary = "   ",
        )
        val addrs = custom.resolveAddresses()
        assertEquals(listOf("10.0.0.1"), addrs)
    }

    @Test
    fun `parse fallback to google when invalid name`() {
        assertEquals(DnsPreset.GOOGLE, DnsPreset.parse(null))
        assertEquals(DnsPreset.GOOGLE, DnsPreset.parse("UNKNOWN_PRESET"))
        assertEquals(DnsPreset.ADGUARD, DnsPreset.parse("ADGUARD"))
    }
}
