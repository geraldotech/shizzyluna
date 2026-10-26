package dev.shizzi

import java.net.InetAddress

enum class DnsPreset(
    val title: String,
    val subtitle: String,
    val primaryV4: String,
    val secondaryV4: String,
    val primaryV6: String,
    val secondaryV6: String,
) {
    GOOGLE(
        title = "Google Public DNS",
        subtitle = "8.8.8.8 / 8.8.4.4",
        primaryV4 = "8.8.8.8",
        secondaryV4 = "8.8.4.4",
        primaryV6 = "2001:4860:4860::8888",
        secondaryV6 = "2001:4860:4860::8844",
    ),
    CLOUDFLARE(
        title = "Cloudflare DNS",
        subtitle = "1.1.1.1 / 1.0.0.1",
        primaryV4 = "1.1.1.1",
        secondaryV4 = "1.0.0.1",
        primaryV6 = "2606:4700:4700::1111",
        secondaryV6 = "2606:4700:4700::1001",
    ),
    QUAD9(
        title = "Quad9 Security",
        subtitle = "9.9.9.9 (Malware blocking)",
        primaryV4 = "9.9.9.9",
        secondaryV4 = "149.112.112.112",
        primaryV6 = "2620:fe::fe",
        secondaryV6 = "2620:fe::9",
    ),
    ADGUARD(
        title = "AdGuard DNS",
        subtitle = "94.140.14.14 (Ad & tracker blocking)",
        primaryV4 = "94.140.14.14",
        secondaryV4 = "94.140.15.15",
        primaryV6 = "2a10:50c0::ad1:ff",
        secondaryV6 = "2a10:50c0::ad2:ff",
    ),
    SYSTEM(
        title = "System Default",
        subtitle = "Fallback upstream / network default",
        primaryV4 = "",
        secondaryV4 = "",
        primaryV6 = "",
        secondaryV6 = "",
    ),
    CUSTOM(
        title = "Custom DNS",
        subtitle = "User-defined primary & secondary servers",
        primaryV4 = "",
        secondaryV4 = "",
        primaryV6 = "",
        secondaryV6 = "",
    );

    companion object {
        fun parse(name: String?): DnsPreset =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: GOOGLE
    }
}

data class DnsSettings(
    val preset: DnsPreset = DnsPreset.GOOGLE,
    val customPrimary: String = "",
    val customSecondary: String = "",
) {
    fun resolveAddresses(): List<String> = when (preset) {
        DnsPreset.CUSTOM -> {
            listOf(customPrimary.trim(), customSecondary.trim()).filter { it.isNotBlank() }
        }
        DnsPreset.SYSTEM -> emptyList()
        else -> {
            listOfNotNull(
                preset.primaryV4.takeIf { it.isNotBlank() },
                preset.secondaryV4.takeIf { it.isNotBlank() },
                preset.primaryV6.takeIf { it.isNotBlank() },
                preset.secondaryV6.takeIf { it.isNotBlank() },
            )
        }
    }

    fun resolveInetAddresses(): List<InetAddress> {
        val raw = resolveAddresses()
        if (raw.isEmpty()) {
            return listOf("8.8.8.8", "8.8.4.4").map(InetAddress::getByName)
        }
        return raw.mapNotNull { address ->
            runCatching { InetAddress.getByName(address) }.getOrNull()
        }.ifEmpty {
            listOf("8.8.8.8", "8.8.4.4").map(InetAddress::getByName)
        }
    }
}
