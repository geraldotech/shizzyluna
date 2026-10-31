package dev.shizzi.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import dev.shizzi.ClientRule
import dev.shizzi.ConnectedClient
import dev.shizzi.DnsSettings
import dev.shizzi.SessionUiState
import dev.shizzi.ShizukuState
import dev.shizzi.VpnMode
import dev.shizzi.ui.theme.AccentChoice
import dev.shizzi.ui.theme.DesignLanguage
import dev.shizzi.ui.theme.ShizziTheme
import dev.shizzi.ui.theme.ThemeChoice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

class ClientsPageRulesConversionTest {

    @Test
    fun `1 parseMbpsToKbps zero returns 0 Kbps unlimited`() {
        assertEquals(0, parseMbpsToKbps("0"))
        assertEquals(0, parseMbpsToKbps("0.0"))
        assertEquals(0, parseMbpsToKbps("0,000"))
        assertEquals("0", formatKbpsAsMbps(0))
    }

    @Test
    fun `2 parseMbpsToKbps converts integer and decimal Mbps to exact Kbps`() {
        assertEquals(500, parseMbpsToKbps("0.5"))
        assertEquals(500, parseMbpsToKbps("0,5"))
        assertEquals(1000, parseMbpsToKbps("1"))
        assertEquals(1500, parseMbpsToKbps("1.5"))
        assertEquals(1500, parseMbpsToKbps("1,5"))
        assertEquals(25000, parseMbpsToKbps("25"))
        assertEquals(512, parseMbpsToKbps("0.512"))
        assertEquals(512, parseMbpsToKbps("0,512"))
        assertEquals(10000, parseMbpsToKbps("10"))
    }

    @Test
    fun `3 roundtrip preserves all legacy presets including 512 Kbps and 25000 Kbps without rounding`() {
        val legacyPresetsKbps = listOf(0, 512, 1000, 2000, 5000, 10000, 25000)
        val expectedMbpsLabels = mapOf(
            0 to "0",
            512 to "0.512",
            1000 to "1",
            2000 to "2",
            5000 to "5",
            10000 to "10",
            25000 to "25",
        )
        for (presetKbps in legacyPresetsKbps) {
            val formattedMbps = formatKbpsAsMbps(presetKbps)
            assertEquals(expectedMbpsLabels[presetKbps], formattedMbps)
            val roundtripKbps = parseMbpsToKbps(formattedMbps)
            assertEquals("Roundtrip failed for $presetKbps Kbps", presetKbps, roundtripKbps)
        }

        // Badge label for 512 Kbps must display 0.512 Mbps and never round to 1 Mbps or 0.5 Mbps
        val client512 = ConnectedClient(
            mac = "AA:BB:CC:DD:EE:FF",
            ip = "192.168.50.145",
            bandwidthLimitKbps = 512,
        )
        val badgeLabel = formatClientBandwidthBadgeLabel(client512, isCurrentlyConnected = false)
        assertTrue("Expected 0.512 Mbps in badge but got: $badgeLabel", badgeLabel.contains("0.512 Mbps"))
        assertFalse(badgeLabel.contains("1 Mbps"))
    }

    @Test
    fun `4 validateMbpsInput rejects empty negative overflow alphabetical and sub-Kbps precision`() {
        // Empty / blank
        assertFalse(validateMbpsInput("").isValid)
        assertFalse(validateMbpsInput("   ").isValid)
        assertNull(parseMbpsToKbps(""))

        // Negative
        assertFalse(validateMbpsInput("-1").isValid)
        assertFalse(validateMbpsInput("-0.5").isValid)
        assertNotNull(validateMbpsInput("-0.5").errorMessage)

        // Alphabetical / NaN / malformed
        assertFalse(validateMbpsInput("abc").isValid)
        assertFalse(validateMbpsInput("NaN").isValid)
        assertFalse(validateMbpsInput("1.2.3").isValid)
        assertFalse(validateMbpsInput("1.").isValid)
        assertFalse(validateMbpsInput(".5").isValid)

        // Sub-Kbps precision (> 3 decimal places in Mbps, e.g. 0.5125 Mbps = 512.5 Kbps)
        val subKbps = validateMbpsInput("0.5125")
        assertFalse(subKbps.isValid)
        assertNull(subKbps.kbps)
        assertTrue(subKbps.errorMessage!!.contains("0.001 Mbps"))

        // Overflow > Int.MAX_VALUE Kbps (2147483.647 Mbps is max; 2147483.648 overflows Int)
        assertEquals(Int.MAX_VALUE, parseMbpsToKbps("2147483.647"))
        val overflow = validateMbpsInput("2147483.648")
        assertFalse(overflow.isValid)
        assertNull(overflow.kbps)
        assertFalse(validateMbpsInput("999999999").isValid)
    }

    @Test
    fun `7 and 8 schedule hour formatting and daytime overnight and same-hour validation`() {
        // Hours 0..23 format strictly as HH:00 (minutes always 00)
        for (h in 0..23) {
            val formatted = formatScheduleHour(h)
            assertTrue("Expected HH:00 format for hour $h, got $formatted", formatted.endsWith(":00"))
            assertEquals(5, formatted.length)
        }
        assertEquals("00:00", formatScheduleHour(0))
        assertEquals("08:00", formatScheduleHour(8))
        assertEquals("22:00", formatScheduleHour(22))
        assertEquals("23:00", formatScheduleHour(23))

        // Daytime window 08:00 -> 22:00
        assertTrue(isValidScheduleHours(scheduleEnabled = true, startHour = 8, endHour = 22))
        assertEquals(
            "Internet allowed from 08:00 to 22:00. Outside this window, access is blocked.",
            formatScheduleExplanation(8, 22),
        )

        // Overnight window 22:00 -> 06:00
        assertTrue(isValidScheduleHours(scheduleEnabled = true, startHour = 22, endHour = 6))
        assertEquals(
            "Internet allowed from 22:00 to 06:00. Outside this window, access is blocked.",
            formatScheduleExplanation(22, 6),
        )

        // Same start and end hour (08:00 -> 08:00) is invalid when scheduleEnabled == true
        assertFalse(isValidScheduleHours(scheduleEnabled = true, startHour = 8, endHour = 8))

        // Same start and end hour does not block saving when scheduleEnabled == false
        assertTrue(isValidScheduleHours(scheduleEnabled = false, startHour = 8, endHour = 8))
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = android.app.Application::class)
class ClientsPageComposeTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `5 and 6 editing bandwidth or schedule without saving does not mutate rule and Save preserves all fields`() {
        var savedRule: ClientRule? = null
        val initialClient = ConnectedClient(
            mac = "E2:15:CD:54:E4:9B",
            ip = "192.168.50.145",
            alias = "Galaxy Client",
            isBlocked = true,
            bandwidthLimitKbps = 512,
            connectionTimeLimitMinutes = 60,
            scheduleEnabled = true,
            scheduleStartHour = 8,
            scheduleEndHour = 22,
        )

        composeTestRule.setContent {
            ShizziTheme {
                ConfigureClientDialog(
                    client = initialClient,
                    onDismiss = {},
                    onSave = { savedRule = it },
                )
            }
        }
        composeTestRule.waitForIdle()

        // 512 Kbps is displayed as 0.512 in the Mbps input
        composeTestRule.onNodeWithTag("bandwidth_limit_mbps_input", useUnmergedTree = true)
            .assertTextContains("0.512")

        // Type invalid input -> Save Rules becomes disabled and savedRule remains null
        composeTestRule.onNodeWithTag("bandwidth_limit_mbps_input")
            .performTextReplacement("")
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsNotEnabled()
        assertNull("Rule must not be saved while typing", savedRule)

        // Type 1.5 Mbps -> Save Rules enabled, still not saved until button clicked
        composeTestRule.onNodeWithTag("bandwidth_limit_mbps_input")
            .performTextReplacement("1.5")
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsEnabled()
        assertNull("Rule must not be saved before clicking Save Rules", savedRule)

        // Click Save Rules -> preserves mac, alias, isBlocked, connectionTimeLimitMinutes, scheduleEnabled, hours
        composeTestRule.onNodeWithTag("save_client_rules_button").performClick()
        composeTestRule.waitForIdle()

        assertNotNull(savedRule)
        assertEquals("E2:15:CD:54:E4:9B", savedRule!!.mac)
        assertEquals("Galaxy Client", savedRule!!.alias)
        assertTrue(savedRule!!.isBlocked)
        assertEquals(1500, savedRule!!.bandwidthLimitKbps)
        assertEquals(60, savedRule!!.connectionTimeLimitMinutes)
        assertTrue(savedRule!!.scheduleEnabled)
        assertEquals(8, savedRule!!.scheduleStartHour)
        assertEquals(22, savedRule!!.scheduleEndHour)
    }

    @Test
    fun `7 8 and 9 whole-hour picker selects 0 to 23 blocks start equals end and preserves hours when schedule toggled off`() {
        var savedRule: ClientRule? = null
        val initialClient = ConnectedClient(
            mac = "F2:FF:8B:3D:B2:A6",
            ip = "192.168.50.17",
            alias = "Test Tablet",
            isBlocked = false,
            bandwidthLimitKbps = 512,
            connectionTimeLimitMinutes = 30,
            scheduleEnabled = true,
            scheduleStartHour = 8,
            scheduleEndHour = 22,
        )

        composeTestRule.setContent {
            ShizziTheme {
                ConfigureClientDialog(
                    client = initialClient,
                    onDismiss = {},
                    onSave = { savedRule = it },
                )
            }
        }
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("schedule_window_summary_text")
            .assertTextContains("08:00 → 22:00")
        composeTestRule.onNodeWithTag("schedule_helper_text")
            .assertTextContains("Internet allowed from 08:00 to 22:00. Outside this window, access is blocked.")

        // Open End time picker and choose 08:00 (same as Start time 08:00) -> invalid when scheduleEnabled == true
        composeTestRule.onNodeWithTag("schedule_end_time_button").performScrollTo().performClick()
        composeTestRule.waitForIdle()
        // Verify all 24 hours 0..23 exist in the picker
        for (h in 0..23) {
            composeTestRule.onAllNodesWithTag("hour_option_$h").assertCountEquals(1)
        }
        composeTestRule.onNodeWithTag("hour_option_8").performScrollTo().performClick()
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("schedule_error_text").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsNotEnabled()

        // Change Start time to 22:00 and End time to 06:00 (overnight window 22:00 -> 06:00)
        composeTestRule.onNodeWithTag("schedule_start_time_button").performScrollTo().performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("hour_option_22").performScrollTo().performClick()
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("schedule_end_time_button").performScrollTo().performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("hour_option_6").performScrollTo().performClick()
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("schedule_window_summary_text")
            .performScrollTo()
            .assertTextContains("22:00 → 06:00")
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsEnabled()

        // Turn schedule switch OFF -> hours (22 and 6) must still be preserved when saved!
        composeTestRule.onNodeWithTag("configure_schedule_switch").performScrollTo().performClick()
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("save_client_rules_button").performClick()
        composeTestRule.waitForIdle()

        assertNotNull(savedRule)
        assertEquals(512, savedRule!!.bandwidthLimitKbps)
        assertFalse(savedRule!!.scheduleEnabled)
        assertEquals(22, savedRule!!.scheduleStartHour)
        assertEquals(6, savedRule!!.scheduleEndHour)
    }

    @Test
    fun `10 Connected Devices removes duplicate BPF card while Settings Developer preserves BPF toggle and diagnostics`() {
        composeTestRule.setContent {
            ShizziTheme {
                ClientsPage(
                    clients = listOf(
                        ConnectedClient(
                            mac = "E2:15:CD:54:E4:9B",
                            ip = "192.168.50.145",
                            alias = "Phone A",
                            bandwidthLimitKbps = 512,
                            scheduleEnabled = true,
                            scheduleStartHour = 8,
                            scheduleEndHour = 22,
                        ),
                    ),
                    actions = ClientActions(
                        onToggleBlock = { _, _ -> },
                        onSaveRule = {},
                        onRemoveRule = {},
                        onRefresh = {},
                    ),
                    onBack = {},
                    sessionState = SessionUiState(),
                    experimentalBpfEnabled = true,
                )
            }
        }
        composeTestRule.waitForIdle()

        // Duplicate BPF card and buttons are completely absent from Connected Devices
        composeTestRule.onAllNodesWithTag("experimental_bpf_card").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("experimental_bpf_switch").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("open_firewall_diagnostic_button").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("collect_bpf_now_clients_button").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("Experimental BPF NAT Attribution").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("BPF & Firewall Diagnostics").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("Collect BPF").assertCountEquals(0)

        // Connected Devices still shows client card, 0.512 Mbps badge, and 08:00 - 22:00 schedule badge
        composeTestRule.onNodeWithTag("client_card_E2:15:CD:54:E4:9B").assertIsDisplayed()
        composeTestRule.onNode(hasText("0.512 Mbps", substring = true)).assertIsDisplayed()
        composeTestRule.onNode(hasText("Sched: 08:00 - 22:00", substring = true)).assertIsDisplayed()
    }

    @Test
    fun `10b SettingsPage Developer section preserves Experimental BPF NAT Attribution and Firewall Diagnostics`() {
        val baseContext = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        val appInstance = dev.shizzi.App()
        android.content.ContextWrapper::class.java
            .getDeclaredMethod("attachBaseContext", android.content.Context::class.java)
            .apply {
                isAccessible = true
                invoke(appInstance, baseContext)
            }
        dev.shizzi.App::class.java.getDeclaredField("instance").apply {
            isAccessible = true
            set(null, appInstance)
        }

        composeTestRule.setContent {
            ShizziTheme {
                SettingsPage(
                    state = SettingsState(
                        shizuku = ShizukuState.Ready(uid = 2000, isRoot = false),
                        permissions = emptyList(),
                        theme = ThemeChoice.DARK,
                        design = DesignLanguage.MATERIAL_EXPRESSIVE,
                        accent = AccentChoice.Default,
                        customAccents = emptyList(),
                        isLogging = true,
                        vpnMode = VpnMode.AUTO,
                        isRunningDiagnostics = false,
                        automation = AutomationState(isEnabled = false, token = ""),
                        dnsSettings = DnsSettings(),
                        experimentalBpfEnabled = true,
                    ),
                    actions = SettingsActions(
                        onSetTheme = {},
                        onSetDesign = {},
                        onSetAccent = {},
                        onAddCustomAccent = {},
                        onSetLogging = {},
                        onSetVpnMode = {},
                        onSetDnsPreset = {},
                        onSetCustomDns = { _, _ -> },
                        onOpenClients = {},
                        onOpenLog = {},
                        onOpenFirewallDiagnostic = {},
                        onSetExperimentalBpfEnabled = {},
                        onRunProbes = {},
                        onGrantPermission = {},
                        onShizukuAction = {},
                        onRestartOnboarding = {},
                        automation = AutomationActions(
                            onSetEnabled = {},
                            onRegenerateToken = {},
                        ),
                    ),
                    toasts = rememberToastState(),
                    onBack = {},
                )
            }
        }
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithText("Experimental BPF NAT Attribution")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Diagnóstico do firewall & BPF NAT")
            .performScrollTo()
            .assertIsDisplayed()
    }
}
