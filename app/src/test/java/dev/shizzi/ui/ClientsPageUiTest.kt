package dev.shizzi.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextReplacement
import dev.shizzi.ClientRule
import dev.shizzi.ConnectedClient
import dev.shizzi.DataQuota
import dev.shizzi.DnsSettings
import dev.shizzi.QuotaResetPeriod
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

        // Connected Devices still shows client card, 0.512 Mbps badge, and 08:00 - 22:00 schedule badge without debug attribution counters or datapath header
        composeTestRule.onNodeWithTag("client_card_E2:15:CD:54:E4:9B").assertIsDisplayed()
        composeTestRule.onNode(hasText("Limit: 0.512 Mbps", substring = true)).assertIsDisplayed()
        composeTestRule.onNode(hasText("Sched: 08:00 - 22:00", substring = true)).assertIsDisplayed()
        composeTestRule.onAllNodesWithText("Datapath:", substring = true).assertCountEquals(0)
        composeTestRule.onAllNodesWithText("seen=", substring = true).assertCountEquals(0)
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
        composeTestRule.onNodeWithTag("export_diagnostics_action")
            .performScrollTo()
            .assertIsDisplayed()
        // Debug panel and Portuguese debug entry are removed in 0.10.3 release
        composeTestRule.onAllNodesWithTag("bpf_diagnostics_debug_card").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("Diagnóstico do firewall & BPF NAT").assertCountEquals(0)
    }

    @Test
    fun `11 v0_10_2 SettingsPage consolidates About into single row opening AboutDialog with version and GeraldoDev`() {
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

        // Legacy 3-row About entries ("Report a bug") are removed
        composeTestRule.onAllNodesWithText("Report a bug").assertCountEquals(0)

        // Single About action row is displayed
        composeTestRule.onNodeWithTag("about_settings_action")
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        composeTestRule.waitForIdle()

        // About modal displays Shizzy Luna, Version 0.10.3, Author: GeraldoDev, GitHub button, and Close button
        composeTestRule.onNodeWithTag("about_modal_title")
            .assertIsDisplayed()
            .assertTextContains("Shizzy Luna")
        composeTestRule.onNodeWithTag("about_modal_version")
            .assertIsDisplayed()
            .assertTextContains("Version 0.10.3")
        composeTestRule.onNodeWithTag("about_modal_author")
            .assertIsDisplayed()
            .assertTextContains("Author: GeraldoDev")
        composeTestRule.onNodeWithTag("about_modal_github_button")
            .assertIsDisplayed()

        // Close button dismisses modal
        composeTestRule.onNodeWithTag("about_modal_close_button").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onAllNodesWithTag("about_modal_title").assertCountEquals(0)
    }

    @Test
    fun `12 v0_10_2 ConfigureClientDialog validates Data Usage Limit MB selects period resets usage and saves quota fields`() {
        var savedRule: ClientRule? = null
        var resetCallbackCount = 0
        val initialClient = ConnectedClient(
            mac = "E2:15:CD:54:E4:9B",
            ip = "192.168.50.145",
            alias = "Galaxy Client",
            isBlocked = false,
            bandwidthLimitKbps = 2000,
            connectionTimeLimitMinutes = 30,
            scheduleEnabled = true,
            scheduleStartHour = 8,
            scheduleEndHour = 22,
            dataLimitBytes = 500L * DataQuota.BYTES_PER_MB,
            quotaResetPeriod = QuotaResetPeriod.MANUAL,
            quotaUsedRxBytes = 120L * DataQuota.BYTES_PER_MB,
            quotaUsedTxBytes = 80L * DataQuota.BYTES_PER_MB,
            quotaResetGeneration = 1L,
        )

        composeTestRule.setContent {
            ShizziTheme {
                ConfigureClientDialog(
                    client = initialClient,
                    onDismiss = {},
                    onSave = { savedRule = it },
                    onResetQuotaUsage = { resetCallbackCount++ },
                )
            }
        }
        composeTestRule.waitForIdle()

        // Verify initial 500 MB and 200 MB / 500 MB (40%) usage summary
        composeTestRule.onNodeWithTag("data_limit_mb_input", useUnmergedTree = true)
            .assertTextContains("500")
        composeTestRule.onNodeWithTag("quota_usage_summary_text")
            .performScrollTo()
            .assertTextContains("200 MB / 500 MB (40%)", substring = true)

        // Invalid data limit input disables Save Rules
        composeTestRule.onNodeWithTag("data_limit_mb_input")
            .performScrollTo()
            .performTextReplacement("-50")
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("data_limit_error_text", useUnmergedTree = true).assertIsDisplayed()
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsNotEnabled()

        // Valid 2048 MB (2 GB) input re-enables Save Rules and shows 2 GB in helper text
        composeTestRule.onNodeWithTag("data_limit_mb_input")
            .performTextReplacement("2048")
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("data_limit_helper_text", useUnmergedTree = true)
            .assertTextContains("Selected: 2 GB", substring = true)
        composeTestRule.onNodeWithTag("save_client_rules_button").assertIsEnabled()

        // Select Daily reset period
        composeTestRule.onNodeWithTag("quota_period_daily")
            .performScrollTo()
            .performClick()
        composeTestRule.waitForIdle()

        // Click Reset Usage -> opens confirmation dialog -> confirm resets usage to 0 B without altering speed/schedule/quota limit
        composeTestRule.onNodeWithTag("reset_quota_usage_button")
            .performScrollTo()
            .performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("confirm_reset_quota_button")
            .assertIsDisplayed()
            .performClick()
        composeTestRule.waitForIdle()

        assertEquals(1, resetCallbackCount)
        composeTestRule.onNodeWithTag("quota_usage_summary_text")
            .performScrollTo()
            .assertTextContains("0 B / 2 GB (0%)", substring = true)

        // Save Rules -> verify all fields preserved + new 2048 MB limit, DAILY period, 0 B usage, incremented resetGeneration
        composeTestRule.onNodeWithTag("save_client_rules_button").performClick()
        composeTestRule.waitForIdle()

        assertNotNull(savedRule)
        assertEquals("E2:15:CD:54:E4:9B", savedRule!!.cleanMac)
        assertEquals(2000, savedRule!!.bandwidthLimitKbps)
        assertEquals(30, savedRule!!.connectionTimeLimitMinutes)
        assertTrue(savedRule!!.scheduleEnabled)
        assertEquals(8, savedRule!!.scheduleStartHour)
        assertEquals(22, savedRule!!.scheduleEndHour)
        assertEquals(2048L * DataQuota.BYTES_PER_MB, savedRule!!.dataLimitBytes)
        assertEquals(QuotaResetPeriod.DAILY, savedRule!!.quotaResetPeriod)
        assertEquals(0L, savedRule!!.quotaUsedRxBytes)
        assertEquals(0L, savedRule!!.quotaUsedTxBytes)
        assertEquals(2L, savedRule!!.quotaResetGeneration)
    }

    @Test
    fun `13 v0_10_3 release Developer Settings removes BPF Attribution Diagnostics debug card and exports redacted files`() {
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

        val sampleReport = dev.shizzi.BpfAttributionStatusReport(
            experimentalEnabled = true,
            state = dev.shizzi.ExperimentalBpfState.MAPPINGS_AVAILABLE,
            collectionStatus = dev.shizzi.BpfCollectionStatus.OK,
            snapshotHealth = dev.shizzi.BpfSnapshotHealth.OK,
            lastSuccessfulRefreshEpochMs = 1_700_000_000_000L,
            snapshotAgeMs = 240L,
            lastCollectionDurationMs = 9L,
            totalCollectionsAttempted = 12L,
            totalCollectionsSucceeded = 12L,
            totalCollectionsFailed = 0L,
            activeMappedFlows = 5,
            totalEligiblePackets = 200L,
            totalEligibleBytes = 240_000L,
            totalAttributedPackets = 190L,
            totalAttributedBytes = 228_000L,
            directAttributedPackets = 40L,
            directAttributedBytes = 48_000L,
            bpfAttributedPackets = 150L,
            bpfAttributedBytes = 180_000L,
            unknownForwardedPackets = 10L,
            unknownForwardedBytes = 12_000L,
            unattributedPacketsByReason = mapOf(dev.shizzi.UnattributedReason.TUPLE_NOT_PRESENT.name to 10L),
            unattributedBytesByReason = mapOf(dev.shizzi.UnattributedReason.TUPLE_NOT_PRESENT.name to 12_000L),
            perClientCounts = listOf(
                dev.shizzi.ClientProtocolFlowCounts(
                    mac = "E2:15:CD:54:E4:9B",
                    originalIpv4 = "192.168.167.151",
                    tcpFlows = 4,
                    udpFlows = 1,
                ),
            ),
        )

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
                        bpfReport = sampleReport,
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

        // AC02: BPF Attribution Diagnostics (Debug) card is absent from SettingsPage in 0.10.3 release
        composeTestRule.onAllNodesWithTag("bpf_diagnostics_debug_card").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("BPF Attribution Diagnostics (Debug)").assertCountEquals(0)

        // AC09: Export diagnostics action is available under Developer section
        composeTestRule.onNodeWithTag("export_diagnostics_action")
            .performScrollTo()
            .assertIsDisplayed()

        // Verify export helper writes redacted Markdown + JSON files with release FileProvider authority
        val exported = writeBpfDiagnosticsExportFiles(
            context = baseContext,
            report = sampleReport,
            includePseudonymousIds = false,
            timestampMs = 1700000000123L,
        )
        assertEquals("dev.shizzyluna.proxy.exports", exported.authority)
        assertTrue(exported.markdownFile.exists())
        assertTrue(exported.jsonFile.exists())
        assertFalse(dev.shizzi.DiagnosticRedactor.containsUnredactedPii(exported.markdownFile.readText()))
        assertFalse(dev.shizzi.DiagnosticRedactor.containsUnredactedPii(exported.jsonFile.readText()))
    }

    @Test
    fun `14 v0_10_3 release SettingsPage renders clean 2-option Blocking Mode section without verbose internals`() {
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

        var selectedMode: dev.shizzi.BlockingMode? = null

        val preNatReport = dev.shizzi.PreNatModeDiagnosticReport(
            requestedMode = dev.shizzi.BlockingMode.BPF_NAT_VPN,
            effectiveMode = dev.shizzi.BlockingMode.BPF_NAT_VPN,
            runtimeState = dev.shizzi.PreNatRuntimeState.CURRENT_ACTIVE,
            exclusiveEngineInvariant = true,
            legacyPreNatMigrated = true,
            legacyPreNatCleanupVerified = true,
        )
        val reportWithPreNat = dev.shizzi.BpfAttributionStatusReport(
            preNatDiagnostics = preNatReport,
        )

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
                        requestedBlockingMode = dev.shizzi.BlockingMode.BPF_NAT_VPN,
                        bpfReport = reportWithPreNat,
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
                        onSelectBlockingMode = { selectedMode = it },
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

        // AC03 & AC04: Clean Blocking Mode card with concise current mode line and no verbose internals
        composeTestRule.onNodeWithTag("blocking_mode_card")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithTag("blocking_mode_active_modes")
            .performScrollTo()
            .assertTextContains("Current mode: BPF/NAT + VPN", substring = true)

        // Verbose internals and legacy debug tags are absent
        composeTestRule.onAllNodesWithTag("blocking_mode_invariant_status").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("legacy_prenat_migration_status").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("prenat_restore_engine_button").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("CURRENT_ACTIVE", substring = true).assertCountEquals(0)
        composeTestRule.onAllNodesWithText("Exclusive Blocking Mode", substring = true).assertCountEquals(0)

        // Radio selection works
        composeTestRule.onNodeWithTag("blocking_mode_radio_bpf")
            .performScrollTo()
            .performClick()
        composeTestRule.waitForIdle()
        assertEquals(dev.shizzi.BlockingMode.BPF_NAT_VPN, selectedMode)
    }

    @Test
    fun `15 v0_10_3 release SettingsPage and ClientsPage render clean SoftAP mode without probe diagnostics and retain offline blocked hosts`() {
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

        var selectedMode: dev.shizzi.BlockingMode? = null

        val softApReport = dev.shizzi.SoftApModeDiagnosticReport(
            selectedMode = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
            effectiveMode = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
            engineState = dev.shizzi.SoftApEngineState.ACTIVE,
            exclusiveEngineInvariant = true,
            clientRecords = listOf(
                dev.shizzi.SoftApClientEnforcementRecord(
                    mac = "E2:15:CD:54:E4:9B",
                    activeReasons = setOf(dev.shizzi.SoftApClientBlockReason.MANUAL_BLOCK),
                    desiredBlocked = true,
                    appliedState = dev.shizzi.SoftApAppliedState.BLOCK_CONFIRMED,
                ),
            ),
        )
        val preNatReport = dev.shizzi.PreNatModeDiagnosticReport(
            requestedMode = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
            effectiveMode = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
            effectiveModeNullable = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
            runtimeState = dev.shizzi.PreNatRuntimeState.CURRENT_ACTIVE,
            exclusiveEngineInvariant = true,
            bpfNatVpnDropPathEnabled = false,
            preNatDropPathEnabled = false,
            softApMacBlockEnabled = true,
        )
        val combinedReport = dev.shizzi.BpfAttributionStatusReport(
            preNatDiagnostics = preNatReport,
            softApDiagnostics = softApReport,
        )

        val clientA = ConnectedClient(
            ip = "192.168.43.101",
            mac = "E2:15:CD:54:E4:9B",
            alias = "galaxy-a",
            interfaceName = "ap0",
            isBlocked = false,
            bandwidthLimitKbps = 5000,
        )
        val clientB = ConnectedClient(
            ip = "192.168.43.102",
            mac = "AA:BB:CC:DD:EE:FF",
            alias = "pixel-b",
            interfaceName = "ap0",
            isBlocked = false,
        )

        val showClientsPage = androidx.compose.runtime.mutableStateOf(false)

        composeTestRule.setContent {
            ShizziTheme {
                if (!showClientsPage.value) {
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
                            requestedBlockingMode = dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK,
                            connectedClients = listOf(clientA, clientB),
                            bpfReport = combinedReport,
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
                            onSelectBlockingMode = { selectedMode = it },
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
                } else {
                    ClientsPage(
                        clients = listOf(clientB),
                        actions = ClientActions(
                            onToggleBlock = { _, _ -> },
                            onSaveRule = {},
                            onRemoveRule = {},
                            onRefresh = {},
                        ),
                        savedRules = emptyList(),
                        bpfReport = combinedReport,
                        onBack = {},
                    )
                }
            }
        }
        composeTestRule.waitForIdle()

        // AC03 & AC05: SoftAP radio option and concise current mode line are shown; probe buttons and engine state badge are absent
        composeTestRule.onNodeWithTag("blocking_mode_radio_softap")
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        composeTestRule.waitForIdle()
        assertEquals(dev.shizzi.BlockingMode.SOFTAP_MAC_BLOCK, selectedMode)

        composeTestRule.onNodeWithTag("blocking_mode_active_modes")
            .performScrollTo()
            .assertTextContains("Current mode: SoftAP MAC Block", substring = true)
        composeTestRule.onAllNodesWithTag("softap_engine_state_badge").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("softap_check_capability_button").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("softap_run_live_probe_button").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("softap_activate_mode_button").assertCountEquals(0)

        // Switch to ClientsPage -> verify SoftAP active mode banner, disconnected SoftAP-blocked client retained with clean user-facing label
        showClientsPage.value = true
        composeTestRule.waitForIdle()

        composeTestRule.onNodeWithTag("softap_active_mode_banner")
            .assertIsDisplayed()

        composeTestRule.onNodeWithTag("clients_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("client_card_E2:15:CD:54:E4:9B"))
        composeTestRule.onNodeWithTag("client_card_E2:15:CD:54:E4:9B")
            .assertIsDisplayed()
        composeTestRule.onNodeWithTag("softap_status_E2:15:CD:54:E4:9B")
            .assertTextContains("Disconnected from hotspot", substring = true)
        composeTestRule.onAllNodesWithText("BLOCK_CONFIRMED", substring = true).assertCountEquals(0)

        // Open Configure dialog -> verify bandwidth limit input is disabled with SoftAP notice
        composeTestRule.onNodeWithTag("configure_client_E2:15:CD:54:E4:9B")
            .performScrollTo()
            .performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("bandwidth_limit_mbps_input")
            .performScrollTo()
            .assertIsNotEnabled()
        composeTestRule.onNodeWithTag("softap_throttle_disabled_notice", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun `16 v0_10_3 release DomainBlockingPage renders concise info note Global and Per-Host tabs without diagnostic status banner`() {
        val rulesState = androidx.compose.runtime.mutableStateListOf(
            dev.shizzi.DomainRule(
                id = "g1",
                scope = dev.shizzi.DomainRuleScope.GLOBAL,
                normalizedDomain = "doubleclick.net",
                matchMode = dev.shizzi.DomainMatchMode.INCLUDE_SUBDOMAINS,
                enabled = true,
            ),
        )
        val clientA = ConnectedClient(
            ip = "192.168.43.101",
            mac = "E2:15:CD:54:E4:9B",
            alias = "galaxy-a",
            interfaceName = "ap0",
            isBlocked = false,
        )

        composeTestRule.setContent {
            ShizziTheme {
                DomainBlockingPage(
                    domainRules = rulesState.toList(),
                    connectedClients = listOf(clientA),
                    savedClientRules = emptyList(),
                    actions = DomainBlockingActions(
                        onUpsertRule = { _, rawDomain, scope, clientMac, matchMode, enabled ->
                            val v = dev.shizzi.DomainNormalizer.validateAndNormalize(rawDomain)
                            if (v.isValid) {
                                rulesState.add(
                                    dev.shizzi.DomainRule(
                                        scope = scope,
                                        clientMac = clientMac,
                                        normalizedDomain = v.normalizedDomain!!,
                                        matchMode = matchMode,
                                        enabled = enabled,
                                    ),
                                )
                            }
                            v
                        },
                    ),
                )
            }
        }
        composeTestRule.waitForIdle()

        // AC06: Domain diagnostic banner and DNS retry engineering toggle are absent; concise note is shown
        composeTestRule.onAllNodesWithTag("domain_capability_banner").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("domain_dns_retry_card").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("PARTIAL_DOMAIN_ENFORCEMENT", substring = true).assertCountEquals(0)
        composeTestRule.onNodeWithTag("domain_info_note")
            .assertIsDisplayed()
            .assertTextContains("Global rules work best with standard DNS. Per-host rules may be limited by traffic attribution.")

        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_rule_card_doubleclick.net"))
        composeTestRule.onNodeWithTag("domain_rule_card_doubleclick.net").assertIsDisplayed()

        // Switch to Per Host tab -> verify "Global rules also apply" notice
        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_tab_client"))
        composeTestRule.onNodeWithTag("domain_tab_client").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_global_also_applies_notice"))
        composeTestRule.onNodeWithTag("domain_global_also_applies_notice")
            .assertIsDisplayed()
            .assertTextContains("Global rules also apply", substring = true)

        // Open Add Host Rule dialog -> enter invalid URL -> verify inline error
        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_add_client_button"))
        composeTestRule.onNodeWithTag("domain_add_client_button").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("domain_rule_dialog").assertIsDisplayed()
        composeTestRule.onNodeWithTag("domain_input_field").performTextReplacement("https://bad.example.com/path")
        composeTestRule.onNodeWithTag("domain_dialog_save_button").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("domain_input_error").assertIsDisplayed()

        // Replace with valid wildcard domain "*.TikTok.com." -> verify normalized rule card appears
        composeTestRule.onNodeWithTag("domain_input_field").performTextReplacement("*.TikTok.com.")
        composeTestRule.onNodeWithTag("domain_dialog_save_button").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_rule_card_tiktok.com"))
        composeTestRule.onNodeWithTag("domain_rule_card_tiktok.com").assertIsDisplayed()
    }

    @Test
    fun `17 v0_10_3 release VpnSection Stop hotspot when VPN disconnects toggle warning and DomainBlockingPage BPF hint`() {
        val vpnModeState = androidx.compose.runtime.mutableStateOf(VpnMode.AUTO)
        val stopOnDisconnectState = androidx.compose.runtime.mutableStateOf(true)
        val showDomainPage = androidx.compose.runtime.mutableStateOf(false)
        val bpfEnabledState = androidx.compose.runtime.mutableStateOf(false)

        composeTestRule.setContent {
            ShizziTheme {
                if (!showDomainPage.value) {
                    VpnSection(
                        selected = vpnModeState.value,
                        onSelect = { vpnModeState.value = it },
                        stopHotspotOnVpnDisconnect = stopOnDisconnectState.value,
                        onSetStopHotspotOnVpnDisconnect = { stopOnDisconnectState.value = it },
                    )
                } else {
                    DomainBlockingPage(
                        domainRules = emptyList(),
                        connectedClients = listOf(
                            ConnectedClient(
                                ip = "192.168.43.101",
                                mac = "E2:15:CD:54:E4:9B",
                                alias = "Phone A",
                                interfaceName = "ap0",
                            ),
                        ),
                        experimentalBpfEnabled = bpfEnabledState.value,
                        initialScope = dev.shizzi.DomainRuleScope.CLIENT,
                        initialClientMac = "E2:15:CD:54:E4:9B",
                        actions = DomainBlockingActions(
                            onSetExperimentalBpfEnabled = { bpfEnabledState.value = it },
                        ),
                    )
                }
            }
        }
        composeTestRule.waitForIdle()

        // 1. Verify "Stop hotspot when VPN disconnects" toggle is ON by default; warning card is not displayed
        composeTestRule.onNodeWithTag("vpn_stop_on_disconnect_toggle").assertIsDisplayed()
        composeTestRule.onAllNodesWithTag("vpn_keep_hotspot_warning_card").assertCountEquals(0)

        // 2. Toggle OFF -> warning card appears with exact non-bypass text
        composeTestRule.onNodeWithTag("vpn_stop_on_disconnect_switch").performClick()
        composeTestRule.waitForIdle()
        assertFalse(stopOnDisconnectState.value)
        composeTestRule.onNodeWithTag("vpn_keep_hotspot_warning_card").assertIsDisplayed()
        composeTestRule.onNodeWithTag("vpn_keep_hotspot_warning_text", useUnmergedTree = true)
            .assertTextContains("While the VPN is disconnected, internet access may be interrupted. Traffic must not silently bypass the VPN.", substring = true)

        // 3. Switch to VpnMode.NEVER -> switch is disabled and warning card is hidden
        vpnModeState.value = VpnMode.NEVER
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("vpn_stop_on_disconnect_switch").assertIsNotEnabled()
        composeTestRule.onAllNodesWithTag("vpn_keep_hotspot_warning_card").assertCountEquals(0)

        // 4. Switch to DomainBlockingPage on Per Host tab with experimentalBpfEnabled = false
        showDomainPage.value = true
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithTag("domain_lazy_column")
            .performScrollToNode(androidx.compose.ui.test.hasTestTag("domain_bpf_disabled_warning_card"))
        composeTestRule.onNodeWithTag("domain_bpf_disabled_warning_card").assertIsDisplayed()
        composeTestRule.onNodeWithTag("domain_enable_bpf_button").performClick()
        composeTestRule.waitForIdle()
        assertTrue(bpfEnabledState.value)
        composeTestRule.onAllNodesWithTag("domain_bpf_disabled_warning_card").assertCountEquals(0)
        composeTestRule.onAllNodesWithTag("domain_dns_retry_toggle").assertCountEquals(0)
    }
}


