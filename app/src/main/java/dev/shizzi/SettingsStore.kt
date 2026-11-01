package dev.shizzi

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.shizzi.ui.theme.AccentChoice
import dev.shizzi.ui.theme.DesignLanguage
import dev.shizzi.ui.theme.ThemeChoice
import dev.shizzi.ui.theme.parseAccent
import dev.shizzi.ui.theme.parseAccents
import dev.shizzi.ui.theme.serialize
import dev.shizzi.ui.theme.serializeAccents
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

data class Settings(
    val theme: ThemeChoice = ThemeChoice.SYSTEM,
    val design: DesignLanguage = DesignLanguage.MATERIAL_EXPRESSIVE,
    val accent: AccentChoice = AccentChoice.Default,
    val customAccents: List<Int> = emptyList(),
    val isLogging: Boolean = true,

    val vpnMode: VpnMode = VpnMode.AUTO,

    val hasCompletedOnboarding: Boolean = false,

    val isAutomationEnabled: Boolean = false,
    val automationToken: String = "",

    val dnsSettings: DnsSettings = DnsSettings(),
    val clientRules: List<ClientRule> = emptyList(),
    val experimentalBpfEnabled: Boolean = true,
    val bpfPollIntervalMs: Int = 1000,
)

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(
    name = "settings",
    produceMigrations = { listOf(RenamedKeys.migration()) },
)

class SettingsStore(private val context: Context) {

    val settings: Flow<Settings> = context.dataStore.data.map(::toSettings)

    suspend fun backfillTokenIfEnabled() {
        context.dataStore.edit { preferences ->
            if (preferences[AUTOMATION] != true) return@edit

            preferences.mintTokenIfAbsent()
        }
    }

    suspend fun setTheme(choice: ThemeChoice) {
        context.dataStore.edit { it[THEME] = choice.name }
    }

    suspend fun setDesign(design: DesignLanguage) {
        context.dataStore.edit { it[DESIGN] = design.name }
    }

    suspend fun setAccent(accent: AccentChoice) {
        context.dataStore.edit { it[ACCENT] = accent.serialize() }
    }

    suspend fun addCustomAccent(argb: Int) {
        context.dataStore.edit { preferences ->
            val existing = parseAccents(preferences[CUSTOM_ACCENTS])
            if (argb in existing) return@edit

            preferences[CUSTOM_ACCENTS] = serializeAccents(existing + argb)
        }
    }

    suspend fun setLogging(enabled: Boolean) {
        context.dataStore.edit { it[LOGGING] = enabled }
    }

    suspend fun setVpnMode(mode: VpnMode) {
        context.dataStore.edit { it[VPN_MODE] = mode.name }
    }

    suspend fun setOnboardingComplete(hasCompleted: Boolean) {
        context.dataStore.edit { it[ONBOARDED] = hasCompleted }
    }

    suspend fun setAutomationEnabled(isEnabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[AUTOMATION] = isEnabled
            if (isEnabled) preferences.mintTokenIfAbsent()
        }
    }

    suspend fun setAutomationToken(token: String) {
        context.dataStore.edit { it[AUTOMATION_TOKEN] = token }
    }

    suspend fun setDnsPreset(preset: DnsPreset) {
        context.dataStore.edit { it[DNS_PRESET] = preset.name }
    }

    suspend fun setCustomDns(primary: String, secondary: String) {
        context.dataStore.edit {
            it[CUSTOM_DNS_PRIMARY] = primary
            it[CUSTOM_DNS_SECONDARY] = secondary
        }
    }

    suspend fun saveClientRule(rule: ClientRule) {
        context.dataStore.edit { preferences ->
            val existing = ClientRule.parseList(preferences[CLIENT_RULES]).toMutableList()
            val index = existing.indexOfFirst { it.mac.equals(rule.mac, ignoreCase = true) }
            val evaluatedIncoming = rule.withEvaluatedQuotaWindow()
            if (index >= 0) {
                val prev = existing[index].withEvaluatedQuotaWindow()
                val merged = if (evaluatedIncoming.quotaResetGeneration > prev.quotaResetGeneration) {
                    evaluatedIncoming
                } else {
                    val sameWindow = prev.quotaWindowId.isEmpty() ||
                        evaluatedIncoming.quotaWindowId.isEmpty() ||
                        prev.quotaWindowId == evaluatedIncoming.quotaWindowId
                    val rx = if (sameWindow) maxOf(prev.quotaUsedRxBytes, evaluatedIncoming.quotaUsedRxBytes) else evaluatedIncoming.quotaUsedRxBytes
                    val tx = if (sameWindow) maxOf(prev.quotaUsedTxBytes, evaluatedIncoming.quotaUsedTxBytes) else evaluatedIncoming.quotaUsedTxBytes
                    evaluatedIncoming.copy(
                        quotaUsedRxBytes = rx,
                        quotaUsedTxBytes = tx,
                        quotaWindowId = evaluatedIncoming.quotaWindowId.ifBlank { prev.quotaWindowId },
                        quotaWindowStartEpochMs = maxOf(prev.quotaWindowStartEpochMs, evaluatedIncoming.quotaWindowStartEpochMs),
                        quotaLastUpdatedEpochMs = maxOf(prev.quotaLastUpdatedEpochMs, evaluatedIncoming.quotaLastUpdatedEpochMs),
                        quotaResetGeneration = maxOf(prev.quotaResetGeneration, evaluatedIncoming.quotaResetGeneration),
                    )
                }
                existing[index] = merged
            } else {
                existing.add(evaluatedIncoming)
            }
            preferences[CLIENT_RULES] = ClientRule.serializeList(existing)
        }
    }

    suspend fun resetClientQuotaUsage(mac: String): ClientRule {
        val cleanMac = mac.uppercase().trim()
        var resetRule = ClientRule(mac = cleanMac).withResetQuotaUsage()
        context.dataStore.edit { preferences ->
            val existing = ClientRule.parseList(preferences[CLIENT_RULES]).toMutableList()
            val index = existing.indexOfFirst { it.mac.equals(cleanMac, ignoreCase = true) }
            if (index >= 0) {
                resetRule = existing[index].withResetQuotaUsage()
                existing[index] = resetRule
            } else {
                existing.add(resetRule)
            }
            preferences[CLIENT_RULES] = ClientRule.serializeList(existing)
        }
        return resetRule
    }

    suspend fun syncClientQuotaSnapshots(hosts: List<DiscoveredHost>, force: Boolean = false) {
        if (hosts.isEmpty()) return
        val hostsByMac = hosts.associateBy { it.mac.uppercase().trim() }
        context.dataStore.edit { preferences ->
            val existing = ClientRule.parseList(preferences[CLIENT_RULES]).toMutableList()
            if (existing.isEmpty()) return@edit
            var changed = false
            for (i in existing.indices) {
                val rule = existing[i]
                val host = hostsByMac[rule.cleanMac] ?: continue
                if (host.quotaResetGeneration < rule.quotaResetGeneration) continue

                val evaluatedRule = rule.withEvaluatedQuotaWindow()
                val sameWindow = host.quotaWindowId.isEmpty() ||
                    evaluatedRule.quotaWindowId.isEmpty() ||
                    host.quotaWindowId == evaluatedRule.quotaWindowId
                val nextRx = if (sameWindow) {
                    maxOf(evaluatedRule.quotaUsedRxBytes, host.quotaUsedRxBytes)
                } else {
                    host.quotaUsedRxBytes
                }
                val nextTx = if (sameWindow) {
                    maxOf(evaluatedRule.quotaUsedTxBytes, host.quotaUsedTxBytes)
                } else {
                    host.quotaUsedTxBytes
                }
                val nextWindowId = host.quotaWindowId.ifBlank { evaluatedRule.quotaWindowId }
                val nextWindowStart = maxOf(evaluatedRule.quotaWindowStartEpochMs, host.quotaWindowStartEpochMs)
                val nextLastUpdated = maxOf(evaluatedRule.quotaLastUpdatedEpochMs, host.quotaLastUpdatedEpochMs)
                val nextGeneration = maxOf(evaluatedRule.quotaResetGeneration, host.quotaResetGeneration)

                val byteDelta = (nextRx - rule.quotaUsedRxBytes).coerceAtLeast(0L) +
                    (nextTx - rule.quotaUsedTxBytes).coerceAtLeast(0L)
                val windowChanged = nextWindowId != rule.quotaWindowId && nextWindowId.isNotEmpty()
                val wasExceeded = rule.dataLimitBytes > 0L &&
                    (rule.quotaUsedRxBytes + rule.quotaUsedTxBytes) >= rule.dataLimitBytes
                val nowExceeded = rule.dataLimitBytes > 0L && (nextRx + nextTx) >= rule.dataLimitBytes
                val crossedQuota = !wasExceeded && nowExceeded

                if (windowChanged || crossedQuota || (force && byteDelta > 0L) || byteDelta >= DataQuota.CHECKPOINT_BYTE_DELTA_THRESHOLD) {
                    existing[i] = evaluatedRule.copy(
                        quotaUsedRxBytes = nextRx,
                        quotaUsedTxBytes = nextTx,
                        quotaWindowId = nextWindowId,
                        quotaWindowStartEpochMs = nextWindowStart,
                        quotaLastUpdatedEpochMs = nextLastUpdated,
                        quotaResetGeneration = nextGeneration,
                    )
                    changed = true
                }
            }
            if (changed) {
                preferences[CLIENT_RULES] = ClientRule.serializeList(existing)
            }
        }
    }

    suspend fun removeClientRule(mac: String) {
        context.dataStore.edit { preferences ->
            val existing = ClientRule.parseList(preferences[CLIENT_RULES]).filterNot {
                it.mac.equals(mac, ignoreCase = true)
            }
            preferences[CLIENT_RULES] = ClientRule.serializeList(existing)
        }
    }

    suspend fun setExperimentalBpfEnabled(enabled: Boolean) {
        context.dataStore.edit { it[EXPERIMENTAL_BPF_ENABLED] = enabled }
    }

    suspend fun setBpfPollIntervalMs(intervalMs: Int) {
        context.dataStore.edit { it[BPF_POLL_INTERVAL_MS] = intervalMs.coerceIn(500, 5000) }
    }

    private fun MutablePreferences.mintTokenIfAbsent() {
        if (!this[AUTOMATION_TOKEN].isNullOrEmpty()) return

        this[AUTOMATION_TOKEN] = AutomationToken.generate()
    }

}

internal val THEME = stringPreferencesKey("theme")
internal val DESIGN = stringPreferencesKey("design")
internal val ACCENT = stringPreferencesKey("accent")
internal val CUSTOM_ACCENTS = stringPreferencesKey("custom_accents")
internal val LOGGING = booleanPreferencesKey("logging")
internal val VPN_MODE = stringPreferencesKey("vpn_mode")
internal val ONBOARDED = booleanPreferencesKey("onboarded")
internal val AUTOMATION = booleanPreferencesKey("automation")
internal val AUTOMATION_TOKEN = stringPreferencesKey("automation_token")
internal val DNS_PRESET = stringPreferencesKey("dns_preset")
internal val CUSTOM_DNS_PRIMARY = stringPreferencesKey("custom_dns_primary")
internal val CUSTOM_DNS_SECONDARY = stringPreferencesKey("custom_dns_secondary")
internal val CLIENT_RULES = stringPreferencesKey("client_rules")
internal val EXPERIMENTAL_BPF_ENABLED = booleanPreferencesKey("experimental_bpf_enabled")
internal val BPF_POLL_INTERVAL_MS = intPreferencesKey("bpf_poll_interval_ms")

internal fun toSettings(preferences: Preferences) = Settings(
    theme = runCatching { ThemeChoice.valueOf(preferences[THEME].orEmpty()) }
        .getOrDefault(ThemeChoice.SYSTEM),
    design = runCatching { DesignLanguage.valueOf(preferences[DESIGN].orEmpty()) }
        .getOrDefault(DesignLanguage.MATERIAL_EXPRESSIVE),
    accent = parseAccent(preferences[ACCENT]),
    customAccents = parseAccents(preferences[CUSTOM_ACCENTS]),
    isLogging = preferences[LOGGING] ?: true,
    vpnMode = parseVpnMode(preferences[VPN_MODE]),
    hasCompletedOnboarding = preferences[ONBOARDED] ?: false,
    isAutomationEnabled = preferences[AUTOMATION] ?: false,
    automationToken = preferences[AUTOMATION_TOKEN].orEmpty(),
    dnsSettings = DnsSettings(
        preset = DnsPreset.parse(preferences[DNS_PRESET]),
        customPrimary = preferences[CUSTOM_DNS_PRIMARY].orEmpty(),
        customSecondary = preferences[CUSTOM_DNS_SECONDARY].orEmpty(),
    ),
    clientRules = ClientRule.parseList(preferences[CLIENT_RULES]),
    experimentalBpfEnabled = preferences[EXPERIMENTAL_BPF_ENABLED] ?: true,
    bpfPollIntervalMs = (preferences[BPF_POLL_INTERVAL_MS] ?: 1000).coerceIn(500, 5000),
)
