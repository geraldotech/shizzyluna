package dev.shizzi

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
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
            if (index >= 0) {
                existing[index] = rule
            } else {
                existing.add(rule)
            }
            preferences[CLIENT_RULES] = ClientRule.serializeList(existing)
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
)
