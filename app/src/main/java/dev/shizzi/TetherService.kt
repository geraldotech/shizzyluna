package dev.shizzi

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

class TetherService : ITetherService.Stub {

    private val context: Context

    private val shellContext: Context by lazy { asShellContext(context) }
    private val runner: ProbeRunner by lazy { ProbeRunner(shellContext) }
    private val session: TetherSession by lazy { TetherSession(shellContext) }
    private val compatibility: CompatibilityCheck by lazy { CompatibilityCheck(shellContext) }
    private val apexInstaller: ApexInstaller by lazy { ApexInstaller() }

    @Suppress("unused")
    constructor() : this(acquireSystemContext())

    constructor(context: Context) {
        this.context = context
        liveInstance = this
        ExclusiveBlockingModeController.softApEngine.platformAdapter =
            ReflectionSoftApPlatformAdapter { shellContext }
    }

    override fun getContractVersion(): Int = CONTRACT_VERSION

    override fun start(logging: Boolean, vpnMode: String?): String =
        startWithDns(logging, vpnMode, null)

    override fun startWithDns(logging: Boolean, vpnMode: String?, dnsServers: Array<out String>?): String {
        SessionLog.setEnabled(logging)
        val dnsList = dnsServers?.toList()?.filter { it.isNotBlank() }
        return runCatching { session.start(parseVpnMode(vpnMode), dnsList) }
            .getOrElse { failure -> sessionError("start", failure) }
    }

    override fun stop(): String {
        runCatching { runner.teardown() }
            .onFailure { failure -> Log.w(TAG, "stop: probe teardown ${failure.message}") }

        return runCatching { session.stop() }
            .getOrElse { failure -> sessionError("stop", failure) }
    }

    override fun getStatus(): String =
        runCatching { session.status() }
            .getOrElse { failure -> sessionError("getStatus", failure) }

    override fun setLogging(enabled: Boolean) {
        SessionLog.setEnabled(enabled)
    }

    override fun checkCompatibility(): String =
        runCatching { compatibility.run().toJson() }
            .getOrElse { failure -> errorReport("checkCompatibility", failure) }

    override fun installTetheringApex(apex: ParcelFileDescriptor): String =
        runCatching { apexInstaller.stage(apex).toJson() }
            .getOrElse { failure -> stagingError(failure) }

    override fun rebootDevice(): String =
        runCatching {
            Runtime.getRuntime().exec(arrayOf("svc", "power", "reboot"))
            ""
        }.getOrElse { failure ->
            Log.e(TAG, "rebootDevice failed", failure)
            "${failure.javaClass.simpleName}: ${failure.message}"
        }

    override fun updateRules(rulesJson: String) {
        runCatching { session.updateRules(rulesJson) }
            .onFailure { failure -> Log.e(TAG, "updateRules failed: ${failure.message}") }
    }

    override fun updateDomainRules(domainRulesJson: String?) {
        runCatching { session.updateDomainRules(domainRulesJson.orEmpty()) }
            .onFailure { failure -> Log.e(TAG, "updateDomainRules failed: ${failure.message}") }
    }

    override fun clearLog() {
        runCatching { SessionLog.clear() }
            .onFailure { failure -> Log.w(TAG, "clearLog: ${failure.message}") }
    }

    override fun runProbes(attemptTethering: Boolean, availabilityTimeoutMs: Int): String =
        publish(
            runCatching { runner.run(attemptTethering, availabilityTimeoutMs) }
                .getOrElse { failure -> errorReport("runProbes", failure) },
        )

    override fun runFirewallDiagnostics(): String =
        runCatching {
            val json = session.runFirewallDiagnostics()
            runCatching { java.io.File(FIREWALL_DIAG_REPORT_PATH).writeText(json) }
            json
        }.getOrElse { failure -> errorReport("runFirewallDiagnostics", failure) }

    override fun runFirewallClientPoc(
        clientAMac: String?,
        clientBMac: String?,
        durationSec: Int,
    ): String =
        runCatching {
            val json = session.runFirewallClientPoc(
                clientAMac = clientAMac.orEmpty(),
                clientBMac = clientBMac.orEmpty(),
                durationSec = durationSec,
            )
            runCatching { java.io.File(FIREWALL_DIAG_REPORT_PATH).writeText(json) }
            json
        }.getOrElse { failure -> errorReport("runFirewallClientPoc", failure) }

    override fun cleanupFirewallTestRules(): String =
        runCatching { session.cleanupFirewallTestRules() }
            .getOrElse { failure -> "CLEANUP_FAILED: ${failure.javaClass.simpleName}: ${failure.message}" }

    override fun setExperimentalBpfConfig(enabled: Boolean, pollIntervalMs: Int): String =
        runCatching { session.setExperimentalBpfConfig(enabled, pollIntervalMs) }
            .getOrElse { failure -> errorReport("setExperimentalBpfConfig", failure) }

    override fun collectBpfSnapshotNow(): String =
        runCatching { session.collectBpfSnapshotNow() }
            .getOrElse { failure -> errorReport("collectBpfSnapshotNow", failure) }

    override fun resetClientQuota(mac: String?) {
        runCatching { session.resetClientQuota(mac.orEmpty()) }
            .onFailure { failure -> Log.e(TAG, "resetClientQuota failed: ${failure.message}") }
    }

    override fun setBpfRefreshOnMissConfig(enabled: Boolean, cooldownMs: Int): String =
        runCatching { session.setBpfRefreshOnMissConfig(enabled, cooldownMs) }
            .getOrElse { failure -> errorReport("setBpfRefreshOnMissConfig", failure) }

    override fun setDeepTupleDiagnosticsEnabled(enabled: Boolean): String =
        runCatching { session.setDeepTupleDiagnosticsEnabled(enabled) }
            .getOrElse { failure -> errorReport("setDeepTupleDiagnosticsEnabled", failure) }

    override fun resetBpfDiagnosticsCounters(): String =
        runCatching { session.resetBpfDiagnosticsCounters() }
            .getOrElse { failure -> errorReport("resetBpfDiagnosticsCounters", failure) }

    override fun setPhaseDEnforcementMode(mode: String?): String =
        runCatching { session.setPhaseDEnforcementMode(mode.orEmpty()) }
            .getOrElse { failure -> errorReport("setPhaseDEnforcementMode", failure) }

    override fun recordPhaseDDeliveryTestMarker(markerType: String?, note: String?): String =
        runCatching { session.recordPhaseDDeliveryTestMarker(markerType.orEmpty(), note.orEmpty()) }
            .getOrElse { failure -> errorReport("recordPhaseDDeliveryTestMarker", failure) }

    override fun selectBlockingMode(mode: String?): String =
        runCatching { session.selectBlockingMode(mode.orEmpty()) }
            .getOrElse { failure -> errorReport("selectBlockingMode", failure) }

    override fun checkPreNatCapability(): String =
        runCatching { session.checkPreNatCapability() }
            .getOrElse { failure -> errorReport("checkPreNatCapability", failure) }

    override fun reviewPreNatScopedProbe(): String =
        runCatching { session.reviewPreNatScopedProbe() }
            .getOrElse { failure -> errorReport("reviewPreNatScopedProbe", failure) }

    override fun runPreNatScopedProbe(userConfirmed: Boolean): String =
        runCatching { session.runPreNatScopedProbe(userConfirmed) }
            .getOrElse { failure -> errorReport("runPreNatScopedProbe", failure) }

    override fun activatePreNatBlockingMode(): String =
        runCatching { session.activatePreNatBlockingMode() }
            .getOrElse { failure -> errorReport("activatePreNatBlockingMode", failure) }

    override fun restoreBpfBlockingMode(): String =
        runCatching { session.restoreBpfBlockingMode() }
            .getOrElse { failure -> errorReport("restoreBpfBlockingMode", failure) }

    override fun checkSoftApCapability(): String =
        runCatching { session.checkSoftApCapability() }
            .getOrElse { failure -> errorReport("checkSoftApCapability", failure) }

    override fun runSoftApLiveProbe(
        clientAMac: String?,
        clientBMac: String?,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Int,
    ): String =
        runCatching {
            session.runSoftApLiveProbe(
                clientAMac = clientAMac.orEmpty(),
                clientBMac = clientBMac.orEmpty(),
                userConfirmed = userConfirmed,
                disconnectTimeoutMs = disconnectTimeoutMs,
            )
        }.getOrElse { failure -> errorReport("runSoftApLiveProbe", failure) }

    override fun activateSoftApBlockingMode(): String =
        runCatching { session.activateSoftApBlockingMode() }
            .getOrElse { failure -> errorReport("activateSoftApBlockingMode", failure) }

    override fun setStopHotspotOnVpnDisconnect(enabled: Boolean): String =
        runCatching { session.setStopHotspotOnVpnDisconnect(enabled) }
            .getOrElse { failure -> sessionError("setStopHotspotOnVpnDisconnect", failure) }

    override fun setDnsAttributionRetryConfig(enabled: Boolean, maxWaitMs: Int): String =
        runCatching { session.setDnsAttributionRetryConfig(enabled, maxWaitMs) }
            .getOrElse { failure -> errorReport("setDnsAttributionRetryConfig", failure) }


    private fun publish(report: String): String {
        runCatching { java.io.File(REPORT_PATH).writeText(report) }
            .onFailure { failure -> Log.w(TAG, "publish: ${failure.message}") }

        Log.i(TAG, "report: $report")
        return report
    }

    private fun sessionError(operation: String, failure: Throwable): String {
        Log.e(TAG, "$operation failed", failure)
        return org.json.JSONObject().apply {
            put("state", SessionState.ERROR.name)
            put("detail", "$operation: ${failure.javaClass.simpleName}: ${failure.message}")
        }.toString()
    }

    private fun stagingError(failure: Throwable): String {
        Log.e(TAG, "installTetheringApex failed", failure)
        return StagingOutcome(
            isStaged = false,
            rawOutput = "installTetheringApex: ${failure.javaClass.simpleName}: ${failure.message}",
        ).toJson()
    }

    private fun errorReport(operation: String, failure: Throwable): String {
        Log.e(TAG, "$operation failed", failure)
        return org.json.JSONObject().apply {
            put("verdict", "ERROR")
            put("operation", operation)
            put("error", "${failure.javaClass.name}: ${failure.message}")
            put("stackTrace", failure.stackTraceToString().take(STACK_TRACE_CHARS))
        }.toString(2)
    }

    companion object {

        val CONTRACT_VERSION = BuildConfig.SERVICE_BUILD_ID

        @Suppress("unused")
        @JvmStatic
        private var liveInstance: TetherService? = null

        private const val TAG = "TetherService"
        private const val STACK_TRACE_CHARS = 4000

        val REPORT_PATH: String =
            if (BuildConfig.APPLICATION_ID.endsWith(".debug")) {
                "/data/local/tmp/shizzi-debug-probe-report.json"
            } else {
                "/data/local/tmp/shizzi-probe-report.json"
            }

        val FIREWALL_DIAG_REPORT_PATH: String =
            if (BuildConfig.APPLICATION_ID.endsWith(".debug")) {
                "/data/local/tmp/shizzi-debug-firewall-diagnostic.json"
            } else {
                "/data/local/tmp/shizzi-firewall-diagnostic.json"
            }

        private const val SHELL_PACKAGE = "com.android.shell"

        @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
        private fun acquireSystemContext(): Context {
            val activityThread = Class.forName("android.app.ActivityThread")
            val systemMain = activityThread.getMethod("systemMain").invoke(null)
            return activityThread.getMethod("getSystemContext").invoke(systemMain) as Context
        }

        private fun asShellContext(context: Context): Context {
            val rebased = runCatching { context.createPackageContext(SHELL_PACKAGE, 0) }
                .getOrElse { failure ->
                    throw IllegalStateException(
                        "asShellContext: could not rebase context (package=" +
                            "${context.packageName}) onto $SHELL_PACKAGE",
                        failure,
                    )
                }
            forceOpPackageName(rebased)
            return rebased
        }

        private fun forceOpPackageName(context: Context) {
            runCatching {
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                        rebaseAttributionSource(context)

                    else -> rebaseOpPackageName(context)
                }
            }.getOrElse { failure ->
                throw IllegalStateException(
                    "forceOpPackageName: could not attribute context to $SHELL_PACKAGE",
                    failure,
                )
            }
        }

        private fun rebaseAttributionSource(context: Context) {
            val field = context.javaClass.getDeclaredField("mAttributionSource")
            field.isAccessible = true

            val current = field.get(context) ?: error("mAttributionSource was null")
            val rebased = current.javaClass
                .getMethod("withPackageName", String::class.java)
                .invoke(current, SHELL_PACKAGE)

            field.set(context, rebased)
        }

        private fun rebaseOpPackageName(context: Context) {
            val field = context.javaClass.getDeclaredField("mOpPackageName")
            field.isAccessible = true
            field.set(context, SHELL_PACKAGE)
        }
    }
}
