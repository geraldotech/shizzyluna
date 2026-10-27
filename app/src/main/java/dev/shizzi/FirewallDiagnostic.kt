package dev.shizzi

import android.content.Context
import android.os.Build
import android.system.Os
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import rikka.shizuku.Shizuku

enum class FirewallDiagnosticStatus {
    NOT_TESTED,
    PERMISSION_DENIED,
    UNSUPPORTED,
    READ_ONLY,
    WRITE_CONFIRMED,
    PARTIAL_COVERAGE,
    SELECTIVE_BLOCK_OBSERVED,
    ENFORCEMENT_UNAVAILABLE,
}

data class ReadOnlyProbeResult(
    val probeName: String,
    val command: String,
    val exitCode: Int,
    val timedOut: Boolean,
    val errorKind: ProbeErrorKind,
    val boundedStdout: String,
    val boundedStderr: String,
)

data class MechanismCapability(
    val mechanism: String,
    val family: String,
    val canReadRules: Boolean,
    val canWriteOwnedRules: Boolean,
    val selectiveEnforcementObserved: Boolean,
    val status: FirewallDiagnosticStatus,
    val detail: String,
)

data class ClientIdentityRecord(
    val clientId: String,
    val currentAddresses: List<String>,
    val ipv4Addresses: List<String>,
    val ipv6Addresses: List<String>,
    val downstreamInterface: String,
    val mappingSource: String,
)

data class TemporaryRuleTestResult(
    val executed: Boolean = false,
    val testId: String = "",
    val targetClientMac: String = "",
    val controlClientMac: String = "",
    val targetAddresses: List<String> = emptyList(),
    val ownedChainName: String = "",
    val ruleInstallStatus: String = "NOT_TESTED",
    val ruleCounterDeltaV4: Long = 0L,
    val ruleCounterDeltaV6: Long = 0L,
    val ipRuleInstallStatusV4: String = "NOT_TESTED",
    val ipRuleInstallStatusV6: String = "NOT_TESTED",
    val cleanupStatus: String = "NOT_APPLICABLE",
    val optionBEmptyCacheTested: Boolean = false,
    val optionBAttributedFlows: Int = 0,
    val optionBPolicyBlockedDropsDelta: Long = 0L,
    val optionBUnmatchedDelta: Long = 0L,
    val optionBFirstPacketLeakObserved: Boolean = false,
    val clientAConnectivity: String = "NOT_TESTED",
    val clientBConnectivity: String = "NOT_TESTED",
    val summaryStatus: FirewallDiagnosticStatus = FirewallDiagnosticStatus.NOT_TESTED,
    val notes: String = "",
)

data class ValidationScenarioRow(
    val id: Int,
    val scenario: String,
    val requiredOutcome: String,
    val status: String,
    val observedEvidence: String,
)

data class FirewallDiagnosticReport(
    val testId: String,
    val timestamp: String,
    val apkVersion: String,
    val versionCode: Int,
    val sourceCommit: String,
    val serviceBuildId: Int,
    val device: String,
    val androidApi: Int,
    val androidRelease: String,
    val vendorBuild: String,
    val tetheringModuleVersion: String,
    val uid: Int,
    val pid: Int,
    val shizukuUid: Int,
    val shizukuMode: String,
    val selinuxContext: String,
    val effectiveCapabilitiesHex: String,
    val downstreamInterface: String,
    val upstreamInterface: String,
    val datapathMode: String,
    val vpnState: String,
    val softApCallbackStatus: String,
    val tetheringCallbackStatus: String,
    val clients: List<ClientIdentityRecord>,
    val probes: List<ReadOnlyProbeResult>,
    val mechanismCapabilities: List<MechanismCapability>,
    val conntrackObservations: List<TunTrafficEngine.ConntrackPathObservation>,
    val conntrackReadStatus: String,
    val parsedFlows: Int,
    val attributedFlows: Int,
    val unmatchedDelta: Long,
    val temporaryRuleTest: TemporaryRuleTestResult,
    val validationMatrix: List<ValidationScenarioRow>,
    val overallStatus: FirewallDiagnosticStatus,
    val finalDecision: String,
    val factsConfirmed: List<String>,
    val hypothesesToVerify: List<String>,
) {
    fun toJsonString(): String {
        val root = JSONObject()
        root.put("testId", testId)
        root.put("timestamp", timestamp)
        root.put("apkVersion", apkVersion)
        root.put("versionCode", versionCode)
        root.put("sourceCommit", sourceCommit)
        root.put("serviceBuildId", serviceBuildId)
        root.put("device", device)
        root.put("androidApi", androidApi)
        root.put("androidRelease", androidRelease)
        root.put("vendorBuild", vendorBuild)
        root.put("tetheringModuleVersion", tetheringModuleVersion)
        root.put("uid", uid)
        root.put("pid", pid)
        root.put("shizukuUid", shizukuUid)
        root.put("shizukuMode", shizukuMode)
        root.put("selinuxContext", selinuxContext)
        root.put("effectiveCapabilitiesHex", effectiveCapabilitiesHex)
        root.put("downstreamInterface", downstreamInterface)
        root.put("upstreamInterface", upstreamInterface)
        root.put("datapathMode", datapathMode)
        root.put("vpnState", vpnState)
        root.put("softApCallbackStatus", softApCallbackStatus)
        root.put("tetheringCallbackStatus", tetheringCallbackStatus)
        root.put("conntrackReadStatus", conntrackReadStatus)
        root.put("parsedFlows", parsedFlows)
        root.put("attributedFlows", attributedFlows)
        root.put("unmatchedDelta", unmatchedDelta)
        root.put("overallStatus", overallStatus.name)
        root.put("finalDecision", finalDecision)

        val clientsArr = JSONArray()
        for (c in clients) {
            clientsArr.put(
                JSONObject().apply {
                    put("clientId", c.clientId)
                    put("currentAddresses", JSONArray(c.currentAddresses))
                    put("ipv4Addresses", JSONArray(c.ipv4Addresses))
                    put("ipv6Addresses", JSONArray(c.ipv6Addresses))
                    put("downstreamInterface", c.downstreamInterface)
                    put("mappingSource", c.mappingSource)
                },
            )
        }
        root.put("clients", clientsArr)

        val probesArr = JSONArray()
        for (p in probes) {
            probesArr.put(
                JSONObject().apply {
                    put("probeName", p.probeName)
                    put("command", p.command)
                    put("exitCode", p.exitCode)
                    put("timedOut", p.timedOut)
                    put("errorKind", p.errorKind.name)
                    put("boundedStdout", p.boundedStdout)
                    put("boundedStderr", p.boundedStderr)
                },
            )
        }
        root.put("probes", probesArr)

        val capArr = JSONArray()
        for (m in mechanismCapabilities) {
            capArr.put(
                JSONObject().apply {
                    put("mechanism", m.mechanism)
                    put("family", m.family)
                    put("canReadRules", m.canReadRules)
                    put("canWriteOwnedRules", m.canWriteOwnedRules)
                    put("selectiveEnforcementObserved", m.selectiveEnforcementObserved)
                    put("status", m.status.name)
                    put("detail", m.detail)
                },
            )
        }
        root.put("mechanismCapabilities", capArr)

        val ctArr = JSONArray()
        for (ct in conntrackObservations) {
            ctArr.put(
                JSONObject().apply {
                    put("path", ct.path)
                    put("existsObserved", ct.existsObserved)
                    put("openReadStatus", ct.openReadStatus)
                    put("rawError", ct.rawError)
                    put("boundedBytesRead", ct.bytesRead)
                    put("parsedRelevantFlows", ct.relevantParsedFlows)
                },
            )
        }
        root.put("conntrackObservations", ctArr)

        root.put(
            "temporaryRuleTest",
            JSONObject().apply {
                put("executed", temporaryRuleTest.executed)
                put("testId", temporaryRuleTest.testId)
                put("targetClientMac", temporaryRuleTest.targetClientMac)
                put("controlClientMac", temporaryRuleTest.controlClientMac)
                put("targetAddresses", JSONArray(temporaryRuleTest.targetAddresses))
                put("ownedChainName", temporaryRuleTest.ownedChainName)
                put("ruleInstallStatus", temporaryRuleTest.ruleInstallStatus)
                put("ruleCounterDeltaV4", temporaryRuleTest.ruleCounterDeltaV4)
                put("ruleCounterDeltaV6", temporaryRuleTest.ruleCounterDeltaV6)
                put("ipRuleInstallStatusV4", temporaryRuleTest.ipRuleInstallStatusV4)
                put("ipRuleInstallStatusV6", temporaryRuleTest.ipRuleInstallStatusV6)
                put("cleanupStatus", temporaryRuleTest.cleanupStatus)
                put("optionBEmptyCacheTested", temporaryRuleTest.optionBEmptyCacheTested)
                put("optionBAttributedFlows", temporaryRuleTest.optionBAttributedFlows)
                put("optionBPolicyBlockedDropsDelta", temporaryRuleTest.optionBPolicyBlockedDropsDelta)
                put("optionBUnmatchedDelta", temporaryRuleTest.optionBUnmatchedDelta)
                put("optionBFirstPacketLeakObserved", temporaryRuleTest.optionBFirstPacketLeakObserved)
                put("clientAConnectivity", temporaryRuleTest.clientAConnectivity)
                put("clientBConnectivity", temporaryRuleTest.clientBConnectivity)
                put("summaryStatus", temporaryRuleTest.summaryStatus.name)
                put("notes", temporaryRuleTest.notes)
            },
        )

        val matrixArr = JSONArray()
        for (row in validationMatrix) {
            matrixArr.put(
                JSONObject().apply {
                    put("id", row.id)
                    put("scenario", row.scenario)
                    put("requiredOutcome", row.requiredOutcome)
                    put("status", row.status)
                    put("observedEvidence", row.observedEvidence)
                },
            )
        }
        root.put("validationMatrix", matrixArr)
        root.put("factsConfirmed", JSONArray(factsConfirmed))
        root.put("hypothesesToVerify", JSONArray(hypothesesToVerify))

        return root.toString(2)
    }

    fun toMarkdownReport(): String = buildString {
        appendLine("# ShizziLuna — Relatório de Capacidade do Firewall por Cliente")
        appendLine()
        appendLine("## 1. Identificação e Processo (Fase 1)")
        appendLine("- **testId**: `$testId`")
        appendLine("- **timestamp**: `$timestamp`")
        appendLine("- **apkVersion**: `$apkVersion` (versionCode `$versionCode`)")
        appendLine("- **sourceCommit**: `$sourceCommit`")
        appendLine("- **serviceBuildId**: `$serviceBuildId`")
        appendLine("- **device**: `$device` (Android `$androidRelease`, API `$androidApi`, build `$vendorBuild`)")
        appendLine("- **tetheringModule**: `$tetheringModuleVersion`")
        appendLine("- **uid / pid / shizukuUid**: `uid=$uid`, `pid=$pid`, `shizukuUid=$shizukuUid`")
        appendLine("- **shizukuMode**: `$shizukuMode`")
        appendLine("- **selinuxContext**: `$selinuxContext`")
        appendLine("- **effectiveCapabilities (CapEff)**: `$effectiveCapabilitiesHex`")
        appendLine("- **downstreamInterface**: `$downstreamInterface`")
        appendLine("- **upstreamInterface**: `$upstreamInterface`")
        appendLine("- **datapathMode**: `$datapathMode`")
        appendLine("- **vpnState**: `$vpnState`")
        appendLine("- **softApCallback**: `$softApCallbackStatus`")
        appendLine("- **tetheringCallback**: `$tetheringCallbackStatus`")
        appendLine("- **overallStatus**: `${overallStatus.name}`")
        appendLine("- **finalDecision**: `$finalDecision`")
        appendLine()

        appendLine("## 2. Clientes Conectados e Bindings Verificados")
        if (clients.isEmpty()) {
            appendLine("_Nenhum cliente conectado no momento do probe._")
        } else {
            for (c in clients) {
                appendLine("- **clientId (MAC)**: `${c.clientId}` | iface=`${c.downstreamInterface}` | source=`${c.mappingSource}`")
                appendLine("  - currentAddresses: `${c.currentAddresses.joinToString(", ").ifBlank { "nenhum" }}`")
            }
        }
        appendLine()

        appendLine("## 3. Capacidades de Filtragem: Leitura vs Escrita vs Efeito Seletivo (Fase 2)")
        appendLine("| Mecanismo | Família | canReadRules | canWriteOwnedRules | selectiveEnforcementObserved | Status | Detalhe |")
        appendLine("| --- | --- | --- | --- | --- | --- | --- |")
        for (m in mechanismCapabilities) {
            appendLine("| `${m.mechanism}` | `${m.family}` | `${m.canReadRules}` | `${m.canWriteOwnedRules}` | `${m.selectiveEnforcementObserved}` | `${m.status.name}` | ${m.detail.replace("|", "/")} |")
        }
        appendLine()

        appendLine("## 4. Acesso Real à Tabela Conntrack (Fase 3 - Opção B)")
        appendLine("- **conntrackReadStatus**: `$conntrackReadStatus`")
        appendLine("- **parsedFlows**: `$parsedFlows` | **attributedFlows**: `$attributedFlows` | **unmatchedDelta**: `$unmatchedDelta`")
        appendLine()
        appendLine("| Caminho | existsObserved | openReadStatus | bytes | parsedFlows | rawError |")
        appendLine("| --- | --- | --- | --- | --- | --- |")
        for (ct in conntrackObservations) {
            appendLine("| `${ct.path}` | `${ct.existsObserved}` | `${ct.openReadStatus}` | `${ct.bytesRead}` | `${ct.relevantParsedFlows}` | ${ct.rawError.ifBlank { "-" }.replace("|", "/")} |")
        }
        appendLine()

        appendLine("## 5. Teste Temporário Controlado (Cliente A vs Cliente B)")
        appendLine("- **executed**: `${temporaryRuleTest.executed}`")
        appendLine("- **targetClientMac (A)**: `${temporaryRuleTest.targetClientMac.ifBlank { "N/A" }}`")
        appendLine("- **controlClientMac (B)**: `${temporaryRuleTest.controlClientMac.ifBlank { "N/A" }}`")
        appendLine("- **ownedChainName**: `${temporaryRuleTest.ownedChainName.ifBlank { "N/A" }}`")
        appendLine("- **ruleInstallStatus**: `${temporaryRuleTest.ruleInstallStatus}`")
        appendLine("- **ruleCounterDelta**: `v4=${temporaryRuleTest.ruleCounterDeltaV4}, v6=${temporaryRuleTest.ruleCounterDeltaV6}`")
        appendLine("- **cleanupStatus**: `${temporaryRuleTest.cleanupStatus}`")
        appendLine("- **optionBEmptyCacheTested**: `${temporaryRuleTest.optionBEmptyCacheTested}` | **firstPacketLeakObserved**: `${temporaryRuleTest.optionBFirstPacketLeakObserved}`")
        appendLine("- **clientAConnectivity**: `${temporaryRuleTest.clientAConnectivity}` | **clientBConnectivity**: `${temporaryRuleTest.clientBConnectivity}`")
        appendLine("- **summaryStatus**: `${temporaryRuleTest.summaryStatus.name}`")
        if (temporaryRuleTest.notes.isNotBlank()) {
            appendLine("- **notes**: ${temporaryRuleTest.notes}")
        }
        appendLine()

        appendLine("## 6. Probes Somente de Leitura (Saída Limitada)")
        for (p in probes) {
            appendLine("### `${p.probeName}` (`${p.command}`)")
            appendLine("- exitCode: `${p.exitCode}` | timedOut: `${p.timedOut}` | errorKind: `${p.errorKind.name}`")
            if (p.boundedStderr.isNotBlank()) {
                appendLine("- stderr: `${p.boundedStderr.replace("\n", " ").take(240)}`")
            }
            if (p.boundedStdout.isNotBlank()) {
                appendLine("```text")
                appendLine(p.boundedStdout.take(600))
                appendLine("```")
            }
        }
        appendLine()

        appendLine("## 7. Matriz de Validação Física (Fase 4)")
        appendLine("| # | Cenário | Resultado Necessário | Status | Evidência Observada |")
        appendLine("| --- | --- | --- | --- | --- |")
        for (row in validationMatrix) {
            appendLine("| ${row.id} | ${row.scenario} | ${row.requiredOutcome} | `${row.status}` | ${row.observedEvidence.replace("|", "/")} |")
        }
        appendLine()

        appendLine("## 8. Fatos Confirmados vs Hipóteses")
        appendLine("### Fatos Confirmados")
        for (f in factsConfirmed) {
            appendLine("- $f")
        }
        appendLine("### Hipóteses / Pendentes de Validação Física")
        for (h in hypothesesToVerify) {
            appendLine("- $h")
        }
    }

    companion object {
        fun fromJsonString(jsonStr: String): FirewallDiagnosticReport {
            val root = JSONObject(jsonStr)
            val clientsArr = root.optJSONArray("clients") ?: JSONArray()
            val clients = mutableListOf<ClientIdentityRecord>()
            for (i in 0 until clientsArr.length()) {
                val obj = clientsArr.getJSONObject(i)
                clients.add(
                    ClientIdentityRecord(
                        clientId = obj.optString("clientId"),
                        currentAddresses = jsonArrayToStringList(obj.optJSONArray("currentAddresses")),
                        ipv4Addresses = jsonArrayToStringList(obj.optJSONArray("ipv4Addresses")),
                        ipv6Addresses = jsonArrayToStringList(obj.optJSONArray("ipv6Addresses")),
                        downstreamInterface = obj.optString("downstreamInterface"),
                        mappingSource = obj.optString("mappingSource"),
                    ),
                )
            }

            val probesArr = root.optJSONArray("probes") ?: JSONArray()
            val probes = mutableListOf<ReadOnlyProbeResult>()
            for (i in 0 until probesArr.length()) {
                val obj = probesArr.getJSONObject(i)
                probes.add(
                    ReadOnlyProbeResult(
                        probeName = obj.optString("probeName"),
                        command = obj.optString("command"),
                        exitCode = obj.optInt("exitCode", -1),
                        timedOut = obj.optBoolean("timedOut", false),
                        errorKind = runCatching { ProbeErrorKind.valueOf(obj.optString("errorKind", "NONE")) }
                            .getOrDefault(ProbeErrorKind.NONE),
                        boundedStdout = obj.optString("boundedStdout"),
                        boundedStderr = obj.optString("boundedStderr"),
                    ),
                )
            }

            val capArr = root.optJSONArray("mechanismCapabilities") ?: JSONArray()
            val caps = mutableListOf<MechanismCapability>()
            for (i in 0 until capArr.length()) {
                val obj = capArr.getJSONObject(i)
                caps.add(
                    MechanismCapability(
                        mechanism = obj.optString("mechanism"),
                        family = obj.optString("family"),
                        canReadRules = obj.optBoolean("canReadRules", false),
                        canWriteOwnedRules = obj.optBoolean("canWriteOwnedRules", false),
                        selectiveEnforcementObserved = obj.optBoolean("selectiveEnforcementObserved", false),
                        status = runCatching { FirewallDiagnosticStatus.valueOf(obj.optString("status", "NOT_TESTED")) }
                            .getOrDefault(FirewallDiagnosticStatus.NOT_TESTED),
                        detail = obj.optString("detail"),
                    ),
                )
            }

            val ctArr = root.optJSONArray("conntrackObservations") ?: JSONArray()
            val cts = mutableListOf<TunTrafficEngine.ConntrackPathObservation>()
            for (i in 0 until ctArr.length()) {
                val obj = ctArr.getJSONObject(i)
                cts.add(
                    TunTrafficEngine.ConntrackPathObservation(
                        path = obj.optString("path"),
                        existsObserved = obj.optBoolean("existsObserved", false),
                        openReadStatus = obj.optString("openReadStatus"),
                        rawError = obj.optString("rawError"),
                        bytesRead = obj.optInt("boundedBytesRead", 0),
                        totalLines = obj.optInt("totalLines", 0),
                        relevantParsedFlows = obj.optInt("parsedRelevantFlows", 0),
                        sampleTuples = emptyList(),
                    ),
                )
            }

            val tempObj = root.optJSONObject("temporaryRuleTest") ?: JSONObject()
            val tempTest = TemporaryRuleTestResult(
                executed = tempObj.optBoolean("executed", false),
                testId = tempObj.optString("testId"),
                targetClientMac = tempObj.optString("targetClientMac"),
                controlClientMac = tempObj.optString("controlClientMac"),
                targetAddresses = jsonArrayToStringList(tempObj.optJSONArray("targetAddresses")),
                ownedChainName = tempObj.optString("ownedChainName"),
                ruleInstallStatus = tempObj.optString("ruleInstallStatus", "NOT_TESTED"),
                ruleCounterDeltaV4 = tempObj.optLong("ruleCounterDeltaV4", 0L),
                ruleCounterDeltaV6 = tempObj.optLong("ruleCounterDeltaV6", 0L),
                ipRuleInstallStatusV4 = tempObj.optString("ipRuleInstallStatusV4", "NOT_TESTED"),
                ipRuleInstallStatusV6 = tempObj.optString("ipRuleInstallStatusV6", "NOT_TESTED"),
                cleanupStatus = tempObj.optString("cleanupStatus", "NOT_APPLICABLE"),
                optionBEmptyCacheTested = tempObj.optBoolean("optionBEmptyCacheTested", false),
                optionBAttributedFlows = tempObj.optInt("optionBAttributedFlows", 0),
                optionBPolicyBlockedDropsDelta = tempObj.optLong("optionBPolicyBlockedDropsDelta", 0L),
                optionBUnmatchedDelta = tempObj.optLong("optionBUnmatchedDelta", 0L),
                optionBFirstPacketLeakObserved = tempObj.optBoolean("optionBFirstPacketLeakObserved", false),
                clientAConnectivity = tempObj.optString("clientAConnectivity", "NOT_TESTED"),
                clientBConnectivity = tempObj.optString("clientBConnectivity", "NOT_TESTED"),
                summaryStatus = runCatching {
                    FirewallDiagnosticStatus.valueOf(tempObj.optString("summaryStatus", "NOT_TESTED"))
                }.getOrDefault(FirewallDiagnosticStatus.NOT_TESTED),
                notes = tempObj.optString("notes"),
            )

            val matrixArr = root.optJSONArray("validationMatrix") ?: JSONArray()
            val matrix = mutableListOf<ValidationScenarioRow>()
            for (i in 0 until matrixArr.length()) {
                val obj = matrixArr.getJSONObject(i)
                matrix.add(
                    ValidationScenarioRow(
                        id = obj.optInt("id", i + 1),
                        scenario = obj.optString("scenario"),
                        requiredOutcome = obj.optString("requiredOutcome"),
                        status = obj.optString("status", "NOT_TESTED"),
                        observedEvidence = obj.optString("observedEvidence"),
                    ),
                )
            }

            return FirewallDiagnosticReport(
                testId = root.optString("testId"),
                timestamp = root.optString("timestamp"),
                apkVersion = root.optString("apkVersion"),
                versionCode = root.optInt("versionCode", 10),
                sourceCommit = root.optString("sourceCommit"),
                serviceBuildId = root.optInt("serviceBuildId", 10),
                device = root.optString("device"),
                androidApi = root.optInt("androidApi"),
                androidRelease = root.optString("androidRelease"),
                vendorBuild = root.optString("vendorBuild"),
                tetheringModuleVersion = root.optString("tetheringModuleVersion"),
                uid = root.optInt("uid", -1),
                pid = root.optInt("pid", -1),
                shizukuUid = root.optInt("shizukuUid", -1),
                shizukuMode = root.optString("shizukuMode"),
                selinuxContext = root.optString("selinuxContext"),
                effectiveCapabilitiesHex = root.optString("effectiveCapabilitiesHex"),
                downstreamInterface = root.optString("downstreamInterface"),
                upstreamInterface = root.optString("upstreamInterface"),
                datapathMode = root.optString("datapathMode"),
                vpnState = root.optString("vpnState"),
                softApCallbackStatus = root.optString("softApCallbackStatus"),
                tetheringCallbackStatus = root.optString("tetheringCallbackStatus"),
                clients = clients,
                probes = probes,
                mechanismCapabilities = caps,
                conntrackObservations = cts,
                conntrackReadStatus = root.optString("conntrackReadStatus"),
                parsedFlows = root.optInt("parsedFlows", 0),
                attributedFlows = root.optInt("attributedFlows", 0),
                unmatchedDelta = root.optLong("unmatchedDelta", 0L),
                temporaryRuleTest = tempTest,
                validationMatrix = matrix,
                overallStatus = runCatching {
                    FirewallDiagnosticStatus.valueOf(root.optString("overallStatus", "NOT_TESTED"))
                }.getOrDefault(FirewallDiagnosticStatus.NOT_TESTED),
                finalDecision = root.optString("finalDecision"),
                factsConfirmed = jsonArrayToStringList(root.optJSONArray("factsConfirmed")),
                hypothesesToVerify = jsonArrayToStringList(root.optJSONArray("hypothesesToVerify")),
            )
        }

        private fun jsonArrayToStringList(arr: JSONArray?): List<String> {
            if (arr == null) return emptyList()
            val list = mutableListOf<String>()
            for (i in 0 until arr.length()) {
                list.add(arr.optString(i))
            }
            return list
        }
    }
}

object FirewallDiagnosticRunner {

    private const val ACTIVE_RULES_JOURNAL_PATH = "/data/local/tmp/shizzi-active-test-rules.json"
    private const val PROBE_MAX_CHARS = 1_500

    @Volatile
    private var lastReport: FirewallDiagnosticReport? = null

    fun getLastReport(): FirewallDiagnosticReport? = lastReport

    /**
     * Recovers and removes any orphaned `SHIZZI_TEST_*` chains/jumps or `priority 19875` ip rules
     * created by previous diagnostic tests that may have been interrupted or crashed.
     * Never touches system chains, OEM rules, or rules from other apps.
     */
    @Synchronized
    fun recoverOrphanedTestRules(): String {
        val cleaned = mutableListOf<String>()
        val failed = mutableListOf<String>()

        // 1. Check journal file if present
        val journalFile = File(ACTIVE_RULES_JOURNAL_PATH)
        if (journalFile.exists() && journalFile.canRead()) {
            runCatching {
                val obj = JSONObject(journalFile.readText())
                val chain = obj.optString("chainName")
                val downIface = obj.optString("downstreamInterface")
                val upIface = obj.optString("upstreamInterface")
                val v4Ips = obj.optJSONArray("v4Ips") ?: JSONArray()
                val v6Ips = obj.optJSONArray("v6Ips") ?: JSONArray()

                if (chain.startsWith("SHIZZI_TEST_")) {
                    cleanupOwnedChain("iptables", chain, downIface, upIface, cleaned, failed)
                    cleanupOwnedChain("ip6tables", chain, downIface, upIface, cleaned, failed)
                }
                for (i in 0 until v4Ips.length()) {
                    val ip = v4Ips.optString(i)
                    if (ip.isNotBlank()) {
                        val r = HostFirewall.executeCommand("ip", "rule", "del", "from", "$ip/32", "unreachable", "priority", "19875")
                        if (r.isSuccess) cleaned.add("ip rule v4 $ip")
                    }
                }
                for (i in 0 until v6Ips.length()) {
                    val ip = v6Ips.optString(i)
                    if (ip.isNotBlank()) {
                        val r = HostFirewall.executeCommand("ip", "-6", "rule", "del", "from", "$ip/128", "unreachable", "priority", "19875")
                        if (r.isSuccess) cleaned.add("ip6 rule v6 $ip")
                    }
                }
                journalFile.delete()
            }
        }

        // 2. Also scan live `iptables -S FORWARD` and `ip6tables -S FORWARD` for any `SHIZZI_TEST_` jumps/chains
        for (bin in listOf("iptables", "ip6tables")) {
            val listRes = HostFirewall.executeCommand(bin, "-S")
            if (listRes.isSuccess) {
                val lines = listRes.stdout.lines()
                val jumpLines = lines.filter { it.startsWith("-A FORWARD ") && it.contains("SHIZZI_TEST_") }
                for (jump in jumpLines) {
                    val delArgs = jump.replaceFirst("-A ", "-D ").split(Regex("\\s+")).toTypedArray()
                    val r = HostFirewall.executeCommand(bin, *delArgs)
                    if (r.isSuccess) cleaned.add("$bin $jump") else failed.add("$bin $jump (${r.stderr})")
                }
                val chainLines = lines.filter { it.startsWith("-N SHIZZI_TEST_") }
                for (chainLine in chainLines) {
                    val chainName = chainLine.removePrefix("-N ").trim()
                    HostFirewall.executeCommand(bin, "-F", chainName)
                    val r = HostFirewall.executeCommand(bin, "-X", chainName)
                    if (r.isSuccess) cleaned.add("$bin chain $chainName") else failed.add("$bin chain $chainName (${r.stderr})")
                }
            }
        }

        // Also clean up any leftover `SHIZZI_CAP_CHK` chain
        for (bin in listOf("iptables", "ip6tables")) {
            HostFirewall.executeCommand(bin, "-F", "SHIZZI_CAP_CHK")
            HostFirewall.executeCommand(bin, "-X", "SHIZZI_CAP_CHK")
        }

        val status = when {
            failed.isNotEmpty() -> "PARTIAL_FAILURE: cleaned=${cleaned.size} failed=${failed.joinToString("; ")}"
            cleaned.isNotEmpty() -> "CLEANED_ORPHANS (${cleaned.size}): ${cleaned.joinToString(", ")}"
            else -> "CLEAN_VERIFIED (0 orphan rules found)"
        }
        SessionLog.info("FirewallDiag: orphan recovery -> $status")
        return status
    }

    private fun cleanupOwnedChain(
        bin: String,
        chainName: String,
        downIface: String,
        upIface: String,
        cleaned: MutableList<String>,
        failed: MutableList<String>,
    ) {
        if (!chainName.startsWith("SHIZZI_TEST_")) return
        if (downIface.isNotBlank() && upIface.isNotBlank()) {
            HostFirewall.executeCommand(bin, "-D", "FORWARD", "-i", downIface, "-o", upIface, "-j", chainName)
            HostFirewall.executeCommand(bin, "-D", "FORWARD", "-i", upIface, "-o", downIface, "-j", chainName)
        }
        HostFirewall.executeCommand(bin, "-D", "FORWARD", "-j", chainName)
        val flushRes = HostFirewall.executeCommand(bin, "-F", chainName)
        val delRes = HostFirewall.executeCommand(bin, "-X", chainName)
        if (flushRes.isSuccess && delRes.isSuccess) {
            cleaned.add("$bin:$chainName")
        } else if (delRes.errorKind != ProbeErrorKind.EXECUTION_FAILED && !delRes.stderr.contains("No chain/target/match")) {
            failed.add("$bin:$chainName(${delRes.stderr})")
        }
    }

    /**
     * Executes Fase 1 + Fase 2 (A1/A2 capability probes) + Fase 3 (B1 conntrack probes)
     * inside the Shizuku UserService process without modifying active client traffic.
     */
    @Synchronized
    fun runReadOnlyDiagnostic(
        context: Context?,
        downstreamInspector: DownstreamInspector,
        upstreamInterfaceName: String?,
        vpnActive: Boolean,
        previousTempResult: TemporaryRuleTestResult = lastReport?.temporaryRuleTest ?: TemporaryRuleTestResult(),
    ): FirewallDiagnosticReport {
        val testId = "DIAG-" + UUID.randomUUID().toString().uppercase().take(8)
        val timestamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).format(Date())

        // Always recover any orphan test rules before probing
        recoverOrphanedTestRules()

        val uid = runCatching { Os.getuid() }.getOrDefault(-1)
        val pid = runCatching { Os.getpid() }.getOrDefault(-1)
        val shizukuUid = runCatching { Shizuku.getUid() }.getOrDefault(uid)
        val shizukuMode = when (uid) {
            0 -> "ROOT (uid=0)"
            2000 -> "ADB_SHELL (uid=2000, rootless)"
            else -> "UID_$uid"
        }

        val selinuxFromProc = runCatching {
            File("/proc/self/attr/current").takeIf { it.canRead() }?.readText()?.trim()?.trimEnd('\u0000')
        }.getOrNull()

        val capEff = readCapEffFromProcStatus()
        val tetheringApex = resolveTetheringModuleVersion(context)

        // Execute mandatory Fase 1 read-only probes separately with bounded output
        val probeSpecs = listOf(
            "id" to arrayOf("id"),
            "id_Z" to arrayOf("id", "-Z"),
            "ip_addr_show" to arrayOf("ip", "addr", "show"),
            "ip_route_show" to arrayOf("ip", "route", "show"),
            "ip6_route_show" to arrayOf("ip", "-6", "route", "show"),
            "ip_rule_show" to arrayOf("ip", "rule", "show"),
            "ip6_rule_show" to arrayOf("ip", "-6", "rule", "show"),
            "ip_neigh_show" to arrayOf("ip", "neigh", "show"),
            "ip6_neigh_show" to arrayOf("ip", "-6", "neigh", "show"),
            "iptables_version" to arrayOf("iptables", "--version"),
            "iptables_S_FORWARD" to arrayOf("iptables", "-S", "FORWARD"),
            "iptables_nat_S" to arrayOf("iptables", "-t", "nat", "-S"),
            "ip6tables_S_FORWARD" to arrayOf("ip6tables", "-S", "FORWARD"),
            "nft_version" to arrayOf("nft", "--version"),
            "conntrack_version" to arrayOf("conntrack", "--version"),
        )

        val probeResults = probeSpecs.map { (name, cmd) ->
            val res = HostFirewall.executeCommand(*cmd, timeoutMs = 2_000L)
            ReadOnlyProbeResult(
                probeName = name,
                command = res.command,
                exitCode = res.exitCode,
                timedOut = res.timedOut,
                errorKind = res.errorKind,
                boundedStdout = res.stdout.take(PROBE_MAX_CHARS),
                boundedStderr = res.stderr.take(PROBE_MAX_CHARS),
            )
        }

        val idZOut = probeResults.firstOrNull { it.probeName == "id_Z" }?.boundedStdout.orEmpty()
        val selinuxContext = selinuxFromProc?.ifBlank { null }
            ?: idZOut.ifBlank { "unknown" }

        // Client discovery snapshot (official callbacks + softap_dump + downstream neighbors)
        val downSnap = downstreamInspector.inspectSnapshot(forceRefresh = true)
        val downIface = downSnap.apInterfaces.firstOrNull()
            ?: downSnap.clients.firstOrNull()?.interfaceName
            ?: "unknown"
        val upIface = upstreamInterfaceName ?: TunTrafficEngine.activeUpstreamName.ifBlank { "unknown" }

        val clientRecords = downSnap.clients.map { host ->
            val all = (listOf(host.ip) + host.allIps).map { it.trim() }.filter { it.isNotBlank() }.distinct()
            ClientIdentityRecord(
                clientId = host.mac,
                currentAddresses = all,
                ipv4Addresses = all.filter { !it.contains(':') },
                ipv6Addresses = all.filter { it.contains(':') },
                downstreamInterface = host.interfaceName,
                mappingSource = host.mappingSource,
            )
        }

        // Fase 2 A2: Evaluate read vs write vs selective enforcement capabilities
        val capMatrix = HostFirewall.probeKernelCapabilities(force = true)
        val binderProbe = probeNetdBinderFirewall()

        val v4Selective = previousTempResult.executed &&
            previousTempResult.ruleInstallStatus.startsWith("INSTALLED") &&
            previousTempResult.ruleCounterDeltaV4 > 0L
        val v6Selective = previousTempResult.executed &&
            previousTempResult.ruleInstallStatus.startsWith("INSTALLED") &&
            previousTempResult.ruleCounterDeltaV6 > 0L

        val mechanismCapabilities = listOf(
            MechanismCapability(
                mechanism = "netfilter_iptables_FORWARD",
                family = "IPv4",
                canReadRules = capMatrix.canReadNetfilterV4,
                canWriteOwnedRules = capMatrix.canWriteNetfilterV4,
                selectiveEnforcementObserved = v4Selective,
                status = computeMechanismStatus(
                    canRead = capMatrix.canReadNetfilterV4,
                    canWrite = capMatrix.canWriteNetfilterV4,
                    selective = v4Selective,
                    writeError = capMatrix.netfilterV4WriteError,
                ),
                detail = if (capMatrix.canWriteNetfilterV4) {
                    "Owned chain SHIZZI_CAP_CHK created & removed"
                } else {
                    "Write denied: ${capMatrix.netfilterV4WriteError.take(120)}"
                },
            ),
            MechanismCapability(
                mechanism = "netfilter_ip6tables_FORWARD",
                family = "IPv6",
                canReadRules = capMatrix.canReadNetfilterV6,
                canWriteOwnedRules = capMatrix.canWriteNetfilterV6,
                selectiveEnforcementObserved = v6Selective,
                status = computeMechanismStatus(
                    canRead = capMatrix.canReadNetfilterV6,
                    canWrite = capMatrix.canWriteNetfilterV6,
                    selective = v6Selective,
                    writeError = capMatrix.netfilterV6WriteError,
                ),
                detail = if (capMatrix.canWriteNetfilterV6) {
                    "Owned chain SHIZZI_CAP_CHK created & removed"
                } else {
                    "Write denied: ${capMatrix.netfilterV6WriteError.take(120)}"
                },
            ),
            MechanismCapability(
                mechanism = "policy_routing_ip_rule",
                family = "IPv4",
                canReadRules = capMatrix.canReadIpRuleV4,
                canWriteOwnedRules = capMatrix.canWriteIpRuleV4,
                selectiveEnforcementObserved = false,
                status = computeMechanismStatus(
                    canRead = capMatrix.canReadIpRuleV4,
                    canWrite = capMatrix.canWriteIpRuleV4,
                    selective = false,
                    writeError = capMatrix.ipRuleV4WriteError,
                ),
                detail = if (capMatrix.canWriteIpRuleV4) {
                    "Temporary priority 19899 rule added & deleted"
                } else {
                    "canRead=${capMatrix.canReadIpRuleV4} (ip rule show is read-only); write denied: ${capMatrix.ipRuleV4WriteError.take(100)}"
                },
            ),
            MechanismCapability(
                mechanism = "policy_routing_ip6_rule",
                family = "IPv6",
                canReadRules = capMatrix.canReadIpRuleV6,
                canWriteOwnedRules = capMatrix.canWriteIpRuleV6,
                selectiveEnforcementObserved = false,
                status = computeMechanismStatus(
                    canRead = capMatrix.canReadIpRuleV6,
                    canWrite = capMatrix.canWriteIpRuleV6,
                    selective = false,
                    writeError = capMatrix.ipRuleV6WriteError,
                ),
                detail = if (capMatrix.canWriteIpRuleV6) {
                    "Temporary priority 19899 IPv6 rule added & deleted"
                } else {
                    "canRead=${capMatrix.canReadIpRuleV6} (ip -6 rule show is read-only); write denied: ${capMatrix.ipRuleV6WriteError.take(100)}"
                },
            ),
            binderProbe,
        )

        // Fase 3 B1: Conntrack path inspection inside Shizuku UserService
        val conntrackObs = TunTrafficEngine.inspectConntrackPaths()
        val readableCt = conntrackObs.firstOrNull { it.openReadStatus == "READ_OK" }
        val ctStatus = when {
            readableCt != null && readableCt.relevantParsedFlows > 0 ->
                "READABLE_WITH_FLOWS (${readableCt.path}: ${readableCt.relevantParsedFlows} flows)"
            readableCt != null ->
                "READABLE_ZERO_RELEVANT_FLOWS (${readableCt.path})"
            conntrackObs.any { it.openReadStatus == "PERMISSION_DENIED" } ->
                "PERMISSION_DENIED (${conntrackObs.first { it.openReadStatus == "PERMISSION_DENIED" }.rawError})"
            else ->
                "FILE_MISSING_OR_UNEXPOSED (${conntrackObs.joinToString(", ") { "${it.path}:${it.openReadStatus}" }})"
        }

        val totalParsedFlows = conntrackObs.maxOfOrNull { it.relevantParsedFlows } ?: 0
        val totalAttributedFlows = clientRecords.sumOf { TunTrafficEngine.getAttributedFlowCount(it.clientId) }
        val unmatchedTotal = TunTrafficEngine.unmatchedPackets.get()

        val optionAWritable = capMatrix.canWriteBothFamiliesNetfilter || capMatrix.canWriteBothFamiliesIpRule
        val optionBReadable = readableCt != null

        val overallStatus = when {
            previousTempResult.summaryStatus == FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED ->
                FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED
            optionAWritable -> FirewallDiagnosticStatus.WRITE_CONFIRMED
            capMatrix.canWriteNetfilterV4 xor capMatrix.canWriteNetfilterV6 ->
                FirewallDiagnosticStatus.PARTIAL_COVERAGE
            optionBReadable && previousTempResult.optionBFirstPacketLeakObserved ->
                FirewallDiagnosticStatus.PARTIAL_COVERAGE
            !optionAWritable && !optionBReadable ->
                FirewallDiagnosticStatus.ENFORCEMENT_UNAVAILABLE
            capMatrix.canReadIpRuleV4 || capMatrix.canReadNetfilterV4 ->
                FirewallDiagnosticStatus.READ_ONLY
            else -> FirewallDiagnosticStatus.PERMISSION_DENIED
        }

        val finalDecision = buildFinalDecision(
            uid = uid,
            shizukuMode = shizukuMode,
            capMatrix = capMatrix,
            readableCt = readableCt,
            tempResult = previousTempResult,
        )

        val facts = buildConfirmedFacts(
            uid = uid,
            shizukuMode = shizukuMode,
            selinuxContext = selinuxContext,
            capEff = capEff,
            capMatrix = capMatrix,
            conntrackObs = conntrackObs,
            clientRecords = clientRecords,
            tempResult = previousTempResult,
        )

        val hypotheses = buildHypotheses(
            capMatrix = capMatrix,
            readableCt = readableCt,
            clientRecords = clientRecords,
            tempResult = previousTempResult,
        )

        val validationMatrix = buildValidationMatrix(
            clientRecords = clientRecords,
            capMatrix = capMatrix,
            readableCt = readableCt,
            tempResult = previousTempResult,
        )

        val report = FirewallDiagnosticReport(
            testId = testId,
            timestamp = timestamp,
            apkVersion = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            sourceCommit = BuildConfig.SOURCE_COMMIT,
            serviceBuildId = BuildConfig.SERVICE_BUILD_ID,
            device = "${Build.MANUFACTURER} ${Build.MODEL}",
            androidApi = Build.VERSION.SDK_INT,
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            vendorBuild = Build.DISPLAY ?: "unknown",
            tetheringModuleVersion = tetheringApex,
            uid = uid,
            pid = pid,
            shizukuUid = shizukuUid,
            shizukuMode = shizukuMode,
            selinuxContext = selinuxContext,
            effectiveCapabilitiesHex = capEff,
            downstreamInterface = downIface,
            upstreamInterface = upIface,
            datapathMode = TunTrafficEngine.datapathMode.name,
            vpnState = if (vpnActive) "VPN_DETECTED" else "NO_VPN",
            softApCallbackStatus = downSnap.callbackObservation.softApCallbackStatus,
            tetheringCallbackStatus = downSnap.callbackObservation.tetheringCallbackStatus,
            clients = clientRecords,
            probes = probeResults,
            mechanismCapabilities = mechanismCapabilities,
            conntrackObservations = conntrackObs,
            conntrackReadStatus = ctStatus,
            parsedFlows = totalParsedFlows,
            attributedFlows = totalAttributedFlows,
            unmatchedDelta = unmatchedTotal,
            temporaryRuleTest = previousTempResult,
            validationMatrix = validationMatrix,
            overallStatus = overallStatus,
            finalDecision = finalDecision,
            factsConfirmed = facts,
            hypothesesToVerify = hypotheses,
        )

        lastReport = report
        SessionLog.info(
            "FirewallDiag: completed testId=$testId mode=$shizukuMode status=${overallStatus.name} " +
                "optA_writeV4=${capMatrix.canWriteNetfilterV4} optA_writeV6=${capMatrix.canWriteNetfilterV6} " +
                "optB_ct=$ctStatus",
        )
        return report
    }

    /**
     * Executes Fase 2 (A3 controlled temporary rule test on Client A) and Fase 3 (B2/B3 empty-cache
     * flow correlation & first-packet leak window test on Client A), with guaranteed deterministic cleanup.
     */
    @Synchronized
    fun runTemporaryClientPoc(
        context: Context?,
        downstreamInspector: DownstreamInspector,
        upstreamInterfaceName: String?,
        vpnActive: Boolean,
        clientAMac: String,
        clientBMac: String,
        durationSec: Int,
    ): FirewallDiagnosticReport {
        val normA = clientAMac.uppercase().trim()
        val normB = clientBMac.uppercase().trim()
        val boundedDurationSec = durationSec.coerceIn(2, 15)
        val shortId = UUID.randomUUID().toString().uppercase().replace("-", "").take(6)
        val testId = "POC-$shortId"
        val chainName = "SHIZZI_TEST_$shortId"

        val downSnap = downstreamInspector.inspectSnapshot(forceRefresh = true)
        val hostA = downSnap.clients.firstOrNull { it.mac.equals(normA, ignoreCase = true) }
        val hostB = if (normB.isNotBlank()) {
            downSnap.clients.firstOrNull { it.mac.equals(normB, ignoreCase = true) }
        } else {
            downSnap.clients.firstOrNull { !it.mac.equals(normA, ignoreCase = true) }
        }

        val downIface = hostA?.interfaceName
            ?: downSnap.apInterfaces.firstOrNull()
            ?: "wlan1"
        val upIface = upstreamInterfaceName ?: TunTrafficEngine.activeUpstreamName.ifBlank { "testtun0" }

        val targetIps = if (hostA != null) {
            (listOf(hostA.ip) + hostA.allIps).map { it.trim() }.filter { it.isNotBlank() }.distinct()
        } else {
            emptyList()
        }
        val v4Ips = targetIps.filter { !it.contains(':') }
        val v6Ips = targetIps.filter { it.contains(':') && !it.lowercase().startsWith("fe80:") }

        val capMatrix = HostFirewall.probeKernelCapabilities(force = true)

        var ruleInstallStatus = "SKIPPED_NO_WRITE_CAPABILITY"
        var v4Delta = 0L
        var v6Delta = 0L
        var ipRuleV4Status = "SKIPPED"
        var ipRuleV6Status = "SKIPPED"
        var cleanupStatus = "NOT_REQUIRED"

        // Record baseline Option B counters before clearing Client A's flow cache
        val beforeCountersA = TunTrafficEngine.getCounterSnapshot(normA)
        val beforeCountersB = if (hostB != null) TunTrafficEngine.getCounterSnapshot(hostB.mac) else null
        val beforeUnmatched = TunTrafficEngine.unmatchedPackets.get()
        val beforePostNatUnmatched = TunTrafficEngine.postNatUnmatchedPackets.get()

        // Fase 3 B3: Clear Client A's flow cache so we explicitly test the empty-cache first-packet window!
        TunTrafficEngine.purgeFlowsForMac(normA)

        // Write journal before installing any temporary kernel rules for crash recovery
        writeActiveRulesJournal(chainName, downIface, upIface, v4Ips, v6Ips)

        try {
            val installedAny = mutableListOf<String>()
            val installErrors = mutableListOf<String>()

            if (capMatrix.canWriteNetfilterV4 && v4Ips.isNotEmpty()) {
                val cRes = HostFirewall.executeCommand("iptables", "-N", chainName)
                if (cRes.isSuccess) {
                    for (ip in v4Ips) {
                        HostFirewall.executeCommand("iptables", "-A", chainName, "-s", ip, "-j", "DROP")
                        HostFirewall.executeCommand("iptables", "-A", chainName, "-d", ip, "-j", "DROP")
                    }
                    val j1 = HostFirewall.executeCommand("iptables", "-I", "FORWARD", "1", "-i", downIface, "-o", upIface, "-j", chainName)
                    val j2 = HostFirewall.executeCommand("iptables", "-I", "FORWARD", "1", "-i", upIface, "-o", downIface, "-j", chainName)
                    if (j1.isSuccess && j2.isSuccess) {
                        installedAny.add("iptables:$chainName")
                    } else {
                        installErrors.add("iptables jump: ${j1.stderr} ${j2.stderr}")
                    }
                } else {
                    installErrors.add("iptables -N: ${cRes.stderr}")
                }
            } else if (!capMatrix.canWriteNetfilterV4) {
                installErrors.add("iptables write denied (${capMatrix.netfilterV4WriteError.take(60)})")
            }

            if (capMatrix.canWriteNetfilterV6 && v6Ips.isNotEmpty()) {
                val cRes6 = HostFirewall.executeCommand("ip6tables", "-N", chainName)
                if (cRes6.isSuccess) {
                    for (ip in v6Ips) {
                        HostFirewall.executeCommand("ip6tables", "-A", chainName, "-s", ip, "-j", "DROP")
                        HostFirewall.executeCommand("ip6tables", "-A", chainName, "-d", ip, "-j", "DROP")
                    }
                    val j1 = HostFirewall.executeCommand("ip6tables", "-I", "FORWARD", "1", "-i", downIface, "-o", upIface, "-j", chainName)
                    val j2 = HostFirewall.executeCommand("ip6tables", "-I", "FORWARD", "1", "-i", upIface, "-o", downIface, "-j", chainName)
                    if (j1.isSuccess && j2.isSuccess) {
                        installedAny.add("ip6tables:$chainName")
                    } else {
                        installErrors.add("ip6tables jump: ${j1.stderr} ${j2.stderr}")
                    }
                } else {
                    installErrors.add("ip6tables -N: ${cRes6.stderr}")
                }
            } else if (!capMatrix.canWriteNetfilterV6) {
                installErrors.add("ip6tables write denied (${capMatrix.netfilterV6WriteError.take(60)})")
            }

            if (capMatrix.canWriteIpRuleV4 && v4Ips.isNotEmpty()) {
                val ok = v4Ips.all { ip ->
                    HostFirewall.executeCommand("ip", "rule", "add", "from", "$ip/32", "unreachable", "priority", "19875").isSuccess
                }
                ipRuleV4Status = if (ok) "INSTALLED" else "FAILED"
            } else {
                ipRuleV4Status = "PERMISSION_DENIED"
            }

            if (capMatrix.canWriteIpRuleV6 && v6Ips.isNotEmpty()) {
                val ok = v6Ips.all { ip ->
                    HostFirewall.executeCommand("ip", "-6", "rule", "add", "from", "$ip/128", "unreachable", "priority", "19875").isSuccess
                }
                ipRuleV6Status = if (ok) "INSTALLED" else "FAILED"
            } else {
                ipRuleV6Status = "PERMISSION_DENIED"
            }

            ruleInstallStatus = when {
                installedAny.isNotEmpty() -> "INSTALLED (${installedAny.joinToString(",")})"
                targetIps.isEmpty() -> "NO_TARGET_CLIENT_IPS"
                else -> "PERMISSION_DENIED (${installErrors.joinToString("; ").take(160)})"
            }

            // Wait bounded window to observe live traffic counters across Client A and Client B
            Thread.sleep(boundedDurationSec * 1_000L)

            if (installedAny.any { it.startsWith("iptables:") }) {
                val cntOut = HostFirewall.executeCommand("iptables", "-L", chainName, "-v", "-n", "-x")
                v4Delta = parseIptablesChainPacketSum(cntOut.stdout)
            }
            if (installedAny.any { it.startsWith("ip6tables:") }) {
                val cntOut6 = HostFirewall.executeCommand("ip6tables", "-L", chainName, "-v", "-n", "-x")
                v6Delta = parseIptablesChainPacketSum(cntOut6.stdout)
            }
        } finally {
            // Guaranteed deterministic cleanup of all owned rules
            val cleaned = mutableListOf<String>()
            val failed = mutableListOf<String>()
            cleanupOwnedChain("iptables", chainName, downIface, upIface, cleaned, failed)
            cleanupOwnedChain("ip6tables", chainName, downIface, upIface, cleaned, failed)
            for (ip in v4Ips) {
                HostFirewall.executeCommand("ip", "rule", "del", "from", "$ip/32", "unreachable", "priority", "19875")
            }
            for (ip in v6Ips) {
                HostFirewall.executeCommand("ip", "-6", "rule", "del", "from", "$ip/128", "unreachable", "priority", "19875")
            }
            runCatching { File(ACTIVE_RULES_JOURNAL_PATH).delete() }

            cleanupStatus = when {
                failed.isNotEmpty() -> "CLEANUP_ERROR: ${failed.joinToString("; ")}"
                cleaned.isNotEmpty() -> "CLEANED_VERIFIED (${cleaned.joinToString(", ")})"
                else -> "CLEAN_NO_RULES_INSTALLED"
            }
        }

        val afterCountersA = TunTrafficEngine.getCounterSnapshot(normA)
        val afterCountersB = if (hostB != null) TunTrafficEngine.getCounterSnapshot(hostB.mac) else null
        val afterUnmatched = TunTrafficEngine.unmatchedPackets.get()
        val afterPostNatUnmatched = TunTrafficEngine.postNatUnmatchedPackets.get()

        val blockedDropsDeltaA = (afterCountersA.blockedDropPackets - beforeCountersA.blockedDropPackets).coerceAtLeast(0L)
        val unmatchedDelta = (afterUnmatched - beforeUnmatched).coerceAtLeast(0L)
        val postNatUnmatchedDelta = (afterPostNatUnmatched - beforePostNatUnmatched).coerceAtLeast(0L)
        val attributedFlowsA = TunTrafficEngine.getAttributedFlowCount(normA)
        val firstPacketLeak = postNatUnmatchedDelta > 0L || afterCountersA.unattributedPostNatObserved

        val bForwardedDelta = if (beforeCountersB != null && afterCountersB != null) {
            (afterCountersB.seenPackets - beforeCountersB.seenPackets).coerceAtLeast(0L)
        } else {
            0L
        }

        val aConnectivity = when {
            (v4Delta + v6Delta) > 0L && !firstPacketLeak ->
                "BLOCKED_BY_OPTION_A (pktsDropped=${v4Delta + v6Delta})"
            blockedDropsDeltaA > 0L && !firstPacketLeak ->
                "BLOCKED_BY_OPTION_B (pktsDropped=$blockedDropsDeltaA, leak=false)"
            firstPacketLeak ->
                "LEAK_OBSERVED (unattributedPostNatDelta=$postNatUnmatchedDelta, blockedDropsDelta=$blockedDropsDeltaA)"
            else ->
                "NO_TRAFFIC_OR_UNBLOCKED (generate traffic on Client A during test)"
        }

        val bConnectivity = when {
            hostB == null -> "NOT_TESTED (connect a 2nd client B)"
            bForwardedDelta > 0L -> "ACTIVE_TRAFFIC_OBSERVED (seenDelta=$bForwardedDelta pkts)"
            else -> "CONNECTED_IDLE (0 packets during ${boundedDurationSec}s window)"
        }

        val summaryStatus = when {
            (v4Delta + v6Delta) > 0L && (v6Ips.isEmpty() || v6Delta > 0L || capMatrix.canWriteNetfilterV6) && hostB != null && bForwardedDelta > 0L ->
                FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED
            blockedDropsDeltaA > 0L && !firstPacketLeak && hostB != null && bForwardedDelta > 0L ->
                FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED
            firstPacketLeak || (blockedDropsDeltaA > 0L && postNatUnmatchedDelta > 0L) ->
                FirewallDiagnosticStatus.PARTIAL_COVERAGE
            ruleInstallStatus.startsWith("PERMISSION_DENIED") && firstPacketLeak ->
                FirewallDiagnosticStatus.ENFORCEMENT_UNAVAILABLE
            ruleInstallStatus.startsWith("PERMISSION_DENIED") ->
                FirewallDiagnosticStatus.PERMISSION_DENIED
            else ->
                FirewallDiagnosticStatus.NOT_TESTED
        }

        val tempResult = TemporaryRuleTestResult(
            executed = true,
            testId = testId,
            targetClientMac = normA,
            controlClientMac = hostB?.mac.orEmpty(),
            targetAddresses = targetIps,
            ownedChainName = chainName,
            ruleInstallStatus = ruleInstallStatus,
            ruleCounterDeltaV4 = v4Delta,
            ruleCounterDeltaV6 = v6Delta,
            ipRuleInstallStatusV4 = ipRuleV4Status,
            ipRuleInstallStatusV6 = ipRuleV6Status,
            cleanupStatus = cleanupStatus,
            optionBEmptyCacheTested = true,
            optionBAttributedFlows = attributedFlowsA,
            optionBPolicyBlockedDropsDelta = blockedDropsDeltaA,
            optionBUnmatchedDelta = unmatchedDelta,
            optionBFirstPacketLeakObserved = firstPacketLeak,
            clientAConnectivity = aConnectivity,
            clientBConnectivity = bConnectivity,
            summaryStatus = summaryStatus,
            notes = "Window=${boundedDurationSec}s; postNatUnmatchedDelta=$postNatUnmatchedDelta; cleanup=$cleanupStatus",
        )

        return runReadOnlyDiagnostic(
            context = context,
            downstreamInspector = downstreamInspector,
            upstreamInterfaceName = upstreamInterfaceName,
            vpnActive = vpnActive,
            previousTempResult = tempResult,
        )
    }

    internal fun parseIptablesChainPacketSum(output: String): Long {
        var sum = 0L
        for (line in output.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("Chain ") || trimmed.startsWith("pkts ")) continue
            val firstToken = trimmed.split(Regex("\\s+")).firstOrNull() ?: continue
            val pkts = firstToken.toLongOrNull() ?: continue
            sum += pkts
        }
        return sum
    }

    private fun writeActiveRulesJournal(
        chainName: String,
        downIface: String,
        upIface: String,
        v4Ips: List<String>,
        v6Ips: List<String>,
    ) {
        runCatching {
            val obj = JSONObject().apply {
                put("chainName", chainName)
                put("downstreamInterface", downIface)
                put("upstreamInterface", upIface)
                put("v4Ips", JSONArray(v4Ips))
                put("v6Ips", JSONArray(v6Ips))
                put("createdAt", System.currentTimeMillis())
            }
            File(ACTIVE_RULES_JOURNAL_PATH).writeText(obj.toString())
        }
    }

    private fun computeMechanismStatus(
        canRead: Boolean,
        canWrite: Boolean,
        selective: Boolean,
        writeError: String,
    ): FirewallDiagnosticStatus = when {
        selective -> FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED
        canWrite -> FirewallDiagnosticStatus.WRITE_CONFIRMED
        canRead -> FirewallDiagnosticStatus.READ_ONLY
        writeError.lowercase().contains("permission") ||
            writeError.lowercase().contains("not permitted") ||
            writeError.lowercase().contains("must be root") -> FirewallDiagnosticStatus.PERMISSION_DENIED
        else -> FirewallDiagnosticStatus.UNSUPPORTED
    }

    private fun probeNetdBinderFirewall(): MechanismCapability {
        return runCatching {
            val smClass = Class.forName("android.os.ServiceManager")
            val getService = smClass.getMethod("getService", String::class.java)
            val netdBinder = getService.invoke(null, "netd")
            if (netdBinder == null) {
                MechanismCapability(
                    mechanism = "binder_netd_INetd",
                    family = "IPv4/IPv6",
                    canReadRules = false,
                    canWriteOwnedRules = false,
                    selectiveEnforcementObserved = false,
                    status = FirewallDiagnosticStatus.PERMISSION_DENIED,
                    detail = "ServiceManager.getService(\"netd\") returned null or restricted by SELinux service_manager find",
                )
            } else {
                val stubClass = Class.forName("android.net.INetd\$Stub")
                val asInterface = stubClass.getMethod("asInterface", android.os.IBinder::class.java)
                val netd = asInterface.invoke(null, netdBinder)
                val isAlive = runCatching {
                    netd.javaClass.getMethod("isAlive").invoke(netd) as? Boolean ?: false
                }.getOrElse { err ->
                    val cause = (err as? java.lang.reflect.InvocationTargetException)?.targetException ?: err
                    return@runCatching MechanismCapability(
                        mechanism = "binder_netd_INetd",
                        family = "IPv4/IPv6",
                        canReadRules = false,
                        canWriteOwnedRules = false,
                        selectiveEnforcementObserved = false,
                        status = FirewallDiagnosticStatus.PERMISSION_DENIED,
                        detail = "INetd call rejected: ${cause.javaClass.simpleName}: ${cause.message?.take(100)}",
                    )
                }
                MechanismCapability(
                    mechanism = "binder_netd_INetd",
                    family = "IPv4/IPv6",
                    canReadRules = isAlive,
                    canWriteOwnedRules = false,
                    selectiveEnforcementObserved = false,
                    status = if (isAlive) FirewallDiagnosticStatus.READ_ONLY else FirewallDiagnosticStatus.PERMISSION_DENIED,
                    detail = "INetd binder reachable (isAlive=$isAlive), but firewallSetUidRule/tetherOffload requires NETWORK_STACK/MAINLINE_NETWORK_STACK",
                )
            }
        }.getOrElse { err ->
            MechanismCapability(
                mechanism = "binder_netd_INetd",
                family = "IPv4/IPv6",
                canReadRules = false,
                canWriteOwnedRules = false,
                selectiveEnforcementObserved = false,
                status = FirewallDiagnosticStatus.UNSUPPORTED,
                detail = "INetd probe failed: ${err.javaClass.simpleName}: ${err.message?.take(100)}",
            )
        }
    }

    private fun readCapEffFromProcStatus(): String {
        return runCatching {
            val file = File("/proc/self/status")
            if (!file.exists() || !file.canRead()) return "unreadable"
            val lines = file.readLines()
            val capEff = lines.firstOrNull { it.startsWith("CapEff:") }?.substringAfter(":")?.trim().orEmpty()
            val capPrm = lines.firstOrNull { it.startsWith("CapPrm:") }?.substringAfter(":")?.trim().orEmpty()
            "CapEff=$capEff CapPrm=$capPrm"
        }.getOrDefault("unknown")
    }

    private fun resolveTetheringModuleVersion(context: Context?): String {
        if (context == null) return "unknown (no context)"
        val pm = context.packageManager
        val candidates = listOf(
            "com.google.android.tethering",
            "com.android.tethering",
            "com.google.mainline.go.telemetry",
        )
        for (pkg in candidates) {
            val info = runCatching { pm.getPackageInfo(pkg, 0) }.getOrNull()
            if (info != null) {
                val verCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
                return "$pkg:${info.versionName}($verCode)"
            }
        }
        return "platform-integrated"
    }

    private fun buildFinalDecision(
        uid: Int,
        shizukuMode: String,
        capMatrix: HostFirewall.KernelCapabilityMatrix,
        readableCt: TunTrafficEngine.ConntrackPathObservation?,
        tempResult: TemporaryRuleTestResult,
    ): String = when {
        capMatrix.canWriteBothFamiliesNetfilter &&
            tempResult.summaryStatus == FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED ->
            "OPÇÃO A CONFIRMADA: Filtragem pre-NAT via netfilter (IPv4 + IPv6) escreve e bloqueia seletivamente."
        capMatrix.canWriteBothFamiliesNetfilter ->
            "OPÇÃO A CANDIDATA (WRITE_CONFIRMED): Processo possui escrita em iptables/ip6tables; execute o teste temporário com tráfego ativo nos clientes A e B para confirmar SELECTIVE_BLOCK_OBSERVED."
        readableCt != null &&
            tempResult.executed &&
            !tempResult.optionBFirstPacketLeakObserved &&
            tempResult.optionBPolicyBlockedDropsDelta > 0L ->
            "OPÇÃO B CANDIDATA: Opção A indisponível; conntrack legível em ${readableCt.path} sem vazamento de primeiro pacote observado na janela testada."
        readableCt != null && tempResult.optionBFirstPacketLeakObserved ->
            "INDISPONÍVEL (VAZAMENTO NA OPÇÃO B): Opção A negada por permissão e Opção B apresentou pacotes pós-NAT não atribuídos (192.0.2.2) escapando na janela de cache vazio."
        !capMatrix.canWriteBothFamiliesNetfilter && readableCt == null ->
            "INDISPONÍVEL EM $shizukuMode: Nem Opção A (escrita em netfilter/ip rule negada ao UID $uid) nem Opção B (/proc/net/nf_conntrack inacessível e pacotes no TUN já chegam pós-NAT como 192.0.2.2) viabilizam bloqueio seletivo por cliente mantendo associação Wi-Fi sem root."
        else ->
            "DIAGNÓSTICO EM ANDAMENTO: Verifique os probes de leitura/escrita e execute o teste temporário controlado com 2 clientes."
    }

    private fun buildConfirmedFacts(
        uid: Int,
        shizukuMode: String,
        selinuxContext: String,
        capEff: String,
        capMatrix: HostFirewall.KernelCapabilityMatrix,
        conntrackObs: List<TunTrafficEngine.ConntrackPathObservation>,
        clientRecords: List<ClientIdentityRecord>,
        tempResult: TemporaryRuleTestResult,
    ): List<String> = buildList {
        add("Processo UserService executando com uid=$uid ($shizukuMode), SELinux=$selinuxContext, $capEff.")
        add(
            "Opção A (netfilter FORWARD): leitura IPv4=${capMatrix.canReadNetfilterV4}, escrita IPv4=${capMatrix.canWriteNetfilterV4}; " +
                "leitura IPv6=${capMatrix.canReadNetfilterV6}, escrita IPv6=${capMatrix.canWriteNetfilterV6}.",
        )
        add(
            "Policy routing (ip rule): leitura IPv4=${capMatrix.canReadIpRuleV4}, escrita IPv4=${capMatrix.canWriteIpRuleV4}; " +
                "leitura IPv6=${capMatrix.canReadIpRuleV6}, escrita IPv6=${capMatrix.canWriteIpRuleV6} " +
                "(`ip rule show` é apenas leitura e não comprova permissão de escrita).",
        )
        val ctSummary = conntrackObs.joinToString(", ") { "${it.path}=${it.openReadStatus}(flows=${it.relevantParsedFlows})" }
        add("Opção B (conntrack procfs): $ctSummary.")
        add("Clientes verificados na interface downstream no momento do diagnóstico: ${clientRecords.size}.")
        if (tempResult.executed) {
            add(
                "Teste temporário (${tempResult.testId}): install=${tempResult.ruleInstallStatus}, " +
                    "deltaV4=${tempResult.ruleCounterDeltaV4}, deltaV6=${tempResult.ruleCounterDeltaV6}, " +
                    "optBBlockedDropsDelta=${tempResult.optionBPolicyBlockedDropsDelta}, " +
                    "firstPacketLeak=${tempResult.optionBFirstPacketLeakObserved}, cleanup=${tempResult.cleanupStatus}.",
            )
        }
    }

    private fun buildHypotheses(
        capMatrix: HostFirewall.KernelCapabilityMatrix,
        readableCt: TunTrafficEngine.ConntrackPathObservation?,
        clientRecords: List<ClientIdentityRecord>,
        tempResult: TemporaryRuleTestResult,
    ): List<String> = buildList {
        if (!capMatrix.canWriteBothFamiliesNetfilter && readableCt == null) {
            add(
                "No caminho TestNetwork TUN do Android Tethering, pacotes IPv4 dos clientes sofrem MASQUERADE/SNAT para o endereço do TUN (ex.: 192.0.2.2) antes de chegarem ao descritor de arquivo da VPN/TUN.",
            )
            add(
                "Sem escrita em netfilter (Opção A) e sem leitura de conntrack (Opção B) sob shell UID 2000 (u:r:shell:s0), o processo em userspace não recebe o IPv4 de origem original de cada cliente nos pacotes pós-NAT.",
            )
        }
        if (clientRecords.size < 2) {
            add("Conecte pelo menos 2 clientes físicos (Cliente A e Cliente B) para completar a matriz de validação física multicliente da Fase 4.")
        }
        if (!tempResult.executed) {
            add("O teste temporário controlado (Fase 2 A3 / Fase 3 B3) ainda não foi acionado nesta sessão.")
        }
    }

    private fun buildValidationMatrix(
        clientRecords: List<ClientIdentityRecord>,
        capMatrix: HostFirewall.KernelCapabilityMatrix,
        readableCt: TunTrafficEngine.ConntrackPathObservation?,
        tempResult: TemporaryRuleTestResult,
    ): List<ValidationScenarioRow> {
        val enforcementPossible = capMatrix.canWriteBothFamiliesNetfilter || readableCt != null
        val twoClientsConnected = clientRecords.size >= 2
        val baseStatus = when {
            !enforcementPossible -> "ENFORCEMENT_UNAVAILABLE"
            !twoClientsConnected -> "NOT_TESTED"
            tempResult.executed -> tempResult.summaryStatus.name
            else -> "NOT_TESTED"
        }
        val baseEvidence = when {
            !enforcementPossible -> "Opção A (escrita netfilter/ip rule) e Opção B (conntrack) indisponíveis para este UID/SELinux"
            !twoClientsConnected -> "Requer >= 2 clientes físicos conectados simultaneamente (atual=${clientRecords.size})"
            tempResult.executed -> "testId=${tempResult.testId} A=${tempResult.clientAConnectivity} B=${tempResult.clientBConnectivity}"
            else -> "Aguardando execução do teste temporário com tráfego real"
        }

        return listOf(
            ValidationScenarioRow(
                id = 1,
                scenario = "A e B permitidos",
                requiredOutcome = "Ambos navegam; baseline registrado",
                status = if (twoClientsConnected) "READY_FOR_BASELINE" else "NOT_TESTED",
                observedEvidence = "clientesConectados=${clientRecords.size}",
            ),
            ValidationScenarioRow(
                id = 2,
                scenario = "Bloquear A",
                requiredOutcome = "A permanece no Wi-Fi, perde internet; B continua navegando",
                status = baseStatus,
                observedEvidence = baseEvidence,
            ),
            ValidationScenarioRow(
                id = 3,
                scenario = "Abrir conexões novas em A",
                requiredOutcome = "Falham; não basta interromper uma conexão antiga",
                status = baseStatus,
                observedEvidence = baseEvidence,
            ),
            ValidationScenarioRow(
                id = 4,
                scenario = "Transferência já aberta em A",
                requiredOutcome = "Para conforme prazo medido e documentado",
                status = baseStatus,
                observedEvidence = baseEvidence,
            ),
            ValidationScenarioRow(
                id = 5,
                scenario = "Desbloquear A",
                requiredOutcome = "Internet volta sem reiniciar hotspot",
                status = if (tempResult.executed && tempResult.cleanupStatus.startsWith("CLEAN")) "CLEANUP_CONFIRMED" else "NOT_TESTED",
                observedEvidence = "cleanupStatus=${tempResult.cleanupStatus}",
            ),
            ValidationScenarioRow(
                id = 6,
                scenario = "Bloquear B com A permitido",
                requiredOutcome = "Somente B perde internet",
                status = "NOT_TESTED",
                observedEvidence = "Requer inversão manual do alvo para Cliente B na tela de diagnóstico",
            ),
            ValidationScenarioRow(
                id = 7,
                scenario = "A sozinho bloqueado, depois B conecta",
                requiredOutcome = "A permanece bloqueado; B funciona",
                status = baseStatus,
                observedEvidence = "Atalho singleActiveClientMac removido; atribuição exige Opção A ou Opção B",
            ),
            ValidationScenarioRow(
                id = 8,
                scenario = "B desconecta e reconecta",
                requiredOutcome = "Regra de A não muda",
                status = "NOT_TESTED",
                observedEvidence = "Políticas indexadas por MAC normalizado independentemente do número de clientes",
            ),
            ValidationScenarioRow(
                id = 9,
                scenario = "A troca IP/reconecta",
                requiredOutcome = "Política acompanha binding atual; endereço antigo não afeta B",
                status = "NOT_TESTED",
                observedEvidence = "Bindings antigos expiram em updatePolicies() e purgeFlowsForMac()",
            ),
            ValidationScenarioRow(
                id = 10,
                scenario = "IPv4, IPv6, TCP, UDP/QUIC e ICMP",
                requiredOutcome = "Nenhum caminho de internet não coberto é tratado como sucesso",
                status = if (tempResult.optionBFirstPacketLeakObserved) "PARTIAL_COVERAGE" else baseStatus,
                observedEvidence = "v4Write=${capMatrix.canWriteNetfilterV4} v6Write=${capMatrix.canWriteNetfilterV6} firstPacketLeak=${tempResult.optionBFirstPacketLeakObserved}",
            ),
            ValidationScenarioRow(
                id = 11,
                scenario = "Mudança de VPN/upstream",
                requiredOutcome = "Capacidade é reavaliada; ausência de proteção fica explícita",
                status = "NOT_TESTED",
                observedEvidence = "datapathMode=${TunTrafficEngine.datapathMode.name}",
            ),
            ValidationScenarioRow(
                id = 12,
                scenario = "Cancelamento/erro do teste",
                requiredOutcome = "Regras temporárias próprias são removidas e estado é reportado",
                status = if (tempResult.executed) tempResult.cleanupStatus else "READY",
                observedEvidence = "Journal em $ACTIVE_RULES_JOURNAL_PATH + cleanup determinístico",
            ),
        )
    }
}
