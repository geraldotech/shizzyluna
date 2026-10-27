package dev.shizzi;

import android.os.ParcelFileDescriptor;

interface ITetherService {

    String start(boolean logging, String vpnMode);

    String startWithDns(boolean logging, String vpnMode, in String[] dnsServers);

    void setLogging(boolean enabled);

    String stop();

    String getStatus();

    String runProbes(boolean attemptTethering, int availabilityTimeoutMs);

    void clearLog();

    String checkCompatibility();

    String installTetheringApex(in ParcelFileDescriptor apex);

    String rebootDevice();

    void updateRules(String rulesJson);

    int getContractVersion();

    String runFirewallDiagnostics();

    String runFirewallClientPoc(String clientAMac, String clientBMac, int durationSec);

    String cleanupFirewallTestRules();

    String setExperimentalBpfConfig(boolean enabled, int pollIntervalMs);

    String collectBpfSnapshotNow();
}
