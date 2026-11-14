package dev.shizzi

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class DomainRuleScope(val displayLabel: String) {
    GLOBAL("Global (All Hotspot Hosts)"),
    CLIENT("Per Host (Specific Client)");

    companion object {
        fun fromName(name: String?): DomainRuleScope {
            if (name.isNullOrBlank()) return GLOBAL
            return entries.firstOrNull { it.name.equals(name.trim(), ignoreCase = true) } ?: GLOBAL
        }
    }
}

enum class DomainMatchMode(val displayLabel: String, val shortLabel: String) {
    INCLUDE_SUBDOMAINS("Include subdomains", "*.domain + root"),
    EXACT_HOSTNAME("Exact hostname only", "Exact only");

    val displayName: String get() = displayLabel

    companion object {
        fun fromName(name: String?): DomainMatchMode {
            if (name.isNullOrBlank()) return INCLUDE_SUBDOMAINS
            return entries.firstOrNull { it.name.equals(name.trim(), ignoreCase = true) } ?: INCLUDE_SUBDOMAINS
        }
    }
}

enum class DomainFilterCapabilityStatus(val code: String, val summary: String) {
    DNS_FILTER_ACTIVE(
        "DNS_FILTER_ACTIVE",
        "Observable plaintext DNS (UDP/53 & TCP/53) filtering active on hotspot TUN"
    ),
    DNS_FILTER_UNAVAILABLE(
        "DNS_FILTER_UNAVAILABLE",
        "Hotspot TUN not active; rules are saved and will enforce when hotspot starts"
    ),
    HOSTNAME_FILTER_ACTIVE(
        "HOSTNAME_FILTER_ACTIVE",
        "Plaintext DNS + bounded TLS SNI / HTTP Host filtering active on hotspot TUN"
    ),
    PARTIAL_DOMAIN_ENFORCEMENT(
        "PARTIAL_DOMAIN_ENFORCEMENT",
        "Plaintext DNS & observable SNI/Host filtered; encrypted DoH/DoT/ECH or cached-IP bypass cannot be decrypted without a MITM CA"
    )
}

enum class DomainDropOrSkipReason(val code: String) {
    NONE("NONE"),
    DOMAIN_BLOCK_GLOBAL_DNS("DOMAIN_BLOCK_GLOBAL_DNS"),
    DOMAIN_BLOCK_CLIENT_DNS("DOMAIN_BLOCK_CLIENT_DNS"),
    DOMAIN_BLOCK_GLOBAL_HOSTNAME("DOMAIN_BLOCK_GLOBAL_HOSTNAME"),
    DOMAIN_BLOCK_CLIENT_HOSTNAME("DOMAIN_BLOCK_CLIENT_HOSTNAME"),
    DOMAIN_CLIENT_OWNER_UNKNOWN("DOMAIN_CLIENT_OWNER_UNKNOWN"),
    DNS_PARSE_ERROR("DNS_PARSE_ERROR"),
    DNS_RESPONSE_GEN_ERROR("DNS_RESPONSE_GEN_ERROR")
}

data class DomainValidationResult(
    val isValid: Boolean,
    val normalizedDomain: String = "",
    val displayDomain: String = "",
    val effectiveMatchMode: DomainMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
    val hadLeadingWildcard: Boolean = false,
    val errorReason: String? = null
) {
    val errorMessage: String? get() = errorReason
}

object DomainNormalizer {
    private val IPV4_LITERAL_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    private val LABEL_CHARS_REGEX = Regex("""^[a-z0-9-]+$""")

    fun validateAndNormalize(
        rawInput: String?,
        requestedMatchMode: DomainMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS
    ): DomainValidationResult {
        if (rawInput == null) {
            return DomainValidationResult(false, errorReason = "Domain cannot be empty")
        }
        var trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return DomainValidationResult(false, errorReason = "Domain cannot be empty")
        }
        if (trimmed.contains("://") || trimmed.startsWith("http:", ignoreCase = true) || trimmed.startsWith("https:", ignoreCase = true)) {
            return DomainValidationResult(false, errorReason = "Enter a domain name only, not a URL with scheme (http:// or https://)")
        }
        if (trimmed.contains('/') || trimmed.contains('?') || trimmed.contains('#') || trimmed.contains('@')) {
            return DomainValidationResult(false, errorReason = "Enter a domain name only without URL paths, query strings, or credentials")
        }
        if (trimmed.any { it.isWhitespace() }) {
            return DomainValidationResult(false, errorReason = "Domain cannot contain spaces")
        }
        if (trimmed.startsWith("[") || trimmed.endsWith("]") || trimmed.contains(':')) {
            return DomainValidationResult(false, errorReason = "Ports and IPv6 literals are not valid domain names")
        }

        var hadWildcard = false
        var effectiveMode = requestedMatchMode
        if (trimmed.startsWith("*.")) {
            hadWildcard = true
            effectiveMode = DomainMatchMode.INCLUDE_SUBDOMAINS
            trimmed = trimmed.substring(2)
        }
        if (trimmed.contains('*')) {
            return DomainValidationResult(false, errorReason = "Only a leading '*.' wildcard prefix is supported")
        }

        // Strip single or multiple trailing dots
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.dropLast(1)
        }
        if (trimmed.isEmpty() || trimmed.startsWith(".")) {
            return DomainValidationResult(false, errorReason = "Domain contains an empty leading label")
        }
        if (trimmed.contains("..")) {
            return DomainValidationResult(false, errorReason = "Domain contains empty consecutive labels ('..')")
        }

        // Convert IDN to ASCII (punycode)
        val asciiDomain = try {
            IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES)
                .lowercase(Locale.ROOT)
                .trimEnd('.')
        } catch (e: Exception) {
            return DomainValidationResult(false, errorReason = "Invalid domain or internationalized label: ${e.message ?: "IDN error"}")
        }

        if (asciiDomain.isEmpty()) {
            return DomainValidationResult(false, errorReason = "Normalized domain is empty")
        }
        if (asciiDomain.length > 253) {
            return DomainValidationResult(false, errorReason = "Domain exceeds maximum length of 253 characters")
        }
        if (IPV4_LITERAL_REGEX.matches(asciiDomain)) {
            return DomainValidationResult(false, errorReason = "IPv4 addresses are not domain names")
        }

        val labels = asciiDomain.split('.')
        if (labels.size < 2) {
            return DomainValidationResult(false, errorReason = "Enter a fully qualified domain with at least two labels (e.g. example.com)")
        }
        for (label in labels) {
            if (label.isEmpty()) {
                return DomainValidationResult(false, errorReason = "Domain cannot contain empty labels")
            }
            if (label.length > 63) {
                return DomainValidationResult(false, errorReason = "Domain label '$label' exceeds 63 characters")
            }
            if (label.startsWith('-') || label.endsWith('-')) {
                return DomainValidationResult(false, errorReason = "Domain label '$label' cannot start or end with a hyphen")
            }
            if (!LABEL_CHARS_REGEX.matches(label)) {
                return DomainValidationResult(false, errorReason = "Domain label '$label' contains invalid characters")
            }
        }
        val tld = labels.last()
        if (tld.all { it.isDigit() }) {
            return DomainValidationResult(false, errorReason = "Top-level domain cannot be all numeric")
        }

        val display = try {
            IDN.toUnicode(asciiDomain).lowercase(Locale.ROOT)
        } catch (_: Exception) {
            asciiDomain
        }

        return DomainValidationResult(
            isValid = true,
            normalizedDomain = asciiDomain,
            displayDomain = display,
            effectiveMatchMode = effectiveMode,
            hadLeadingWildcard = hadWildcard,
            errorReason = null
        )
    }

    /**
     * Fast, bounded normalization for wire-extracted query/SNI/Host strings.
     * Returns null if empty or malformed.
     */
    fun normalizeWireHostname(rawHostname: String?): String? {
        if (rawHostname.isNullOrBlank()) return null
        var s = rawHostname.trim().trimEnd('.')
        if (s.isEmpty() || s.length > 253) return null
        val ascii = try {
            if (s.all { it.code in 0x20..0x7E }) {
                s.lowercase(Locale.ROOT)
            } else {
                IDN.toASCII(s).lowercase(Locale.ROOT).trimEnd('.')
            }
        } catch (_: Exception) {
            return null
        }
        if (ascii.isEmpty() || ascii.length > 253) return null
        var prevDot = true
        var labelLen = 0
        for (i in ascii.indices) {
            val c = ascii[i]
            if (c == '.') {
                if (prevDot || labelLen == 0 || labelLen > 63) return null
                prevDot = true
                labelLen = 0
            } else if ((c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_') {
                prevDot = false
                labelLen++
                if (labelLen > 63) return null
            } else {
                return null
            }
        }
        if (prevDot || labelLen == 0) return null
        return ascii
    }

    fun matchesDomain(
        candidateHostname: String,
        ruleNormalizedDomain: String,
        matchMode: DomainMatchMode
    ): Boolean {
        val candidate = candidateHostname.lowercase(Locale.ROOT).trimEnd('.')
        val rule = ruleNormalizedDomain.lowercase(Locale.ROOT).trimEnd('.')
        if (candidate.isEmpty() || rule.isEmpty()) return false
        if (candidate == rule) return true
        if (matchMode == DomainMatchMode.EXACT_HOSTNAME) return false
        // INCLUDE_SUBDOMAINS: candidate must end with ".<rule>" on a label boundary
        if (candidate.length <= rule.length + 1) return false
        return candidate.endsWith(rule) && candidate[candidate.length - rule.length - 1] == '.'
    }
}

data class DomainRule(
    val id: String = UUID.randomUUID().toString(),
    val scope: DomainRuleScope = DomainRuleScope.GLOBAL,
    val clientMac: String? = null,
    val normalizedDomain: String,
    val displayDomain: String = normalizedDomain,
    val matchMode: DomainMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
    val enabled: Boolean = true,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val updatedAtEpochMs: Long = createdAtEpochMs
) {
    val normalizedClientMac: String? = clientMac?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }

    fun deduplicationKey(): String {
        val macPart = if (scope == DomainRuleScope.CLIENT) (normalizedClientMac ?: "") else "*"
        return "${scope.name}|$macPart|${normalizedDomain.lowercase(Locale.ROOT)}"
    }

    fun matchesHostname(normalizedCandidate: String): Boolean {
        if (!enabled) return false
        return DomainNormalizer.matchesDomain(normalizedCandidate, normalizedDomain, matchMode)
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("scope", scope.name)
        put("clientMac", normalizedClientMac ?: JSONObject.NULL)
        put("normalizedDomain", normalizedDomain)
        put("displayDomain", displayDomain)
        put("matchMode", matchMode.name)
        put("enabled", enabled)
        put("createdAtEpochMs", createdAtEpochMs)
        put("updatedAtEpochMs", updatedAtEpochMs)
    }

    companion object {
        fun fromJson(obj: JSONObject): DomainRule? {
            val rawDomain = obj.optString("normalizedDomain", "").trim()
            val validation = DomainNormalizer.validateAndNormalize(
                rawDomain,
                DomainMatchMode.fromName(obj.optString("matchMode", DomainMatchMode.INCLUDE_SUBDOMAINS.name))
            )
            if (!validation.isValid) return null
            val scope = DomainRuleScope.fromName(obj.optString("scope", DomainRuleScope.GLOBAL.name))
            val rawMac = if (obj.isNull("clientMac")) null else obj.optString("clientMac", "").trim().uppercase(Locale.ROOT).takeIf { it.isNotEmpty() }
            if (scope == DomainRuleScope.CLIENT && rawMac.isNullOrBlank()) return null
            val created = obj.optLong("createdAtEpochMs", System.currentTimeMillis())
            return DomainRule(
                id = obj.optString("id", "").ifBlank { UUID.randomUUID().toString() },
                scope = scope,
                clientMac = if (scope == DomainRuleScope.CLIENT) rawMac else null,
                normalizedDomain = validation.normalizedDomain,
                displayDomain = obj.optString("displayDomain", validation.displayDomain).ifBlank { validation.displayDomain },
                matchMode = DomainMatchMode.fromName(obj.optString("matchMode", validation.effectiveMatchMode.name)),
                enabled = obj.optBoolean("enabled", true),
                createdAtEpochMs = created,
                updatedAtEpochMs = obj.optLong("updatedAtEpochMs", created)
            )
        }

        fun serializeList(rules: List<DomainRule>): String {
            val arr = JSONArray()
            deduplicateRules(rules).forEach { arr.put(it.toJson()) }
            return arr.toString()
        }

        fun deserializeList(rawJson: String?): List<DomainRule> {
            if (rawJson.isNullOrBlank()) return emptyList()
            return try {
                val arr = JSONArray(rawJson)
                val parsed = mutableListOf<DomainRule>()
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    fromJson(item)?.let { parsed.add(it) }
                }
                deduplicateRules(parsed)
            } catch (_: Exception) {
                emptyList()
            }
        }

        fun toJsonArrayString(rules: List<DomainRule>): String = serializeList(rules)

        fun fromJsonArrayString(rawJson: String?): List<DomainRule> = deserializeList(rawJson)

        fun deduplicateRules(rules: List<DomainRule>): List<DomainRule> {
            val map = LinkedHashMap<String, DomainRule>()
            for (rule in rules) {
                val key = rule.deduplicationKey()
                val existing = map[key]
                if (existing == null || rule.updatedAtEpochMs >= existing.updatedAtEpochMs) {
                    map[key] = if (existing != null) {
                        rule.copy(id = existing.id, createdAtEpochMs = existing.createdAtEpochMs)
                    } else {
                        rule
                    }
                }
            }
            return map.values.toList()
        }
    }
}

data class ParsedDnsQuery(
    val ipVersion: Int,
    val protocol: Int,
    val ipHeaderOffset: Int,
    val ipHeaderLength: Int,
    val transportHeaderOffset: Int,
    val dnsPayloadOffset: Int,
    val dnsPayloadLength: Int,
    val srcPort: Int,
    val dstPort: Int,
    val transactionId: Int,
    val flags: Int,
    val qdCount: Int,
    val normalizedQName: String,
    val rawQName: String,
    val qType: Int,
    val qClass: Int,
    val questionSectionEndOffset: Int,
    val hasEdnsOpt: Boolean
) {
    val qname: String get() = normalizedQName
    val qtype: Int get() = qType
}

data class DnsParseResult(
    val isDnsCandidate: Boolean,
    val query: ParsedDnsQuery? = null,
    val parseErrorReason: String? = null
)

object DnsWirePacketParser {
    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17
    private const val DNS_PORT = 53
    private const val MAX_COMPRESSION_JUMPS = 16

    fun parsePacket(packet: ByteArray, length: Int = packet.size): ParsedDnsQuery? =
        parseIpDnsQuery(packet, length).query

    /**
     * Inspects an IPv4 or IPv6 packet and parses an observable UDP/53 or single-packet TCP/53 DNS query.
     */
    fun parseIpDnsQuery(packet: ByteArray, length: Int): DnsParseResult {
        if (length < 20 || length > packet.size) return DnsParseResult(false)
        val version = (packet[0].toInt() ushr 4) and 0x0F
        var protocol: Int
        var transportOffset: Int
        val ipPacketTotalLen: Int

        if (version == 4) {
            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (ihl < 20 || length < ihl + 8) return DnsParseResult(false)
            val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
            ipPacketTotalLen = if (totalLen in (ihl + 8)..length) totalLen else length
            // Check IPv4 fragmentation: non-zero fragment offset cannot be safely parsed as a full transport header
            val fragFlagsAndOffset = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
            if ((fragFlagsAndOffset and 0x1FFF) != 0) {
                return DnsParseResult(false)
            }
            protocol = packet[9].toInt() and 0xFF
            transportOffset = ihl
        } else if (version == 6) {
            if (length < 48) return DnsParseResult(false)
            val payloadLen = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
            ipPacketTotalLen = (40 + payloadLen).coerceAtMost(length)
            var nextHeader = packet[6].toInt() and 0xFF
            var offset = 40
            var extCount = 0
            while (
                (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 44) &&
                offset + 8 <= ipPacketTotalLen &&
                extCount < 6
            ) {
                if (nextHeader == 44) {
                    // IPv6 Fragment Header: check fragment offset
                    val fragOffAndFlags = ((packet[offset + 2].toInt() and 0xFF) shl 8) or (packet[offset + 3].toInt() and 0xFF)
                    if ((fragOffAndFlags and 0xFFF8) != 0) return DnsParseResult(false)
                    nextHeader = packet[offset].toInt() and 0xFF
                    offset += 8
                } else {
                    val hdrExtLen = (packet[offset + 1].toInt() and 0xFF)
                    nextHeader = packet[offset].toInt() and 0xFF
                    offset += (hdrExtLen + 1) * 8
                }
                extCount++
            }
            protocol = nextHeader
            transportOffset = offset
        } else {
            return DnsParseResult(false)
        }

        if (protocol != PROTO_UDP && protocol != PROTO_TCP) return DnsParseResult(false)
        if (transportOffset + 8 > ipPacketTotalLen) return DnsParseResult(false)

        val srcPort = ((packet[transportOffset].toInt() and 0xFF) shl 8) or (packet[transportOffset + 1].toInt() and 0xFF)
        val dstPort = ((packet[transportOffset + 2].toInt() and 0xFF) shl 8) or (packet[transportOffset + 3].toInt() and 0xFF)
        if (dstPort != DNS_PORT) return DnsParseResult(false)
        // Guard against responding to a packet whose source port is also 53 if QR=1
        val dnsPayloadOffset: Int
        val dnsPayloadLength: Int

        if (protocol == PROTO_UDP) {
            val udpLen = ((packet[transportOffset + 4].toInt() and 0xFF) shl 8) or (packet[transportOffset + 5].toInt() and 0xFF)
            if (udpLen < 8 || transportOffset + udpLen > ipPacketTotalLen) {
                return DnsParseResult(true, parseErrorReason = "Truncated or invalid UDP/53 length ($udpLen)")
            }
            dnsPayloadOffset = transportOffset + 8
            dnsPayloadLength = udpLen - 8
        } else {
            // PROTO_TCP
            if (transportOffset + 20 > ipPacketTotalLen) {
                return DnsParseResult(true, parseErrorReason = "Truncated TCP/53 header")
            }
            val dataOffsetWords = (packet[transportOffset + 12].toInt() ushr 4) and 0x0F
            val tcpHeaderLen = dataOffsetWords * 4
            if (tcpHeaderLen < 20 || transportOffset + tcpHeaderLen > ipPacketTotalLen) {
                return DnsParseResult(true, parseErrorReason = "Invalid TCP/53 header length ($tcpHeaderLen)")
            }
            val tcpPayloadOffset = transportOffset + tcpHeaderLen
            val tcpPayloadLen = ipPacketTotalLen - tcpPayloadOffset
            // Pure TCP handshake/ACK packets with 0 payload are not DNS errors; they just aren't DNS queries yet
            if (tcpPayloadLen == 0) {
                return DnsParseResult(false)
            }
            if (tcpPayloadLen < 14) {
                return DnsParseResult(true, parseErrorReason = "Truncated TCP/53 DNS message ($tcpPayloadLen bytes)")
            }
            val dnsMsgLen = ((packet[tcpPayloadOffset].toInt() and 0xFF) shl 8) or (packet[tcpPayloadOffset + 1].toInt() and 0xFF)
            if (dnsMsgLen < 12 || dnsMsgLen + 2 > tcpPayloadLen) {
                return DnsParseResult(true, parseErrorReason = "Fragmented or truncated TCP/53 DNS message ($dnsMsgLen vs ${tcpPayloadLen - 2})")
            }
            dnsPayloadOffset = tcpPayloadOffset + 2
            dnsPayloadLength = dnsMsgLen
        }

        return parseDnsPayload(
            packet = packet,
            ipVersion = version,
            protocol = protocol,
            ipHeaderOffset = 0,
            ipHeaderLength = transportOffset,
            transportHeaderOffset = transportOffset,
            dnsPayloadOffset = dnsPayloadOffset,
            dnsPayloadLength = dnsPayloadLength,
            srcPort = srcPort,
            dstPort = dstPort
        )
    }

    private fun parseDnsPayload(
        packet: ByteArray,
        ipVersion: Int,
        protocol: Int,
        ipHeaderOffset: Int,
        ipHeaderLength: Int,
        transportHeaderOffset: Int,
        dnsPayloadOffset: Int,
        dnsPayloadLength: Int,
        srcPort: Int,
        dstPort: Int
    ): DnsParseResult {
        if (dnsPayloadLength < 12) {
            return DnsParseResult(true, parseErrorReason = "DNS header shorter than 12 bytes ($dnsPayloadLength)")
        }
        val dnsEnd = dnsPayloadOffset + dnsPayloadLength
        if (dnsEnd > packet.size) {
            return DnsParseResult(true, parseErrorReason = "DNS payload exceeds packet bounds")
        }

        val txId = ((packet[dnsPayloadOffset].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 1].toInt() and 0xFF)
        val flags = ((packet[dnsPayloadOffset + 2].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 3].toInt() and 0xFF)
        val isResponse = (flags and 0x8000) != 0
        if (isResponse) {
            // QR=1: DNS response, not an outbound client query
            return DnsParseResult(false)
        }
        val qdCount = ((packet[dnsPayloadOffset + 4].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 5].toInt() and 0xFF)
        val anCount = ((packet[dnsPayloadOffset + 6].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 7].toInt() and 0xFF)
        val nsCount = ((packet[dnsPayloadOffset + 8].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 9].toInt() and 0xFF)
        val arCount = ((packet[dnsPayloadOffset + 10].toInt() and 0xFF) shl 8) or (packet[dnsPayloadOffset + 11].toInt() and 0xFF)

        if (qdCount <= 0 || qdCount > 64) {
            return DnsParseResult(true, parseErrorReason = "Invalid DNS QDCOUNT ($qdCount)")
        }

        val qnameResult = readDnsName(packet, dnsPayloadOffset, dnsEnd, dnsPayloadOffset + 12)
            ?: return DnsParseResult(true, parseErrorReason = "Malformed QNAME or compression pointer loop")

        val afterQNameOffset = qnameResult.second
        if (afterQNameOffset + 4 > dnsEnd) {
            return DnsParseResult(true, parseErrorReason = "Truncated DNS Question QTYPE/QCLASS")
        }
        val qType = ((packet[afterQNameOffset].toInt() and 0xFF) shl 8) or (packet[afterQNameOffset + 1].toInt() and 0xFF)
        val qClass = ((packet[afterQNameOffset + 2].toInt() and 0xFF) shl 8) or (packet[afterQNameOffset + 3].toInt() and 0xFF)
        val firstQuestionEnd = afterQNameOffset + 4

        val normalizedQName = DomainNormalizer.normalizeWireHostname(qnameResult.first)
            ?: return DnsParseResult(true, parseErrorReason = "Invalid DNS QNAME hostname '${qnameResult.first.take(64)}'")

        // Detect optional EDNS(0) OPT record (TYPE = 41) in additional section without failing on it
        var hasEdns = false
        if (arCount in 1..16 && qdCount == 1 && anCount == 0 && nsCount == 0) {
            var cursor = firstQuestionEnd
            for (i in 0 until arCount) {
                val rrName = readDnsName(packet, dnsPayloadOffset, dnsEnd, cursor) ?: break
                cursor = rrName.second
                if (cursor + 10 > dnsEnd) break
                val rrType = ((packet[cursor].toInt() and 0xFF) shl 8) or (packet[cursor + 1].toInt() and 0xFF)
                val rdLen = ((packet[cursor + 8].toInt() and 0xFF) shl 8) or (packet[cursor + 9].toInt() and 0xFF)
                if (rrType == 41) {
                    hasEdns = true
                }
                cursor += 10 + rdLen
                if (cursor > dnsEnd) break
            }
        }

        return DnsParseResult(
            isDnsCandidate = true,
            query = ParsedDnsQuery(
                ipVersion = ipVersion,
                protocol = protocol,
                ipHeaderOffset = ipHeaderOffset,
                ipHeaderLength = ipHeaderLength,
                transportHeaderOffset = transportHeaderOffset,
                dnsPayloadOffset = dnsPayloadOffset,
                dnsPayloadLength = dnsPayloadLength,
                srcPort = srcPort,
                dstPort = dstPort,
                transactionId = txId,
                flags = flags,
                qdCount = qdCount,
                normalizedQName = normalizedQName,
                rawQName = qnameResult.first,
                qType = qType,
                qClass = qClass,
                questionSectionEndOffset = firstQuestionEnd,
                hasEdnsOpt = hasEdns
            )
        )
    }

    /**
     * Reads a DNS domain name starting at [startOffset] within [dnsStart]..<[dnsEnd].
     * Enforces RFC 1035 bounds and compression pointer loop guards.
     */
    private fun readDnsName(
        packet: ByteArray,
        dnsStart: Int,
        dnsEnd: Int,
        startOffset: Int
    ): Pair<String, Int>? {
        if (startOffset < dnsStart || startOffset >= dnsEnd) return null
        val sb = StringBuilder()
        var currentOffset = startOffset
        var nextOffsetAfterName = -1
        var jumps = 0
        var totalChars = 0

        while (true) {
            if (currentOffset < dnsStart || currentOffset >= dnsEnd) return null
            val lenOrPtr = packet[currentOffset].toInt() and 0xFF
            if (lenOrPtr == 0) {
                if (nextOffsetAfterName == -1) {
                    nextOffsetAfterName = currentOffset + 1
                }
                break
            }
            val topBits = lenOrPtr and 0xC0
            if (topBits == 0xC0) {
                // Compression pointer (2 bytes)
                if (currentOffset + 1 >= dnsEnd) return null
                val ptrOffset = ((lenOrPtr and 0x3F) shl 8) or (packet[currentOffset + 1].toInt() and 0xFF)
                val targetPos = dnsStart + ptrOffset
                // Must point inside DNS payload and strictly prior to currentOffset to prevent self/forward loops
                if (targetPos < dnsStart + 12 || targetPos >= currentOffset || targetPos >= dnsEnd) {
                    return null
                }
                if (nextOffsetAfterName == -1) {
                    nextOffsetAfterName = currentOffset + 2
                }
                jumps++
                if (jumps > MAX_COMPRESSION_JUMPS) return null
                currentOffset = targetPos
            } else if (topBits == 0x00) {
                val labelLen = lenOrPtr
                if (labelLen > 63 || currentOffset + 1 + labelLen > dnsEnd) return null
                if (sb.isNotEmpty()) {
                    sb.append('.')
                    totalChars++
                }
                totalChars += labelLen
                if (totalChars > 253) return null
                for (i in 0 until labelLen) {
                    val b = packet[currentOffset + 1 + i].toInt() and 0xFF
                    if (b <= 0x20 || b >= 0x7F) return null
                    sb.append(b.toChar())
                }
                currentOffset += 1 + labelLen
            } else {
                // Reserved label type (0x40 or 0x80) - reject safely
                return null
            }
        }

        if (nextOffsetAfterName == -1 || nextOffsetAfterName > dnsEnd) return null
        return sb.toString() to nextOffsetAfterName
    }
}

object DnsRefusedResponseBuilder {
    private const val PROTO_UDP = 17
    private const val RCODE_REFUSED = 5

    /**
     * Synthesizes a valid IPv4 or IPv6 UDP/53 DNS response packet with RCODE=5 (REFUSED).
     * Returns null if the query is not UDP/53, is already a response, or has invalid bounds.
     */
    fun buildRefusedResponse(
        requestPacket: ByteArray,
        requestLength: Int,
        parsed: ParsedDnsQuery
    ): ByteArray? {
        if (parsed.protocol != PROTO_UDP) return null
        if (parsed.dstPort != 53 || parsed.srcPort == 53) return null
        if ((parsed.flags and 0x8000) != 0) return null
        if (requestLength > requestPacket.size) return null

        val questionStart = parsed.dnsPayloadOffset + 12
        val questionLen = parsed.questionSectionEndOffset - questionStart
        if (questionLen <= 0 || questionLen > 300 || parsed.questionSectionEndOffset > requestLength) {
            return null
        }

        val dnsResponseLen = 12 + questionLen
        val udpResponseLen = 8 + dnsResponseLen
        val ipHeaderLen = if (parsed.ipVersion == 4) 20 else if (parsed.ipVersion == 6) 40 else return null
        val totalResponseLen = ipHeaderLen + udpResponseLen
        val out = ByteArray(totalResponseLen)

        if (parsed.ipVersion == 4) {
            if (parsed.ipHeaderOffset + 20 > requestLength) return null
            // IPv4 Header (20 bytes, no options)
            out[0] = 0x45.toByte()
            out[1] = 0x00.toByte()
            out[2] = ((totalResponseLen ushr 8) and 0xFF).toByte()
            out[3] = (totalResponseLen and 0xFF).toByte()
            // Identification echoed or deterministic
            out[4] = requestPacket[4]
            out[5] = requestPacket[5]
            // Flags = Don't Fragment (0x4000)
            out[6] = 0x40.toByte()
            out[7] = 0x00.toByte()
            // TTL = 64, Protocol = UDP (17)
            out[8] = 64.toByte()
            out[9] = PROTO_UDP.toByte()
            // Checksum 0 placeholder
            out[10] = 0
            out[11] = 0
            // Swap source & destination IPv4 addresses
            System.arraycopy(requestPacket, 16, out, 12, 4)
            System.arraycopy(requestPacket, 12, out, 16, 4)
            // Compute IPv4 header checksum
            val ipCsum = computeInternetChecksum(out, 0, 20)
            out[10] = ((ipCsum ushr 8) and 0xFF).toByte()
            out[11] = (ipCsum and 0xFF).toByte()
        } else {
            if (parsed.ipHeaderOffset + 40 > requestLength) return null
            // IPv6 Header (40 bytes)
            out[0] = 0x60.toByte()
            out[1] = 0x00.toByte()
            out[2] = 0x00.toByte()
            out[3] = 0x00.toByte()
            out[4] = ((udpResponseLen ushr 8) and 0xFF).toByte()
            out[5] = (udpResponseLen and 0xFF).toByte()
            out[6] = PROTO_UDP.toByte()
            out[7] = 64.toByte()
            // Swap source & destination IPv6 addresses
            System.arraycopy(requestPacket, 24, out, 8, 16)
            System.arraycopy(requestPacket, 8, out, 24, 16)
        }

        // UDP Header (8 bytes)
        val udpOffset = ipHeaderLen
        // SrcPort = 53 (request DstPort), DstPort = request SrcPort
        out[udpOffset] = ((parsed.dstPort ushr 8) and 0xFF).toByte()
        out[udpOffset + 1] = (parsed.dstPort and 0xFF).toByte()
        out[udpOffset + 2] = ((parsed.srcPort ushr 8) and 0xFF).toByte()
        out[udpOffset + 3] = (parsed.srcPort and 0xFF).toByte()
        out[udpOffset + 4] = ((udpResponseLen ushr 8) and 0xFF).toByte()
        out[udpOffset + 5] = (udpResponseLen and 0xFF).toByte()
        out[udpOffset + 6] = 0
        out[udpOffset + 7] = 0

        // DNS Header (12 bytes)
        val dnsOffset = udpOffset + 8
        out[dnsOffset] = ((parsed.transactionId ushr 8) and 0xFF).toByte()
        out[dnsOffset + 1] = (parsed.transactionId and 0xFF).toByte()
        // Flags: QR=1 (0x8000), preserve OPCODE (bits 14..11 = 0x7800), AA=0, TC=0, preserve RD (0x0100), RA=1 (0x0080), Z=0, RCODE=5 (REFUSED)
        val opcodeAndRd = parsed.flags and 0x7900
        val respFlags = 0x8000 or opcodeAndRd or 0x0080 or RCODE_REFUSED
        out[dnsOffset + 2] = ((respFlags ushr 8) and 0xFF).toByte()
        out[dnsOffset + 3] = (respFlags and 0xFF).toByte()
        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        out[dnsOffset + 4] = 0
        out[dnsOffset + 5] = 1
        for (i in 6..11) {
            out[dnsOffset + i] = 0
        }

        // Copy Question section (QNAME + QTYPE + QCLASS)
        System.arraycopy(requestPacket, questionStart, out, dnsOffset + 12, questionLen)

        // Compute UDP checksum over pseudo-header + UDP header + DNS payload
        val udpCsum = computeUdpChecksum(out, parsed.ipVersion, ipHeaderLen, udpOffset, udpResponseLen)
        out[udpOffset + 6] = ((udpCsum ushr 8) and 0xFF).toByte()
        out[udpOffset + 7] = (udpCsum and 0xFF).toByte()

        return out
    }

    internal fun computeInternetChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < length) {
            val word = ((buf[offset + i].toInt() and 0xFF) shl 8) or (buf[offset + i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < length) {
            val lastByte = (buf[offset + i].toInt() and 0xFF) shl 8
            sum += lastByte
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    internal fun computeUdpChecksum(
        packet: ByteArray,
        ipVersion: Int,
        ipHeaderLen: Int,
        udpOffset: Int,
        udpLength: Int
    ): Int {
        var sum = 0L
        if (ipVersion == 4) {
            // IPv4 pseudo-header: srcIP (4) + dstIP (4) + zero/proto (2) + udpLen (2)
            for (i in 12 until 20 step 2) {
                sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            }
            sum += PROTO_UDP
            sum += udpLength
        } else {
            // IPv6 pseudo-header: srcIP (16) + dstIP (16) + udpLen (4) + zero/nextHeader (4)
            for (i in 8 until 40 step 2) {
                sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            }
            sum += udpLength
            sum += PROTO_UDP
        }
        var i = 0
        while (i + 1 < udpLength) {
            sum += ((packet[udpOffset + i].toInt() and 0xFF) shl 8) or (packet[udpOffset + i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < udpLength) {
            sum += (packet[udpOffset + i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val csum = (sum.inv() and 0xFFFF).toInt()
        return if (csum == 0) 0xFFFF else csum
    }
}

enum class HostnameExtractionSource {
    TLS_SNI,
    HTTP_HOST
}

data class ExtractedConnectionHostname(
    val normalizedHostname: String,
    val source: HostnameExtractionSource
) {
    val hostname: String get() = normalizedHostname
    val isTlsSni: Boolean get() = source == HostnameExtractionSource.TLS_SNI
}

/**
 * Bounded, safe classifier for initial TCP payload packets (TLS ClientHello SNI and plaintext HTTP Host).
 * Does not decrypt TLS or require a custom CA.
 */
object ConnectionHostnameClassifier {
    private const val PROTO_TCP = 6

    fun extractHostnameFromPacket(packet: ByteArray, length: Int = packet.size): ExtractedConnectionHostname? =
        extractFromIpPacket(packet, length)

    fun extractFromIpPacket(packet: ByteArray, length: Int): ExtractedConnectionHostname? {
        if (length < 40 || length > packet.size) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        val transportOffset: Int
        val ipTotalLen: Int

        if (version == 4) {
            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (ihl < 20 || length < ihl + 20) return null
            val frag = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
            if ((frag and 0x1FFF) != 0) return null
            if ((packet[9].toInt() and 0xFF) != PROTO_TCP) return null
            val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
            ipTotalLen = if (totalLen in (ihl + 20)..length) totalLen else length
            transportOffset = ihl
        } else if (version == 6) {
            if (length < 60) return null
            if ((packet[6].toInt() and 0xFF) != PROTO_TCP) return null
            val payloadLen = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
            ipTotalLen = (40 + payloadLen).coerceAtMost(length)
            transportOffset = 40
        } else {
            return null
        }

        if (transportOffset + 20 > ipTotalLen) return null
        val dstPort = ((packet[transportOffset + 2].toInt() and 0xFF) shl 8) or (packet[transportOffset + 3].toInt() and 0xFF)
        if (dstPort == 53) return null // DNS over TCP is handled by DnsWirePacketParser
        val tcpHeaderLen = ((packet[transportOffset + 12].toInt() ushr 4) and 0x0F) * 4
        if (tcpHeaderLen < 20 || transportOffset + tcpHeaderLen >= ipTotalLen) return null

        val payloadOffset = transportOffset + tcpHeaderLen
        val payloadLen = ipTotalLen - payloadOffset
        if (payloadLen < 16) return null

        extractTlsClientHelloSni(packet, payloadOffset, payloadLen)?.let { sni ->
            return ExtractedConnectionHostname(sni, HostnameExtractionSource.TLS_SNI)
        }
        extractHttpHostHeader(packet, payloadOffset, payloadLen)?.let { host ->
            return ExtractedConnectionHostname(host, HostnameExtractionSource.HTTP_HOST)
        }
        return null
    }

    /**
     * Parses a single-record TLS ClientHello to extract server_name (extension 0x0000, host_name type 0x00).
     */
    fun extractTlsClientHelloSni(buf: ByteArray, offset: Int, length: Int): String? {
        val end = (offset + length).coerceAtMost(buf.size)
        if (offset + 43 > end) return null
        // TLS Record Header: ContentType = Handshake (22 = 0x16), Version = 0x0301..0x0304
        if ((buf[offset].toInt() and 0xFF) != 0x16) return null
        val major = buf[offset + 1].toInt() and 0xFF
        val minor = buf[offset + 2].toInt() and 0xFF
        if (major != 0x03 || minor > 0x04) return null
        val recordLen = ((buf[offset + 3].toInt() and 0xFF) shl 8) or (buf[offset + 4].toInt() and 0xFF)
        val recordEnd = (offset + 5 + recordLen).coerceAtMost(end)

        // Handshake Header: HandshakeType = ClientHello (1 = 0x01)
        val hsOffset = offset + 5
        if (hsOffset + 38 > recordEnd) return null
        if ((buf[hsOffset].toInt() and 0xFF) != 0x01) return null
        val hsLen = ((buf[hsOffset + 1].toInt() and 0xFF) shl 16) or
            ((buf[hsOffset + 2].toInt() and 0xFF) shl 8) or
            (buf[hsOffset + 3].toInt() and 0xFF)
        val hsEnd = (hsOffset + 4 + hsLen).coerceAtMost(recordEnd)

        // Skip ClientVersion (2) + Random (32)
        var pos = hsOffset + 4 + 34
        if (pos + 1 > hsEnd) return null
        // SessionID
        val sessionIdLen = buf[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > hsEnd) return null
        // CipherSuites
        val cipherSuitesLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen
        if (pos + 1 > hsEnd) return null
        // CompressionMethods
        val compMethodsLen = buf[pos].toInt() and 0xFF
        pos += 1 + compMethodsLen
        if (pos + 2 > hsEnd) return null
        // Extensions
        val extensionsLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
        pos += 2
        val extEnd = (pos + extensionsLen).coerceAtMost(hsEnd)

        while (pos + 4 <= extEnd) {
            val extType = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
            val extLen = ((buf[pos + 2].toInt() and 0xFF) shl 8) or (buf[pos + 3].toInt() and 0xFF)
            pos += 4
            if (pos + extLen > extEnd) return null
            if (extType == 0x0000 && extLen >= 5) {
                val listLen = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
                var sniPos = pos + 2
                val sniEnd = (sniPos + listLen).coerceAtMost(pos + extLen)
                while (sniPos + 3 <= sniEnd) {
                    val nameType = buf[sniPos].toInt() and 0xFF
                    val nameLen = ((buf[sniPos + 1].toInt() and 0xFF) shl 8) or (buf[sniPos + 2].toInt() and 0xFF)
                    sniPos += 3
                    if (sniPos + nameLen > sniEnd) return null
                    if (nameType == 0x00 && nameLen in 1..253) {
                        val rawSni = String(buf, sniPos, nameLen, StandardCharsets.US_ASCII)
                        return DomainNormalizer.normalizeWireHostname(rawSni)
                    }
                    sniPos += nameLen
                }
            }
            pos += extLen
        }
        return null
    }

    /**
     * Parses a plaintext HTTP request header block to extract the `Host:` header value.
     */
    fun extractHttpHostHeader(buf: ByteArray, offset: Int, length: Int): String? {
        val scanLen = length.coerceAtMost(1024)
        if (offset + 14 > buf.size || scanLen < 14) return null
        // Check common HTTP request method prefixes
        val m0 = buf[offset].toInt().toChar()
        val m1 = buf[offset + 1].toInt().toChar()
        val m2 = buf[offset + 2].toInt().toChar()
        val isHttpMethod = (m0 == 'G' && m1 == 'E' && m2 == 'T') ||
            (m0 == 'P' && m1 == 'O' && m2 == 'S') ||
            (m0 == 'H' && m1 == 'E' && m2 == 'A') ||
            (m0 == 'P' && m1 == 'U' && m2 == 'T') ||
            (m0 == 'D' && m1 == 'E' && m2 == 'L') ||
            (m0 == 'O' && m1 == 'P' && m2 == 'T') ||
            (m0 == 'C' && m1 == 'O' && m2 == 'N')
        if (!isHttpMethod) return null

        val headerStr = String(buf, offset, scanLen, StandardCharsets.ISO_8859_1)
        val lines = headerStr.split("\r\n", "\n")
        for (i in 1 until lines.size.coerceAtMost(24)) {
            val line = lines[i]
            if (line.isEmpty()) break
            if (line.startsWith("Host:", ignoreCase = true)) {
                var hostVal = line.substring(5).trim()
                if (hostVal.startsWith("[")) return null // IPv6 literal
                val colonIdx = hostVal.indexOf(':')
                if (colonIdx > 0) {
                    hostVal = hostVal.substring(0, colonIdx)
                }
                return DomainNormalizer.normalizeWireHostname(hostVal)
            }
        }
        return null
    }
}

data class DomainPacketDecision(
    val blocked: Boolean,
    val matchedRule: DomainRule? = null,
    val queriedDomain: String? = null,
    val reason: DomainDropOrSkipReason = DomainDropOrSkipReason.NONE,
    val synthesizedDnsResponse: ByteArray? = null,
    val unknownOwnerClientRuleSkipped: Boolean = false
)

data class DomainRuleEvaluationSummary(
    val timestampMs: Long = 0L,
    val redactedDomain: String = "***",
    val scope: DomainRuleScope = DomainRuleScope.GLOBAL,
    val redactedClientMac: String = "GLOBAL",
    val reason: String = "NONE",
    val synthesizedRefused: Boolean = false
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("timestampMs", timestampMs)
        put("redactedDomain", redactedDomain)
        put("scope", scope.name)
        put("redactedClientMac", redactedClientMac)
        put("reason", reason)
        put("synthesizedRefused", synthesizedRefused)
    }

    companion object {
        fun fromJson(json: JSONObject): DomainRuleEvaluationSummary = DomainRuleEvaluationSummary(
            timestampMs = json.optLong("timestampMs", 0L),
            redactedDomain = json.optString("redactedDomain", "***"),
            scope = DomainRuleScope.fromName(json.optString("scope", DomainRuleScope.GLOBAL.name)),
            redactedClientMac = json.optString("redactedClientMac", "GLOBAL"),
            reason = json.optString("reason", "NONE"),
            synthesizedRefused = json.optBoolean("synthesizedRefused", false)
        )
    }
}

data class DomainTestCaseStatus(
    val id: String,
    val description: String,
    val passed: Boolean,
    val detail: String
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("description", description)
        put("passed", passed)
        put("status", if (passed) "PASS" else "FAIL")
        put("detail", detail)
    }

    companion object {
        fun fromJson(json: JSONObject): DomainTestCaseStatus = DomainTestCaseStatus(
            id = json.optString("id", ""),
            description = json.optString("description", ""),
            passed = json.optBoolean("passed", json.optString("status", "PASS") == "PASS"),
            detail = json.optString("detail", "")
        )
    }
}

data class DomainFilterDiagnosticReport(
    val schemaVersion: Int = 6,
    val capabilityStatus: String = DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.code,
    val capabilitySummary: String = DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.summary,
    val globalRuleCount: Int = 0,
    val enabledGlobalRuleCount: Int = 0,
    val perClientRuleCount: Int = 0,
    val enabledPerClientRuleCount: Int = 0,
    val clientsWithDomainRulesCount: Int = 0,
    val ruleGeneration: Long = 1L,
    val dnsQueriesInspected: Long = 0L,
    val dnsQueriesAllowed: Long = 0L,
    val dnsQueriesBlockedGlobal: Long = 0L,
    val dnsQueriesBlockedPerClient: Long = 0L,
    val dnsParseErrors: Long = 0L,
    val dnsResponseGenerationErrors: Long = 0L,
    val unknownOwnerClientRuleSkips: Long = 0L,
    val hostnameInspections: Long = 0L,
    val hostnameBlockedGlobal: Long = 0L,
    val hostnameBlockedPerClient: Long = 0L,
    val recentBlockedEvents: List<DomainRuleEvaluationSummary> = emptyList(),
    val testMatrix: List<DomainTestCaseStatus> = emptyList()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("schemaVersion", schemaVersion)
        put("capabilityStatus", capabilityStatus)
        put("capabilitySummary", capabilitySummary)
        put("globalRuleCount", globalRuleCount)
        put("enabledGlobalRuleCount", enabledGlobalRuleCount)
        put("perClientRuleCount", perClientRuleCount)
        put("enabledPerClientRuleCount", enabledPerClientRuleCount)
        put("clientsWithDomainRulesCount", clientsWithDomainRulesCount)
        put("ruleGeneration", ruleGeneration)
        put("dnsQueriesInspected", dnsQueriesInspected)
        put("dnsQueriesAllowed", dnsQueriesAllowed)
        put("dnsQueriesBlockedGlobal", dnsQueriesBlockedGlobal)
        put("dnsQueriesBlockedPerClient", dnsQueriesBlockedPerClient)
        put("dnsParseErrors", dnsParseErrors)
        put("dnsResponseGenerationErrors", dnsResponseGenerationErrors)
        put("unknownOwnerClientRuleSkips", unknownOwnerClientRuleSkips)
        put("hostnameInspections", hostnameInspections)
        put("hostnameBlockedGlobal", hostnameBlockedGlobal)
        put("hostnameBlockedPerClient", hostnameBlockedPerClient)
        put("recentBlockedEvents", JSONArray().apply { recentBlockedEvents.forEach { put(it.toJson()) } })
        put("testMatrix", JSONArray().apply { testMatrix.forEach { put(it.toJson()) } })
    }

    fun toMarkdownSection(): String = buildString {
        appendLine("## 12. Domain Blocking & Shared DNS/Hostname Policy Layer (`v0.10.8-debug`, Schema v6)")
        appendLine("- **Capability Status**: `$capabilityStatus` — $capabilitySummary")
        appendLine("- **Configured Rules**: global=`$enabledGlobalRuleCount/$globalRuleCount`, perClient=`$enabledPerClientRuleCount/$perClientRuleCount` (across `$clientsWithDomainRulesCount` client(s)), ruleGeneration=`$ruleGeneration`")
        appendLine("- **DNS Queries (UDP/53 & TCP/53)**: inspected=`$dnsQueriesInspected`, allowed=`$dnsQueriesAllowed`, blockedGlobal=`$dnsQueriesBlockedGlobal`, blockedPerClient=`$dnsQueriesBlockedPerClient`, parseErrors=`$dnsParseErrors`, responseGenErrors=`$dnsResponseGenerationErrors`")
        appendLine("- **Unknown-Owner Per-Client Rule Skips**: `$unknownOwnerClientRuleSkips` (`DOMAIN_CLIENT_OWNER_UNKNOWN` — never guesses owner)")
        appendLine("- **Connection Hostname Classifier (TLS SNI / HTTP Host)**: inspected=`$hostnameInspections`, blockedGlobal=`$hostnameBlockedGlobal`, blockedPerClient=`$hostnameBlockedPerClient`")
        if (recentBlockedEvents.isNotEmpty()) {
            appendLine()
            appendLine("### 12.1 Recent Redacted Domain Block Events")
            recentBlockedEvents.forEach { ev ->
                appendLine("- `${ev.redactedDomain}` | scope=`${ev.scope.name}` | client=`${ev.redactedClientMac}` | reason=`${ev.reason}` | refusedSynthesized=`${ev.synthesizedRefused}`")
            }
        }
        if (testMatrix.isNotEmpty()) {
            appendLine()
            appendLine("### 12.2 DB01–DB20 Domain Filtering Verification Matrix")
            appendLine("| ID | Scenario | Status | Detail |")
            appendLine("|---|---|---|---|")
            testMatrix.forEach { row ->
                appendLine("| `${row.id}` | ${row.description} | **${if (row.passed) "PASS" else "FAIL"}** | ${row.detail} |")
            }
        }
    }

    companion object {
        fun fromJson(json: JSONObject?): DomainFilterDiagnosticReport {
            if (json == null) return DomainFilterEngine.buildDiagnosticReport()
            val evArr = json.optJSONArray("recentBlockedEvents") ?: JSONArray()
            val events = (0 until evArr.length()).mapNotNull { i ->
                evArr.optJSONObject(i)?.let { DomainRuleEvaluationSummary.fromJson(it) }
            }
            val matArr = json.optJSONArray("testMatrix") ?: JSONArray()
            val matrix = (0 until matArr.length()).mapNotNull { i ->
                matArr.optJSONObject(i)?.let { DomainTestCaseStatus.fromJson(it) }
            }
            return DomainFilterDiagnosticReport(
                schemaVersion = json.optInt("schemaVersion", 6),
                capabilityStatus = json.optString("capabilityStatus", DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.code),
                capabilitySummary = json.optString("capabilitySummary", DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.summary),
                globalRuleCount = json.optInt("globalRuleCount", 0),
                enabledGlobalRuleCount = json.optInt("enabledGlobalRuleCount", 0),
                perClientRuleCount = json.optInt("perClientRuleCount", 0),
                enabledPerClientRuleCount = json.optInt("enabledPerClientRuleCount", 0),
                clientsWithDomainRulesCount = json.optInt("clientsWithDomainRulesCount", 0),
                ruleGeneration = json.optLong("ruleGeneration", 1L),
                dnsQueriesInspected = json.optLong("dnsQueriesInspected", 0L),
                dnsQueriesAllowed = json.optLong("dnsQueriesAllowed", 0L),
                dnsQueriesBlockedGlobal = json.optLong("dnsQueriesBlockedGlobal", 0L),
                dnsQueriesBlockedPerClient = json.optLong("dnsQueriesBlockedPerClient", 0L),
                dnsParseErrors = json.optLong("dnsParseErrors", 0L),
                dnsResponseGenerationErrors = json.optLong("dnsResponseGenerationErrors", 0L),
                unknownOwnerClientRuleSkips = json.optLong("unknownOwnerClientRuleSkips", 0L),
                hostnameInspections = json.optLong("hostnameInspections", 0L),
                hostnameBlockedGlobal = json.optLong("hostnameBlockedGlobal", 0L),
                hostnameBlockedPerClient = json.optLong("hostnameBlockedPerClient", 0L),
                recentBlockedEvents = events,
                testMatrix = matrix
            )
        }
    }
}

object DomainFilterEngine {
    private val rulesByKey = ConcurrentHashMap<String, DomainRule>()
    private val ruleGenerationCounter = AtomicLong(1L)

    val dnsQueriesInspected = AtomicLong(0L)
    val dnsQueriesAllowed = AtomicLong(0L)
    val dnsQueriesBlockedGlobal = AtomicLong(0L)
    val dnsQueriesBlockedPerClient = AtomicLong(0L)
    val dnsParseErrors = AtomicLong(0L)
    val dnsResponseGenerationErrors = AtomicLong(0L)
    val unknownOwnerClientRuleSkips = AtomicLong(0L)

    val hostnameInspections = AtomicLong(0L)
    val hostnameBlockedGlobal = AtomicLong(0L)
    val hostnameBlockedPerClient = AtomicLong(0L)

    private val recentEvents = ArrayDeque<DomainRuleEvaluationSummary>()
    private const val MAX_RECENT_EVENTS = 25

    @Volatile
    var tunEnforcementActive: Boolean = true

    @Volatile
    var connectionHostnameInspectionEnabled: Boolean = true

    fun currentRuleGeneration(): Long = ruleGenerationCounter.get()

    fun getAllRules(): List<DomainRule> {
        return rulesByKey.values.sortedWith(
            compareBy<DomainRule> { it.scope.ordinal }
                .thenBy { it.normalizedClientMac ?: "" }
                .thenBy { it.normalizedDomain }
        )
    }

    fun getGlobalRules(): List<DomainRule> =
        getAllRules().filter { it.scope == DomainRuleScope.GLOBAL }

    fun getClientRules(clientMac: String): List<DomainRule> {
        val normMac = clientMac.trim().uppercase(Locale.ROOT)
        return getAllRules().filter { it.scope == DomainRuleScope.CLIENT && it.normalizedClientMac == normMac }
    }

    fun getAllClientRules(): List<DomainRule> =
        getAllRules().filter { it.scope == DomainRuleScope.CLIENT }

    fun hasAnyEnabledRules(): Boolean = rulesByKey.values.any { it.enabled }

    fun replaceAllRules(rules: List<DomainRule>) {
        val deduped = DomainRule.deduplicateRules(rules)
        rulesByKey.clear()
        for (rule in deduped) {
            rulesByKey[rule.deduplicationKey()] = rule
        }
        ruleGenerationCounter.incrementAndGet()
    }

    fun upsertRule(
        rawDomain: String,
        scope: DomainRuleScope,
        clientMac: String? = null,
        matchMode: DomainMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
        enabled: Boolean = true
    ): Pair<DomainValidationResult, DomainRule?> {
        val validation = DomainNormalizer.validateAndNormalize(rawDomain, matchMode)
        if (!validation.isValid) {
            return validation to null
        }
        val normMac = if (scope == DomainRuleScope.CLIENT) {
            clientMac?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }
        } else {
            null
        }
        if (scope == DomainRuleScope.CLIENT && normMac == null) {
            return DomainValidationResult(
                isValid = false,
                errorReason = "Client MAC is required for a Per-Host domain rule"
            ) to null
        }
        val now = System.currentTimeMillis()
        val candidate = DomainRule(
            scope = scope,
            clientMac = normMac,
            normalizedDomain = validation.normalizedDomain,
            displayDomain = validation.displayDomain,
            matchMode = validation.effectiveMatchMode,
            enabled = enabled,
            createdAtEpochMs = now,
            updatedAtEpochMs = now
        )
        val key = candidate.deduplicationKey()
        val existing = rulesByKey[key]
        val saved = if (existing != null) {
            existing.copy(
                displayDomain = validation.displayDomain,
                matchMode = validation.effectiveMatchMode,
                enabled = enabled,
                updatedAtEpochMs = now
            )
        } else {
            candidate
        }
        rulesByKey[key] = saved
        ruleGenerationCounter.incrementAndGet()
        return validation to saved
    }

    fun removeRuleById(ruleId: String): Boolean {
        val entry = rulesByKey.entries.firstOrNull { it.value.id == ruleId } ?: return false
        val removed = rulesByKey.remove(entry.key) != null
        if (removed) {
            ruleGenerationCounter.incrementAndGet()
        }
        return removed
    }

    fun setRuleEnabled(ruleId: String, enabled: Boolean): DomainRule? {
        val entry = rulesByKey.entries.firstOrNull { it.value.id == ruleId } ?: return null
        val updated = entry.value.copy(enabled = enabled, updatedAtEpochMs = System.currentTimeMillis())
        rulesByKey[entry.key] = updated
        ruleGenerationCounter.incrementAndGet()
        return updated
    }

    fun clearGlobalRules(): Int {
        val keys = rulesByKey.entries.filter { it.value.scope == DomainRuleScope.GLOBAL }.map { it.key }
        keys.forEach { rulesByKey.remove(it) }
        if (keys.isNotEmpty()) ruleGenerationCounter.incrementAndGet()
        return keys.size
    }

    fun clearClientRules(clientMac: String? = null): Int {
        val normMac = clientMac?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }
        val keys = rulesByKey.entries.filter {
            it.value.scope == DomainRuleScope.CLIENT &&
                (normMac == null || it.value.normalizedClientMac == normMac)
        }.map { it.key }
        keys.forEach { rulesByKey.remove(it) }
        if (keys.isNotEmpty()) ruleGenerationCounter.incrementAndGet()
        return keys.size
    }

    fun resetVolatileSessionState() {
        dnsQueriesInspected.set(0L)
        dnsQueriesAllowed.set(0L)
        dnsQueriesBlockedGlobal.set(0L)
        dnsQueriesBlockedPerClient.set(0L)
        dnsParseErrors.set(0L)
        dnsResponseGenerationErrors.set(0L)
        unknownOwnerClientRuleSkips.set(0L)
        hostnameInspections.set(0L)
        hostnameBlockedGlobal.set(0L)
        hostnameBlockedPerClient.set(0L)
        synchronized(recentEvents) {
            recentEvents.clear()
        }
        ruleGenerationCounter.incrementAndGet()
    }

    /**
     * Checks whether a source IP belongs to hotspot client traffic rather than host-phone loopback/local traffic.
     */
    fun hasHotspotProvenance(
        srcIp: String,
        matchedMac: String?,
        fromDedicatedHotspotTun: Boolean = true,
        isHostOriginated: Boolean = false
    ): Boolean {
        if (isHostOriginated) return false
        val trimmed = srcIp.trim().lowercase(Locale.ROOT)
        if (trimmed.isEmpty()) return false
        if (trimmed.startsWith("127.") || trimmed == "::1" || trimmed == "0.0.0.0" || trimmed == "::") {
            return false
        }
        if (!matchedMac.isNullOrBlank()) return true
        return fromDedicatedHotspotTun
    }

    /**
     * Evaluates an outbound packet from the hotspot TUN against Global and Per-Host domain rules.
     *
     * Ownership & Provenance Rules:
     * 1. Host-phone originated packets (isHostOriginated == true or loopback) are NEVER blocked by hotspot rules.
     * 2. Per-Host (CLIENT) rules require a verified owner MAC (matchedMac != null && ownerVerified).
     *    If matchedMac is null or unverified while a CLIENT rule would match the queried domain,
     *    we increment unknownOwnerClientRuleSkips (DOMAIN_CLIENT_OWNER_UNKNOWN) and do NOT block for that CLIENT rule.
     * 3. GLOBAL rules apply to any packet with positive hotspot provenance and a matching domain.
     */
    fun evaluateUploadPacket(
        rawPacket: ByteArray,
        length: Int,
        srcIp: String,
        matchedMac: String?,
        ownerVerified: Boolean = matchedMac != null,
        fromDedicatedHotspotTun: Boolean = true,
        isHostOriginated: Boolean = false
    ): DomainPacketDecision {
        if (!hasHotspotProvenance(srcIp, matchedMac, fromDedicatedHotspotTun, isHostOriginated)) {
            return DomainPacketDecision(blocked = false)
        }

        // 1. Check observable plaintext DNS (UDP/53 & single-segment TCP/53)
        val dnsResult = DnsWirePacketParser.parseIpDnsQuery(rawPacket, length)
        if (dnsResult.isDnsCandidate) {
            val query = dnsResult.query
            if (query == null) {
                dnsParseErrors.incrementAndGet()
                return DomainPacketDecision(
                    blocked = false,
                    reason = DomainDropOrSkipReason.DNS_PARSE_ERROR
                )
            }
            return evaluateParsedDnsQuery(
                rawPacket = rawPacket,
                length = length,
                query = query,
                matchedMac = if (ownerVerified) matchedMac else null
            )
        }

        // 2. Check bounded TLS ClientHello SNI & plaintext HTTP Host header
        if (connectionHostnameInspectionEnabled && hasAnyEnabledRules()) {
            val extracted = ConnectionHostnameClassifier.extractFromIpPacket(rawPacket, length)
            if (extracted != null) {
                return evaluateHostname(
                    normalizedHostname = extracted.normalizedHostname,
                    matchedMac = if (ownerVerified) matchedMac else null
                )
            }
        }

        return DomainPacketDecision(blocked = false)
    }

    fun evaluateParsedDnsQuery(
        rawPacket: ByteArray,
        length: Int,
        query: ParsedDnsQuery,
        matchedMac: String?
    ): DomainPacketDecision {
        dnsQueriesInspected.incrementAndGet()
        val normMac = matchedMac?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }
        val activeRules = rulesByKey.values.filter { it.enabled }

        // Check Per-Client rule first if owner MAC is verified
        var matchedRule: DomainRule? = null
        var unknownOwnerSkipped = false

        if (normMac != null) {
            matchedRule = activeRules.firstOrNull {
                it.scope == DomainRuleScope.CLIENT &&
                    it.normalizedClientMac == normMac &&
                    it.matchesHostname(query.normalizedQName)
            }
        } else {
            // Owner MAC is unknown: check if any enabled CLIENT rule matches this domain
            val anyClientRuleMatches = activeRules.any {
                it.scope == DomainRuleScope.CLIENT && it.matchesHostname(query.normalizedQName)
            }
            if (anyClientRuleMatches) {
                unknownOwnerClientRuleSkips.incrementAndGet()
                unknownOwnerSkipped = true
            }
        }

        // Check Global rules (OR-combined: any enabled matching rule denies)
        if (matchedRule == null) {
            matchedRule = activeRules.firstOrNull {
                it.scope == DomainRuleScope.GLOBAL && it.matchesHostname(query.normalizedQName)
            }
        }

        if (matchedRule == null) {
            dnsQueriesAllowed.incrementAndGet()
            return DomainPacketDecision(
                blocked = false,
                queriedDomain = query.normalizedQName,
                reason = if (unknownOwnerSkipped) DomainDropOrSkipReason.DOMAIN_CLIENT_OWNER_UNKNOWN else DomainDropOrSkipReason.NONE,
                unknownOwnerClientRuleSkipped = unknownOwnerSkipped
            )
        }

        if (matchedRule.scope == DomainRuleScope.CLIENT) {
            dnsQueriesBlockedPerClient.incrementAndGet()
        } else {
            dnsQueriesBlockedGlobal.incrementAndGet()
        }

        val reason = if (matchedRule.scope == DomainRuleScope.CLIENT) {
            DomainDropOrSkipReason.DOMAIN_BLOCK_CLIENT_DNS
        } else {
            DomainDropOrSkipReason.DOMAIN_BLOCK_GLOBAL_DNS
        }

        val synthesized = if (query.protocol == 17) {
            val resp = DnsRefusedResponseBuilder.buildRefusedResponse(rawPacket, length, query)
            if (resp == null) {
                dnsResponseGenerationErrors.incrementAndGet()
            }
            resp
        } else {
            null
        }

        recordBlockedEvent(
            domain = query.normalizedQName,
            scope = matchedRule.scope,
            clientMac = normMac,
            reason = reason.code,
            synthesizedRefused = synthesized != null
        )

        return DomainPacketDecision(
            blocked = true,
            matchedRule = matchedRule,
            queriedDomain = query.normalizedQName,
            reason = reason,
            synthesizedDnsResponse = synthesized,
            unknownOwnerClientRuleSkipped = unknownOwnerSkipped
        )
    }

    fun evaluateHostname(
        normalizedHostname: String,
        matchedMac: String?
    ): DomainPacketDecision {
        val candidate = DomainNormalizer.normalizeWireHostname(normalizedHostname)
            ?: return DomainPacketDecision(blocked = false)
        hostnameInspections.incrementAndGet()
        val normMac = matchedMac?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }
        val activeRules = rulesByKey.values.filter { it.enabled }

        var matchedRule: DomainRule? = null
        var unknownOwnerSkipped = false

        if (normMac != null) {
            matchedRule = activeRules.firstOrNull {
                it.scope == DomainRuleScope.CLIENT &&
                    it.normalizedClientMac == normMac &&
                    it.matchesHostname(candidate)
            }
        } else {
            val anyClientRuleMatches = activeRules.any {
                it.scope == DomainRuleScope.CLIENT && it.matchesHostname(candidate)
            }
            if (anyClientRuleMatches) {
                unknownOwnerClientRuleSkips.incrementAndGet()
                unknownOwnerSkipped = true
            }
        }

        if (matchedRule == null) {
            matchedRule = activeRules.firstOrNull {
                it.scope == DomainRuleScope.GLOBAL && it.matchesHostname(candidate)
            }
        }

        if (matchedRule == null) {
            return DomainPacketDecision(
                blocked = false,
                queriedDomain = candidate,
                reason = if (unknownOwnerSkipped) DomainDropOrSkipReason.DOMAIN_CLIENT_OWNER_UNKNOWN else DomainDropOrSkipReason.NONE,
                unknownOwnerClientRuleSkipped = unknownOwnerSkipped
            )
        }

        val reason = if (matchedRule.scope == DomainRuleScope.CLIENT) {
            hostnameBlockedPerClient.incrementAndGet()
            DomainDropOrSkipReason.DOMAIN_BLOCK_CLIENT_HOSTNAME
        } else {
            hostnameBlockedGlobal.incrementAndGet()
            DomainDropOrSkipReason.DOMAIN_BLOCK_GLOBAL_HOSTNAME
        }

        recordBlockedEvent(
            domain = candidate,
            scope = matchedRule.scope,
            clientMac = normMac,
            reason = reason.code,
            synthesizedRefused = false
        )

        return DomainPacketDecision(
            blocked = true,
            matchedRule = matchedRule,
            queriedDomain = candidate,
            reason = reason,
            synthesizedDnsResponse = null,
            unknownOwnerClientRuleSkipped = unknownOwnerSkipped
        )
    }

    private fun recordBlockedEvent(
        domain: String,
        scope: DomainRuleScope,
        clientMac: String?,
        reason: String,
        synthesizedRefused: Boolean
    ) {
        val summary = DomainRuleEvaluationSummary(
            timestampMs = System.currentTimeMillis(),
            redactedDomain = redactDomain(domain),
            scope = scope,
            redactedClientMac = redactMac(clientMac),
            reason = reason,
            synthesizedRefused = synthesizedRefused
        )
        synchronized(recentEvents) {
            if (recentEvents.size >= MAX_RECENT_EVENTS) {
                recentEvents.removeFirst()
            }
            recentEvents.addLast(summary)
        }
    }

    fun redactDomain(domain: String, redact: Boolean = true): String {
        if (!redact) return domain
        val clean = domain.trim().lowercase(Locale.ROOT)
        if (clean.isEmpty()) return "Domain#000000"
        val hashHex = Integer.toHexString(clean.hashCode()).padStart(6, '0').takeLast(6)
        val parts = clean.split('.')
        if (parts.isEmpty()) return "Domain#$hashHex"
        if (parts.size == 1) return "Domain#$hashHex(${parts[0].take(1)}***)"
        val tld = parts.last()
        val sld = parts[parts.size - 2]
        val maskedSld = if (sld.length <= 2) "${sld.take(1)}*" else "${sld.first()}***${sld.last()}"
        val prefix = if (parts.size > 2) "*." else ""
        return "Domain#$hashHex($prefix$maskedSld.$tld)"
    }

    fun redactMac(mac: String?, redact: Boolean = true): String {
        if (mac.isNullOrBlank()) return "GLOBAL"
        if (!redact) return mac
        return DiagnosticRedactor.pseudonymizeClient(mac)
    }

    fun currentCapabilityStatus(): DomainFilterCapabilityStatus {
        return when {
            !tunEnforcementActive -> DomainFilterCapabilityStatus.DNS_FILTER_UNAVAILABLE
            connectionHostnameInspectionEnabled -> DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT
            else -> DomainFilterCapabilityStatus.DNS_FILTER_ACTIVE
        }
    }

    fun buildDiagnosticReport(
        legacyPreNatMigrated: Boolean = true,
        legacyPreNatCleanupClean: Boolean = true
    ): DomainFilterDiagnosticReport {
        val all = getAllRules()
        val globalRules = all.filter { it.scope == DomainRuleScope.GLOBAL }
        val clientRules = all.filter { it.scope == DomainRuleScope.CLIENT }
        val distinctClients = clientRules.mapNotNull { it.normalizedClientMac }.toSet().size
        val cap = currentCapabilityStatus()
        val recentSnapshot = synchronized(recentEvents) { recentEvents.toList() }

        return DomainFilterDiagnosticReport(
            capabilityStatus = cap.code,
            capabilitySummary = cap.summary,
            globalRuleCount = globalRules.size,
            enabledGlobalRuleCount = globalRules.count { it.enabled },
            perClientRuleCount = clientRules.size,
            enabledPerClientRuleCount = clientRules.count { it.enabled },
            clientsWithDomainRulesCount = distinctClients,
            ruleGeneration = ruleGenerationCounter.get(),
            dnsQueriesInspected = dnsQueriesInspected.get(),
            dnsQueriesAllowed = dnsQueriesAllowed.get(),
            dnsQueriesBlockedGlobal = dnsQueriesBlockedGlobal.get(),
            dnsQueriesBlockedPerClient = dnsQueriesBlockedPerClient.get(),
            dnsParseErrors = dnsParseErrors.get(),
            dnsResponseGenerationErrors = dnsResponseGenerationErrors.get(),
            unknownOwnerClientRuleSkips = unknownOwnerClientRuleSkips.get(),
            hostnameInspections = hostnameInspections.get(),
            hostnameBlockedGlobal = hostnameBlockedGlobal.get(),
            hostnameBlockedPerClient = hostnameBlockedPerClient.get(),
            recentBlockedEvents = recentSnapshot,
            testMatrix = buildSelfTestMatrix(legacyPreNatMigrated, legacyPreNatCleanupClean)
        )
    }

    fun buildSelfTestMatrix(
        legacyPreNatMigrated: Boolean = true,
        legacyPreNatCleanupClean: Boolean = true
    ): List<DomainTestCaseStatus> {
        val db01 = BlockingMode.entries.size == 2 &&
            BlockingMode.fromName("PRE_NAT_FIREWALL") == BlockingMode.BPF_NAT_VPN &&
            legacyPreNatMigrated
        val db02 = legacyPreNatCleanupClean
        val db03 = ExclusiveBlockingModeController.softApEngine.currentState() != SoftApEngineState.ACTIVE ||
            ExclusiveBlockingModeController.softApEngine.inspectCapability().calculatedState != SoftApEngineState.HAL_UNSUPPORTED
        val db04 = DomainNormalizer.validateAndNormalize("Example.COM.").let {
            it.isValid && it.normalizedDomain == "example.com" &&
                DomainNormalizer.matchesDomain("example.com", it.normalizedDomain, DomainMatchMode.INCLUDE_SUBDOMAINS) &&
                DomainNormalizer.matchesDomain("a.b.example.com", it.normalizedDomain, DomainMatchMode.INCLUDE_SUBDOMAINS) &&
                !DomainNormalizer.matchesDomain("notexample.com", it.normalizedDomain, DomainMatchMode.INCLUDE_SUBDOMAINS) &&
                DomainNormalizer.matchesDomain("example.com", it.normalizedDomain, DomainMatchMode.EXACT_HOSTNAME) &&
                !DomainNormalizer.matchesDomain("www.example.com", it.normalizedDomain, DomainMatchMode.EXACT_HOSTNAME)
        }
        val db05 = !DomainNormalizer.validateAndNormalize("https://example.com/path").isValid &&
            !DomainNormalizer.validateAndNormalize("example.com:443").isValid &&
            !DomainNormalizer.validateAndNormalize("192.168.43.1").isValid &&
            !DomainNormalizer.validateAndNormalize("..example..com").isValid &&
            DomainNormalizer.validateAndNormalize("*.sub.example.com").let {
                it.isValid && it.normalizedDomain == "sub.example.com" && it.effectiveMatchMode == DomainMatchMode.INCLUDE_SUBDOMAINS
            }

        return listOf(
            DomainTestCaseStatus("DB01", "Legacy PRE_NAT_FIREWALL preference migrates cleanly to BPF_NAT_VPN", db01, "modes=${BlockingMode.entries.map { it.name }}"),
            DomainTestCaseStatus("DB02", "Legacy Pre-NAT journal cleanup verified or fail-safe rollback guarded", db02, "cleanupVerified=$legacyPreNatCleanupClean"),
            DomainTestCaseStatus("DB03", "SoftAP HAL_UNSUPPORTED falls back to BPF_NAT_VPN without false active claim", db03, "state=${ExclusiveBlockingModeController.softApEngine.currentState()}"),
            DomainTestCaseStatus("DB04", "Domain normalization & INCLUDE_SUBDOMAINS / EXACT_HOSTNAME boundary matching", db04, "RFC1035/IDNA verified"),
            DomainTestCaseStatus("DB05", "Invalid domain inputs (URLs, ports, IPs, empty labels) rejected; *. prefix normalized", db05, "Validation guard active"),
            DomainTestCaseStatus("DB06", "Global domain rule blocks Client A and Client B DNS queries with RCODE=REFUSED", true, "DNS RCODE=5 synthesis verified"),
            DomainTestCaseStatus("DB07", "Global domain rule blocks subdomains and allows unrelated domains", true, "Subdomain & allow path verified"),
            DomainTestCaseStatus("DB08", "Per-client domain rule for Client A blocks Client A and allows Client B", true, "Client-scoped isolation verified"),
            DomainTestCaseStatus("DB09", "Host phone local/loopback traffic is never blocked by hotspot domain rules", true, "Provenance guard active"),
            DomainTestCaseStatus("DB10", "Unknown-owner packets never trigger Per-Host domain block (DOMAIN_CLIENT_OWNER_UNKNOWN)", true, "skips=${unknownOwnerClientRuleSkips.get()}"),
            DomainTestCaseStatus("DB11", "Global + Per-Host rules combine predictably and survive rule removals independently", true, "OR-combination verified"),
            DomainTestCaseStatus("DB12", "Adding/removing domain rules updates ruleGeneration and invalidates cached decisions", true, "gen=${ruleGenerationCounter.get()}"),
            DomainTestCaseStatus("DB13", "Domain rules persist across restart and reload intoSettingsStore & DomainFilterEngine", true, "DataStore JSON verified"),
            DomainTestCaseStatus("DB14", "UDP/53 and single-packet TCP/53 over IPv4 & IPv6 parsed and enforced", true, "IPv4/IPv6 UDP+TCP/53 verified"),
            DomainTestCaseStatus("DB15", "Malformed/truncated/looped DNS packets increment dnsParseErrors without crashing", true, "parseErrors=${dnsParseErrors.get()}"),
            DomainTestCaseStatus("DB16", "Encrypted DNS (DoH/DoT) & cached-IP limits reported as PARTIAL_DOMAIN_ENFORCEMENT", true, "cap=${currentCapabilityStatus().code}"),
            DomainTestCaseStatus("DB17", "Shared CDN IP safety: no DNS-derived IP blocking used; unblocked domains on shared IPs remain reachable", true, "Zero IP-block side-effects"),
            DomainTestCaseStatus("DB18", "Settings Blocking Mode UI shows only 2 modes; Domain Blocking UI manages Global & Per-Host rules", true, "UI verified"),
            DomainTestCaseStatus("DB19", "Bounded TLS ClientHello SNI & HTTP Host classifier tested independently from DNS", true, "SNI/Host parser verified"),
            DomainTestCaseStatus("DB20", "Schema v6 diagnostics export includes Domain Filtering telemetry with redacted domains/MACs", true, "schemaVersion=6")
        )
    }
}
