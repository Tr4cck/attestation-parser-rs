use crate::error::KeyAttestationError;
use crate::extension;
use x509_cert::Certificate;
use der::{Decode, Encode};

#[derive(Debug, Clone)]
pub struct Cert {
    pub parsed: Certificate,
    pub tbs_der: Vec<u8>,
    /// DER-encoded issuer Name for comparison.
    pub issuer_der: Vec<u8>,
    /// DER-encoded subject Name for comparison.
    pub subject_der: Vec<u8>,
}

impl Cert {
    pub fn from_der(bytes: &[u8]) -> Result<Self, KeyAttestationError> {
        let parsed = Certificate::from_der(bytes).map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to parse certificate: {e}"))
        })?;
        let tbs_der = parsed.tbs_certificate.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode TBSCertificate: {e}"))
        })?;
        let issuer_der = parsed.tbs_certificate.issuer.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode issuer DN: {e}"))
        })?;
        let subject_der = parsed.tbs_certificate.subject.to_der().map_err(|e| {
            KeyAttestationError::ChainParsing(format!("Failed to encode subject DN: {e}"))
        })?;
        Ok(Self { parsed, tbs_der, issuer_der, subject_der })
    }

    /// Format as RFC 1779-like string for display/provisioning parsing.
    pub fn issuer_dn(&self) -> String {
        name_to_string(&self.parsed.tbs_certificate.issuer)
    }

    pub fn subject_dn(&self) -> String {
        name_to_string(&self.parsed.tbs_certificate.subject)
    }

    /// Compare issuer DER encoding for name chaining.
    pub fn issuer_eq(&self, subject_der: &[u8]) -> bool {
        self.issuer_der == subject_der
    }

    pub fn serial_number_hex(&self) -> String {
        let hex_str = hex::encode(self.parsed.tbs_certificate.serial_number.as_bytes())
            .to_ascii_lowercase();
        let trimmed: &str = hex_str.trim_start_matches('0');
        if trimmed.is_empty() { "0".into() } else { trimmed.to_string() }
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer_der == self.subject_der
    }

    pub fn has_attestation_extension(&self) -> bool {
        self.parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .map(|exts| {
                exts.iter().any(|ext| {
                    ext.extn_id.to_string() == extension::KEY_DESCRIPTION_OID && !ext.critical
                })
            })
            .unwrap_or(false)
    }

    pub fn get_extension_value(&self, oid: &str) -> Option<Vec<u8>> {
        self.parsed
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| exts.iter().find(|ext| ext.extn_id.to_string() == oid))
            .map(|ext| ext.extn_value.as_bytes().to_vec())
    }
}

/// Format a Name as an RFC 1779-like string by converting to Display.
fn name_to_string(name: &x509_cert::name::Name) -> String {
    name.to_string()
}

fn parse_dn(dn: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in dn.split(',') {
        let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
        if kv.len() == 2 {
            map.insert(kv[0].trim().to_string(), kv[1].trim().to_string());
        }
    }
    map
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningMethod {
    Unknown,
    FactoryProvisioned,
    RemotelyProvisioned,
}

pub struct KeyAttestationCertPath {
    pub certificates_with_anchor: Vec<Cert>,
}

// ── Lightweight DER walker for error diagnostics ──────────────────────────
// When Certificate::from_der() fails, we walk the raw DER to extract as much
// info as possible (subject, issuer, serial, validity) for a helpful error.

fn read_tl(data: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    if off >= data.len() { return None; }
    let tag = data[off];
    if off + 1 >= data.len() { return None; }
    let lb = data[off + 1];
    if lb & 0x80 == 0 {
        Some((tag, lb as usize, 2))
    } else {
        let nb = (lb & 0x7f) as usize;
        if off + 2 + nb > data.len() { return None; }
        let len = data[off + 2..off + 2 + nb].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        Some((tag, len, 2 + nb))
    }
}

/// Skip one ASN.1 element, returning the offset past it.
fn skip_element(data: &[u8], off: usize) -> Option<usize> {
    let (_, len, hdr) = read_tl(data, off)?;
    Some(off + hdr + len)
}

/// Read the content bytes of an ASN.1 element at `off`.
fn element_content(data: &[u8], off: usize) -> Option<(u8, &[u8])> {
    let (tag, len, hdr) = read_tl(data, off)?;
    if off + hdr + len > data.len() { return None; }
    Some((tag, &data[off + hdr..off + hdr + len]))
}

/// Decode a UTCTime or GeneralizedTime string to millis since epoch.
/// Returns None if the time string is unparseable.
fn decode_time_bytes(tag: u8, content: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(content).ok()?;
    match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() < 13 { return None; }
            let yy: i32 = s[0..2].parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let month: u32 = s[2..4].parse().ok()?;
            let day: u32 = s[4..6].parse().ok()?;
            let hour: u32 = s[6..8].parse().ok()?;
            let min: u32 = s[8..10].parse().ok()?;
            let sec: u32 = s[10..12].parse().ok()?;
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec))
                .map(|dt| dt.and_utc().timestamp_millis())
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() < 15 { return None; }
            let year: i32 = s[0..4].parse().ok()?;
            let month: u32 = s[4..6].parse().ok()?;
            let day: u32 = s[6..8].parse().ok()?;
            let hour: u32 = s[8..10].parse().ok()?;
            let min: u32 = s[10..12].parse().ok()?;
            let sec: u32 = s[12..14].parse().ok()?;
            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec))
                .map(|dt| dt.and_utc().timestamp_millis())
        }
        _ => None,
    }
}

/// Format a Name (SEQUENCE of SET of SEQUENCE of OID+value) from raw DER
/// into a best-effort DN string like "CN=..., O=..., C=...".
fn name_from_der(data: &[u8]) -> String {
    let mut parts = Vec::new();
    // data is the content of a SEQUENCE
    let mut pos = 0;
    while pos < data.len() {
        // Each element is a SET
        let (_, set_len, set_hdr) = match read_tl(data, pos) {
            Some(v) => v,
            None => break,
        };
        let set_content = &data[pos + set_hdr..pos + set_hdr + set_len];
        // Inside SET, each element is a SEQUENCE of (OID, value)
        let mut spos = 0;
        while spos < set_content.len() {
            let (_, seq_len, seq_hdr) = match read_tl(set_content, spos) {
                Some(v) => v,
                None => break,
            };
            let seq_content = &set_content[spos + seq_hdr..spos + seq_hdr + seq_len];
            // First element: OID, second: value
            if let Some((0x06, oid_bytes)) = element_content(seq_content, 0) {
                let oid_str = decode_oid_bytes(oid_bytes);
                let short_name = oid_short_name(&oid_str);
                // Skip to value element
                if let Some(val_off) = skip_element(seq_content, 0) {
                    if let Some((_, val_bytes)) = element_content(seq_content, val_off) {
                        let val_str = String::from_utf8_lossy(val_bytes).to_string();
                        parts.push(format!("{}={}", short_name, val_str));
                    }
                }
            }
            spos += seq_hdr + seq_len;
        }
        pos += set_hdr + set_len;
    }
    parts.join(", ")
}

/// Decode OID bytes to dotted string.
fn decode_oid_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let mut components = Vec::new();
    let first = bytes[0];
    components.push((first / 40) as u64);
    components.push((first % 40) as u64);
    let mut val: u64 = 0;
    for &b in &bytes[1..] {
        val = (val << 7) | ((b & 0x7f) as u64);
        if b & 0x80 == 0 {
            components.push(val);
            val = 0;
        }
    }
    components.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(".")
}

fn oid_short_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "ST",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "emailAddress",
        _ => oid,
    }
}

/// Walk the raw DER of a certificate and extract diagnostic info.
/// Returns a formatted string with as much detail as possible.
fn diagnose_cert_der(der: &[u8], index: usize, role: &str) -> String {
    let mut info = Vec::new();
    info.push(format!("  certificate[{}] ({}): {} bytes, SHA-256={}",
        index, role, der.len(), sha256_hex(der)));

    // Certificate = SEQUENCE { TBS, sigAlg, sig }
    let (tbs_tag, tbs_len, tbs_hdr) = match read_tl(der, 0) {
        Some(v) => v,
        None => {
            info.push("  (cannot parse outer SEQUENCE)".into());
            return info.join("\n");
        }
    };
    if tbs_tag != 0x30 {
        info.push(format!("  (expected SEQUENCE tag 0x30, got 0x{tbs_tag:02x})"));
        return info.join("\n");
    }
    let tbs_content = &der[tbs_hdr..tbs_hdr + tbs_len];

    // TBS Certificate = SEQUENCE { version?, serial, sigAlg, issuer, validity, subject, ... }
    let (_, tbs_inner_len, tbs_inner_hdr) = match read_tl(tbs_content, 0) {
        Some(v) => v,
        None => {
            info.push("  (cannot parse TBS SEQUENCE)".into());
            return info.join("\n");
        }
    };
    let tbs_inner = &tbs_content[tbs_inner_hdr..tbs_inner_hdr + tbs_inner_len];

    let mut pos = 0;

    // [0] version (optional, explicit tag 0xa0)
    if pos < tbs_inner.len() && tbs_inner[pos] == 0xa0 {
        pos = match skip_element(tbs_inner, pos) {
            Some(p) => p,
            None => { info.push("  (error skipping version)".into()); return info.join("\n"); }
        };
    }

    // serialNumber (INTEGER)
    if let Some((_, serial_bytes)) = element_content(tbs_inner, pos) {
        let serial_hex = hex::encode(serial_bytes);
        let serial_dec = serial_bytes.iter().fold(0u128, |a, &b| (a << 8) | b as u128);
        info.push(format!("  serialNumber: {} (0x{})", serial_dec, serial_hex));
    }
    pos = match skip_element(tbs_inner, pos) {
        Some(p) => p,
        None => { info.push("  (error skipping serialNumber)".into()); return info.join("\n"); }
    };

    // signatureAlgorithm (SEQUENCE)
    if let Some((_, sigalg_bytes)) = element_content(tbs_inner, pos) {
        // Try to find OID inside
        if let Some((0x06, oid_bytes)) = element_content(sigalg_bytes, 0) {
            let oid_str = decode_oid_bytes(oid_bytes);
            info.push(format!("  signatureAlgorithm: {} ({})", sig_alg_name(&oid_str), oid_str));
        }
    }
    pos = match skip_element(tbs_inner, pos) {
        Some(p) => p,
        None => { info.push("  (error skipping signatureAlgorithm)".into()); return info.join("\n"); }
    };

    // issuer (Name = SEQUENCE)
    if let Some((_, issuer_bytes)) = element_content(tbs_inner, pos) {
        info.push(format!("  issuer: {}", name_from_der(issuer_bytes)));
    }
    pos = match skip_element(tbs_inner, pos) {
        Some(p) => p,
        None => { info.push("  (error skipping issuer)".into()); return info.join("\n"); }
    };

    // validity (SEQUENCE { notBefore, notAfter })
    if let Some((0x30, validity_bytes)) = element_content(tbs_inner, pos) {
        let mut vpos = 0;
        // notBefore
        if let Some((tag, time_bytes)) = element_content(validity_bytes, vpos) {
            let time_name = if tag == 0x17 { "UTCTime" } else if tag == 0x18 { "GeneralizedTime" } else { "Unknown" };
            let time_str = String::from_utf8_lossy(time_bytes);
            let millis = decode_time_bytes(tag, time_bytes);
            match millis {
                Some(ms) => {
                    let iso = chrono::DateTime::from_timestamp_millis(ms)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                        .unwrap_or_else(|| format!("{ms}"));
                    info.push(format!("  notBefore: {} ({}) = {}ms ({})", time_name, time_str, ms, iso));
                }
                None => {
                    info.push(format!("  notBefore: {} ({}) = ⚠ UNPARSEABLE", time_name, time_str));
                }
            }
            vpos = match skip_element(validity_bytes, vpos) {
                Some(p) => p,
                None => { info.push("  (error in validity)".into()); return info.join("\n"); }
            };
        }
        // notAfter
        if let Some((tag, time_bytes)) = element_content(validity_bytes, vpos) {
            let time_name = if tag == 0x17 { "UTCTime" } else if tag == 0x18 { "GeneralizedTime" } else { "Unknown" };
            let time_str = String::from_utf8_lossy(time_bytes);
            let millis = decode_time_bytes(tag, time_bytes);
            match millis {
                Some(ms) => {
                    let iso = chrono::DateTime::from_timestamp_millis(ms)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                        .unwrap_or_else(|| format!("{ms}"));
                    info.push(format!("  notAfter: {} ({}) = {}ms ({})", time_name, time_str, ms, iso));
                }
                None => {
                    info.push(format!("  notAfter: {} ({}) = ⚠ UNPARSEABLE", time_name, time_str));
                }
            }
        }
    }
    pos = match skip_element(tbs_inner, pos) {
        Some(p) => p,
        None => { info.push("  (error skipping validity)".into()); return info.join("\n"); }
    };

    // subject (Name = SEQUENCE)
    if let Some((_, subject_bytes)) = element_content(tbs_inner, pos) {
        info.push(format!("  subject: {}", name_from_der(subject_bytes)));
    }

    info.join("\n")
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    Digest::update(&mut h, data);
    hex::encode(h.finalize())
}

pub fn sig_alg_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.4.3.2" => "SHA256withECDSA".into(),
        "1.2.840.10045.4.3.3" => "SHA384withECDSA".into(),
        "1.2.840.10045.4.3.4" => "SHA512withECDSA".into(),
        "1.2.840.113549.1.1.11" => "SHA256withRSA".into(),
        "1.2.840.113549.1.1.12" => "SHA384withRSA".into(),
        "1.2.840.113549.1.1.13" => "SHA512withRSA".into(),
        _ => oid.into(),
    }
}

impl KeyAttestationCertPath {
    pub fn from_der_blobs(certs: Vec<Vec<u8>>) -> Result<Self, KeyAttestationError> {
        if certs.len() < 3 {
            return Err(KeyAttestationError::ChainParsing(
                "At least 3 certificates are required".into(),
            ));
        }

        let chain_len = certs.len();
        let mut parsed = Vec::with_capacity(chain_len);

        for (i, der) in certs.iter().enumerate() {
            let role = if i == 0 {
                "attestation"
            } else if i == chain_len - 1 {
                "root"
            } else {
                "attestationSigner"
            };

            match Cert::from_der(der) {
                Ok(cert) => parsed.push(cert),
                Err(original_err) => {
                    // Certificate failed to parse. Extract as much diagnostic info
                    // as possible from the raw DER to help the user understand why.
                    let diag = diagnose_cert_der(der, i, role);
                    return Err(KeyAttestationError::ChainParsing(format!(
                        "Failed to parse certificate[{}] ({}): {}\n\
                         Diagnostic info from raw DER:\n{}\n\
                         Possible causes:\n\
                         - Malformed or corrupted DER encoding\n\
                         - Invalid ASN.1 time values (e.g. UTCTime with pre-epoch dates)\n\
                         - Non-standard extension encoding that the strict DER parser rejects\n\
                         Tip: verify with `openssl x509 -inform DER -text -noout <cert.der>`",
                        i, role, original_err, diag
                    )));
                }
            }
        }

        if !parsed.last().unwrap().is_self_issued() {
            return Err(KeyAttestationError::ChainParsing(
                "Root certificate not found (last cert must be self-issued)".into(),
            ));
        }

        Ok(Self { certificates_with_anchor: parsed })
    }

    pub fn leaf_cert(&self) -> &Cert { &self.certificates_with_anchor[0] }
    pub fn attestation_cert(&self) -> &Cert { &self.certificates_with_anchor[1] }
    pub fn intermediate_cert(&self) -> &Cert {
        // The certificate immediately before the root (last non-root).
        &self.certificates_with_anchor[self.certificates_with_anchor.len() - 2]
    }

    pub fn certificates(&self) -> &[Cert] {
        &self.certificates_with_anchor[..self.certificates_with_anchor.len() - 1]
    }

    pub fn serial_numbers(&self) -> Vec<String> {
        self.certificates_with_anchor.iter().map(|c| c.serial_number_hex()).collect()
    }

    pub fn provisioning_method(&self) -> ProvisioningMethod {
        if self.is_factory_provisioned() {
            ProvisioningMethod::FactoryProvisioned
        } else if self.is_remotely_provisioned() {
            ProvisioningMethod::RemotelyProvisioned
        } else {
            ProvisioningMethod::Unknown
        }
    }

    pub fn security_level(&self) -> crate::extension::SecurityLevel {
        match self.provisioning_method() {
            ProvisioningMethod::FactoryProvisioned => {
                let dn = self.intermediate_cert().subject_dn();
                let parsed = parse_dn(&dn);
                parsed.get("OID.2.5.4.12")
                    .map(|t| dn_title_to_security_level(t))
                    .unwrap_or(crate::extension::SecurityLevel::Software)
            }
            ProvisioningMethod::RemotelyProvisioned => {
                let dn = self.attestation_cert().subject_dn();
                let parsed = parse_dn(&dn);
                parsed.get("O").map(|o| org_to_security_level(o))
                    .unwrap_or(crate::extension::SecurityLevel::Software)
            }
            ProvisioningMethod::Unknown => crate::extension::SecurityLevel::Software,
        }
    }

    fn is_factory_provisioned(&self) -> bool {
        let dn = self.intermediate_cert().subject_dn();
        let parsed = parse_dn(&dn);
        parsed.contains_key("OID.2.5.4.5")
            && parsed.get("OID.2.5.4.12")
                .is_some_and(|t| *t == "TEE" || *t == "StrongBox")
    }

    fn is_remotely_provisioned(&self) -> bool {
        let dn = self.intermediate_cert().subject_dn();
        let parsed = parse_dn(&dn);
        parsed.get("CN") == Some(&"Droid CA2".to_string())
            && parsed.get("O") == Some(&"Google LLC".to_string())
    }
}

fn dn_title_to_security_level(title: &str) -> crate::extension::SecurityLevel {
    match title {
        "TEE" => crate::extension::SecurityLevel::TrustedEnvironment,
        "StrongBox" => crate::extension::SecurityLevel::StrongBox,
        _ => crate::extension::SecurityLevel::Software,
    }
}

fn org_to_security_level(org: &str) -> crate::extension::SecurityLevel {
    match org {
        "TEE" => crate::extension::SecurityLevel::TrustedEnvironment,
        "StrongBox" => crate::extension::SecurityLevel::StrongBox,
        _ => crate::extension::SecurityLevel::Software,
    }
}

/// Parse keyUsage extension value (inner content, OCTET STRING wrapper stripped).
/// Returns 9 boolean values for the standard key usage bits.
pub fn parse_key_usage(extn_value: &[u8]) -> Vec<bool> {
    let mut bits = vec![false; 9];
    if extn_value.len() < 3 || extn_value[0] != 0x03 {
        return bits;
    }

    let (_, len, hdr) = match read_tl(extn_value, 0) {
        Some(v) => v,
        None => return bits,
    };

    let bs_content = &extn_value[hdr..hdr + len];
    if bs_content.is_empty() {
        return bits;
    }

    let _unused_bits = bs_content[0] as usize;
    let data = &bs_content[1..];

    for (byte_idx, &byte) in data.iter().enumerate() {
        for bit_idx in 0..8 {
            let i = byte_idx * 8 + (7 - bit_idx);
            if i >= 9 {
                return bits;
            }
            bits[i] = (byte >> bit_idx) & 1 == 1;
        }
    }

    bits
}

/// Parse basicConstraints extension value (inner content, OCTET STRING wrapper stripped).
/// Returns the pathLenConstraint value, 2147483647 for CA:true without pathLen, -1 for non-CA.
pub fn parse_basic_constraints(extn_value: &[u8]) -> i64 {
    if extn_value.is_empty() || extn_value[0] != 0x30 {
        return -1;
    }

    let (_, len, hdr) = match read_tl(extn_value, 0) {
        Some(v) => v,
        None => return -1,
    };

    let seq_content = &extn_value[hdr..hdr + len];
    if seq_content.is_empty() {
        return -1;
    }

    let mut pos = 0;
    let mut is_ca = false;

    while pos < seq_content.len() {
        let tag = seq_content[pos];
        let (el_len, el_hdr) = match read_tl(&seq_content[pos..], 0) {
            Some((_, l, h)) => (l, h),
            None => break,
        };

        if pos + el_hdr + el_len > seq_content.len() {
            break;
        }

        match tag {
            0x01 if el_len == 1 => {
                is_ca = seq_content[pos + el_hdr] != 0x00;
            }
            0x02 if is_ca && el_len <= 8 => {
                let int_bytes = &seq_content[pos + el_hdr..pos + el_hdr + el_len];
                let val = int_bytes.iter().fold(0i64, |a, &b| (a << 8) | b as i64);
                return val;
            }
            _ => {}
        }
        pos += el_hdr + el_len;
    }

    if is_ca {
        2147483647 // Java Integer.MAX_VALUE
    } else {
        -1
    }
}

#[cfg(test)]
#[path = "cert_chain_tests.rs"]
mod tests;
