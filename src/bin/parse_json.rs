//! Parse an Android Key Attestation from a JSON file or stdin.
//!
//! Input:
//! ```json
//! { "alias": "...", "certificateChainBlob": "<base64>", "challenge": "<base64>" }
//! ```
//!
//! Output: structured JSON with certificate chain details, key description,
//! validation errors, and per-tag rendering.

use attestation_parser_rs::*;
use attestation_parser_rs::extension;
use base64::Engine;
use serde_json::{json, Value};
use std::io::Read;
use sha2::{Sha256, Digest};
use der::Encode;

// ── certificateChainBlob decoder ──────────────────────────────────────────

fn decode_certificate_chain_blob(blob: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    // Normalize base64 padding: strip existing padding, then add correct amount.
    // Android Keystore may produce base64 with incorrect padding.
    let b64_trimmed = blob.trim().trim_end_matches('=');
    let pad_needed = (4 - b64_trimmed.len() % 4) % 4;
    let b64_padded = format!("{}{}", b64_trimmed, "=".repeat(pad_needed));
    let raw = base64::engine::general_purpose::STANDARD.decode(&b64_padded)?;
    if raw.is_empty() || raw[0] != 0x30 {
        return Err("Expected DER SEQUENCE tag (0x30)".into());
    }
    let (outer_len, outer_header) = read_der_tl(&raw, 0)?;
    // The content of the outer SEQUENCE contains individual Certificate SEQUENCEs
    let inner = &raw[outer_header..outer_header + outer_len];
    let mut certs = Vec::new();
    let mut pos = 0;
    while pos < inner.len() {
        if inner[pos] != 0x30 {
            return Err(format!("Expected cert SEQUENCE at offset {pos}, got 0x{:02x}", inner[pos]).into());
        }
        let (clen, chdr) = read_der_tl(inner, pos)?;
        let total = chdr + clen;
        certs.push(inner[pos..pos + total].to_vec());
        pos += total;
    }
    certs.reverse(); // root-first → leaf-first
    Ok(certs)
}

fn read_der_tl(data: &[u8], offset: usize) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    if offset + 1 >= data.len() { return Err("Unexpected end of DER".into()); }
    let len_byte = data[offset + 1];
    if len_byte & 0x80 == 0 {
        Ok((len_byte as usize, 2))
    } else {
        let nb = (len_byte & 0x7f) as usize;
        if offset + 1 + nb >= data.len() { return Err("Unexpected end of DER length".into()); }
        let len = data[offset + 2..offset + 2 + nb].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        Ok((len, 2 + nb))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

fn int_to_u64(val: &der::asn1::Int) -> u64 {
    val.as_bytes().iter().fold(0u64, |a, &b| (a << 8) | b as u64)
}

fn int_to_i64(val: &der::asn1::Int) -> i64 {
    let bytes = val.as_bytes();
    if bytes.is_empty() { return 0; }
    if bytes[0] & 0x80 != 0 {
        bytes.iter().fold(0i64, |a, &b| (a << 8) | b as i64)
    } else {
        int_to_u64(val) as i64
    }
}

/// Convert serial number bytes to an unsigned decimal string.
/// Serial numbers in X.509 are INTEGER but should be treated as unsigned for display.
fn serial_to_string(sn: &x509_cert::serial_number::SerialNumber) -> String {
    let bytes = sn.as_bytes();
    if bytes.is_empty() { return "0".into(); }
    // Interpret as unsigned big-endian integer.
    // Serial numbers can be up to 20 octets; fall back to hex for very long ones.
    if bytes.len() > 16 {
        return format!("0x{}", hex::encode(bytes));
    }
    let value = bytes.iter().fold(0u128, |a, &b| (a << 8) | b as u128);
    value.to_string()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    Digest::update(&mut h, data);
    hex::encode(h.finalize())
}

fn millis_to_iso(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| format!("{millis}"))
}

fn os_version_decode(v: u64) -> String {
    let major = (v / 10000) as u32;
    let minor = ((v % 10000) / 100) as u32;
    let patch = (v % 100) as u32;
    format!("{major}.{minor}.{patch}")
}

fn purpose_name(v: u64) -> String { match v { 0=>"Encrypt",1=>"Decrypt",2=>"Sign",3=>"Verify",4=>"DeriveKey",5=>"WrapKey",6=>"AgreeKey",_=>"Unknown" }.into() }
fn algorithm_name(v: u64) -> String { match v { 1=>"RSA",2=>"AES",3=>"EC",4=>"HMAC",5=>"3DES",32=>"ML-DSA",_=>"Unknown" }.into() }
fn digest_name(v: u64) -> String { match v { 0=>"NONE",1=>"MD5",2=>"SHA1",3=>"SHA2_224",4=>"SHA2_256",5=>"SHA2_384",6=>"SHA2_512",_=>"Unknown" }.into() }
fn ec_curve_name(v: u64) -> String { match v { 1=>"P_256",2=>"P_384",3=>"P_521",4=>"P_224",_=>"Unknown" }.into() }
fn origin_name(o: &extension::Origin) -> String { match o { extension::Origin::Generated=>"Generated",extension::Origin::Derived=>"Derived",extension::Origin::Imported=>"Imported",extension::Origin::Reserved=>"Reserved",extension::Origin::SecurelyImported=>"SecurelyImported" }.into() }
fn boot_state_name(s: extension::VerifiedBootState) -> String { match s { extension::VerifiedBootState::Verified=>"Verified",extension::VerifiedBootState::SelfSigned=>"SelfSigned",extension::VerifiedBootState::Unverified=>"Unverified",extension::VerifiedBootState::Failed=>"Failed" }.into() }
fn sec_level_name(s: extension::SecurityLevel) -> String { match s { extension::SecurityLevel::Software=>"Software",extension::SecurityLevel::TrustedEnvironment=>"TrustedEnvironment",extension::SecurityLevel::StrongBox=>"StrongBox" }.into() }
fn sig_alg_oid_name(oid: &str) -> String { match oid { "1.2.840.10045.4.3.2"=>"SHA256withECDSA".into(),"1.2.840.10045.4.3.3"=>"SHA384withECDSA".into(),"1.2.840.10045.4.3.4"=>"SHA512withECDSA".into(),"1.2.840.113549.1.1.11"=>"SHA256withRSA".into(),"1.2.840.113549.1.1.12"=>"SHA384withRSA".into(),"1.2.840.113549.1.1.13"=>"SHA512withRSA".into(),_=>oid.into() } }

// ── build per-cert JSON ───────────────────────────────────────────────────

fn build_cert_json(cert: &Cert, der_bytes: &[u8], index: usize, chain_len: usize) -> Value {
    let tbs = &cert.parsed.tbs_certificate;
    let role = match index {
        0 => "attestation",
        n if n == chain_len - 1 => "root",
        _ => "attestationSigner",
    };

    // validity
    let not_before_ms = tbs.validity.not_before.to_unix_duration().as_millis() as i64;
    let not_after_ms = tbs.validity.not_after.to_unix_duration().as_millis() as i64;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let expired = now_ms > not_after_ms;

    // serial - use unsigned interpretation
    let serial_hex = cert.serial_number_hex();
    let serial_dec = serial_to_string(&tbs.serial_number);

    // sig alg
    let sig_oid = cert.parsed.signature_algorithm.oid.to_string();
    let sig_alg_name = sig_alg_oid_name(&sig_oid);

    // public key algorithm from SPKI OID
    let pk_alg_oid = tbs.subject_public_key_info.algorithm.oid.to_string();
    let pk_alg = match pk_alg_oid.as_str() {
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.113549.1.1.1" => "RSA",
        _ => "Unknown",
    };

    // extensions
    let mut critical_oids = Vec::new();
    let mut non_critical_oids = Vec::new();
    let mut has_ka = false;
    let mut has_pi = false;
    let mut basic_constraints_val: i64 = -1;
    let mut key_usage_bits = vec![false; 9];

    if let Some(exts) = &tbs.extensions {
        for ext in exts.iter() {
            let oid_str = ext.extn_id.to_string();
            if ext.critical {
                critical_oids.push(oid_str.clone());
            } else {
                non_critical_oids.push(oid_str.clone());
            }
            match oid_str.as_str() {
                "2.5.29.19" => { // basicConstraints
                    basic_constraints_val = cert_chain::parse_basic_constraints(ext.extn_value.as_bytes());
                }
                "2.5.29.15" => { // keyUsage
                    key_usage_bits = cert_chain::parse_key_usage(ext.extn_value.as_bytes());
                }
                "1.3.6.1.4.1.11129.2.1.17" => has_ka = true,
                "1.3.6.1.4.1.11129.2.1.30" => has_pi = true,
                _ => {}
            }
        }
    }

    // SHA-256 hashes
    let cert_sha = sha256_hex(der_bytes);
    let spki_der = tbs.subject_public_key_info.to_der().unwrap_or_default();
    let spki_sha = sha256_hex(&spki_der);

    json!({
        "index": index,
        "role": role,
        "type": "X.509",
        "version": 3, // all attestation certs are v3
        "subjectDN": cert.subject_dn(),
        "issuerDN": cert.issuer_dn(),
        "serialNumber": serial_dec,
        "serialNumberHex": serial_hex,
        "notBefore": format!("{} ({})", not_before_ms, millis_to_iso(not_before_ms)),
        "notAfter": format!("{} ({})", not_after_ms, millis_to_iso(not_after_ms)),
        "expired": expired,
        "signatureAlgorithm": sig_alg_name,
        "signatureAlgorithmOid": sig_oid,
        "publicKeyAlgorithm": pk_alg,
        "publicKeyFormat": "X.509",
        "basicConstraints": basic_constraints_val,
        "keyUsage": key_usage_bits,
        "extendedKeyUsage": [],
        "criticalExtensionOids": critical_oids,
        "nonCriticalExtensionOids": non_critical_oids,
        "certSha256": cert_sha,
        "spkiSha256": spki_sha,
        "hasKeyAttestationExtension": has_ka,
        "hasProvisioningInfoExtension": has_pi,
    })
}

// ── build auth list tags & fields ─────────────────────────────────────────

fn build_auth_list(al: &extension::AuthorizationList, _label: &str) -> Value {
    let mut tags = Vec::new();
    let mut fields = serde_json::Map::new();

    let push_tag = |no: u64, name: &str, val: Value| {
        json!({ "tagNo": no, "name": name, "value": val })
    };

    if let Some(ref v) = al.purposes {
        let nums: Vec<u64> = v.iter().map(int_to_u64).collect();
        let names: Vec<String> = nums.iter().map(|n| format!("{}({})", purpose_name(*n), n)).collect();
        let val = format!("[{}]", names.join(", "));
        tags.push(push_tag(1, "purpose", json!(val)));
        fields.insert("purpose".into(), json!(val));
    }
    if let Some(ref v) = al.algorithm {
        let n = int_to_u64(v);
        let s = format!("{}({})", algorithm_name(n), n);
        tags.push(push_tag(2, "algorithm", json!(s)));
        fields.insert("algorithm".into(), json!(s));
    }
    if let Some(ref v) = al.key_size {
        let n = int_to_u64(v);
        let s = n.to_string();
        tags.push(push_tag(3, "keySize", json!(s)));
        fields.insert("keySize".into(), json!(s));
    }
    if let Some(ref v) = al.block_modes {
        let nums: Vec<u64> = v.iter().map(int_to_u64).collect();
        let s = format!("{:?}", nums);
        tags.push(push_tag(4, "blockMode", json!(s)));
        fields.insert("blockMode".into(), json!(s));
    }
    if let Some(ref v) = al.digests {
        let nums: Vec<u64> = v.iter().map(int_to_u64).collect();
        let names: Vec<String> = nums.iter().map(|n| format!("{}({})", digest_name(*n), n)).collect();
        let val = format!("[{}]", names.join(", "));
        tags.push(push_tag(5, "digest", json!(val)));
        fields.insert("digest".into(), json!(val));
    }
    if let Some(ref v) = al.paddings {
        let nums: Vec<u64> = v.iter().map(int_to_u64).collect();
        let s = format!("{:?}", nums);
        tags.push(push_tag(6, "padding", json!(s)));
        fields.insert("padding".into(), json!(s));
    }
    if let Some(ref v) = al.ec_curve {
        let n = int_to_u64(v);
        let s = format!("{}({})", ec_curve_name(n), n);
        tags.push(push_tag(10, "ecCurve", json!(s)));
        fields.insert("ecCurve".into(), json!(s));
    }
    if al.no_auth_required.is_some() {
        tags.push(push_tag(503, "noAuthRequired", json!("true")));
        fields.insert("noAuthRequired".into(), json!("true"));
    }
    if let Some(ref v) = al.creation_date_time {
        let ms = int_to_i64(v);
        let s = format!("{} ({})", ms, millis_to_iso(ms));
        tags.push(push_tag(701, "creationDateTime", json!(s)));
        fields.insert("creationDateTime".into(), json!(s));
    }
    if let Some(ref v) = al.origin {
        let n = *v as u64;
        let s = format!("{}({})", origin_name(v), n);
        tags.push(push_tag(702, "origin", json!(s)));
        fields.insert("origin".into(), json!(s));
    }
    if let Some(ref v) = al.root_of_trust {
        let key_hex = hex::encode(&v.verified_boot_key);
        let locked = v.device_locked;
        let bs_name = boot_state_name(v.verified_boot_state);
        let bs_val = v.verified_boot_state as u64;
        let val = format!("{{verifiedBootKey=0x{}, deviceLocked={}, verifiedBootState={}({})}}", key_hex, locked, bs_name, bs_val);
        tags.push(push_tag(704, "rootOfTrust", json!(val)));
        fields.insert("rootOfTrust".into(), json!(val));
        fields.insert("verifiedBootKey".into(), json!(format!("0x{}", key_hex)));
        fields.insert("deviceLocked".into(), json!(locked));
        fields.insert("verifiedBootState".into(), json!(format!("{}({})", bs_name, bs_val)));
    }
    if let Some(ref v) = al.os_version {
        let n = int_to_u64(v);
        let s = format!("{} ({})", n, os_version_decode(n));
        tags.push(push_tag(705, "osVersion", json!(s)));
        fields.insert("osVersion".into(), json!(s));
    }
    if let Some(ref v) = al.os_patch_level {
        let s = format!("{}{:02} ({}-{:02})", v.year, v.month, v.year, v.month);
        tags.push(push_tag(706, "osPatchLevel", json!(s)));
        fields.insert("osPatchLevel".into(), json!(s));
    }
    if let Some(ref v) = al.attestation_application_id {
        let pkg_infos: Vec<String> = v.packages.iter().map(|p| format!("packageName={}, version={}", p.name, int_to_u64(&p.version))).collect();
        let sig_digests: Vec<String> = v.signatures.iter().map(|s| format!("0x{}", hex::encode(s))).collect();
        let raw_hex = hex::encode(&v.raw_der);
        let val = format!("{{raw=0x{}, packageInfos=[{{{}}}], signatureDigests=[{}]}}", raw_hex, pkg_infos.join(", "), sig_digests.join(", "));
        tags.push(push_tag(709, "attestationApplicationId", json!(val)));
        fields.insert("attestationApplicationId".into(), json!(val));
        if let Some(pkg) = v.packages.first() {
            fields.insert("packageName".into(), json!(pkg.name));
            fields.insert("packageVersion".into(), json!(int_to_u64(&pkg.version)));
        }
        if let Some(sig) = v.signatures.first() {
            fields.insert("packageSignatureDigest".into(), json!(format!("0x{}", hex::encode(sig))));
        }
    }
    if let Some(ref v) = al.vendor_patch_level {
        let s = format!("{}{:02} ({}-{:02})", v.year, v.month, v.year, v.month);
        tags.push(push_tag(718, "vendorPatchLevel", json!(s)));
        fields.insert("vendorPatchLevel".into(), json!(s));
    }
    if let Some(ref v) = al.boot_patch_level {
        let s = format!("{}{:02} ({}-{:02})", v.year, v.month, v.year, v.month);
        tags.push(push_tag(719, "bootPatchLevel", json!(s)));
        fields.insert("bootPatchLevel".into(), json!(s));
    }
    if let Some(ref v) = al.attestation_id_brand { fields.insert("attestationIdBrand".into(), json!(v)); }
    if let Some(ref v) = al.attestation_id_device { fields.insert("attestationIdDevice".into(), json!(v)); }
    if let Some(ref v) = al.attestation_id_product { fields.insert("attestationIdProduct".into(), json!(v)); }
    if let Some(ref v) = al.attestation_id_manufacturer { fields.insert("attestationIdManufacturer".into(), json!(v)); }
    if let Some(ref v) = al.attestation_id_model { fields.insert("attestationIdModel".into(), json!(v)); }

    json!({
        "tagCount": tags.len(),
        "tags": tags,
        "fields": fields,
    })
}

// ── CLI argument parsing ───────────────────────────────────────────────────

/// Parsed command-line arguments for `parse_json`.
struct CliArgs {
    /// Path to the JSON input file, or None to read from stdin.
    input_file: Option<String>,
    /// Whether to fetch Google trust anchors and revocation list from the network.
    /// Defaults to true; use `--no-live` to disable.
    live: bool,
}

fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input_file: Option<String> = None;
    let mut no_live = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-live" => no_live = true,
            "--live" => no_live = false,
            "--help" | "-h" => {
                eprintln!("Usage: parse_json [OPTIONS] [INPUT]");
                eprintln!();
                eprintln!("Arguments:");
                eprintln!("  INPUT           JSON file path (reads stdin if omitted)");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --live          Fetch Google trust anchors & revocation list (default)");
                eprintln!("  --no-live       Use embedded trust anchors, skip revocation check");
                eprintln!("  -h, --help      Show this help message");
                std::process::exit(0);
            }
            s if !s.starts_with('-') => {
                input_file = Some(s.to_string());
            }
            other => {
                eprintln!("Unknown option: {other}");
                eprintln!("Use --help for usage information.");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    CliArgs {
        input_file,
        live: !no_live,
    }
}

// ── main ──────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_args();

    let json_str = if let Some(ref path) = cli.input_file {
        std::fs::read_to_string(path)?
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    };

    let v: Value = serde_json::from_str(&json_str)?;
    let alias = v["alias"].as_str().unwrap_or("unknown").to_string();
    let blob = v["certificateChainBlob"].as_str().ok_or("Missing certificateChainBlob")?;
    let challenge_b64 = v["challenge"].as_str().unwrap_or("");
    let challenge_bytes = if !challenge_b64.is_empty() {
        let pad_needed = (4 - challenge_b64.trim().trim_end_matches('=').len() % 4) % 4;
        let padded = format!("{}{}", challenge_b64.trim().trim_end_matches('='), "=".repeat(pad_needed));
        base64::engine::general_purpose::STANDARD.decode(&padded).ok()
    } else {
        None
    };

    let certs_der = decode_certificate_chain_blob(blob)?;
    let cert_path = KeyAttestationCertPath::from_der_blobs(certs_der.clone())?;

    // ── Resolve trust anchors and revocation list ──
    // Google trust anchor check is always enabled (both live and embedded).
    let check_google_root = true;
    // Revocation check requires network; only enabled when live fetch succeeds.
    let check_revocation: bool;
    let anchors: Vec<trust_anchors::TrustAnchor>;
    let revoked_serials: std::collections::HashSet<String>;

    if cli.live {
        eprintln!("[live] Fetching Google trust anchors and revocation status...");
        match trust_anchors::fetch_google_roots() {
            Ok(live_anchors) => {
                eprintln!("[live] Trust anchors fetched: {} roots", live_anchors.len());
                anchors = live_anchors;
            }
            Err(e) => {
                eprintln!("[live] Failed to fetch trust anchors: {e}");
                eprintln!("[live] Falling back to embedded trust anchors");
                anchors = trust_anchors::google_trust_anchors();
            }
        }
        match trust_anchors::fetch_revoked_serials() {
            Ok(serials) => {
                eprintln!("[live] Revocation list fetched: {} revoked serials", serials.len());
                revoked_serials = serials;
                check_revocation = true;
            }
            Err(e) => {
                eprintln!("[live] Failed to fetch revocation list: {e}");
                eprintln!("[live] Skipping revocation check");
                revoked_serials = std::collections::HashSet::new();
                check_revocation = false;
            }
        }
    } else {
        eprintln!("[offline] Using embedded trust anchors, no revocation check");
        anchors = trust_anchors::google_trust_anchors();
        revoked_serials = std::collections::HashSet::new();
        check_revocation = false;
    }

    // ── Validation errors ──
    let mut errors = Vec::new();
    let chain_len = cert_path.certificates_with_anchor.len();
    let now_ms = chrono::Utc::now().timestamp_millis();

    // Certificate validity check
    for (i, cert) in cert_path.certificates_with_anchor.iter().enumerate() {
        let tbs = &cert.parsed.tbs_certificate;
        let not_after_ms = tbs.validity.not_after.to_unix_duration().as_millis() as i64;
        let not_before_ms = tbs.validity.not_before.to_unix_duration().as_millis() as i64;

        if now_ms > not_after_ms {
            errors.push(json!({
                "type": "certificate_validity_failed",
                "message": format!("java.security.cert.CertificateExpiredException: NotAfter: {}", millis_to_iso(not_after_ms)),
                "certIndex": i,
                "serialNumber": serial_to_string(&tbs.serial_number),
                "serialNumberHex": cert.serial_number_hex(),
                "subjectDN": cert.subject_dn(),
                "issuerDN": cert.issuer_dn(),
                "certSha256": sha256_hex(&certs_der[i]),
                "spkiSha256": sha256_hex(&tbs.subject_public_key_info.to_der().unwrap_or_default()),
            }));
        } else if now_ms < not_before_ms {
            errors.push(json!({
                "type": "certificate_validity_failed",
                "message": format!("java.security.cert.CertificateNotYetValidException: NotBefore: {}", millis_to_iso(not_before_ms)),
                "certIndex": i,
                "serialNumber": serial_to_string(&tbs.serial_number),
                "serialNumberHex": cert.serial_number_hex(),
                "subjectDN": cert.subject_dn(),
                "issuerDN": cert.issuer_dn(),
                "certSha256": sha256_hex(&certs_der[i]),
                "spkiSha256": sha256_hex(&tbs.subject_public_key_info.to_der().unwrap_or_default()),
            }));
        }
    }

    // Google trust anchor check
    if check_google_root {
        let root = cert_path.certificates_with_anchor.last().unwrap();
        let is_software = trust_anchors::is_software_root(root);
        let root_in_anchors = anchors.iter().any(|a| a.cert.subject_der == root.subject_der);

        if is_software || !root_in_anchors {
            let root_idx = chain_len - 1;
            let root_tbs = &root.parsed.tbs_certificate;
            errors.push(json!({
                "type": "google_root_untrusted",
                "message": "attestation root is not in Google trust anchors",
                "certIndex": root_idx,
                "serialNumber": serial_to_string(&root_tbs.serial_number),
                "serialNumberHex": root.serial_number_hex(),
                "subjectDN": root.subject_dn(),
                "issuerDN": root.issuer_dn(),
                "certSha256": sha256_hex(&certs_der[root_idx]),
                "spkiSha256": sha256_hex(&root_tbs.subject_public_key_info.to_der().unwrap_or_default()),
            }));
        }
    }

    // Revocation check
    if check_revocation {
        for (i, cert) in cert_path.certificates_with_anchor.iter().enumerate() {
            let serial = cert.serial_number_hex();
            if revoked_serials.contains(&serial) {
                let tbs = &cert.parsed.tbs_certificate;
                errors.push(json!({
                    "type": "certificate_revoked",
                    "message": format!("Certificate with serial {} has been revoked by Google", serial),
                    "certIndex": i,
                    "serialNumber": serial_to_string(&tbs.serial_number),
                    "serialNumberHex": serial,
                    "subjectDN": cert.subject_dn(),
                    "issuerDN": cert.issuer_dn(),
                    "certSha256": sha256_hex(&certs_der[i]),
                    "spkiSha256": sha256_hex(&tbs.subject_public_key_info.to_der().unwrap_or_default()),
                }));
            }
        }
    }

    // Challenge mismatch check
    let (_actual_challenge_hex, _challenge_ok) = if let Some(ext_value) = cert_path.leaf_cert().get_extension_value(extension::KEY_DESCRIPTION_OID) {
        if let Ok(Some(kd)) = extension::KeyDescription::parse_from_der(&ext_value) {
            let actual = format!("0x{}", hex::encode(&kd.attestation_challenge));
            if let Some(ref expected) = challenge_bytes {
                if &kd.attestation_challenge != expected {
                    let expected_hex = format!("0x{}", hex::encode(expected));
                    errors.push(json!({
                        "type": "challenge_mismatch",
                        "message": format!("Challenge mismatch: expected {}, got {}", expected_hex, actual),
                        "expected": expected_hex,
                        "actual": actual,
                    }));
                    (actual, false)
                } else {
                    (actual, true)
                }
            } else {
                (actual, true)
            }
        } else {
            ("0x".into(), true)
        }
    } else {
        ("0x".into(), true)
    };

    let ok = errors.is_empty();

    // ── Certificate chain ──
    let chain_json: Vec<Value> = cert_path
        .certificates_with_anchor
        .iter()
        .enumerate()
        .map(|(i, c)| build_cert_json(c, &certs_der[i], i, chain_len))
        .collect();

    // ── Key Description ──
    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID);

    let (kd_json, sw_json, hw_json, boot_json) = if let Some(ext_bytes) = ext_value {
        if let Ok(Some(kd)) = extension::KeyDescription::parse_from_der(&ext_bytes) {
            let kd_j = json!({
                "attestationVersion": int_to_u64(&kd.attestation_version),
                "attestationSecurityLevel": format!("{}({})", sec_level_name(kd.attestation_security_level), kd.attestation_security_level as u64),
                "keymasterVersion": int_to_u64(&kd.key_mint_version),
                "keymasterSecurityLevel": format!("{}({})", sec_level_name(kd.key_mint_security_level), kd.key_mint_security_level as u64),
                "attestationChallenge": format!("0x{}", hex::encode(&kd.attestation_challenge)),
                "uniqueId": if kd.unique_id.is_empty() { "0x".into() } else { format!("0x{}", hex::encode(&kd.unique_id)) },
            });

            let sw_j = build_auth_list(&kd.software_enforced, "softwareEnforced");
            let hw_j = build_auth_list(&kd.hardware_enforced, "hardwareEnforced");

            let rot = kd.hardware_enforced.root_of_trust.as_ref();
            let boot_j = json!({
                "sourceList": "hardwareEnforced",
                "verifiedBootKeyHex": rot.map(|r| hex::encode(&r.verified_boot_key)).unwrap_or_default(),
                "deviceLocked": rot.map(|r| r.device_locked).unwrap_or(false),
                "verifiedBootState": rot.map(|r| r.verified_boot_state as u64).unwrap_or(2),
                "verifiedBootStateName": rot.map(|r| boot_state_name(r.verified_boot_state)).unwrap_or_else(|| "Unverified".into()),
                "verifiedBootHashHex": rot.and_then(|r| r.verified_boot_hash.as_ref()).map(hex::encode).unwrap_or_default(),
                "bootPatchLevel": kd.hardware_enforced.boot_patch_level.as_ref().map(|p| json!(format!("{}-{:02}", p.year, p.month))).unwrap_or(Value::Null),
            });

            (kd_j, sw_j, hw_j, boot_j)
        } else {
            (json!(null), json!(null), json!(null), json!(null))
        }
    } else {
        (json!(null), json!(null), json!(null), json!(null))
    };

    // ── Result (bootState summary) ──
    let result_json = boot_json.clone();

    // ── Assemble ──
    let output = json!([{
        "index": 0,
        "error": errors,
        "alias": alias,
        "ok": ok,
        "result": result_json,
        "fields": {
            "certificate": {
                "chainLength": chain_len,
                "attestationCertIndex": 0,
                "attestationSignerCertIndex": if chain_len > 1 { 1 } else { 0 },
                "rootCertIndex": chain_len - 1,
                "chain": chain_json,
                "checkValidityEnabled": true,
                "checkChainEnabled": true,
                "checkGoogleRootEnabled": check_google_root,
                "checkRevocationEnabled": check_revocation,
            },
            "keyDescription": kd_json,
            "softwareEnforced": sw_json,
            "hardwareEnforced": hw_json,
            "bootState": boot_json,
        }
    }]);

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
