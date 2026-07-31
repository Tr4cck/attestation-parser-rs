//! Parse and process an Android Key Attestation JSON record.
//!
//! Input format:
//! ```json
//! { "alias": "...", "certificateChainBlob": "<base64>", "challenge": "<base64>" }
//! ```

use crate::cert_chain;
use crate::extension;
use crate::trust_anchors;
use crate::Cert;
use crate::KeyAttestationCertPath;
use base64::Engine;
use der::Encode;
use serde_json::{json, Value};

// ── Public entry point ────────────────────────────────────────────────────

/// Parse and validate a JSON attestation record. Prints the output as pretty
/// JSON to stdout. Returns Ok(()) on success, or an error on parse failure.
pub fn run(json_str: &str, live_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let v: Value = serde_json::from_str(json_str)?;
    let alias = v["alias"].as_str().unwrap_or("unknown").to_string();
    let blob = v["certificateChainBlob"]
        .as_str()
        .ok_or("Missing certificateChainBlob")?;
    let challenge_b64 = v["challenge"].as_str().unwrap_or("");
    let challenge_bytes = if !challenge_b64.is_empty() {
        let pad_needed =
            (4 - challenge_b64.trim().trim_end_matches('=').len() % 4) % 4;
        let padded = format!(
            "{}{}",
            challenge_b64.trim().trim_end_matches('='),
            "=".repeat(pad_needed)
        );
        base64::engine::general_purpose::STANDARD
            .decode(&padded)
            .ok()
    } else {
        None
    };

    let certs_der = decode_certificate_chain_blob(blob)?;
    let cert_path = KeyAttestationCertPath::from_der_blobs(certs_der.clone())?;

    // ── Resolve trust anchors and revocation list ──
    let check_google_root = true;
    let (anchors, revoked_serials, check_revocation) =
        resolve_anchors_and_revocation(live_mode);

    // ── Build errors ──
    let mut errors = Vec::new();
    let chain_len = cert_path.certificates_with_anchor.len();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let known_fingerprints = trust_anchors::embedded_root_sha256s();

    // Certificate validity
    build_validity_errors(&cert_path, &certs_der, now_ms, &mut errors);

    // Google trust anchor check
    if check_google_root {
        build_anchor_errors(&cert_path, &certs_der, &anchors, &known_fingerprints, &mut errors);
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
                    "certSha256": cert_chain::sha256_hex(&certs_der[i]),
                    "spkiSha256": cert_chain::sha256_hex(&tbs.subject_public_key_info.to_der().unwrap_or_default()),
                }));
            }
        }
    }

    // Challenge mismatch
    let _ = build_challenge_error(&cert_path, challenge_bytes.as_deref(), &mut errors);

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
    let (kd_json, sw_json, hw_json, boot_json) =
        build_key_description_json(&ext_value);

    let result_json = boot_json.clone();

    // ── Assemble output ──
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

// ── Internal helpers ──────────────────────────────────────────────────────

fn resolve_anchors_and_revocation(
    live_mode: bool,
) -> (
    Vec<trust_anchors::TrustAnchor>,
    std::collections::HashSet<String>,
    bool,
) {
    if live_mode {
        eprintln!("[live] Fetching Google trust anchors and revocation status...");
        let anchors = match trust_anchors::fetch_google_roots() {
            Ok(a) => {
                eprintln!("[live] Trust anchors fetched: {} roots", a.len());
                a
            }
            Err(e) => {
                eprintln!("[live] Failed to fetch trust anchors: {e}");
                eprintln!("[live] Falling back to embedded trust anchors");
                trust_anchors::google_trust_anchors()
            }
        };
        let (revoked, check_rev) = match trust_anchors::fetch_revoked_serials() {
            Ok(serials) => {
                eprintln!(
                    "[live] Revocation list fetched: {} revoked serials",
                    serials.len()
                );
                if let Err(e) = crate::cache::save_cache(&anchors, &serials) {
                    eprintln!("[live] Warning: failed to save attestation cache: {e}");
                }
                (serials, true)
            }
            Err(e) => {
                eprintln!("[live] Failed to fetch revocation list: {e}");
                (std::collections::HashSet::new(), false)
            }
        };
        (anchors, revoked, check_rev)
    } else {
        match crate::cache::load_cache() {
            Some((anchors, revoked)) => {
                eprintln!(
                    "[offline] Loaded {} roots and {} revoked serials from cache",
                    anchors.len(),
                    revoked.len()
                );
                (anchors, revoked, true)
            }
            None => {
                eprintln!("[offline] No cache found, using embedded trust anchors");
                (
                    trust_anchors::google_trust_anchors(),
                    std::collections::HashSet::new(),
                    false,
                )
            }
        }
    }
}

fn build_validity_errors(
    cert_path: &KeyAttestationCertPath,
    certs_der: &[Vec<u8>],
    now_ms: i64,
    errors: &mut Vec<Value>,
) {
    for (i, cert) in cert_path.certificates_with_anchor.iter().enumerate() {
        let tbs = &cert.parsed.tbs_certificate;
        let not_after = tbs.validity.not_after.to_unix_duration().as_millis() as i64;
        let not_before = tbs.validity.not_before.to_unix_duration().as_millis() as i64;
        let spki_der = tbs.subject_public_key_info.to_der().unwrap_or_default();

        if now_ms > not_after || now_ms < not_before {
            errors.push(json!({
                "type": "certificate_validity_failed",
                "message": if now_ms > not_after {
                    format!("NotAfter: {}", millis_to_iso(not_after))
                } else {
                    format!("NotYetValid: NotBefore: {}", millis_to_iso(not_before))
                },
                "certIndex": i,
                "serialNumber": serial_to_string(&tbs.serial_number),
                "serialNumberHex": cert.serial_number_hex(),
                "subjectDN": cert.subject_dn(),
                "issuerDN": cert.issuer_dn(),
                "certSha256": cert_chain::sha256_hex(&certs_der[i]),
                "spkiSha256": cert_chain::sha256_hex(&spki_der),
            }));
        }
    }
}

fn build_anchor_errors(
    cert_path: &KeyAttestationCertPath,
    certs_der: &[Vec<u8>],
    anchors: &[trust_anchors::TrustAnchor],
    known_fingerprints: &std::collections::HashSet<String>,
    errors: &mut Vec<Value>,
) {
    let chain_len = cert_path.certificates_with_anchor.len();
    let root = cert_path.certificates_with_anchor.last().unwrap();
    let root_idx = chain_len - 1;
    let root_tbs = &root.parsed.tbs_certificate;
    let root_sha256 = cert_chain::sha256_hex(&certs_der[root_idx]);
    let root_spki_sha = cert_chain::sha256_hex(
        &root_tbs.subject_public_key_info.to_der().unwrap_or_default(),
    );
    let is_software = trust_anchors::is_software_root(root);

    let root_in_anchors = anchors
        .iter()
        .any(|a| a.cert.subject_der == root.subject_der)
        && !is_software;

    if !root_in_anchors {
        errors.push(json!({
            "type": "google_root_untrusted",
            "message": "attestation root is not in Google trust anchors",
            "certIndex": root_idx,
            "serialNumber": serial_to_string(&root_tbs.serial_number),
            "serialNumberHex": root.serial_number_hex(),
            "subjectDN": root.subject_dn(),
            "issuerDN": root.issuer_dn(),
            "certSha256": root_sha256,
            "spkiSha256": root_spki_sha,
        }));
    } else if !known_fingerprints.contains(&root_sha256) {
        errors.push(json!({
            "type": "google_root_fingerprint_unknown",
            "message": format!(
                "attestation root SHA-256 {} does not match any known Google root fingerprint ({})",
                root_sha256, known_fingerprints.len()
            ),
            "certIndex": root_idx,
            "serialNumber": serial_to_string(&root_tbs.serial_number),
            "serialNumberHex": root.serial_number_hex(),
            "subjectDN": root.subject_dn(),
            "issuerDN": root.issuer_dn(),
            "certSha256": root_sha256,
            "spkiSha256": root_spki_sha,
        }));
    }
}

fn build_challenge_error(
    cert_path: &KeyAttestationCertPath,
    challenge_bytes: Option<&[u8]>,
    errors: &mut Vec<Value>,
) {
    let expected = match challenge_bytes {
        Some(b) => b,
        None => return,
    };
    let ext_value = cert_path
        .leaf_cert()
        .get_extension_value(extension::KEY_DESCRIPTION_OID);
    let ext_bytes = match ext_value {
        Some(b) => b,
        None => return,
    };
    let kd = match extension::KeyDescription::parse_from_der(&ext_bytes) {
        Ok(Some(kd)) => kd,
        _ => return,
    };

    if kd.attestation_challenge != expected {
        let actual = format!("0x{}", hex::encode(&kd.attestation_challenge));
        let expected_hex = format!("0x{}", hex::encode(expected));
        errors.push(json!({
            "type": "challenge_mismatch",
            "message": format!("Challenge mismatch: expected {}, got {}", expected_hex, actual),
            "expected": expected_hex,
            "actual": actual,
        }));
    }
}

fn build_key_description_json(ext_value: &Option<Vec<u8>>) -> (Value, Value, Value, Value) {
    let ext_bytes = match ext_value {
        Some(b) => b,
        None => return (json!(null), json!(null), json!(null), json!(null)),
    };
    let kd = match extension::KeyDescription::parse_from_der(ext_bytes) {
        Ok(Some(kd)) => kd,
        _ => return (json!(null), json!(null), json!(null), json!(null)),
    };

    let kd_j = json!({
        "attestationVersion": int_to_u64(&kd.attestation_version),
        "attestationSecurityLevel": format!("{}({})", sec_level_name(kd.attestation_security_level), kd.attestation_security_level as u64),
        "keymasterVersion": int_to_u64(&kd.key_mint_version),
        "keymasterSecurityLevel": format!("{}({})", sec_level_name(kd.key_mint_security_level), kd.key_mint_security_level as u64),
        "attestationChallenge": format!("0x{}", hex::encode(&kd.attestation_challenge)),
        "uniqueId": if kd.unique_id.is_empty() { "0x".into() } else { format!("0x{}", hex::encode(&kd.unique_id)) },
    });

    let sw_j = build_auth_list(&kd.software_enforced);
    let hw_j = build_auth_list(&kd.hardware_enforced);

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
}

// ── certificateChainBlob decoder ──────────────────────────────────────────

fn decode_certificate_chain_blob(blob: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let b64_trimmed = blob.trim().trim_end_matches('=');
    let pad_needed = (4 - b64_trimmed.len() % 4) % 4;
    let b64_padded = format!("{}{}", b64_trimmed, "=".repeat(pad_needed));
    let raw = base64::engine::general_purpose::STANDARD.decode(&b64_padded)?;
    if raw.is_empty() || raw[0] != 0x30 {
        return Err("Expected DER SEQUENCE tag (0x30)".into());
    }
    let (outer_len, outer_header) = read_tl_value_offset(&raw, 0)?;
    let inner = &raw[outer_header..outer_header + outer_len];
    let mut certs = Vec::new();
    let mut pos = 0;
    while pos < inner.len() {
        if inner[pos] != 0x30 {
            return Err(
                format!("Expected cert SEQUENCE at offset {pos}, got 0x{:02x}", inner[pos])
                    .into(),
            );
        }
        let (clen, chdr) = read_tl_value_offset(inner, pos)?;
        let total = chdr + clen;
        certs.push(inner[pos..pos + total].to_vec());
        pos += total;
    }
    certs.reverse(); // root-first → leaf-first
    Ok(certs)
}

/// Call cert_chain::read_tl and map to (value_length, header_length).
fn read_tl_value_offset(data: &[u8], pos: usize) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    cert_chain::read_tl(data, pos)
        .ok_or_else(|| "Unexpected end of DER".into())
        .map(|(_tag, len, hdr)| (len, hdr))
}

// ── Display helpers ───────────────────────────────────────────────────────

fn int_to_u64(val: &der::asn1::Int) -> u64 {
    val.as_bytes()
        .iter()
        .fold(0u64, |a, &b| (a << 8) | b as u64)
}

fn serial_to_string(sn: &x509_cert::serial_number::SerialNumber) -> String {
    let bytes = sn.as_bytes();
    if bytes.is_empty() {
        return "0".into();
    }
    if bytes.len() > 16 {
        return format!("0x{}", hex::encode(bytes));
    }
    let value = bytes.iter().fold(0u128, |a, &b| (a << 8) | b as u128);
    value.to_string()
}

fn millis_to_iso(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| format!("{millis}"))
}

fn purpose_name(v: u64) -> String {
    match v {
        0 => "Encrypt", 1 => "Decrypt", 2 => "Sign", 3 => "Verify",
        4 => "DeriveKey", 5 => "WrapKey", 6 => "AgreeKey", _ => "Unknown",
    }.into()
}
fn algorithm_name(v: u64) -> String {
    match v { 1=>"RSA",2=>"AES",3=>"EC",4=>"HMAC",5=>"3DES",32=>"ML-DSA",_=>"Unknown" }.into()
}
fn digest_name(v: u64) -> String {
    match v { 0=>"NONE",1=>"MD5",2=>"SHA1",3=>"SHA2_224",4=>"SHA2_256",5=>"SHA2_384",6=>"SHA2_512",_=>"Unknown" }.into()
}
fn ec_curve_name(v: u64) -> String {
    match v { 1=>"P_256",2=>"P_384",3=>"P_521",4=>"P_224",_=>"Unknown" }.into()
}
fn origin_name(o: &extension::Origin) -> String {
    match o { extension::Origin::Generated=>"Generated",extension::Origin::Derived=>"Derived",extension::Origin::Imported=>"Imported",extension::Origin::Reserved=>"Reserved",extension::Origin::SecurelyImported=>"SecurelyImported" }.into()
}
fn boot_state_name(s: extension::VerifiedBootState) -> String {
    match s { extension::VerifiedBootState::Verified=>"Verified",extension::VerifiedBootState::SelfSigned=>"SelfSigned",extension::VerifiedBootState::Unverified=>"Unverified",extension::VerifiedBootState::Failed=>"Failed" }.into()
}
fn sec_level_name(s: extension::SecurityLevel) -> String {
    match s { extension::SecurityLevel::Software=>"Software",extension::SecurityLevel::TrustedEnvironment=>"TrustedEnvironment",extension::SecurityLevel::StrongBox=>"StrongBox" }.into()
}

// ── JSON builders ─────────────────────────────────────────────────────────

fn build_cert_json(cert: &Cert, der_bytes: &[u8], index: usize, chain_len: usize) -> Value {
    let tbs = &cert.parsed.tbs_certificate;
    let role = match index {
        0 => "attestation",
        n if n == chain_len - 1 => "root",
        _ => "attestationSigner",
    };

    let not_before_ms = tbs.validity.not_before.to_unix_duration().as_millis() as i64;
    let not_after_ms = tbs.validity.not_after.to_unix_duration().as_millis() as i64;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let expired = now_ms > not_after_ms;

    let sig_oid = cert.parsed.signature_algorithm.oid.to_string();

    let pk_alg_oid = tbs.subject_public_key_info.algorithm.oid.to_string();
    let pk_alg = match pk_alg_oid.as_str() {
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.113549.1.1.1" => "RSA",
        _ => "Unknown",
    };

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
                "2.5.29.19" => {
                    basic_constraints_val =
                        cert_chain::parse_basic_constraints(ext.extn_value.as_bytes());
                }
                "2.5.29.15" => {
                    key_usage_bits =
                        cert_chain::parse_key_usage(ext.extn_value.as_bytes());
                }
                "1.3.6.1.4.1.11129.2.1.17" => has_ka = true,
                "1.3.6.1.4.1.11129.2.1.30" => has_pi = true,
                _ => {}
            }
        }
    }

    let cert_sha = cert_chain::sha256_hex(der_bytes);
    let spki_der = tbs.subject_public_key_info.to_der().unwrap_or_default();
    let spki_sha = cert_chain::sha256_hex(&spki_der);

    json!({
        "index": index,
        "role": role,
        "type": "X.509",
        "version": 3,
        "subjectDN": cert.subject_dn(),
        "issuerDN": cert.issuer_dn(),
        "serialNumber": serial_to_string(&tbs.serial_number),
        "serialNumberHex": cert.serial_number_hex(),
        "notBefore": format!("{} ({})", not_before_ms, millis_to_iso(not_before_ms)),
        "notAfter": format!("{} ({})", not_after_ms, millis_to_iso(not_after_ms)),
        "expired": expired,
        "signatureAlgorithm": sig_alg_oid_name(&sig_oid),
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

fn sig_alg_oid_name(oid: &str) -> String {
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

fn build_auth_list(al: &extension::AuthorizationList) -> Value {
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
        tags.push(push_tag(3, "keySize", json!(n.to_string())));
        fields.insert("keySize".into(), json!(n.to_string()));
    }
    if let Some(ref v) = al.block_modes {
        let nums: Vec<u64> = v.iter().map(int_to_u64).collect();
        tags.push(push_tag(4, "blockMode", json!(format!("{:?}", nums))));
        fields.insert("blockMode".into(), json!(format!("{:?}", nums)));
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
        tags.push(push_tag(6, "padding", json!(format!("{:?}", nums))));
        fields.insert("padding".into(), json!(format!("{:?}", nums)));
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
        tags.push(push_tag(701, "creationDateTime", json!(format!("{} ({})", ms, millis_to_iso(ms)))));
        fields.insert("creationDateTime".into(), json!(format!("{} ({})", ms, millis_to_iso(ms))));
    }
    if let Some(ref v) = al.origin {
        let n = *v as u64;
        let s = format!("{}({})", origin_name(v), n);
        tags.push(push_tag(702, "origin", json!(s)));
        fields.insert("origin".into(), json!(s));
    }
    if let Some(ref v) = al.root_of_trust {
        let key_hex = hex::encode(&v.verified_boot_key);
        let bs_name = boot_state_name(v.verified_boot_state);
        let bs_val = v.verified_boot_state as u64;
        let val = format!("{{verifiedBootKey=0x{}, deviceLocked={}, verifiedBootState={}({})}}", key_hex, v.device_locked, bs_name, bs_val);
        tags.push(push_tag(704, "rootOfTrust", json!(val)));
        fields.insert("rootOfTrust".into(), json!(val));
        fields.insert("verifiedBootKey".into(), json!(format!("0x{}", key_hex)));
        fields.insert("deviceLocked".into(), json!(v.device_locked));
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

fn int_to_i64(val: &der::asn1::Int) -> i64 {
    let bytes = val.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    if bytes[0] & 0x80 != 0 {
        bytes.iter().fold(0i64, |a, &b| (a << 8) | b as i64)
    } else {
        int_to_u64(val) as i64
    }
}

fn os_version_decode(v: u64) -> String {
    let major = (v / 10000) as u32;
    let minor = ((v % 10000) / 100) as u32;
    let patch = (v % 100) as u32;
    format!("{major}.{minor}.{patch}")
}