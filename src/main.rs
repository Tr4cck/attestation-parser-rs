use attestation_parser_rs::{parse_keybox_xml, Keybox, Verifier};
use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") {
        print_usage(&args[0]);
        std::process::exit(0);
    }
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    let live_mode = args.iter().any(|a| a == "--live");
    let json_mode = args.iter().any(|a| a == "--json");

    let file_content: Option<String> = if args[1] == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Some(buf)
    } else if !path.is_dir() && path.exists() {
        Some(fs::read_to_string(path)?)
    } else if path.is_dir() {
        None
    } else {
        eprintln!("Error: file not found: {}", args[1]);
        std::process::exit(1);
    };

    // ── JSON attestation record ───────────────────────────────────────────
    if json_mode {
        let json_str = file_content.as_deref().unwrap_or("");
        if let Err(e) = attestation_parser_rs::parse_json::run(json_str, live_mode) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // Auto-detect input format
    if let Some(ref content) = file_content {
        // JSON auto-detection
        if content.trim_start().starts_with('{')
            && (content.contains("certificateChainBlob")
                || content.contains("\"alias\""))
        {
            if let Err(e) = attestation_parser_rs::parse_json::run(content, live_mode) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return Ok(());
        }

        // Keybox XML auto-detection
        if content.contains("<AndroidAttestation") {
            let keyboxes = match parse_keybox_xml(content) {
                Ok(kb) => kb,
                Err(e) => {
                    eprintln!("Error: Failed to parse keybox XML: {e}");
                    std::process::exit(1);
                }
            };
            dump_keybox(&keyboxes);
            return Ok(());
        }
    }

    // ── PEM chain verification (default for non-keybox, non-json input) ───
    let certs = if path.is_dir() {
        load_certs_from_dir(path)?
    } else {
        load_certs_from_pem_file_from_str(file_content.as_ref().unwrap())?
    };

    if certs.is_empty() {
        eprintln!("No certificates found");
        std::process::exit(1);
    }

    eprintln!("Loaded {} certificates from {}", certs.len(), args[1]);
    let instant = || chrono::Utc::now();
    let verifier = build_verifier(live_mode, instant);
    eprintln!("Verifying certificate chain...");
    let ok = verify_and_report(&verifier, &certs, "cert_chain");
    if !ok {
        std::process::exit(1);
    }

    Ok(())
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {prog} <input> [--live] [--json]");
    eprintln!();
    eprintln!("  input     PEM file / directory, keybox XML file, or JSON attestation record.");
    eprintln!("  --live    Fetch Google trust anchors and revocation status from the web.");
    eprintln!("  --json    Parse input as JSON attestation record (certificateChainBlob format).");
    eprintln!();
    eprintln!("Auto-detection by input content:");
    eprintln!("  - Starts with '{{' and contains 'certificateChainBlob' → JSON mode");
    eprintln!("  - Contains '<AndroidAttestation' → keybox dump mode");
    eprintln!("  - Otherwise → PEM chain verification mode");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Keybox dump — always succeeds, extracts every piece of information
// ═══════════════════════════════════════════════════════════════════════════

fn dump_keybox(keyboxes: &[Keybox]) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  Keybox Dump                                 ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Keyboxes: {}", keyboxes.len());
    println!(
        "  Total Keys: {}",
        keyboxes.iter().map(|kb| kb.keys.len()).sum::<usize>()
    );

    for (ki, keybox) in keyboxes.iter().enumerate() {
        println!();
        println!("┌── Keybox {} ─────────────────────────────────────", ki);
        println!("│  DeviceID: {}", keybox.device_id);
        println!("│  Keys: {}", keybox.keys.len());

        for (ji, key) in keybox.keys.iter().enumerate() {
            println!("│");
            println!("│  ┌── Key {} ──────────────────────────────────", ji);
            println!("│  │  Algorithm: {}", key.algorithm);
            println!(
                "│  │  PrivateKey: {} bytes PEM",
                key.private_key_pem.len()
            );

            dump_private_key_info(key);

            println!(
                "│  │  CertificateChain: {} certificates",
                key.certificates_pem.len()
            );

            for (ci, cert_pem) in key.certificates_pem.iter().enumerate() {
                println!("│  │");
                println!("│  │  ┌── Certificate {} ────────────────────", ci);
                dump_cert_info(cert_pem, "│  │  │");
                println!("│  │  └──────────────────────────────────────");
            }
            println!("│  └──────────────────────────────────────────");
        }
        println!("└──────────────────────────────────────────────");
    }
}

// ── ASN.1 helpers — reuses cert_chain::read_tl for consistent TLV parsing ──

/// Call cert_chain::read_tl and map back to (value_offset, value_length).
fn read_tl_value_offset(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    attestation_parser_rs::cert_chain::read_tl(data, pos)
        .map(|(_tag, len, hdr_len)| (pos + hdr_len, len))
}

/// Read first element's version byte from a SEQUENCE-like DER blob.
fn read_pkcs_version(der: &[u8], pos: usize) -> Option<u64> {
    let (content_start, _content_len) = read_tl_value_offset(der, pos)?;
    if content_start >= der.len() {
        return None;
    }
    if der[content_start] != 0x02 {
        return None;
    }
    let (int_start, int_len) = read_tl_value_offset(der, content_start)?;
    if int_start + int_len > der.len() || int_len == 0 {
        return None;
    }
    let mut val: u64 = 0;
    for &b in &der[int_start..int_start + int_len] {
        val = (val << 8) | b as u64;
    }
    Some(val)
}

fn dump_private_key_info(key: &attestation_parser_rs::KeyEntry) {
    let der = match key.private_key_der() {
        Ok(d) => d,
        Err(_) => {
            println!("│  │  PrivateKey DER: FAILED TO PARSE PEM");
            return;
        }
    };
    println!("│  │  PrivateKey DER: {} bytes", der.len());

    let version = match read_pkcs_version(&der, 0) {
        Some(v) => v,
        None => {
            println!("│  │  Key type: Unknown DER format");
            return;
        }
    };

    match version {
        1 => {
            println!("│  │  Key type: EC (SEC1 format)");
            let (content_start, _) = read_tl_value_offset(&der, 0).unwrap();
            let (int_start, int_len) = read_tl_value_offset(&der, content_start).unwrap();
            let pos = int_start + int_len;
            if pos < der.len() && der[pos] == 0x04 {
                if let Some((_scalar_start, scalar_len)) = read_tl_value_offset(&der, pos) {
                    println!(
                        "│  │  EC private key scalar: {} bytes ({} bits)",
                        scalar_len, scalar_len * 8
                    );
                }
            }
        }
        0 => {
            println!("│  │  Key type: RSA (PKCS#1 format)");
            let (content_start, _) = read_tl_value_offset(&der, 0).unwrap();
            let (int_start, int_len) = read_tl_value_offset(&der, content_start).unwrap();
            let pos = int_start + int_len;
            if pos < der.len() && der[pos] == 0x02 {
                if let Some((mod_start, mod_len)) = read_tl_value_offset(&der, pos) {
                    let actual_bits = if mod_len > 0
                        && mod_start < der.len()
                        && der[mod_start] == 0x00
                    {
                        mod_len.saturating_sub(1) * 8
                    } else {
                        mod_len * 8
                    };
                    println!("│  │  RSA modulus size: {} bits", actual_bits);
                }
            }
        }
        v => println!("│  │  Key type: Unknown PKCS version {v}"),
    }
}

fn dump_cert_info(pem_str: &str, indent: &str) {
    let der = match pem::parse(pem_str).map(|p| p.contents().to_vec()) {
        Ok(d) => d,
        Err(e) => {
            println!("{indent}  PEM parse error: {e}");
            return;
        }
    };

    match attestation_parser_rs::Cert::from_der(&der) {
        Ok(cert) => {
            let sig_oid = cert.parsed.signature_algorithm.oid.to_string();
            let sig_name = attestation_parser_rs::cert_chain::sig_alg_name(&sig_oid);

            println!("{indent}  Subject:    {}", cert.subject_dn());
            println!("{indent}  Issuer:     {}", cert.issuer_dn());
            println!("{indent}  Serial:     {}", cert.serial_number_hex());
            println!("{indent}  SigAlg:     {} ({})", sig_name, sig_oid);
            println!("{indent}  Self-signed: {}", cert.is_self_issued());
            println!(
                "{indent}  Attestation ext: {}",
                cert.has_attestation_extension()
            );

            let v = &cert.parsed.tbs_certificate.validity;
            println!("{indent}  NotBefore:  {}", v.not_before);
            println!("{indent}  NotAfter:   {}", v.not_after);

            let spki = &cert.parsed.tbs_certificate.subject_public_key_info;
            println!("{indent}  SPKI alg:   {}", spki.algorithm.oid);

            if cert.has_attestation_extension() {
                if let Some(ext_bytes) = cert.get_extension_value(
                    attestation_parser_rs::extension::KEY_DESCRIPTION_OID,
                ) {
                    if let Ok(Some(kd)) =
                        attestation_parser_rs::extension::KeyDescription::parse_from_der(
                            &ext_bytes,
                        )
                    {
                        println!(
                            "{indent}  Attestation version: {:?}",
                            kd.attestation_version
                        );
                        println!(
                            "{indent}  Attestation sec level: {:?}",
                            kd.attestation_security_level
                        );
                        println!(
                            "{indent}  KeyMint version: {:?}",
                            kd.key_mint_version
                        );
                        println!(
                            "{indent}  KeyMint sec level: {:?}",
                            kd.key_mint_security_level
                        );
                        if let Some(ref rot) = kd.hardware_enforced.root_of_trust {
                            println!("{indent}  Device locked: {}", rot.device_locked);
                            println!(
                                "{indent}  Verified boot state: {:?}",
                                rot.verified_boot_state
                            );
                        }
                        let device_id =
                            attestation_parser_rs::extension::DeviceIdentity::parse_from(&kd);
                        if let Some(brand) = &device_id.brand {
                            println!("{indent}  Brand:      {brand}");
                        }
                        if let Some(model) = &device_id.model {
                            println!("{indent}  Model:      {model}");
                        }
                        if let Some(manufacturer) = &device_id.manufacturer {
                            println!("{indent}  Manufacturer: {manufacturer}");
                        }
                        if let Some(serial) = &device_id.serial_number {
                            println!("{indent}  Serial:     {serial}");
                        }
                        for imei in &device_id.imeis {
                            println!("{indent}  IMEI:       {imei}");
                        }
                        if let Some(meid) = &device_id.meid {
                            println!("{indent}  MEID:       {meid}");
                        }
                    } else {
                        println!("{indent}  Attestation ext: (failed to parse)");
                    }
                }
            }
        }
        Err(e) => {
            println!("{indent}  Cert parse error: {e}");
            dump_raw_der_info(&der, indent);
        }
    }
}

fn dump_raw_der_info(der: &[u8], indent: &str) {
    let sha256 = attestation_parser_rs::cert_chain::sha256_hex(der);
    println!("{indent}  SHA-256: {sha256}");
    println!("{indent}  DER bytes: {}", der.len());
}

// ═══════════════════════════════════════════════════════════════════════════
//  Shared helpers
// ═══════════════════════════════════════════════════════════════════════════

fn build_verifier(
    live_mode: bool,
    instant: fn() -> chrono::DateTime<chrono::Utc>,
) -> Verifier<fn() -> chrono::DateTime<chrono::Utc>> {
    let mut verifier_opt: Option<Verifier<_>> = if live_mode {
        eprintln!("Fetching Google trust anchors and revocation status...");
        match Verifier::google_live(instant) {
            Ok(v) => {
                eprintln!("  Trust anchors and revocation list fetched successfully");
                eprintln!("  Data saved to cache for future offline verification");
                Some(v)
            }
            Err(e) => {
                eprintln!("ERROR: Failed to fetch live data: {e}");
                eprintln!("Falling back to local cache...");
                None
            }
        }
    } else {
        None
    };
    verifier_opt.take().unwrap_or_else(|| {
        eprintln!("Loading attestation data from local cache...");
        Verifier::google_cached(instant)
    })
}

fn verify_and_report(
    verifier: &Verifier<fn() -> chrono::DateTime<chrono::Utc>>,
    certs: &[Vec<u8>],
    label: &str,
) -> bool {
    let result = verifier.verify(certs, None);

    match result {
        attestation_parser_rs::VerificationResult::Success {
            security_level,
            verified_boot_state,
            device_locked,
            attested_device_ids,
            ..
        } => {
            println!("  Verification successful ({label})");
            println!("    Security level: {:?}", security_level);
            println!("    Verified boot state: {:?}", verified_boot_state);
            println!("    Device locked: {}", device_locked);
            if let Some(brand) = &attested_device_ids.brand {
                println!("    Brand: {brand}");
            }
            if let Some(model) = &attested_device_ids.model {
                println!("    Model: {model}");
            }
            if let Some(manufacturer) = &attested_device_ids.manufacturer {
                println!("    Manufacturer: {manufacturer}");
            }
            true
        }
        other => {
            eprintln!("  Verification failed ({label}): {other:?}");
            match other {
                attestation_parser_rs::VerificationResult::PathValidationFailure {
                    ref message,
                } => {
                    if message.contains("No matching trust anchor") {
                        eprintln!("  => Not signed by Google trust anchor.");
                    } else if message.contains("revoked") {
                        eprintln!("  => Certificates have been revoked by Google.");
                    } else if message.contains("Signature") {
                        eprintln!(
                            "  => Signature verification failed — chain is tampered or untrusted."
                        );
                    }
                }
                attestation_parser_rs::VerificationResult::ChainParsingFailure { .. } => {
                    eprintln!("  => Certificate chain is malformed.");
                }
                attestation_parser_rs::VerificationResult::ExtensionParsingFailure { .. } => {
                    eprintln!("  => Key attestation extension missing or unparseable.");
                }
                _ => {}
            }
            false
        }
    }
}

// ── PEM helpers ──────────────────────────────────────────────────────────

fn load_certs_from_dir(dir: &Path) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut certs = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "pem")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let pem_content = fs::read_to_string(entry.path())?;
        let cert = parse_pem(&pem_content)?;
        certs.push(cert);
    }

    Ok(certs)
}

fn load_certs_from_pem_file_from_str(
    pem_content: &str,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut certs = Vec::new();
    for pem_block in pem::parse_many(pem_content)? {
        certs.push(pem_block.contents().to_vec());
    }
    Ok(certs)
}

fn parse_pem(pem_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pem = pem::parse(pem_str)?;
    Ok(pem.contents().to_vec())
}