use attestation_parser_rs::Verifier;
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <cert_chain.pem> [--live]", args[0]);
        eprintln!();
        eprintln!("  cert_chain.pem  A PEM file containing the certificate chain (leaf first, root last)");
        eprintln!("  --live          Fetch Google trust anchors and revocation status from the web");
        eprintln!();
        eprintln!("Verification performs three mandatory checks:");
        eprintln!("  1. Certificate chain validation (signatures, name chaining, expiry)");
        eprintln!("  2. Google trust anchor check (root must be signed by Google)");
        eprintln!("  3. Revocation check (serial numbers must not appear in revocation list)");
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    let live_mode = args.iter().any(|a| a == "--live");

    let certs = if path.is_dir() {
        load_certs_from_dir(path)?
    } else {
        load_certs_from_pem_file(path)?
    };

    if certs.is_empty() {
        eprintln!("No certificates found");
        std::process::exit(1);
    }

    eprintln!("Loaded {} certificates from {}", certs.len(), args[1]);

    let instant = || chrono::Utc::now();

    let mut verifier_opt: Option<Verifier<_>> = if live_mode {
        eprintln!("Fetching Google trust anchors and revocation status...");
        match Verifier::google_live(instant) {
            Ok(v) => {
                eprintln!("  Trust anchors and revocation list fetched successfully");
                Some(v)
            }
            Err(e) => {
                eprintln!("ERROR: Failed to initialize verifier: {e}");
                eprintln!("Falling back to embedded trust anchors (no revocation list)");
                None
            }
        }
    } else {
        None
    };
    let verifier = verifier_opt.take().unwrap_or_else(|| Verifier::google(instant));

    eprintln!("Verifying certificate chain...");
    let result = verifier.verify(&certs, None);

    match result {
        attestation_parser_rs::VerificationResult::Success {
            security_level,
            verified_boot_state,
            device_locked,
            attested_device_ids,
            ..
        } => {
            println!("Verification successful");
            println!("  Security level: {:?}", security_level);
            println!("  Verified boot state: {:?}", verified_boot_state);
            println!("  Device locked: {}", device_locked);
            if let Some(brand) = &attested_device_ids.brand {
                println!("  Brand: {brand}");
            }
            if let Some(model) = &attested_device_ids.model {
                println!("  Model: {model}");
            }
            if let Some(manufacturer) = &attested_device_ids.manufacturer {
                println!("  Manufacturer: {manufacturer}");
            }
        }
        other => {
            eprintln!("Verification failed: {other:?}");
            eprintln!();
            match other {
                attestation_parser_rs::VerificationResult::PathValidationFailure { ref message } => {
                    if message.contains("No matching trust anchor") {
                        eprintln!("=> The certificate chain does not trace to a Google trust anchor.");
                        eprintln!("   This may indicate a non-Google signed certificate or tampering.");
                    } else if message.contains("revoked") {
                        eprintln!("=> One or more certificates in the chain have been revoked by Google.");
                    } else if message.contains("Signature") {
                        eprintln!("=> Certificate signature verification failed.");
                        eprintln!("   The chain may be tampered with or signed by an untrusted key.");
                    }
                }
                attestation_parser_rs::VerificationResult::ChainParsingFailure { .. } => {
                    eprintln!("=> The certificate chain is malformed or incomplete.");
                }
                attestation_parser_rs::VerificationResult::ExtensionParsingFailure { .. } => {
                    eprintln!("=> The key attestation extension is missing or unparseable.");
                }
                _ => {}
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

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

fn load_certs_from_pem_file(path: &Path) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let pem_content = fs::read_to_string(path)?;
    let mut certs = Vec::new();

    for pem_block in pem::parse_many(&pem_content)? {
        certs.push(pem_block.contents().to_vec());
    }

    Ok(certs)
}

fn parse_pem(pem_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pem = pem::parse(pem_str)?;
    Ok(pem.contents().to_vec())
}
