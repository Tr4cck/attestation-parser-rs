# attestation-parser-rs

A strict Rust parser and verifier for [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) certificate chains.

## Overview

Android Key Attestation proves that a cryptographic key was generated inside a hardware-backed keystore (TEE or StrongBox). The attestation is delivered as an X.509 certificate chain whose leaf certificate contains a [KeyDescription](https://source.android.com/docs/security/features/keystore/attestation) extension (OID `1.3.6.1.4.1.11129.2.1.17`) with hardware-enforced and software-enforced authorization lists.

This crate:

- **Parses** the full KeyDescription extension, including all KeyMint/Keymaster tags (purposes, algorithm, root of trust, device identity, patch levels, etc.)
- **Parses** keybox XML provisioning files and extracts all keys, certificates, and private key metadata
- **Validates** the certificate chain: signature verification, name chaining, expiry, extension expectations
- **Checks** against Google's production trust anchors (embedded or fetched live)
- **Checks** Google's revocation list (fetched live and cached locally for offline use)
- **Rejects** software attestation roots — only hardware-backed chains are accepted by the strict verifier
- **Supports** both factory-provisioned and remotely-provisioned (RKP) chains

## Quick Start

### CLI

A single binary handles all input formats with auto-detection:

```bash
# PEM chain verification (offline, using cached revocation data)
cargo run -- cert_chain.pem

# Fetch latest trust anchors & revocation list from Google, then verify
cargo run -- cert_chain.pem --live

# Keybox XML dump — extracts all keys, certificates, and metadata
cargo run -- keybox.xml

# JSON attestation record (auto-detected)
cargo run -- attestation.json

# Or pipe stdin:
cat attestation.json | cargo run -- --json -
```

**Auto-detection rules:**

| Input content | Mode |
|---------------|------|
| Contains `<AndroidAttestation` | Keybox dump |
| Starts with `{` and contains `certificateChainBlob` | JSON attestation record |
| Everything else | PEM chain verification |

Use `--json` to force JSON mode when auto-detection fails.

**Cache behavior:**

- `--live` fetches fresh data from Google and saves it to `~/.cache/attestation-parser-rs/attestation_cache.json`
- Without `--live`, the verifier loads from the cache (full revocation checking, no network)
- If no cache exists yet, it falls back to embedded trust anchors and prints a hint to run `--live` first

### JSON attestation record

The JSON format matches the output of Android Keystore's `getCertificateChain()` and `getAttestationChallenge()`:

```json
{
  "alias": "my_key_alias",
  "certificateChainBlob": "<base64-encoded DER certificate chain>",
  "challenge": "<base64-encoded challenge>"
}
```

> **Note:** The `certificateChainBlob` from the Android Keystore API wraps all certificates in an outer DER SEQUENCE, ordered root-first. The parser automatically extracts and reorders them to leaf-first. Base64 padding is normalized automatically.

The output includes:

- **Validation errors** — certificate expiry, trust anchor checks, revocation checks
- **Certificate chain details** — subject/issuer DN, serial number, key usage, basic constraints, SHA-256 fingerprints
- **KeyDescription** — attestation version, security level, challenge
- **Authorization lists** — software-enforced and hardware-enforced tags with per-tag rendering
- **Boot state** — verified boot key, device lock status, boot state

Serial numbers are displayed as unsigned decimal. `basicConstraints` uses Java-compatible values: `2147483647` (Integer.MAX_VALUE) for CA:true without pathLen, `-1` for non-CA.

### Keybox XML dump

The Android Attestation Keybox format is a provisioning file used by device manufacturers. The tool extracts:

- **Device ID** — the `DeviceID` attribute from the `<Keybox>` element
- **Private keys** — algorithm, key type (EC/RSA), key size (EC scalar / RSA modulus)
- **Certificate chains** — subject, issuer, serial number, signature algorithm, validity dates, SPKI algorithm
- **Attestation extension** — if present on leaf certificates, full KeyDescription data including device identity (brand, model, IMEI, etc.)

Keybox dump mode does not verify — it always succeeds and prints everything. Use the PEM verification path for validation.

### As a library

```rust
use attestation_parser_rs::{Verifier, VerificationResult, KeyAttestationCertPath, extension};

// Load DER-encoded certificates (leaf first, root last)
let certs: Vec<Vec<u8>> = /* ... */;

// Strict verification using cached revocation data (offline-safe)
let verifier = Verifier::google_cached(|| chrono::Utc::now());

// Or fetch live data (requires network, saves to cache)
// let verifier = Verifier::google_live(|| chrono::Utc::now())?;

// Or use embedded trust anchors only (no revocation checking)
// let verifier = Verifier::google(|| chrono::Utc::now());

let result = verifier.verify(&certs, Some(&expected_challenge));

match result {
    VerificationResult::Success {
        security_level,
        verified_boot_state,
        device_locked,
        attested_device_ids,
        ..
    } => {
        println!("Security level: {:?}", security_level);
        println!("Boot state: {:?}", verified_boot_state);
    }
    VerificationResult::PathValidationFailure { message } => {
        eprintln!("Validation failed: {message}");
    }
    other => eprintln!("Result: {other:?}"),
}
```

#### Parsing the KeyDescription extension without verification

```rust
let cert_path = KeyAttestationCertPath::from_der_blobs(certs)?;

let ext_value = cert_path
    .leaf_cert()
    .get_extension_value(extension::KEY_DESCRIPTION_OID)
    .expect("extension not found");

let kd = extension::KeyDescription::parse_from_der(&ext_value)?.unwrap();

println!("Attestation security level: {:?}", kd.attestation_security_level);
println!("KeyMint security level: {:?}", kd.key_mint_security_level);
println!("Challenge: {}", hex::encode(&kd.attestation_challenge));

// Hardware-enforced fields
if let Some(rot) = &kd.hardware_enforced.root_of_trust {
    println!("Device locked: {}", rot.device_locked);
    println!("Boot state: {:?}", rot.verified_boot_state);
}

// Device identity
let device_id = extension::DeviceIdentity::parse_from(&kd);
if let Some(brand) = &device_id.brand {
    println!("Brand: {brand}");
}
if let Some(model) = &device_id.model {
    println!("Model: {model}");
}
```

#### Parsing keybox XML

```rust
use attestation_parser_rs::parse_keybox_xml;

let xml = std::fs::read_to_string("keybox.xml")?;
let keyboxes = parse_keybox_xml(&xml)?;

for keybox in &keyboxes {
    println!("Device ID: {}", keybox.device_id);
    for key in &keybox.keys {
        println!("  Algorithm: {}", key.algorithm);
        println!("  Private key PEM: {} bytes", key.private_key_pem.len());
        println!("  Certificates: {}", key.certificates_pem.len());

        // Convert to DER for verification or further processing
        let certs_der = key.cert_chain_der()?;
        let pk_der = key.private_key_der()?;
    }
}
```

#### Custom constraints

```rust
use attestation_parser_rs::{Verifier, constraint::{ConstraintConfig, SecurityLevelConstraint}};

let config = ConstraintConfig::builder()
    .security_level(SecurityLevelConstraint::Strict(
        extension::SecurityLevel::StrongBox,
    ))
    .build();

let verifier = Verifier::google(|| chrono::Utc::now())
    .with_constraint_config(config);
```

## Architecture

```
src/
├── lib.rs            # Public API re-exports
├── cert_chain.rs     # Certificate chain parsing (Cert, KeyAttestationCertPath)
├── extension.rs      # KeyDescription / AuthorizationList parsing
├── keybox.rs         # Keybox XML parsing (Keybox, KeyEntry)
├── parse_json.rs     # JSON attestation record parsing
├── validator.rs      # Path validation (signatures, chaining, expectations)
├── verifier.rs       # Top-level Verifier with trust anchors + revocation
├── trust_anchors.rs  # Google root certificates & revocation status
├── provisioning.rs   # Remotely-provisioned (RKP) info extension parsing
├── constraint.rs     # Constraint framework (security level, origin, etc.)
├── cache.rs          # Live-data caching (roots + revocation list)
├── revocation.rs     # Revocation checking
├── error.rs          # Error types
└── main.rs           # CLI: unified binary (PEM chains, keybox dump, JSON records)
```

## Verification Checks

The strict verifier performs three mandatory checks:

| # | Check | Description |
|---|-------|-------------|
| 1 | **Chain validation** | Signature verification (ECDSA P-256/384/521, RSA SHA-256/384/512), name chaining, expiry, extension expectations |
| 2 | **Trust anchor** | The chain must trace to a Google production trust anchor; software roots are rejected |
| 3 | **Revocation** | Certificate serial numbers are checked against Google's revocation list |

Additional constraint checks (configurable):

- **Security level**: reject software-only attestation (default), or require specific level
- **Key origin**: must be `GENERATED` in hardware (default)
- **Root of trust**: must be present (default)
- **Tag order**: AuthorizationList tags must appear in ascending order

## Supported KeyDescription Tags

| Tag | Name | Type |
|-----|------|------|
| 1 | PURPOSE | SET of INTEGER |
| 2 | ALGORITHM | INTEGER |
| 3 | KEY_SIZE | INTEGER |
| 4 | BLOCK_MODE | SET of INTEGER |
| 5 | DIGEST | SET of INTEGER |
| 6 | PADDING | SET of INTEGER |
| 10 | EC_CURVE | INTEGER |
| 11 | ML_DSA_VARIANT | INTEGER |
| 200 | RSA_PUBLIC_EXPONENT | INTEGER |
| 203 | RSA_OAEP_MGF_DIGEST | SET of INTEGER |
| 400 | ACTIVE_DATE_TIME | INTEGER |
| 401 | ORIGINATION_EXPIRE_DATE_TIME | INTEGER |
| 402 | USAGE_EXPIRE_DATE_TIME | INTEGER |
| 503 | NO_AUTH_REQUIRED | BOOLEAN |
| 504 | USER_AUTH_TYPE | INTEGER |
| 505 | AUTH_TIMEOUT | INTEGER |
| 507 | TRUSTED_USER_PRESENCE_REQUIRED | BOOLEAN |
| 509 | UNLOCKED_DEVICE_REQUIRED | BOOLEAN |
| 701 | CREATION_DATE_TIME | INTEGER |
| 702 | ORIGIN | ENUMERATED |
| 703 | ROLLBACK_RESISTANT | BOOLEAN |
| 704 | ROOT_OF_TRUST | SEQUENCE |
| 705 | OS_VERSION | INTEGER |
| 706 | OS_PATCH_LEVEL | INTEGER |
| 709 | ATTESTATION_APPLICATION_ID | SEQUENCE |
| 710–717 | ATTESTATION_ID_* | OCTET STRING |
| 718 | VENDOR_PATCH_LEVEL | INTEGER |
| 719 | BOOT_PATCH_LEVEL | INTEGER |
| 723 | ATTESTATION_ID_SECOND_IMEI | OCTET STRING |
| 724 | MODULE_HASH | OCTET STRING |

## Testing

```bash
# All tests (unit + integration + PEM parse)
cargo test

# Only unit tests
cargo test --lib

# Only integration tests
cargo test --test integration

# Only PEM parse tests
cargo test --test pem_parse
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `x509-cert` | X.509 certificate parsing |
| `der` | ASN.1 DER encoding/decoding |
| `ecdsa` / `p256` / `p384` / `p521` | ECDSA signature verification |
| `rsa` | RSA signature verification |
| `sha2` | SHA-2 hashing |
| `ciborium` | CBOR decoding (provisioning info) |
| `serde_json` | JSON parsing (roots, status) |
| `quick-xml` | XML parsing (keybox files) |
| `ureq` | HTTP client (live trust anchor / revocation fetch) |
| `dirs` | Platform cache directory resolution |
| `chrono` | Date/time handling |
| `base64` | Base64 decoding (certificateChainBlob) |
| `hex` | Hex encoding/decoding |

**Cache location:** `~/.cache/attestation-parser-rs/attestation_cache.json` (Linux/macOS).

## Caching

Live data (trust anchors and revocation list) fetched from Google's servers is cached to disk for offline use, so subsequent verification runs do not require network access.

| Mode | Network | Revocation Check | Cache Update |
|------|---------|------------------|-------------|
| `--live` / `google_live()` | Yes | Yes (fresh) | Writes |
| No flag / `google_cached()` | No | Yes (from cache) | Reads only |
| `google()` (embedded only) | No | No | — |

If the cache is missing or corrupted, `google_cached()` falls back to embedded trust anchors with no revocation data and prints a hint to run `--live` once.

## References

- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Keymaster / KeyMint HAL](https://source.android.com/docs/security/features/keystore/attestation)
- [Google attestation root certificates](https://android.googleapis.com/attestation/root)
- [Google attestation status (revocation)](https://android.googleapis.com/attestation/status)

## License

This project is provided as-is for educational and verification purposes.