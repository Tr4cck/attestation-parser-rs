# attestation-parser-rs

A strict Rust parser and verifier for [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) certificate chains.

## Overview

Android Key Attestation proves that a cryptographic key was generated inside a hardware-backed keystore (TEE or StrongBox). The attestation is delivered as an X.509 certificate chain whose leaf certificate contains a [KeyDescription](https://source.android.com/docs/security/features/keystore/attestation) extension (OID `1.3.6.1.4.1.11129.2.1.17`) with hardware-enforced and software-enforced authorization lists.

This crate:

- **Parses** the full KeyDescription extension, including all KeyMint/Keymaster tags (purposes, algorithm, root of trust, device identity, patch levels, etc.)
- **Validates** the certificate chain: signature verification, name chaining, expiry, extension expectations
- **Checks** against Google's production trust anchors (embedded or fetched live)
- **Checks** Google's revocation list (fetched live from `android.googleapis.com/attestation/status`)
- **Rejects** software attestation roots — only hardware-backed chains are accepted by the strict verifier
- **Supports** both factory-provisioned and remotely-provisioned (RKP) chains

## Quick Start

### Verify a PEM chain

```bash
# Verify against embedded Google trust anchors
cargo run -- cert_chain.pem

# Verify with live trust anchors and revocation list (requires network)
cargo run -- cert_chain.pem --live
```

The PEM file should contain the certificate chain with **leaf first, root last**.

### Parse a JSON blob from Android Keystore

```bash
# From a JSON file (live mode is default — fetches Google trust anchors & revocation list)
cargo run --bin parse_json -- attestation.json

# Or pipe via stdin
cat attestation.json | cargo run --bin parse_json

# Offline mode: use embedded trust anchors, skip revocation check
cargo run --bin parse_json -- --no-live attestation.json
```

The JSON format matches the output of Android Keystore's `getCertificateChain()` and `getAttestationChallenge()`:

```json
{
  "alias": "my_key_alias",
  "certificateChainBlob": "<base64-encoded DER certificate chain>",
  "challenge": "<base64-encoded challenge>"
}
```

> **Note:** The `certificateChainBlob` from the Android Keystore API wraps all certificates in an outer DER SEQUENCE, ordered root-first. The `parse_json` binary automatically extracts and reorders them to leaf-first. Base64 padding is normalized automatically.

#### CLI options

| Option | Description |
|--------|-------------|
| `--live` | Fetch Google trust anchors and revocation list from `android.googleapis.com` (default) |
| `--no-live` | Use embedded trust anchors, skip revocation check (no network required) |
| `-h`, `--help` | Show usage information |
| `[INPUT]` | JSON file path; reads stdin if omitted |

When `--live` is active (the default), the binary:

1. **Fetches trust anchors** from `https://android.googleapis.com/attestation/root` — falls back to embedded anchors if the fetch fails
2. **Fetches the revocation list** from `https://android.googleapis.com/attestation/status` — skips revocation checking if the fetch fails

The `checkGoogleRootEnabled` and `checkRevocationEnabled` fields in the output JSON reflect whether these checks were actually performed.

The `parse_json` binary outputs structured JSON with:

- **Validation errors** — certificate expiry, trust anchor checks, revocation checks
- **Certificate chain details** — subject/issuer DN, serial number, key usage, basic constraints, SHA-256 fingerprints
- **KeyDescription** — attestation version, security level, challenge
- **Authorization lists** — software-enforced and hardware-enforced tags with per-tag rendering
- **Boot state** — verified boot key, device lock status, boot state

Key output formatting notes:

- Serial numbers are displayed as unsigned decimal (high-bit-set values like `0xA2059ED10E435B57` are shown as `11674912229752527703`, not negative)
- `basicConstraints` uses Java-compatible values: `2147483647` (Integer.MAX_VALUE) for CA:true without pathLen, `0` for CA:true with pathLen:0, `-1` for non-CA
- Purpose names use Java-style PascalCase: `Verify`, `Sign`, `Encrypt`, etc.
- `attestationApplicationId` includes the raw DER hex and per-package version info

### As a library

```rust
use attestation_parser_rs::{Verifier, VerificationResult, KeyAttestationCertPath, extension};

// Load DER-encoded certificates (leaf first, root last)
let certs: Vec<Vec<u8>> = /* ... */;

// Strict verification against Google trust anchors
let verifier = Verifier::google(|| chrono::Utc::now());
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
├── validator.rs      # Path validation (signatures, chaining, expectations)
├── verifier.rs       # Top-level Verifier with trust anchors + revocation
├── trust_anchors.rs  # Google root certificates & revocation status
├── provisioning.rs   # Remotely-provisioned (RKP) info extension parsing
├── constraint.rs     # Constraint framework (security level, origin, etc.)
├── revocation.rs     # Revocation checking
├── error.rs          # Error types
├── main.rs           # CLI: verify PEM chains
└── bin/
    └── parse_json.rs # CLI: parse Android Keystore JSON → structured output
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

Unit tests (6):

- PatchLevel parsing (6-digit, 8-digit, invalid)
- DN parsing
- Trust anchor JSON loading
- Attestation status parsing

Integration tests (13):

- Public Google root/intermediate certificate parsing
- Software root detection
- Chain structure validation (minimum length, self-issued root)
- Embedded trust anchor loading
- Revocation checker (empty list and revoked serial)
- File-based tests (require `keyattestation` testdata submodule, auto-skipped if absent)

PEM parse tests (17):

- Root and intermediate subject/serial parsing
- Unsigned serial number handling (high-bit-set values)
- Self-issued detection
- Signature algorithm verification
- Extension parsing (basicConstraints, keyUsage)
- **keyUsage bit-level verification** — confirms digitalSignature + keyCertSign for CA certs
- **basicConstraints value verification** — confirms `2147483647` for root (CA:true, no pathLen), `0` for intermediate (CA:true, pathLen:0)
- Issuer/subject chain linking
- Public key algorithm detection
- SPKI DER encoding

File-based tests (e.g., `parse_blueline_sdk28_tee_ec_none`) require the `keyattestation` testdata submodule and are automatically skipped when not present.

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
| `ureq` | HTTP client (live trust anchor / revocation fetch) |
| `chrono` | Date/time handling |
| `base64` | Base64 decoding (certificateChainBlob) |
| `hex` | Hex encoding/decoding |

## References

- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Keymaster / KeyMint HAL](https://source.android.com/docs/security/features/keystore/attestation)
- [Google attestation root certificates](https://android.googleapis.com/attestation/root)
- [Google attestation status (revocation)](https://android.googleapis.com/attestation/status)

## License

This project is provided as-is for educational and verification purposes.
