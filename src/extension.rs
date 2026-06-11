use crate::error::{KeyAttestationError, KeyAttestationReason};
use der::asn1::{Int, OctetString};
use der::{Decode, Length};
use std::collections::HashMap;

// OIDs
pub const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";
pub const PROVISIONING_INFO_OID: &str = "1.3.6.1.4.1.11129.2.1.30";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl SecurityLevel {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Generated = 0,
    Derived = 1,
    Imported = 2,
    Reserved = 3,
    SecurelyImported = 4,
}

impl Origin {
    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Generated),
            1 => Some(Self::Derived),
            2 => Some(Self::Imported),
            3 => Some(Self::Reserved),
            4 => Some(Self::SecurelyImported),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl VerifiedBootState {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Verified),
            1 => Some(Self::SelfSigned),
            2 => Some(Self::Unverified),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchLevel {
    pub year: u16,
    pub month: u8,
    pub version: Option<u8>,
}

impl PatchLevel {
    fn parse(s: &str, _partition: &str) -> Option<Self> {
        if s.len() != 6 && s.len() != 8 {
            return None;
        }
        let year: u16 = s[0..4].parse().ok()?;
        let month: u8 = s[4..6].parse().ok()?;
        if month < 1 || month > 12 {
            return None;
        }
        let version = if s.len() == 8 {
            Some(s[6..8].parse().ok()?)
        } else {
            None
        };
        Some(Self {
            year,
            month,
            version,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPackageInfo {
    pub name: String,
    pub version: Int,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationApplicationId {
    pub packages: Vec<AttestationPackageInfo>,
    pub signatures: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub brand: Option<String>,
    pub device: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub imeis: Vec<String>,
    pub meid: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    pub purposes: Option<Vec<Int>>,
    pub algorithm: Option<Int>,
    pub key_size: Option<Int>,
    pub block_modes: Option<Vec<Int>>,
    pub digests: Option<Vec<Int>>,
    pub paddings: Option<Vec<Int>>,
    pub ec_curve: Option<Int>,
    pub ml_dsa_variant: Option<Int>,
    pub rsa_public_exponent: Option<Int>,
    pub rsa_oaep_mgf_digests: Option<Vec<Int>>,
    pub active_date_time: Option<Int>,
    pub origination_expire_date_time: Option<Int>,
    pub usage_expire_date_time: Option<Int>,
    pub no_auth_required: Option<bool>,
    pub user_auth_type: Option<Int>,
    pub auth_timeout: Option<Int>,
    pub trusted_user_presence_required: Option<bool>,
    pub unlocked_device_required: Option<bool>,
    pub creation_date_time: Option<Int>,
    pub origin: Option<Origin>,
    pub rollback_resistant: Option<bool>,
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<Int>,
    pub os_patch_level: Option<PatchLevel>,
    pub attestation_application_id: Option<AttestationApplicationId>,
    pub attestation_id_brand: Option<String>,
    pub attestation_id_device: Option<String>,
    pub attestation_id_product: Option<String>,
    pub attestation_id_serial: Option<String>,
    pub attestation_id_imei: Option<String>,
    pub attestation_id_meid: Option<String>,
    pub attestation_id_manufacturer: Option<String>,
    pub attestation_id_model: Option<String>,
    pub vendor_patch_level: Option<PatchLevel>,
    pub boot_patch_level: Option<PatchLevel>,
    pub attestation_id_second_imei: Option<String>,
    pub module_hash: Option<Vec<u8>>,
    pub are_tags_ordered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    pub attestation_version: Int,
    pub attestation_security_level: SecurityLevel,
    pub key_mint_version: Int,
    pub key_mint_security_level: SecurityLevel,
    pub attestation_challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub hardware_enforced: AuthorizationList,
}

// KeyMint tag numbers
#[allow(dead_code)]
mod tag {
    pub const PURPOSE: u16 = 1;
    pub const ALGORITHM: u16 = 2;
    pub const KEY_SIZE: u16 = 3;
    pub const BLOCK_MODE: u16 = 4;
    pub const DIGEST: u16 = 5;
    pub const PADDING: u16 = 6;
    pub const EC_CURVE: u16 = 10;
    pub const ML_DSA_VARIANT: u16 = 11;
    pub const RSA_PUBLIC_EXPONENT: u16 = 200;
    pub const RSA_OAEP_MGF_DIGEST: u16 = 203;
    pub const ACTIVE_DATE_TIME: u16 = 400;
    pub const ORIGINATION_EXPIRE_DATE_TIME: u16 = 401;
    pub const USAGE_EXPIRE_DATE_TIME: u16 = 402;
    pub const NO_AUTH_REQUIRED: u16 = 503;
    pub const USER_AUTH_TYPE: u16 = 504;
    pub const AUTH_TIMEOUT: u16 = 505;
    pub const ALLOW_WHILE_ON_BODY: u16 = 506;
    pub const TRUSTED_USER_PRESENCE_REQUIRED: u16 = 507;
    pub const UNLOCKED_DEVICE_REQUIRED: u16 = 509;
    pub const CREATION_DATE_TIME: u16 = 701;
    pub const ORIGIN: u16 = 702;
    pub const ROLLBACK_RESISTANT: u16 = 703;
    pub const ROOT_OF_TRUST: u16 = 704;
    pub const OS_VERSION: u16 = 705;
    pub const OS_PATCH_LEVEL: u16 = 706;
    pub const ATTESTATION_APPLICATION_ID: u16 = 709;
    pub const ATTESTATION_ID_BRAND: u16 = 710;
    pub const ATTESTATION_ID_DEVICE: u16 = 711;
    pub const ATTESTATION_ID_PRODUCT: u16 = 712;
    pub const ATTESTATION_ID_SERIAL: u16 = 713;
    pub const ATTESTATION_ID_IMEI: u16 = 714;
    pub const ATTESTATION_ID_MEID: u16 = 715;
    pub const ATTESTATION_ID_MANUFACTURER: u16 = 716;
    pub const ATTESTATION_ID_MODEL: u16 = 717;
    pub const VENDOR_PATCH_LEVEL: u16 = 718;
    pub const BOOT_PATCH_LEVEL: u16 = 719;
    pub const ATTESTATION_ID_SECOND_IMEI: u16 = 723;
    pub const MODULE_HASH: u16 = 724;
}

/// Parse the tag and length of an ASN.1 element, returning (tag, length, content_offset).
fn parse_asn1_header(data: &[u8]) -> Result<(u8, usize, usize), der::Error> {
    if data.len() < 2 {
        return Err(der::Error::incomplete(Length::new(1)));
    }
    let tag = data[0];
    let mut offset = 1;

    // Handle multi-byte tag
    if (tag & 0x1F) == 0x1F {
        while offset < data.len() && (data[offset] & 0x80) != 0 {
            offset += 1;
        }
        offset += 1;
    }

    if offset >= data.len() {
        return Err(der::Error::incomplete(Length::new(1)));
    }

    let len_byte = data[offset];
    let (len, len_bytes): (usize, usize) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 1)
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        let mut len_val: usize = 0;
        for i in 0..num_octets {
            len_val = (len_val << 8) | data[offset + 1 + i] as usize;
        }
        (len_val, 1 + num_octets)
    };

    let content_offset = offset + len_bytes;
    Ok((tag, len, content_offset))
}

/// Returns an iterator over the raw bytes of each element in an ASN.1 SEQUENCE or SET.
fn iterate_sequence(data: &[u8]) -> Result<Vec<&[u8]>, der::Error> {
    if data.is_empty() || (data[0] != 0x30 && data[0] != 0x31) {
        return Err(der::Tag::Sequence.value_error());
    }
    let (_tag, seq_len, content_offset) = parse_asn1_header(data)?;
    let content = &data[content_offset..content_offset + seq_len];

    let mut elements = Vec::new();
    let mut pos: usize = 0;
    while pos < content.len() {
        let (_el_tag, el_len, el_offset) = parse_asn1_header(&content[pos..])?;
        let el_total_len = el_offset + el_len;
        elements.push(&content[pos..pos + el_total_len]);
        pos += el_total_len;
    }
    Ok(elements)
}

/// Parse a tagged context-specific object from raw ASN.1 bytes.
/// Returns (tag_number, inner_bytes).
fn parse_tagged_object(data: &[u8]) -> Result<(u16, &[u8]), der::Error> {
    if data.is_empty() {
        return Err(der::Error::incomplete(Length::new(1)));
    }
    let tag_byte = data[0];
    // Context-specific tag: bits 7-6 = 10, bit 5 = constructed
    let tag_class = tag_byte >> 6;
    let _constructed = (tag_byte & 0x20) != 0;
    if tag_class != 0b10 {
        return Err(der::Tag::Integer.value_error());
    }

    let tag_number: u16;
    let len_start: usize;
    if (tag_byte & 0x1F) == 0x1F {
        // Multi-byte tag number
        let mut idx = 1;
        let mut tn: u32 = 0;
        while idx < data.len() {
            let b = data[idx];
            idx += 1;
            tn = (tn << 7) | (b & 0x7F) as u32;
            if (b & 0x80) == 0 {
                break;
            }
        }
        tag_number = tn as u16;
        len_start = idx;
    } else {
        tag_number = (tag_byte & 0x1F) as u16;
        len_start = 1;
    }

    // Parse length
    if len_start >= data.len() {
        return Err(der::Error::incomplete(Length::new(1)));
    }
    let len_byte = data[len_start];
    let (inner_len, inner_start): (usize, usize) = if len_byte & 0x80 == 0 {
        (len_byte as usize, len_start + 1)
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        let mut len_val: usize = 0;
        for i in 0..num_octets {
            len_val = (len_val << 8) | data[len_start + 1 + i] as usize;
        }
        (len_val, len_start + 1 + num_octets)
    };

    if inner_start + inner_len > data.len() {
        return Err(der::Error::incomplete(Length::new(1)));
    }

    Ok((tag_number, &data[inner_start..inner_start + inner_len]))
}

fn decode_int(data: &[u8]) -> Result<Int, der::Error> {
    Int::from_der(data)
}

fn decode_octet_string(data: &[u8]) -> Result<Vec<u8>, der::Error> {
    OctetString::from_der(data).map(|os| os.as_bytes().to_vec())
}

fn decode_int_set(data: &[u8]) -> Result<Vec<Int>, der::Error> {
    let elements = iterate_sequence(data)?;
    let mut result = Vec::with_capacity(elements.len());
    for el in elements {
        result.push(Int::from_der(el)?);
    }
    Ok(result)
}

fn decode_str(data: &[u8]) -> Result<String, der::Error> {
    let bytes = decode_octet_string(data)?;
    String::from_utf8(bytes)
        .map_err(|_| der::Tag::Utf8String.value_error())
}

fn decode_enumerated(data: &[u8]) -> Result<i32, der::Error> {
    // ENUMERATED is encoded like INTEGER but with tag 0x0A
    if data.len() < 3 || data[0] != 0x0A {
        return Err(der::Tag::Enumerated.value_error());
    }
    let len = data[1] as usize;
    if data.len() < 2 + len || len > 4 {
        return Err(der::Tag::Enumerated.value_error());
    }
    let first = data[2];
    let sign_extend = first & 0x80 != 0;
    let mut val: i64 = if sign_extend { -1 } else { 0 };
    for i in 0..len {
        val = (val << 8) | data[2 + i] as i64;
    }
    // Clamp to i32
    Ok(val as i32)
}

fn decode_boolean(data: &[u8]) -> Result<bool, der::Error> {
    // BOOLEAN: tag 0x01, length 1. DER requires value 0xFF for TRUE, 0x00 for FALSE.
    if data.len() != 3 || data[0] != 0x01 || data[1] != 0x01 {
        return Err(der::Tag::Boolean.value_error());
    }
    match data[2] {
        0x00 => Ok(false),
        0xFF => Ok(true),
        _ => Err(der::Tag::Boolean.value_error()),
    }
}

fn decode_root_of_trust(data: &[u8]) -> Result<RootOfTrust, der::Error> {
    let items = iterate_sequence(data)?;
    if items.len() < 3 || items.len() > 4 {
        return Err(der::Tag::Sequence.value_error());
    }
    let verified_boot_key = OctetString::from_der(items[0])?.as_bytes().to_vec();
    let device_locked = decode_boolean(items[1])?;
    let verified_boot_state_val = decode_enumerated(items[2])?;
    let verified_boot_state = VerifiedBootState::from_i32(verified_boot_state_val)
        .ok_or_else(|| der::Tag::Enumerated.value_error())?;
    let verified_boot_hash = if items.len() == 4 {
        Some(OctetString::from_der(items[3])?.as_bytes().to_vec())
    } else {
        None
    };
    Ok(RootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot_state,
        verified_boot_hash,
    })
}

fn decode_origin(data: &[u8]) -> Result<Origin, der::Error> {
    let val = decode_int(data)?;
    let v: u64 = val.as_bytes().iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    Origin::from_u64(v)
        .ok_or_else(|| der::Tag::Integer.value_error())
}

fn decode_patch_level(data: &[u8], partition: &str) -> Option<PatchLevel> {
    let val = decode_int(data).ok()?;
    let v: u64 = val.as_bytes().iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    PatchLevel::parse(&v.to_string(), partition)
}

fn decode_attestation_application_id(data: &[u8]) -> Result<AttestationApplicationId, der::Error> {
    let bytes = decode_octet_string(data)?;
    let items = iterate_sequence(&bytes)?;
    if items.len() != 2 {
        return Err(der::Tag::Sequence.value_error());
    }

    // Parse packages (SET OF SEQUENCE)
    let pkg_items = iterate_sequence(items[0])?;
    let mut packages = Vec::new();
    for pkg_bytes in pkg_items {
        let pkg_inner = iterate_sequence(pkg_bytes)?;
        if pkg_inner.len() != 2 {
            return Err(der::Tag::Sequence.value_error());
        }
        let name = decode_str(pkg_inner[0])?;
        let version = Int::from_der(pkg_inner[1])?;
        packages.push(AttestationPackageInfo { name, version });
    }

    // Parse signatures (SET OF OCTET STRING)
    let sig_items = iterate_sequence(items[1])?;
    let mut signatures = Vec::new();
    for sig_bytes in sig_items {
        let sig = OctetString::from_der(sig_bytes)?;
        signatures.push(sig.as_bytes().to_vec());
    }

    Ok(AttestationApplicationId {
        packages,
        signatures,
    })
}

fn decode_authorization_list(data: &[u8], log_fn: &mut dyn FnMut(String)) -> Result<AuthorizationList, KeyAttestationError> {
    let items = iterate_sequence(data).map_err(|e| KeyAttestationError::ExtensionParsing {
        message: format!("Failed to parse AuthorizationList SEQUENCE: {e}"),
        reason: None,
    })?;

    let mut tagged_map: HashMap<u16, &[u8]> = HashMap::with_capacity(items.len());
    let mut tag_order: Vec<u16> = Vec::with_capacity(items.len());

    for item_bytes in &items {
        let (tn, inner) = parse_tagged_object(item_bytes)
            .map_err(|e| KeyAttestationError::ExtensionParsing {
                message: format!("Failed to parse tagged object: {e}"),
                reason: Some(KeyAttestationReason::UnknownTagNumber),
            })?;
        tagged_map.insert(tn, inner);
        tag_order.push(tn);
    }

    let mut are_tags_ordered = true;
    for w in tag_order.windows(2) {
        if w[0] >= w[1] {
            are_tags_ordered = false;
            break;
        }
    }
    if !are_tags_ordered {
        log_fn("AuthorizationList tags should appear in ascending order".into());
    }

    let get_int = |tag_num: u16| -> Option<Int> {
        tagged_map.get(&tag_num).and_then(|d| decode_int(d).ok())
    };

    let get_int_set = |tag_num: u16| -> Option<Vec<Int>> {
        tagged_map.get(&tag_num).and_then(|d| decode_int_set(d).ok())
    };

    let get_str = |tag_num: u16| -> Option<String> {
        tagged_map.get(&tag_num).and_then(|d| decode_str(d).ok())
    };

    let get_bytes = |tag_num: u16| -> Option<Vec<u8>> {
        tagged_map.get(&tag_num).and_then(|d| decode_octet_string(d).ok())
    };

    let has_flag = |tag_num: u16| -> bool {
        tagged_map.contains_key(&tag_num)
    };

    let mut parse_tag = |tag_num: u16, tag_name: &str| -> Option<String> {
        get_str(tag_num).or_else(|| {
            log_fn(format!("Exception when parsing {tag_name}: not a valid string"));
            None
        })
    };

    Ok(AuthorizationList {
        purposes: get_int_set(tag::PURPOSE),
        algorithm: get_int(tag::ALGORITHM),
        key_size: get_int(tag::KEY_SIZE),
        block_modes: get_int_set(tag::BLOCK_MODE),
        digests: get_int_set(tag::DIGEST),
        paddings: get_int_set(tag::PADDING),
        ec_curve: get_int(tag::EC_CURVE),
        ml_dsa_variant: get_int(tag::ML_DSA_VARIANT),
        rsa_public_exponent: get_int(tag::RSA_PUBLIC_EXPONENT),
        rsa_oaep_mgf_digests: get_int_set(tag::RSA_OAEP_MGF_DIGEST),
        active_date_time: get_int(tag::ACTIVE_DATE_TIME),
        origination_expire_date_time: get_int(tag::ORIGINATION_EXPIRE_DATE_TIME),
        usage_expire_date_time: get_int(tag::USAGE_EXPIRE_DATE_TIME),
        no_auth_required: if has_flag(tag::NO_AUTH_REQUIRED) { Some(true) } else { None },
        user_auth_type: get_int(tag::USER_AUTH_TYPE),
        auth_timeout: get_int(tag::AUTH_TIMEOUT),
        trusted_user_presence_required: if has_flag(tag::TRUSTED_USER_PRESENCE_REQUIRED) { Some(true) } else { None },
        unlocked_device_required: if has_flag(tag::UNLOCKED_DEVICE_REQUIRED) { Some(true) } else { None },
        creation_date_time: get_int(tag::CREATION_DATE_TIME),
        origin: tagged_map
            .get(&tag::ORIGIN)
            .and_then(|d| decode_origin(d).ok()),
        rollback_resistant: if has_flag(tag::ROLLBACK_RESISTANT) { Some(true) } else { None },
        root_of_trust: tagged_map
            .get(&tag::ROOT_OF_TRUST)
            .and_then(|d| decode_root_of_trust(d).ok()),
        os_version: get_int(tag::OS_VERSION),
        os_patch_level: tagged_map
            .get(&tag::OS_PATCH_LEVEL)
            .and_then(|d| decode_patch_level(d, "OS")),
        attestation_application_id: tagged_map
            .get(&tag::ATTESTATION_APPLICATION_ID)
            .and_then(|d| decode_attestation_application_id(d).ok()),
        attestation_id_brand: parse_tag(tag::ATTESTATION_ID_BRAND, "brand"),
        attestation_id_device: parse_tag(tag::ATTESTATION_ID_DEVICE, "device"),
        attestation_id_product: parse_tag(tag::ATTESTATION_ID_PRODUCT, "product"),
        attestation_id_serial: parse_tag(tag::ATTESTATION_ID_SERIAL, "serial"),
        attestation_id_imei: parse_tag(tag::ATTESTATION_ID_IMEI, "imei"),
        attestation_id_meid: parse_tag(tag::ATTESTATION_ID_MEID, "meid"),
        attestation_id_manufacturer: parse_tag(tag::ATTESTATION_ID_MANUFACTURER, "manufacturer"),
        attestation_id_model: parse_tag(tag::ATTESTATION_ID_MODEL, "model"),
        vendor_patch_level: tagged_map
            .get(&tag::VENDOR_PATCH_LEVEL)
            .and_then(|d| decode_patch_level(d, "vendor")),
        boot_patch_level: tagged_map
            .get(&tag::BOOT_PATCH_LEVEL)
            .and_then(|d| decode_patch_level(d, "boot")),
        attestation_id_second_imei: parse_tag(tag::ATTESTATION_ID_SECOND_IMEI, "second_imei"),
        module_hash: get_bytes(tag::MODULE_HASH),
        are_tags_ordered,
    })
}

impl KeyDescription {
    pub fn parse_from_der(bytes: &[u8]) -> Result<Option<Self>, KeyAttestationError> {
        let items = iterate_sequence(bytes).map_err(|e| KeyAttestationError::ExtensionParsing {
            message: format!("Failed to parse KeyDescription SEQUENCE: {e}"),
            reason: None,
        })?;

        if items.len() != 8 {
            return Ok(None);
        }

        let attestation_version = Int::from_der(items[0]).map_err(|e| {
            KeyAttestationError::ExtensionParsing {
                message: format!("attestationVersion: {e}"),
                reason: None,
            }
        })?;

        let attestation_security_level_val = decode_enumerated(items[1]).map_err(|e| {
            KeyAttestationError::ExtensionParsing {
                message: format!("attestationSecurityLevel: {e}"),
                reason: None,
            }
        })?;
        let attestation_security_level =
            SecurityLevel::from_i32(attestation_security_level_val).ok_or_else(|| {
                KeyAttestationError::ExtensionParsing {
                    message: format!("Unknown attestationSecurityLevel: {attestation_security_level_val}"),
                    reason: None,
                }
            })?;

        let key_mint_version = Int::from_der(items[2]).map_err(|e| {
            KeyAttestationError::ExtensionParsing {
                message: format!("keyMintVersion: {e}"),
                reason: None,
            }
        })?;

        let key_mint_security_level_val = decode_enumerated(items[3]).map_err(|e| {
            KeyAttestationError::ExtensionParsing {
                message: format!("keyMintSecurityLevel: {e}"),
                reason: None,
            }
        })?;
        let key_mint_security_level =
            SecurityLevel::from_i32(key_mint_security_level_val).ok_or_else(|| {
                KeyAttestationError::ExtensionParsing {
                    message: format!(
                        "Unknown keyMintSecurityLevel: {key_mint_security_level_val}"
                    ),
                    reason: None,
                }
            })?;

        let attestation_challenge = OctetString::from_der(items[4])
            .map_err(|e| KeyAttestationError::ExtensionParsing {
                message: format!("attestationChallenge: {e}"),
                reason: None,
            })?
            .as_bytes()
            .to_vec();

        let unique_id = OctetString::from_der(items[5])
            .map_err(|e| KeyAttestationError::ExtensionParsing {
                message: format!("uniqueId: {e}"),
                reason: None,
            })?
            .as_bytes()
            .to_vec();

        let mut log_fn = |msg: String| {
            eprintln!("{msg}");
        };

        let software_enforced = decode_authorization_list(items[6], &mut log_fn)?;
        let hardware_enforced = decode_authorization_list(items[7], &mut log_fn)?;

        Ok(Some(Self {
            attestation_version,
            attestation_security_level,
            key_mint_version,
            key_mint_security_level,
            attestation_challenge,
            unique_id,
            software_enforced,
            hardware_enforced,
        }))
    }
}

impl DeviceIdentity {
    pub fn parse_from(desc: &KeyDescription) -> Self {
        let hw = &desc.hardware_enforced;
        let mut imeis = Vec::new();
        if let Some(ref imei) = hw.attestation_id_imei {
            imeis.push(imei.clone());
        }
        if let Some(ref imei2) = hw.attestation_id_second_imei {
            imeis.push(imei2.clone());
        }

        Self {
            brand: hw.attestation_id_brand.clone(),
            device: hw.attestation_id_device.clone(),
            product: hw.attestation_id_product.clone(),
            serial_number: hw.attestation_id_serial.clone(),
            imeis,
            meid: hw.attestation_id_meid.clone(),
            manufacturer: hw.attestation_id_manufacturer.clone(),
            model: hw.attestation_id_model.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_level_parse_6_digit() {
        let pl = PatchLevel::parse("202503", "OS").unwrap();
        assert_eq!(pl.year, 2025);
        assert_eq!(pl.month, 3);
        assert!(pl.version.is_none());
    }

    #[test]
    fn test_patch_level_parse_8_digit() {
        let pl = PatchLevel::parse("20250301", "vendor").unwrap();
        assert_eq!(pl.year, 2025);
        assert_eq!(pl.month, 3);
        assert_eq!(pl.version, Some(1));
    }

    #[test]
    fn test_patch_level_parse_invalid() {
        assert!(PatchLevel::parse("12345", "OS").is_none());
        assert!(PatchLevel::parse("202513", "OS").is_none());
    }
}
