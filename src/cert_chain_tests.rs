    use super::*;

    #[test]
    fn test_parse_dn() {
        let dn = "CN=Test, O=Google LLC, OID.2.5.4.5=123456";
        let parsed = parse_dn(dn);
        assert_eq!(parsed.get("CN"), Some(&"Test".to_string()));
        assert_eq!(parsed.get("O"), Some(&"Google LLC".to_string()));
    }
