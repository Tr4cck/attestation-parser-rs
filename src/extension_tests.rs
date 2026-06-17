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
