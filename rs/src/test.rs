/*
    DISKHASHER v0.2 - 2023 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DISKHASHER.

    DISKHASHER is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DISKHASHER is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DISKHASHER. If not, see
    <https://www.gnu.org/licenses/>.
*/

mod hashfile {
    use std::path::{Path, PathBuf};

    #[test]
    fn replace_prefix() {
        let file_to_fix = Path::new("/path/to/this/file");
        let root_dir = Path::new("/path/to");
        let fixed_path = file_to_fix.strip_prefix(root_dir);
        assert!(fixed_path.is_ok());
        let result_str = format!("{}", fixed_path.unwrap().display());
        let expected_str = String::from("this/file");
        assert_eq!(result_str, expected_str);
    }
}

mod canonicalize_path {
    use crate::util::canonicalize_filepath;
    use std::{
        env,
        fs::{remove_file, File},
        path::{Path, PathBuf},
    };

    #[test]
    fn relative_path_not_exists() {
        let rel: &str = "rel_does_not_exist.txt";
        let base: PathBuf = env::current_dir().unwrap();
        let val = canonicalize_filepath(rel, &base);
        assert!(val.is_err());
    }

    #[test]
    fn relative_path_exists() {
        let rel: &str = "rel_exists.txt";
        assert!(File::create(&rel).is_ok());
        let base: PathBuf = env::current_dir().unwrap();
        let expected = base.clone().join(rel);
        let val = canonicalize_filepath(rel, &base);
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), expected);
        remove_file(rel).unwrap();
    }

    #[test]
    fn absolute_path_not_exists() {
        let rel: &str = "abs_does_not_exist.txt";
        let base: PathBuf = env::current_dir().unwrap().join(rel);
        let absolute = Path::new(&base);
        let val = canonicalize_filepath(&absolute.display().to_string(), &base);
        assert!(val.is_err());
    }

    #[test]
    fn absolute_path_exists() {
        let rel: &str = "abs_exists.txt";
        let base: PathBuf = env::current_dir().unwrap().join(rel);
        let absolute = Path::new(&base);
        assert!(File::create(&absolute).is_ok());
        let val = canonicalize_filepath(&absolute.display().to_string(), &base);
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), absolute);
        remove_file(absolute).unwrap();
    }
}

mod path_matches_regex {
    use crate::util::path_matches_regex;
    use regex::Regex;
    use std::path::PathBuf;

    #[test]
    fn good_matches() {
        let regex = Regex::new("result(.)*").unwrap();
        let path: Vec<PathBuf> = vec![
            PathBuf::from("result1.txt"),             // numeral
            PathBuf::from("resultAAAA.txt"),          //extra chars
            PathBuf::from("result is this file.txt"), // whitepace
            PathBuf::from("result_bohème.txt"),      // non-ascii chars
        ];
        for p in path {
            assert!(path_matches_regex(&regex, &p));
        }
    }

    #[test]
    fn bad_matches() {
        let regex = Regex::new("result(.)*").unwrap();
        let path: Vec<PathBuf> = vec![
            PathBuf::from("esult1.txt"),   // missing letter
            PathBuf::from("ressult1.txt"), // doubled letter
            PathBuf::from("resualt1.txt"), // extra letter
        ];
        for p in path {
            assert!(!path_matches_regex(&regex, &p));
        }
    }
}

mod splitline {
    use crate::util::split_hashfile_line;
    use std::fs::{canonicalize, remove_file, File};
    use std::path::PathBuf;

    #[test]
    fn empty() {
        let newline: String = "".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn notenough_args() {
        let newline: String = "asdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn badhash() {
        let newline: String = "asdfasdfasdf asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn hashtooshort() {
        let newline: String = "abcdef123456 asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn hashnothex() {
        // MD5 length but has char that is not valid hex
        let newline: String = "abcdef1234567890abcdef123456789X asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn badpath() {
        let bad_path = "./doesnotexist.txt".to_string();
        let newline: String = format!("abcdef1234567890abcdef1234567890 {bad_path}");
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn checklengths() {
        let good_path = "./exists.txt".to_string();
        assert!(File::create(&good_path).is_ok());
        let good_path_display: PathBuf = canonicalize(&good_path).unwrap();

        let newlines: Vec<String> = vec![
            format!("abcdef1234567890abcdef1234567890 {good_path}"), //md5
            format!("abcdef1234567890abcdef1234567890aabbccdd {good_path}"), //SHA1
            format!("abcdef1234567890abcdef1234567890abcdef1234567890aabbccdd {good_path}"), //SHA224
            format!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}"), //SHA256
            format!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}"), //SHA384
            format!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}") //SHA512
        ];
        for case in newlines {
            let hashpath: PathBuf = PathBuf::new();
            let result = split_hashfile_line(&case, &hashpath);
            println!("{result:?}");
            assert!(result.is_ok());
            assert_eq!(result.unwrap().0, good_path_display);
        }
        remove_file(&good_path).unwrap_or_else(|err| println!("File error: {err}"));
    }
}

mod implements_traits {
    use crate::enums::HashAlg;
    use crate::hasher::Hasher;

    #[test]
    fn debug_print() {
        let hasher: Hasher =
            Hasher::new(HashAlg::MD5, String::from("./"), None, None, None, None).unwrap();
        println!("{:?}", hasher);
    }

    #[test]
    fn can_clone() {
        let hasher: Hasher =
            Hasher::new(HashAlg::MD5, String::from("./"), None, None, None, None).unwrap();
        let _myclone = hasher.clone();
    }
}

mod validate_hexstring {
    use crate::util::validate_hexstring;

    #[test]
    fn good_input() {
        let good_strings: [&str; 6] = [
            "abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890aabbccdd",
            "abcdef1234567890abcdef1234567890abcdef1234567890aabbccdd",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ];
        for g in good_strings {
            assert!(validate_hexstring(g).is_ok());
        }
    }

    #[test]
    fn bad_input() {
        let bad_strings: [&str; 6] = [
            "",                                          // zero length
            "abcdef1234567890abcdef1234567890aabbccd",   // one too short
            "abcdef1234567890abcdef1234567890aabbccdda", // one too long
            "abcdef1234567890abc ef1234567890aabbccdd",  // space in the middle
            "abcdef1234567890abcQef1234567890aabbccdd",  // non-hex char in the middle
            "abcdef1234567890abcèef1234567890aabbccdd", // unicode char in the middle
        ];
        for b in bad_strings {
            assert!(validate_hexstring(b).is_err());
        }
    }
}
