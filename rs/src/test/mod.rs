/*
    DKHASH - 2025 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DKHASH.

    DKHASH is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DKHASH is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DKHASH. If not, see
    <https://www.gnu.org/licenses/>.
*/

mod hashfile {
    use std::path::Path;

    #[test]
    fn replace_prefix() {
        let file_to_fix = Path::new("/path/to/this/file");
        let root_dir = Path::new("/path/to");
        let fixed_path = file_to_fix.strip_prefix(root_dir);
        assert!(fixed_path.is_ok());
        assert_eq!(fixed_path.unwrap().display().to_string(), "this/file");
    }

    #[test]
    fn replace_prefix_fail() {
        let file_to_fix = Path::new("/path/to/this/file");
        let root_dir = Path::new("/path/to/that");
        assert!(file_to_fix.strip_prefix(root_dir).is_err());
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
            PathBuf::from("result_bohème.txt"),       // non-ascii chars
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

mod implements_traits {
    use crate::enums::HashAlg;
    use crate::hasher::DirHasher;

    #[test]
    fn debug_print() {
        let hasher: DirHasher = DirHasher::new(
            HashAlg::MD5,
            &String::from("./").clone(),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        println!("{:?}", hasher);
    }

    #[test]
    fn can_clone() {
        let hasher: DirHasher =
            DirHasher::new(HashAlg::MD5, &String::from("./"), None, None, None, None).unwrap();
        let _myclone = hasher.clone();
    }
}

mod hashtest {
    use crate::{
        enums::HashAlg, filedata::FileData, threadfunc::hash_file, util::canonicalize_filepath,
    };
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::{
        collections::HashMap,
        env,
        fs::{File, remove_file},
        path::{Path, PathBuf},
    };

    fn run_all_hashes(testfile: &str) {
        let algs = HashMap::from([
            ("md5", HashAlg::MD5),
            ("sha1", HashAlg::SHA1),
            ("sha256", HashAlg::SHA256),
            ("sha512", HashAlg::SHA512),
        ]);

        let base: PathBuf = env::current_dir().unwrap().join(testfile);
        let absolute = Path::new(&base);
        let path = canonicalize_filepath(&absolute.display().to_string(), &base).unwrap();
        let fdata = FileData::new(
            std::fs::metadata(&path).unwrap().len(),
            path.clone(),
            #[cfg(target_os = "linux")]
            std::fs::metadata(&path).unwrap().ino(),
        );

        for (algstr, alg) in algs {
            let expected = get_os_hash(testfile, algstr);
            let result = hash_file(&fdata, alg, &None);
            assert!(result.is_ok());
            let result_str = result.unwrap();
            assert_eq!(result_str, expected);
        }
    }

    fn get_os_hash(testfile: &str, alg: &str) -> String {
        if cfg!(target_os = "windows") {
            let strarg = format!(
                "$env:PSModulePath = \"$PSHOME/Modules\"; (Get-Filehash .\\{testfile} -Algorithm {alg} | Select-Object Hash).Hash.ToLower()"
            );
            let output = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &strarg])
                .output()
                .expect("failed to execute PowerShell")
                .stdout;
            String::from_utf8(output).unwrap().trim().to_string()
        } else if cfg!(target_os = "linux") {
            let output = std::process::Command::new(format!("{alg}sum"))
                .arg(format!("./{testfile}"))
                .output()
                .expect("failed to execute BASH")
                .stdout;
            String::from_utf8(output).unwrap().split_whitespace().next().unwrap().to_string()
        } else {
            panic!("Unsupported OS");
        }
    }

    #[test]
    fn hash_empty_file() {
        let testfile = "empty.txt";
        assert!(File::create(testfile).is_ok());
        run_all_hashes(testfile);
        assert!(remove_file(testfile).is_ok());
    }

    #[test]
    fn hash_random_file() {
        let testfile = "random.txt";
        let random_bytes: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();
        assert!(File::create(testfile).is_ok());
        assert!(std::fs::write(testfile, random_bytes).is_ok());
        run_all_hashes(testfile);
        assert!(remove_file(testfile).is_ok());
    }

    #[test]
    fn hash_known_file() {
        let testfile = "Cargo.toml";
        run_all_hashes(testfile);
    }
}

mod util_test {
    use crate::util::{
        add_extension, canonicalize_filepath, split_hashfile_line, validate_hexstring,
    };
    use std::{
        env,
        fs::{File, canonicalize, remove_file},
        path::{Path, PathBuf},
    };

    // canonicalize_filepath tests
    #[test]
    fn canonicalize_relative_path_not_exists() {
        let rel: &str = "rel_does_not_exist.txt";
        let base: PathBuf = env::current_dir().unwrap();
        let val = canonicalize_filepath(rel, &base);
        assert!(val.is_err());
    }

    #[test]
    fn canonicalize_relative_path_exists() {
        let rel: &str = "rel_exists.txt";
        assert!(File::create(&rel).is_ok());
        let base: PathBuf = env::current_dir().unwrap();
        let expected = base.clone().join(rel).display().to_string();
        let val = canonicalize_filepath(rel, &base);
        assert!(val.is_ok());
        let temp = val.unwrap().display().to_string();
        // Windows canonical paths are....janky. If windows, this string replace will remove
        // the canonical prefix, if any exists. in Nix, it is a No-Op.
        let actual = temp.replace("\\\\?\\", "");
        assert_eq!(actual, expected);
        remove_file(rel).unwrap();
    }

    #[test]
    fn canonicalize_absolute_path_not_exists() {
        let rel: &str = "abs_does_not_exist.txt";
        let base: PathBuf = env::current_dir().unwrap().join(rel);
        let absolute = Path::new(&base);
        let val = canonicalize_filepath(&absolute.display().to_string(), &base);
        assert!(val.is_err());
    }

    #[test]
    fn canonicalize_absolute_path_exists() {
        let rel: &str = "abs_exists.txt";
        let base: PathBuf = env::current_dir().unwrap().join(rel);
        let absolute = Path::new(&base);
        assert!(File::create(&absolute).is_ok());
        let val = canonicalize_filepath(&absolute.display().to_string(), &base);
        assert!(val.is_ok());
        assert_eq!(val.unwrap(), absolute);
        remove_file(absolute).unwrap();
    }

    // split_hashfile_line tests
    #[test]
    fn splitline_empty() {
        let newline: String = "".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_notenough_args() {
        let newline: String = "asdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_badhash() {
        let newline: String = "asdfasdfasdf asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_hashtooshort() {
        let newline: String = "abcdef123456 asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_hashnothex() {
        // MD5 length but has char that is not valid hex
        let newline: String = "abcdef1234567890abcdef123456789X asdfasdfasdfasdf".to_string();
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_badpath() {
        let bad_path = "./doesnotexist.txt".to_string();
        let newline: String = format!("abcdef1234567890abcdef1234567890 {bad_path}");
        let hashpath: PathBuf = PathBuf::new();
        assert!(split_hashfile_line(&newline, &hashpath).is_err());
    }

    #[test]
    fn splitline_checklengths() {
        let good_path = "./exists.txt".to_string();
        assert!(File::create(&good_path).is_ok());
        let good_path_display: PathBuf = canonicalize(&good_path).unwrap();

        let newlines: Vec<String> = vec![
            format!("abcdef1234567890abcdef1234567890 {good_path}"), //md5
            format!("abcdef1234567890abcdef1234567890aabbccdd {good_path}"), //SHA1
            format!("abcdef1234567890abcdef1234567890abcdef1234567890aabbccdd {good_path}"), //SHA224
            format!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}"), //SHA256
            format!(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}"
            ), //SHA384
            format!(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 {good_path}"
            ), //SHA512
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

    // validate_hexstring tests
    #[test]
    fn hexstrings_good_input() {
        let good_strings: [&str; 6] = [
            "abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890aabbccdd",
            "abcdef1234567890abcdef1234567890abcdef1234567890aabbccdd",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        ];
        for g in good_strings {
            assert!(validate_hexstring(g).is_ok());
        }
    }

    #[test]
    fn hexstrings_bad_input() {
        let bad_strings: [&str; 6] = [
            "",                                          // zero length
            "abcdef1234567890abcdef1234567890aabbccd",   // one too short
            "abcdef1234567890abcdef1234567890aabbccdda", // one too long
            "abcdef1234567890abc ef1234567890aabbccdd",  // space in the middle
            "abcdef1234567890abcQef1234567890aabbccdd",  // non-hex char in the middle
            "abcdef1234567890abcèef1234567890aabbccdd",  // unicode char in the middle
        ];
        for b in bad_strings {
            assert!(validate_hexstring(b).is_err());
        }
    }

    // add_extension tests
    #[test]
    fn add_extension_test() {
        let mut path = PathBuf::from("testfile.txt");
        let ext = "newext";
        add_extension(&mut path, ext);
        assert_eq!(path.to_str().unwrap(), "testfile.txt.newext");
    }

    #[test]
    fn add_extension_no_ext() {
        let mut path = PathBuf::from("testfile");
        let ext = "newext";
        add_extension(&mut path, ext);
        assert_eq!(path.to_str().unwrap(), "testfile.newext");
    }
}

mod filesign_test {
    use crate::filesigner::{gen_keypair, keynum_to_string, sign_file, verify_file};
    use crate::util::add_extension;
    use std::fs::{File, remove_file};
    use std::path::PathBuf;

    #[test]
    fn key_generation_and_usage() {
        let testfile = "keygen_testfile.txt".to_string();
        let key_prefix = "keygen_test";
        let pubkey = format!("{key_prefix}.pub");
        let privkey = format!("{key_prefix}.key");
        let content = b"Test content for key generation";
        let password = "password";

        // Cleanup before test
        for file in [&testfile, &pubkey, &privkey] {
            let _ = remove_file(file);
        }

        // Create test file
        assert!(File::create(&testfile).is_ok());
        assert!(std::fs::write(&testfile, content).is_ok());

        // Generate keypair
        assert!(gen_keypair(key_prefix, Some(password.to_string())).is_ok());

        // Derive signature file name
        let mut signature_file: PathBuf = testfile.clone().into();
        {
            let sk = minisign::SecretKey::from_file(&privkey, Some(password.to_string()))
                .expect("Failed to read private key");
            let pk = minisign::PublicKey::from_secret_key(&sk).expect("Failed to derive public key");
            add_extension(&mut signature_file, &keynum_to_string(&pk));
        }

        // Sign and verify file
        assert!(sign_file(&testfile, &privkey, Some(password.to_string())).is_ok());
        assert!(verify_file(&testfile, &pubkey).is_ok());

        // Cleanup after test
        for file in [&testfile, signature_file.to_str().unwrap(), &pubkey, &privkey] {
            assert!(remove_file(file).is_ok());
        }
    }
}
