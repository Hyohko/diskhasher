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

mod dirhasher_filtering {
    use crate::enums::{FileSortLogic, HashAlg};
    use crate::hasher::DirHasher;
    use std::fs::{create_dir_all, remove_dir_all, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::env; // For current_dir
    use std::io::ErrorKind; // Error was unused

    const TEST_SUB_DIR: &str = "dkhash_test_data"; // Subdirectory within target
    // TEST_DIR_NAME will now be a base, tests will append to it.

    fn get_target_dir_path() -> PathBuf {
        PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string()))
    }

    fn setup_test_directory(test_id: &str) -> PathBuf {
        let target_dir = get_target_dir_path();
        let test_data_base_dir = target_dir.join(TEST_SUB_DIR);

        create_dir_all(&test_data_base_dir)
            .expect(&format!("Failed to create test data base directory: {:?}", test_data_base_dir));

        let unique_test_dir_name = format!("temp_test_dir_filtering_{}", test_id);
        let test_run_dir = test_data_base_dir.join(unique_test_dir_name);

        // eprintln!("[SETUP {}] Test directory to be created/used: {:?}", test_id, test_run_dir); // DEBUG

        // Attempt to remove if it exists. Panic if removal fails for a reason other than NotFound.
        if test_run_dir.exists() {
            if let Err(e) = remove_dir_all(&test_run_dir) {
                if e.kind() != ErrorKind::NotFound {
                    panic!("[SETUP {}] Failed to remove pre-existing test directory {:?}: {}", test_id, test_run_dir, e);
                } else {
                    eprintln!("[SETUP {}] Warning: Test directory {:?} reported existing, but remove_dir_all failed with NotFound. Proceeding.", test_id, test_run_dir);
                }
            }
        }

        create_dir_all(&test_run_dir)
            .expect(&format!("[SETUP {}] Failed to create root test directory: {:?}", test_id, test_run_dir));

        // Canonicalize the path that will be returned and used for creating contents
        let canonical_test_run_dir = match test_run_dir.canonicalize() {
             Ok(path) => path,
             Err(e) => panic!("[SETUP {}] Failed to canonicalize test run directory path {:?}: {}", test_id, test_run_dir, e),
        };
        // eprintln!("[SETUP {}] Canonical test run directory for content creation: {:?}", test_id, canonical_test_run_dir); // DEBUG


        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, f1); // DEBUG
        File::create(canonical_test_run_dir.join("file1.txt")).and_then(|mut f| f.write_all(b"content1")).expect("Failed to create file1.txt");

        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, f2); // DEBUG
        File::create(canonical_test_run_dir.join("file2.log")).and_then(|mut f| f.write_all(b"content2")).expect("Failed to create file2.log");

        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, hf1); // DEBUG
        File::create(canonical_test_run_dir.join(".hidden_file.txt")).and_then(|mut f| f.write_all(b"hidden_content")).expect("Failed to create .hidden_file.txt");

        let subdir1_path = canonical_test_run_dir.join("subdir1");
        // eprintln!("[SETUP {}] Creating directory: {:?}", test_id, subdir1_path); // DEBUG
        create_dir_all(&subdir1_path).expect("Failed to create subdir1");

        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, f3); // DEBUG
        File::create(subdir1_path.join("file3.txt")).and_then(|mut f| f.write_all(b"content3")).expect("Failed to create subdir1/file3.txt");

        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, hf2); // DEBUG
        File::create(subdir1_path.join(".hidden_file2.txt")).and_then(|mut f| f.write_all(b"hidden_content2")).expect("Failed to create subdir1/.hidden_file2.txt");

        let hidden_subdir_path = canonical_test_run_dir.join(".hidden_subdir");
        // eprintln!("[SETUP {}] Creating directory: {:?}", test_id, hidden_subdir_path); // DEBUG
        create_dir_all(&hidden_subdir_path).expect("Failed to create .hidden_subdir");

        // eprintln!("[SETUP {}] Creating file: {:?}", test_id, f4); // DEBUG
        File::create(hidden_subdir_path.join("file4.txt")).and_then(|mut f| f.write_all(b"content4")).expect("Failed to create .hidden_subdir/file4.txt");

        canonical_test_run_dir
    }

    fn cleanup_test_directory(root_dir_path: &PathBuf, test_id: &str) {
        // eprintln!("[CLEANUP {}] Attempting to remove directory: {:?}", test_id, root_dir_path); // DEBUG
        if root_dir_path.exists() {
            if let Err(e) = remove_dir_all(root_dir_path) {
                eprintln!("[CLEANUP {}] Warning: Failed to remove test directory {:?}: {}", test_id, root_dir_path, e); // Keep this warning
            }
        } else {
            // eprintln!("[CLEANUP {}] Directory already removed or never existed: {:?}", test_id, root_dir_path); // DEBUG
        }
    }

    // Helper to extract filenames from DirHasher output
    // Actual output line format in `output.hashes` is: HASH ./filepath
    // e.g., 7e55db001d319a94b0b713529a756623 ./file1.txt
    // or dc1c8eb6097ddaf0068ddb43e6fc1410 ./.hidden_file.txt
    fn extract_filename_from_output(line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 { // Expecting HASH and PATH
            let path_with_dot_slash = parts[1];
            // Remove leading "./" to match expected format like "file1.txt" or ".hidden_file.txt"
            // If path is just ".", like for ".hidden_file.txt" becoming ".hidden_file.txt" after stripping "./"
            // which is what we want.
            if let Some(stripped_path) = path_with_dot_slash.strip_prefix("./") {
                return Some(stripped_path.to_string());
            } else {
                // This case handles paths that might not have "./" like absolute paths (not expected here)
                // or if the path itself is just "." (e.g. for a file named "." in root, unlikely for this project)
                return Some(path_with_dot_slash.to_string());
            }
        }
        None
    }

    #[test]
    fn test_hash_hidden_false() {
        let test_id = "test_hash_hidden_false";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern (not used for this test)
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            None, // include_regex
            None, // exclude_regex
            Some(false), // hash_hidden
        )
        .expect("Hasher creation failed");

        hasher
            .run(true, false, FileSortLogic::SmallestFirst) // force=true to hash all found files
            .expect("Hasher run failed");

        drop(hasher); // Explicitly drop hasher to ensure file handles are closed/flushed

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        eprintln!("[CONTENT {}] Output hash file content:\n{}", test_id, output_content);
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort(); // Sort for consistent comparison

        // Expected files when hash_hidden is false
        let mut expected_files = vec![
            "file1.txt",
            "file2.log",
            "subdir1/file3.txt",
        ];
        // The paths in output are relative to the root_dir used by DirHasher,
        // which itself is canonicalized.
        // extract_filename_from_output already strips "./"
        // Let's adjust expected to match this format.
        expected_files.sort();

        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_hash_hidden_true() {
        let test_id = "test_hash_hidden_true";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            None, // include_regex
            None, // exclude_regex
            Some(true), // hash_hidden
        )
        .expect("Hasher creation failed");

        hasher
            .run(true, false, FileSortLogic::SmallestFirst)
            .expect("Hasher run failed");

        drop(hasher); // Explicitly drop hasher to ensure file handles are closed/flushed

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        // eprintln!("[CONTENT {}] Output hash file content:\n{}", test_id, output_content); // DEBUG Commented out
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        // Expected files when hash_hidden is true
        let mut expected_files = vec![
            ".hidden_file.txt",
            ".hidden_subdir/file4.txt",
            "file1.txt",
            "file2.log",
            "subdir1/.hidden_file2.txt",
            "subdir1/file3.txt",
        ];
        expected_files.sort();

        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_include_regex_txt_files() {
        let test_id = "test_include_regex_txt_files";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            Some(r"\.txt$".to_string()), // include_regex_pattern
            None, // exclude_regex_pattern
            Some(true), // hash_hidden = true
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        let mut expected_files = vec![
            "file1.txt",
            ".hidden_file.txt",
            "subdir1/file3.txt",
            "subdir1/.hidden_file2.txt",
            ".hidden_subdir/file4.txt", // This was missing
        ];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_include_regex_log_files_hash_hidden_false() {
        let test_id = "test_include_regex_log_files_hash_hidden_false";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            Some(r"\.log$".to_string()), // include_regex_pattern
            None, // exclude_regex_pattern
            Some(false), // hash_hidden = false
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        let mut expected_files = vec!["file2.log"];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_include_regex_no_match() {
        let test_id = "test_include_regex_no_match";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            Some(r"non_existent_pattern".to_string()), // include_regex_pattern
            None, // exclude_regex_pattern
            Some(true), // hash_hidden = true
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();

        assert!(processed_files.is_empty(), "Expected no files to be processed, but got: {:?}", processed_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_exclude_regex_log_files() {
        let test_id = "test_exclude_regex_log_files";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            None, // include_regex_pattern
            Some(r"\.log$".to_string()), // exclude_regex_pattern
            Some(true), // hash_hidden = true
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        let mut expected_files = vec![
            "file1.txt",
            ".hidden_file.txt",
            "subdir1/file3.txt",
            "subdir1/.hidden_file2.txt",
            ".hidden_subdir/file4.txt",
            // file2.log is excluded
        ];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_exclude_regex_subdir1_hash_hidden_false() {
        let test_id = "test_exclude_regex_subdir1_hash_hidden_false";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            None, // include_regex_pattern
            Some(r"^subdir1/".to_string()), // exclude_regex_pattern for subdir1
            Some(false), // hash_hidden = false
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        // Expected: file1.txt, file2.log.
        // Hidden files (.hidden_file.txt, .hidden_subdir/file4.txt) are excluded by hash_hidden=false.
        // subdir1/* is excluded by regex.
        let mut expected_files = vec!["file1.txt", "file2.log"];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_exclude_regex_all_txt_files() {
        let test_id = "test_exclude_regex_all_txt_files";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            None, // include_regex_pattern
            Some(r"\.txt$".to_string()), // exclude_regex_pattern for all .txt files
            Some(true), // hash_hidden = true (so hidden .txt files are also considered for exclusion)
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        // Only file2.log should remain as all .txt files are excluded.
        let mut expected_files = vec!["file2.log"];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }

    #[test]
    fn test_exclude_overrides_include() {
        let test_id = "test_exclude_overrides_include";
        let root_dir = setup_test_directory(test_id);
        let output_hash_file = root_dir.join("output.hashes");

        let mut hasher = DirHasher::new(
            HashAlg::MD5,
            &root_dir.to_string_lossy(),
            None, // hashfile_pattern
            None, // logfile
            Some(1), // jobs
            Some(output_hash_file.to_string_lossy().to_string()), // gen_hashfile
            Some(r"\.txt$".to_string()), // include_regex_pattern for all .txt files
            Some(r"file1\.txt".to_string()), // exclude_regex_pattern for file1.txt specifically
            Some(true), // hash_hidden = true
        )
        .expect("Hasher creation failed");

        hasher.run(true, false, FileSortLogic::SmallestFirst).expect("Hasher run failed");
        drop(hasher);

        let output_content = std::fs::read_to_string(&output_hash_file).expect("Failed to read output hash file");
        let mut processed_files: Vec<String> = output_content
            .lines()
            .filter_map(|line| extract_filename_from_output(line))
            .collect();
        processed_files.sort();

        // All .txt files included, except file1.txt
        let mut expected_files = vec![
            ".hidden_file.txt",
            "subdir1/file3.txt",
            "subdir1/.hidden_file2.txt",
            ".hidden_subdir/file4.txt",
        ];
        expected_files.sort();
        assert_eq!(processed_files, expected_files);
        cleanup_test_directory(&root_dir, test_id);
    }
}

mod dirhasher_errors {
    use crate::enums::HashAlg;
    use crate::hasher::DirHasher;
    use std::fs::{File, remove_file};

    #[test]
    fn new_dirhasher_non_existent_path() {
        let non_existent_path = String::from("path/does/not/exist");
        let result = DirHasher::new(
            HashAlg::MD5,
            &non_existent_path,
            None, // hashfile_pattern
            None, // logfile
            None, // jobs
            None, // gen_hashfile
            None, // include_regex_pattern
            None, // exclude_regex_pattern
            None, // hash_hidden_opt
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_dirhasher_path_is_file() {
        let temp_file_path = "temp_test_file.txt";
        // Create a temporary file for the test
        assert!(File::create(temp_file_path).is_ok());

        let result = DirHasher::new(
            HashAlg::MD5,
            &String::from(temp_file_path),
            None, // hashfile_pattern
            None, // logfile
            None, // jobs
            None, // gen_hashfile
            None, // include_regex_pattern
            None, // exclude_regex_pattern
            None, // hash_hidden_opt
        );
        assert!(result.is_err());

        // Clean up the temporary file
        assert!(remove_file(temp_file_path).is_ok());
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
            None, // hashfile_pattern
            None, // logfile
            None, // jobs
            None, // gen_hashfile
            None, // include_regex_pattern
            None, // exclude_regex_pattern
            None, // hash_hidden_opt
        )
        .unwrap();
        println!("{:?}", hasher);
    }

    #[test]
    fn can_clone() {
        let hasher: DirHasher = DirHasher::new(
            HashAlg::MD5,
            &String::from("./"),
            None, // hashfile_pattern
            None, // logfile
            None, // jobs
            None, // gen_hashfile
            None, // include_regex_pattern
            None, // exclude_regex_pattern
            None, // hash_hidden_opt
        )
        .unwrap();
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
    use std::fs::{File, remove_file, remove_dir_all}; // Removed create_dir_all
    use std::io::Write; // Added for write_all
    use std::path::PathBuf;

    #[test]
    fn test_gen_keypair_invalid_path() {
        let invalid_path_prefix = "non_existent_dir/mykey";
        // Ensure the directory does not exist (and cannot be created by gen_keypair implicitly)
        // For this test, we rely on gen_keypair not creating parent directories.
        // If it did, this test would need a different approach, e.g. unwritable directory.

        let result = gen_keypair(invalid_path_prefix, Some("password".to_string()));
        assert!(result.is_err(), "gen_keypair should fail for invalid path prefix");

        // Cleanup: Attempt to remove if any part of the path was created (unlikely for this error)
        let pubkey_path = format!("{}.pub", invalid_path_prefix);
        let privkey_path = format!("{}.key", invalid_path_prefix);
        let _ = remove_file(pubkey_path);
        let _ = remove_file(privkey_path);
        if let Some(parent_dir) = PathBuf::from(invalid_path_prefix).parent() {
            if parent_dir.exists() && parent_dir.file_name().map_or(false, |name| name == "non_existent_dir") {
                 // Only remove if it's the specific dir we "conceptually" tried to use
                let _ = remove_dir_all(parent_dir);
            }
        }
    }

    #[test]
    fn test_sign_file_non_existent_private_key() {
        let test_file = "sign_test_file1.txt";
        File::create(test_file).expect("Failed to create test file").write_all(b"test content").unwrap();

        let result = sign_file(&test_file.to_string(), &"non_existent_private.key".to_string(), Some("password".to_string()));
        assert!(result.is_err(), "sign_file should fail for non-existent private key");

        let _ = remove_file(test_file);
        // No signature file should be created
    }

    #[test]
    fn test_sign_file_wrong_password() {
        let key_prefix = "test_sign_key_wrong_pw";
        let pubkey_path = format!("{}.pub", key_prefix);
        let privkey_path = format!("{}.key", key_prefix);
        gen_keypair(key_prefix, Some("actual_password".to_string())).expect("Key generation failed");

        let test_file = "sign_test_file2.txt";
        File::create(test_file).expect("Failed to create test file").write_all(b"test content").unwrap();

        let result = sign_file(&test_file.to_string(), &privkey_path, Some("wrong_password".to_string()));
        assert!(result.is_err(), "sign_file should fail for wrong password");

        let _ = remove_file(test_file);
        let _ = remove_file(pubkey_path);
        let _ = remove_file(privkey_path);
        // remove any potential signature file (though it shouldn't be created on error)
        // To get the keynum for potential signature file:
        if let Ok(pk) = minisign::PublicKey::from_file(format!("{}.pub",key_prefix)) {
             let mut sig_file_path = PathBuf::from(test_file);
             add_extension(&mut sig_file_path, &keynum_to_string(&pk));
             let _ = remove_file(sig_file_path);
        }
    }

    #[test]
    fn test_sign_file_non_existent_input_file() {
        let key_prefix = "test_sign_key_no_input";
        let pubkey_path = format!("{}.pub", key_prefix);
        let privkey_path = format!("{}.key", key_prefix);
        gen_keypair(key_prefix, Some("password".to_string())).expect("Key generation failed");

        let result = sign_file(&"non_existent_input.txt".to_string(), &privkey_path, Some("password".to_string()));
        assert!(result.is_err(), "sign_file should fail for non-existent input file");

        let _ = remove_file(pubkey_path);
        let _ = remove_file(privkey_path);
    }


    #[test]
    fn test_verify_file_non_existent_public_key() {
        let test_file = "verify_test_file1.txt";
        let sig_file = "verify_test_file1.txt.minisig"; // Dummy signature file name

        File::create(test_file).expect("Failed to create test file").write_all(b"test content").unwrap();
        File::create(sig_file).expect("Failed to create dummy sig file").write_all(b"dummy sig").unwrap(); // Content doesn't matter

        // verify_file derives the signature filename from the public key's embedded ID.
        // However, if the public key itself is missing, it should fail before that.
        let result = verify_file(&test_file.to_string(), &"non_existent_public.key".to_string());
        assert!(result.is_err(), "verify_file should fail for non-existent public key");

        let _ = remove_file(test_file);
        let _ = remove_file(sig_file);
    }

    #[test]
    fn test_verify_file_tampered_content() {
        let key_prefix = "test_verify_tamper_key";
        let pubkey_path_str = format!("{}.pub", key_prefix);
        let privkey_path_str = format!("{}.key", key_prefix);
        gen_keypair(key_prefix, Some("password".to_string())).expect("Key generation failed");

        let test_file_name = "verify_test_file_tamper.txt";
        File::create(test_file_name).expect("Failed to create test file").write_all(b"original content").unwrap();

        // Sign the original content
        sign_file(&test_file_name.to_string(), &privkey_path_str, Some("password".to_string())).expect("Signing failed");

        // Tamper the content
        File::create(test_file_name).expect("Failed to open for tampering").write_all(b"tampered content").unwrap();

        let result = verify_file(&test_file_name.to_string(), &pubkey_path_str);
        assert!(result.is_err(), "verify_file should fail for tampered content");

        // Cleanup
        let _ = remove_file(test_file_name); // Tampered file
        if let Ok(pk) = minisign::PublicKey::from_file(&pubkey_path_str) {
            let mut sig_file_path = PathBuf::from(test_file_name);
            add_extension(&mut sig_file_path, &keynum_to_string(&pk));
            let _ = remove_file(sig_file_path);
        }
        let _ = remove_file(pubkey_path_str);
        let _ = remove_file(privkey_path_str);
    }

    #[test]
    fn test_verify_file_wrong_signature_file() {
        let key_a_prefix = "test_key_a";
        let pubkey_a_path = format!("{}.pub", key_a_prefix);
        let privkey_a_path = format!("{}.key", key_a_prefix);
        gen_keypair(key_a_prefix, Some("pw_a".to_string())).expect("KeyA generation failed");

        let key_b_prefix = "test_key_b";
        // let pubkey_b_path = format!("{}.pub", key_b_prefix); // Not needed for this test logic
        let privkey_b_path = format!("{}.key", key_b_prefix);
        gen_keypair(key_b_prefix, Some("pw_b".to_string())).expect("KeyB generation failed");

        let file_a_name = "fileA_to_verify.txt";
        File::create(file_a_name).expect("Failed to create fileA").write_all(b"content for A").unwrap();

        // Sign file_a_name with key_a (this creates fileA_to_verify.txt.sigA - name depends on keyA's ID)
        sign_file(&file_a_name.to_string(), &privkey_a_path, Some("pw_a".to_string())).expect("Signing fileA failed");

        let file_b_name = "fileB_for_sig.txt"; // A different file
        File::create(file_b_name).expect("Failed to create fileB").write_all(b"content for B").unwrap();
        // Sign file_b_name with key_b to get a signature file. Let's call it fileB.sigB
        sign_file(&file_b_name.to_string(), &privkey_b_path, Some("pw_b".to_string())).expect("Signing fileB failed");

        // Manually rename fileB's signature to what verify_file would expect for fileA if keyA was used.
        // This is a bit tricky because verify_file derives the sig filename from pubkey_a_path.
        // Instead, let's try to verify file_a_name using pubkey_a_path, but ensure the actual signature file
        // on disk is the one generated by key_b for file_b_name.
        // This means we need to:
        // 1. Get signature path for file_a_name based on key_a.
        // 2. Get signature path for file_b_name based on key_b.
        // 3. Delete signature from step 1 (if it exists, though sign_file creates it).
        // 4. Rename signature from step 2 to the name from step 1.

        let pk_a = minisign::PublicKey::from_file(&pubkey_a_path).unwrap();
        let mut sig_path_for_file_a_with_key_a = PathBuf::from(file_a_name);
        add_extension(&mut sig_path_for_file_a_with_key_a, &keynum_to_string(&pk_a));

        // This is the signature from keyB for fileB
        let pk_b = minisign::PublicKey::from_file(format!("{}.pub", key_b_prefix)).unwrap();
        let mut sig_path_for_file_b_with_key_b = PathBuf::from(file_b_name);
        add_extension(&mut sig_path_for_file_b_with_key_b, &keynum_to_string(&pk_b));

        // Ensure sig_path_for_file_a_with_key_a (created by signing file_a_name with key_a_path) is replaced by
        // the signature from file_b_name signed by key_b_path.
        // The signature for file_a_name with key_a already exists. We want to replace its *content* effectively.
        // Easiest: just try to verify file_a_name with pubkey_a, but provide file_b's *actual signature data*.
        // The `verify_file` function internally constructs the expected signature file path.
        // So, we need to overwrite the *content* of file_a_name's signature file with file_b_name's signature content.

        let sig_b_content = std::fs::read(&sig_path_for_file_b_with_key_b).expect("Failed to read sig_B content");
        std::fs::write(&sig_path_for_file_a_with_key_a, sig_b_content).expect("Failed to overwrite sig_A with sig_B content");

        let result = verify_file(&file_a_name.to_string(), &pubkey_a_path);
        assert!(result.is_err(), "verify_file should fail when signature is for a different file/key");

        // Cleanup
        let _ = remove_file(file_a_name);
        let _ = remove_file(sig_path_for_file_a_with_key_a); // This was originally sig_A, then overwritten
        let _ = remove_file(file_b_name);
        let _ = remove_file(sig_path_for_file_b_with_key_b);
        let _ = remove_file(pubkey_a_path);
        let _ = remove_file(privkey_a_path);
        let _ = remove_file(format!("{}.pub", key_b_prefix));
        let _ = remove_file(privkey_b_path);
    }

    #[test]
    fn test_verify_file_non_existent_input_file() {
        let key_prefix = "test_verify_no_input_key";
        let pubkey_path_str = format!("{}.pub", key_prefix);
        let privkey_path_str = format!("{}.key", key_prefix);
        gen_keypair(key_prefix, Some("password".to_string())).expect("Key generation failed");

        let dummy_file_name_str = "verify_dummy_to_delete.txt";
        File::create(dummy_file_name_str).unwrap().write_all(b"content").unwrap();
        sign_file(&dummy_file_name_str.to_string(), &privkey_path_str, Some("password".to_string())).expect("Signing failed");

        let pk = minisign::PublicKey::from_file(&pubkey_path_str).unwrap();
        let mut sig_file_path_expected = PathBuf::from(dummy_file_name_str);
        add_extension(&mut sig_file_path_expected, &keynum_to_string(&pk));

        remove_file(dummy_file_name_str).expect("Failed to delete dummy input file");

        let result = verify_file(&"verify_dummy_to_delete.txt".to_string(), &pubkey_path_str); // Input file does not exist
        assert!(result.is_err(), "verify_file should fail for non-existent input file");

        let _ = remove_file(sig_file_path_expected);
        let _ = remove_file(pubkey_path_str);
        let _ = remove_file(privkey_path_str);
    }

    #[test]
    fn test_verify_file_non_existent_signature_file() {
        let key_prefix = "test_verify_no_sig_key";
        let pubkey_path_str = format!("{}.pub", key_prefix);
        let privkey_path_str = format!("{}.key", key_prefix); // Not strictly needed but good for cleanup
        gen_keypair(key_prefix, Some("password".to_string())).expect("Key generation failed");

        let test_file_name = "verify_test_file_no_sig.txt";
        File::create(test_file_name).expect("Failed to create test file").write_all(b"content").unwrap();

        // Signature file is NOT created for this test.
        // verify_file will derive the expected path and find nothing.

        let result = verify_file(&test_file_name.to_string(), &pubkey_path_str);
        assert!(result.is_err(), "verify_file should fail if the derived signature file does not exist");

        let _ = remove_file(test_file_name);
        let _ = remove_file(pubkey_path_str);
        let _ = remove_file(privkey_path_str);
    }

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
