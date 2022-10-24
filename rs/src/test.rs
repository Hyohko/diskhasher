use super::*;

#[test]
fn splitline_empty() {
    let newline: String = "".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath, &hash_hexpattern());
    assert!(result.is_err());
}

#[test]
fn splitline_notenough_args() {
    let newline: String = "asdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath, &hash_hexpattern());
    assert!(result.is_err());
}

#[test]
fn splitline_badhash() {
    let newline: String = "asdfasdfasdf asdfasdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath, &hash_hexpattern());
    assert!(result.is_err());
}

#[test]
fn splitline_hashtooshort() {
    let newline: String = "abcdef123456 asdfasdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath, &hash_hexpattern());
    assert!(result.is_err());
}
