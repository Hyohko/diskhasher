/*
    DISKHASHER v0.1 - 2022 by Hyohko

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
use super::*;

#[test]
fn splitline_empty() {
    let newline: String = "".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath /*&hash_hexpattern()*/);
    assert!(result.is_err());
}

#[test]
fn splitline_notenough_args() {
    let newline: String = "asdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath /*&hash_hexpattern()*/);
    assert!(result.is_err());
}

#[test]
fn splitline_badhash() {
    let newline: String = "asdfasdfasdf asdfasdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath /*&hash_hexpattern()*/);
    assert!(result.is_err());
}

#[test]
fn splitline_hashtooshort() {
    let newline: String = "abcdef123456 asdfasdfasdfasdf".to_string();
    let hashpath: PathBuf = PathBuf::new();
    let result = split_hashfile_line(&newline, &hashpath /*&hash_hexpattern()*/);
    assert!(result.is_err());
}
