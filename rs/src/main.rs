/*
    DISKHASHER - 2023 by Hyohko

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

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use {
    dkhash::{gen_keypair, hash_single_file, parse_cli, sign_file, verify_file, HashMode, Hasher},
    log::LevelFilter,
};

/// Main function
fn main() {
    if !(cfg!(target_os = "windows") || cfg!(target_os = "linux")) {
        panic!("Unsupported operating system")
    }
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Info)
        .init();

    let cli = match parse_cli() {
        Ok(v) => v,
        Err(err) => {
            error!("[!] Arguments: {err}");
            return;
        }
    };

    match cli {
        HashMode::RecursiveDir(args) => {
            let mut myhasher = match Hasher::new(
                args.algorithm,
                &args.path_string,
                args.pattern,
                args.logfile,
                args.jobs,
                args.generate_hashfile,
            ) {
                Ok(v) => v,
                Err(err) => {
                    error!("[!] Init: {err}");
                    return;
                }
            };
            if let Err(err) = myhasher.run(args.force, args.verbose, args.sorting) {
                error!("[!] Runtime: {err}");
                return;
            };
        }
        HashMode::SingleFile(args) => {
            if let Err(err) = hash_single_file(&args.path_string, args.algorithm) {
                error!("[!] Runtime: {err}");
                return;
            }
        }
        HashMode::SignFile(args) => match sign_file(args.path_string, args.keyfile) {
            Ok(()) => info!("[+] File signed successfully"),
            Err(err) => {
                error!("[!] Failed to sign file");
                error!("[!] Runtime: {err}");
                return;
            }
        },
        HashMode::VerifyFile(args) => match verify_file(args.path_string, args.keyfile) {
            Ok(()) => info!("[+] Signature is valid"),
            Err(err) => {
                error!("[!] Signature failed to validate");
                error!("[!] Runtime: {err}");
                return;
            }
        },
        HashMode::GenKeyPair(args) => {
            if let Err(err) = gen_keypair(&args.keyfile) {
                error!("[!] Runtime: {err}");
                return;
            }
        }
    }
    info!("[+] Done");
}
