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

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use {
    clap::Parser,
    diskhasher::{HashAlg, Hasher, HasherError},
    log::LevelFilter,
};

#[derive(Parser)]
#[clap(
    author = "Hyohko",
    version = "0.1",
    about = "Hash a directory's files and optionally check against existing hashfile"
)]
struct Arguments {
    /// Path to the directory we want to validate
    #[clap(short, long)]
    pub directory: String,
    /// Algorithm to use
    #[clap(short, long)]
    #[arg(value_enum)]
    pub algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles
    #[clap(short, long)]
    pub pattern: Option<String>,
    /// Force computation of hashes even if hash pattern fails or is omitted
    #[clap(short, long, action)]
    pub force: bool,
    /// Print all results to stdout
    #[clap(short, long, action)]
    pub verbose: bool,
    /// Hash largest files first instead of smallest files
    #[clap(short, long, action)]
    pub largest: bool,
}

fn main() -> Result<(), HasherError> {
    let mut _logbuilder = pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Info)
        .init();

    let args = Arguments::parse();
    let pattern = args
        .pattern
        .clone()
        .unwrap_or("NO_VALID_PATTERN".to_string());
    let root = args.directory.clone();
    let mut myhasher = match Hasher::new(args.algorithm, root, pattern) {
        Ok(v) => v,
        Err(_e) => {
            error!("[!] Hasher constructor error => {}", _e);
            return Err(_e);
        }
    };
    let _runval = match myhasher.run(args.force, args.verbose, args.largest) {
        Ok(v) => v,
        Err(_e) => {
            error!("[!] Hasher runtime failure => {}", _e);
            return Err(_e);
        }
    };
    info!("[+] Done");
    Ok(())
}
