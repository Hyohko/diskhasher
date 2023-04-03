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
    diskhasher::{FileSortLogic, HashAlg, Hasher},
    log::LevelFilter,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Arguments {
    /// Path to the directory we want to validate
    ///
    /// Diskhasher will perform a cryptographic hash on every regular
    /// file in this directory and every one of its subdirectories. Symlinks
    /// and other non-file entities will be ignored.
    #[clap(short, long = "dir")]
    pub directory: String,
    /// Algorithm to use
    ///
    /// Diskhasher currently supports 7 hashing algorithms:
    /// MD5, SHA1, SHA224, SHA256, SHA284, and SHA512. Users are encouraged
    /// to use more secure algorithms where possible, although MD5 and SHA1
    /// are included for backwards compatibility purposes, despite the
    /// fact that they are cryptographically broken and untrustworthy.
    #[clap(short, long = "alg")]
    #[arg(value_enum)]
    pub algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles (e.g. md5sum*.txt)
    ///
    /// This regular expression is used to identify hashfiles, i.e.
    /// files that were generated by md5sum or its equivalent for other
    /// hash algorithms. Each line in a hashfile should be formatted
    /// <hash_in_hexadecimal> <relative path to file from this hashfile>
    /// or
    /// <<hash_in_hexadecimal> <absolute path to file>
    /// The parser will canonicalize all paths and validate that each
    /// file specified in the hashfile exists or print a relevant error
    /// message such as FileNotFound
    #[clap(short = 'f', long = "file-pattern")]
    pub pattern: Option<String>,
    /// Force computation of hashes even if hash pattern fails or is omitted
    ///
    /// If the --force option is set, then every regular file in the target
    /// directory will be hashed even if there is no corresponding
    /// entry in an hashfile, and no validation of hashes will be performed.
    #[clap(short = 'x', long, action)]
    pub force: bool,
    /// Print all results to stdout
    ///
    /// Normally, when a hashfile pattern is set, only hash failures (ones
    /// that don't match a hashfile entry) is printed to STDOUT - if verbose
    /// is called, print successes and failures.
    #[clap(short, long, action)]
    pub verbose: bool,
    /// File sorting order
    ///
    /// Depending on the size of the files in the directory, the user
    /// may want to see the largest files sorted first or the smallest.
    /// Inode-order hashing is the default method (ostensibly) for disk
    /// I/O speed especially on HDD drives to avoid thrashing the read/write
    /// heads above the platters.
    #[clap(short, long = "sort")]
    #[cfg(target_os = "linux")]
    #[cfg_attr(target_os = "linux", arg(value_enum, default_value_t=FileSortLogic::InodeOrder))]
    pub sorting: FileSortLogic,
    /// File sorting order
    ///
    /// Depending on the size of the files in the directory, the user
    /// may want to see the largest files sorted first or the smallest.
    #[clap(short, long = "sort")]
    #[cfg(target_os = "windows")]
    #[cfg_attr(target_os = "windows", arg(value_enum, default_value_t=FileSortLogic::LargestFirst))]
    pub sorting: FileSortLogic,
    /// [Optional] File to log hashing results
    ///
    /// If provided, the logfile will record the hash results (success/failure)
    /// at this provided file location. If no directory is given as part
    /// of the file path, then this file will be written to the same directory
    /// as the diskhasher executable.
    #[clap(short, long = "log")]
    pub logfile: Option<String>,
    /// [Optional] number of jobs (will be capped by number of cores)
    ///
    /// For readability, the number of concurrently running threads
    /// performing file hashing is capped at either 12 threads or the
    /// max number of CPU cores available, whichever is smaller. The user
    /// may optionally run more jobs up to the max number of cores, but
    /// be warned that this may make the display unreadable.
    #[clap(short, long)]
    pub jobs: Option<usize>,
}

fn main() {
    if !(cfg!(target_os = "windows") || cfg!(target_os = "linux")) {
        panic!("Unsupported operating system")
    }
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Info)
        .init();

    let args = Arguments::parse();

    let mut myhasher = match Hasher::new(
        args.algorithm,
        args.directory.clone(),
        args.pattern,
        args.logfile,
        args.jobs,
    ) {
        Ok(v) => v,
        Err(err) => {
            error!("[!] Hasher constructor error => {err}");
            return;
        }
    };
    if let Err(err) = myhasher.run(args.force, args.verbose, args.sorting) {
        error!("[!] Hasher runtime failure => {err}");
        return;
    };
    info!("[+] Done");
}
