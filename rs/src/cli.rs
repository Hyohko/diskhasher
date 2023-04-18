/*
    DISKHASHER v0.3 - 2023 by Hyohko

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
use crate::enums::{FileSortLogic, HashAlg};

use clap::{
    command,
    error::{Error, ErrorKind},
    value_parser, Arg, ArgAction, ArgMatches, Command, FromArgMatches,
};

pub enum HashMode {
    RecursiveDir,
    SingleFile,
    NoneSelected,
}

pub struct Arguments {
    pub path_string: String,
    pub algorithm: HashAlg,
    pub pattern: Option<String>,
    pub force: bool,
    pub verbose: bool,
    pub sorting: FileSortLogic,
    pub logfile: Option<String>,
    pub jobs: Option<usize>,
    pub generate_hashfile: Option<String>,
    pub mode: HashMode,
}

impl FromArgMatches for Arguments {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::error::Error> {
        if let Some(matches) = matches.subcommand_matches("dir") {
            let sorting = match matches.get_one::<FileSortLogic>("sorting") {
                Some(v) => *v,
                #[cfg(target_os = "windows")]
                None => FileSortLogic::LargestFirst,
                #[cfg(target_os = "linux")]
                None => FileSortLogic::InodeOrder,
            };
            Ok(Arguments {
                path_string: matches.get_one::<String>("directory").unwrap().to_string(),
                algorithm: *matches.get_one::<HashAlg>("algorithm").unwrap(),
                pattern: matches.get_one::<String>("pattern").cloned(),
                force: matches.get_flag("force"),
                verbose: matches.get_flag("verbose"),
                sorting,
                logfile: matches.get_one::<String>("logfile").cloned(),
                jobs: matches.get_one::<usize>("jobs").copied(),
                generate_hashfile: matches.get_one::<String>("generate_hashfile").cloned(),
                mode: HashMode::RecursiveDir,
            })
        } else if let Some(matches) = matches.subcommand_matches("file") {
            Ok(Self {
                path_string: matches.get_one::<String>("filepath").unwrap().to_string(),
                algorithm: *matches.get_one::<HashAlg>("algorithm").unwrap(),
                pattern: None,
                force: true,
                verbose: true,
                sorting: FileSortLogic::SmallestFirst, //unused
                logfile: None,
                jobs: None,
                generate_hashfile: None,
                mode: HashMode::SingleFile,
            })
        } else {
            Err(Error::new(ErrorKind::UnknownArgument))
        }
    }
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::error::Error> {
        if let Some(matches) = matches.subcommand_matches("dir") {
            self.path_string = matches.get_one::<String>("directory").unwrap().to_string();
            self.algorithm = *matches.get_one::<HashAlg>("algorithm").unwrap();
            self.pattern = matches.get_one::<String>("pattern").cloned();
            self.force = matches.get_flag("force");
            self.verbose = matches.get_flag("verbose");
            self.sorting = match matches.get_one::<FileSortLogic>("sorting") {
                Some(v) => *v,
                #[cfg(target_os = "windows")]
                None => FileSortLogic::LargestFirst,
                #[cfg(target_os = "linux")]
                None => FileSortLogic::InodeOrder,
            };
            self.logfile = matches.get_one::<String>("logfile").cloned();
            self.jobs = matches.get_one::<usize>("jobs").copied();
            self.generate_hashfile = matches.get_one::<String>("generate_hashfile").cloned();
            return Ok(());
        } else if let Some(matches) = matches.subcommand_matches("file") {
            self.path_string = matches.get_one::<String>("filepath").unwrap().to_string();
            self.algorithm = *matches.get_one::<HashAlg>("algorithm").unwrap();
            return Ok(());
        } else {
            return Err(Error::new(ErrorKind::UnknownArgument));
        }
    }
}

pub fn parse_cli() -> Result<Arguments, clap::error::Error> {
    #[cfg(target_os = "linux")]
    let sorting_long_help =
        "[Optional] Depending on the size of the files in the directory, the user \
    may want to see the largest files sorted first or the smallest. \
    \n[Linux only] Inode-order hashing is the default method (ostensibly) for disk \
    I/O speed especially on HDD drives to avoid thrashing the read/write \
    heads above the platters";

    #[cfg(target_os = "windows")]
    let sorting_long_help =
        "[Optional] Depending on the size of the files in the directory, the user \
    may want to see the largest files sorted first or the smallest. \
    \n[Windows only] File sorting defaults to largest file first.";

    let alg_arg = Arg::new("algorithm")
        .short('a')
        .long("alg")
        .required(true)
        .value_parser(value_parser!(HashAlg))
        .help("Algorithm to use")
        .long_help(
            "Diskhasher currently supports multiple hashing algorithms. Users are \
            encouraged to use more secure algorithms where possible, and although MD5 \
            and SHA1 are included for backwards compatibility purposes, users should \
            be aware that they are cryptographically broken and untrustworthy for more \
            than basic error detection.",
        );

    let args = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("dir")
            .about("Recursively hash a single directory")
            .arg(
                Arg::new("directory")
                    .required(true)
                    .help("Path to the directory we want to validate")
                    .long_help(
                        "Diskhasher will perform a cryptographic hash on every regular \
                        file in this directory and every one of its subdirectories. \
                        Symlinks and other non-file entities will be ignored"
                    ),
                )
            .arg(&alg_arg)
            .arg(
                Arg::new("pattern")
                    .short('f')
                    .long("file-pattern")
                    .required(false)
                    .help("[Optional] Regex pattern used to identify hashfiles (e.g. md5sum*.txt)")
                    .long_help(
                        "[Optional] This regular expression is used to identify hashfiles, i.e. \
                        files that were generated by md5sum or its equivalent for other \
                        hash algorithms. Each line in a hashfile should be formatted \
                        \n\t<hash_in_hexadecimal> <relative path to file from this hashfile> \
                        \n \
                        or \
                        \n\t<hash_in_hexadecimal> <absolute path to file> \
                        \nThe parser will canonicalize all paths and validate that each \
                        file specified in the hashfile exists or print a relevant error \
                        message such as FileNotFound",
                    ),
            )
            .arg(
                Arg::new("sorting")
                    .short('s')
                    .long("sort")
                    .required(false)
                    .value_parser(value_parser!(FileSortLogic))
                    .help("File sorting order")
                    .long_help(sorting_long_help),
            )
            .arg(
                Arg::new("jobs")
                    .short('j')
                    .long("jobs")
                    .required(false)
                    .value_parser(value_parser!(u8).range(1..))
                    .help("[Optional] number of jobs (will be capped by number of cores)")
                    .long_help(
                        "For readability, the number of concurrently running threads \
                        performing file hashing is capped at either 12 threads or the \
                        max number of CPU cores available, whichever is smaller. The user \
                        may optionally run more jobs up to the max number of cores, but \
                        be warned that this may make the display unreadable.",
                    ),
            )
            .arg(
                Arg::new("logfile")
                    .short('l')
                    .long("log")
                    .required(false)
                    .help("[Optional] File to log hashing results")
                    .long_help(
                        "If provided, the logfile will record the hash results (success/failure) \
                        at this provided file location. If no directory is given as part \
                        of the file path, then this file will be written to the same directory \
                        as the dkhash executable.",
                    ),
            )
            .arg(
                Arg::new("generate_hashfile")
                    .short('g')
                    .long("generate-hashfile")
                    .required(false)
                    .requires("force")
                    .help("[Optional] create hashfile in a similar format to md5sum, etc.")
                    .long_help(
                        "Writes a hashfile in the root directory as given by the --dir \
                        parameter, matching the format that md5sum, sha1sum, etc. use, e.g. \
                        \n\t<hash_hexstring> <relative_path_to_file_from_root>",
                    ),
            )
            .arg(
                Arg::new("force")
                    .short('x')
                    .long("force")
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("Force computation of hashes even if hash pattern fails or is omitted")
                    .long_help(
                        "If the --force option is set, then every regular file in the target \
                        directory will be hashed even if there is no corresponding \
                        entry in an hashfile, and no validation of hashes will be performed",
                    ),
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("Print all results to stdout")
                    .long_help(
                        "Normally, when a hashfile pattern is set, only hash failures (ones \
                        that don't match a hashfile entry) is printed to STDOUT - if verbose \
                        is called, print successes and failures",
                    ),
            )
        )
        .subcommand(Command::new("file")
            .about("Compute the cryptographic checksum of a single file")
            .arg(
                Arg::new("filepath")
                    .required(true)
                    .help("Path to the file")
                    .long_help(
                        "Compute the selected cryptographic checksum of the given \
                        file. If the file path given is not absolute, then assume it is \
                        in the local directory."
                    ),
                )
            .arg(&alg_arg)
        )
        .max_term_width(80)
        .get_matches();
    Arguments::from_arg_matches(&args)
}
