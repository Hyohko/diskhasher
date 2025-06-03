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
use crate::enums::{FileSortLogic, HashAlg};

use clap::{
    Arg, ArgAction, ArgMatches, Command, FromArgMatches, command,
    error::{Error, ErrorKind},
    value_parser,
};

/// Various modes of operation for DKHASH - hash whole directories,
/// single files, sign/verify hashfiles, and generate Ed22519 keypairs
pub enum HashMode {
    /// Recursively hash every file in a directory and all subdirectories
    RecursiveDir(Arguments),
    /// Compute the hash of a single file
    OneFile(Arguments),
    /// Digitally sign a file with Ed22519
    SignFile(Arguments),
    /// Verify the Ed22519 digital signature
    VerifyFile(Arguments),
    /// Generate an Ed22519 keypair
    GenKeyPair(Arguments),
}

/// Structure for storing command line arguments as parsed by `clap`
pub struct Arguments {
    /// Path to file/directory we are processing. Used for directories
    /// being hashed, single files being hashed, or public/private keys
    /// used during signing/validation
    pub path_string: String,
    /// Hash algorithm used
    pub algorithm: HashAlg,
    /// Regex pattern used to identify hashfiles that will be parsed
    /// during directory hashing
    pub pattern: Option<String>,
    /// Force the hashing of a directory even if no hashfile is found
    pub force: bool,
    /// Print all the user-visible debug statements
    pub verbose: bool,
    /// The sorting order when hashing a directory
    pub sorting: FileSortLogic,
    /// Path for storing the results of a hashing run
    pub logfile: Option<String>,
    /// Number of concurrent threads that will operate simultaneously
    pub jobs: Option<u64>,
    /// Path to a hashfile that mimics the output of 'md5sum', used
    /// to store (on disk) the results of a hashing run when sending
    /// to someone else.
    pub generate_hashfile: Option<String>,
    /// Path to the public or private key being used in signing/verifying.
    /// Also stores the prefix for 'genkey'
    pub keyfile: String,
    /// Regex pattern to include files
    pub include_regex: Option<String>,
    /// Regex pattern to exclude files
    pub exclude_regex: Option<String>,
    /// Whether to hash hidden files and folders
    pub hash_hidden: Option<bool>,
}

const fn sorting_default() -> FileSortLogic {
    #[cfg(target_os = "windows")]
    {
        FileSortLogic::LargestFirst
    }
    #[cfg(target_os = "linux")]
    {
        FileSortLogic::InodeOrder
    }
}

impl FromArgMatches for Arguments {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::error::Error> {
        if let Some(matches) = matches.subcommand_matches("dir") {
            Ok(Self {
                path_string: matches.get_one::<String>("directory").unwrap().to_string(),
                algorithm: *matches.get_one::<HashAlg>("algorithm").unwrap(),
                pattern: matches.get_one::<String>("pattern").cloned(),
                force: matches.get_flag("force"),
                verbose: matches.get_flag("verbose"),
                sorting: matches.get_one::<FileSortLogic>("sorting").copied().unwrap_or_else(sorting_default),
                logfile: matches.get_one::<String>("logfile").cloned(),
                jobs: matches.get_one::<u64>("jobs").copied(),
                generate_hashfile: matches.get_one::<String>("generate_hashfile").cloned(),
                keyfile: "".to_string(),
                include_regex: matches.get_one::<String>("include_regex").cloned(),
                exclude_regex: matches.get_one::<String>("exclude_regex").cloned(),
                hash_hidden: matches.get_one::<bool>("hash_hidden").copied(),
            })
        } else if let Some(matches) = matches.subcommand_matches("file") {
            Ok(Self {
                path_string: matches.get_one::<String>("filepath").unwrap().to_string(),
                algorithm: *matches.get_one::<HashAlg>("algorithm").unwrap(),
                pattern: None,
                force: true,
                verbose: true,
                sorting: FileSortLogic::SmallestFirst, // unused
                logfile: None,
                jobs: None,
                generate_hashfile: None,
                keyfile: "".to_string(),
                include_regex: None,
                exclude_regex: None,
                hash_hidden: None,
            })
        } else if let Some(matches) = matches.subcommand_matches("sign") {
            Ok(Self {
                path_string: matches.get_one::<String>("filepath").unwrap().to_string(),
                algorithm: HashAlg::MD5, // Ignored
                pattern: None,
                force: true,
                verbose: true,
                sorting: FileSortLogic::SmallestFirst, // unused
                logfile: None,
                jobs: None,
                generate_hashfile: None,
                keyfile: matches.get_one::<String>("private_key").unwrap().to_string(),
                include_regex: None,
                exclude_regex: None,
                hash_hidden: None,
            })
        } else if let Some(matches) = matches.subcommand_matches("verify") {
            Ok(Self {
                path_string: matches.get_one::<String>("filepath").unwrap().to_string(),
                algorithm: HashAlg::MD5, // Ignored
                pattern: None,
                force: true,
                verbose: true,
                sorting: FileSortLogic::SmallestFirst, // unused
                logfile: None,
                jobs: None,
                generate_hashfile: None,
                keyfile: matches.get_one::<String>("public_key").unwrap().to_string(),
                include_regex: None,
                exclude_regex: None,
                hash_hidden: None,
            })
        } else if let Some(matches) = matches.subcommand_matches("genkey") {
            Ok(Self {
                path_string: "".to_string(),
                algorithm: HashAlg::MD5, // Ignored
                pattern: None,
                force: true,
                verbose: true,
                sorting: FileSortLogic::SmallestFirst, // unused
                logfile: None,
                jobs: None,
                generate_hashfile: None,
                keyfile: matches.get_one::<String>("prefix").unwrap().to_string(),
                include_regex: None,
                exclude_regex: None,
                hash_hidden: None,
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
            self.sorting = matches.get_one::<FileSortLogic>("sorting").copied().unwrap_or_else(sorting_default);
            self.logfile = matches.get_one::<String>("logfile").cloned();
            self.jobs = matches.get_one::<u64>("jobs").copied();
            self.generate_hashfile = matches.get_one::<String>("generate_hashfile").cloned();
            self.include_regex = matches.get_one::<String>("include_regex").cloned();
            self.exclude_regex = matches.get_one::<String>("exclude_regex").cloned();
            self.hash_hidden = matches.get_one::<bool>("hash_hidden").copied();
            Ok(())
        } else if let Some(matches) = matches.subcommand_matches("file") {
            self.path_string = matches.get_one::<String>("filepath").unwrap().to_string();
            self.algorithm = *matches.get_one::<HashAlg>("algorithm").unwrap();
            Ok(())
        } else if let Some(matches) = matches.subcommand_matches("sign") {
            self.path_string = matches.get_one::<String>("filepath").unwrap().to_string();
            self.keyfile = matches.get_one::<String>("private_key").unwrap().to_string();
            Ok(())
        } else if let Some(matches) = matches.subcommand_matches("verify") {
            self.path_string = matches.get_one::<String>("filepath").unwrap().to_string();
            self.keyfile = matches.get_one::<String>("public_key").unwrap().to_string();
            Ok(())
        } else if let Some(matches) = matches.subcommand_matches("genkey") {
            self.keyfile = matches.get_one::<String>("prefix").unwrap().to_string();
            Ok(())
        } else {
            Err(Error::new(ErrorKind::UnknownArgument))
        }
    }
}

fn dir_subcommand(alg_arg: &Arg) -> Command {
    #[cfg(target_os = "linux")]
    let sorting_long_help = "[Optional] Depending on the size of the files in the directory, the user \
    may want to see the largest files sorted first or the smallest. \
    \n[Linux only] Inode-order hashing is the default method (ostensibly) for disk \
    I/O speed especially on HDD drives to avoid thrashing the read/write \
    heads above the platters";

    #[cfg(target_os = "windows")]
    let sorting_long_help = "[Optional] Depending on the size of the files in the directory, the user \
    may want to see the largest files sorted first or the smallest. \
    \n[Windows only] File sorting defaults to largest file first.";

    Command::new("dir")
        .about("Recursively hash a single directory")
        .arg(
            Arg::new("directory")
                .required(true)
                .help("Path to the directory we want to validate")
                .long_help(
                    "dkhash will perform a cryptographic hash on every regular \
                file in this directory and every one of its subdirectories. \
                Symlinks and other non-file entities will be ignored",
                ),
        )
        .arg(alg_arg)
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
                .value_parser(value_parser!(u64).range(1..=255))
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
        .arg(
            Arg::new("include_regex")
                .long("include-regex")
                .required(false)
                .help("[Optional] Regex pattern for files to include in hashing")
                .long_help(
                    "Only files matching this regex will be processed. \
                    Cannot be used with --exclude-regex.",
                ),
        )
        .arg(
            Arg::new("exclude_regex")
                .long("exclude-regex")
                .required(false)
                .conflicts_with("include_regex")
                .help("[Optional] Regex pattern for files/directories to exclude from hashing")
                .long_help(
                    "Files or directories matching this regex will be skipped. \
                    Cannot be used with --include-regex.",
                ),
        )
        .arg(
            Arg::new("hash_hidden")
                .long("hash-hidden")
                .required(false)
                .action(ArgAction::SetTrue) // Makes it a flag, if present it's true
                .help("[Optional] Include hidden files and directories in hashing")
                .long_help(
                    "If set, hidden files and directories (those starting with a '.') \
                    will be processed. By default, they are skipped unless an include_regex matches them explicitly.",
                ),
        )
}

fn file_subcommand(alg_arg: &Arg) -> Command {
    Command::new("file")
        .about("Compute the cryptographic checksum of a single file")
        .arg(
            Arg::new("filepath")
                .required(true)
                .help("Path to the file")
                .long_help(
                    "Compute the selected cryptographic checksum of the given \
        file. If the file path given is not absolute, then assume it is \
        in the local directory.",
                ),
        )
        .arg(alg_arg)
}

fn sign_subcommand() -> Command {
    Command::new("sign")
        .about("Compute the Ed22519 digital signature of a single file")
        .arg(
            Arg::new("filepath")
                .required(true)
                .help("Path to the file to be signed (see --help for details)")
                .long_help(
                    "After generating a hashfile, use this command to \
                    apply an Ed22519 Digital Signature to the file. If no pre-existing \
                    public/private keypair exist, you must create one using the 'genkey' \
                    command. \n\n\
                    FILE EXTENSION EXAMPLE: \n\n\
                    If the file you are signing is at '/path/to/hashfile.txt', \
                    then your signature file will be have the key identifier number \
                    appended to it. If your key id is '942505F94A549326' and you \
                    are signing '/path/to/hashfile.txt', the signature file will be at \
                    '/path/to/hashfile.txt.942505F94A549326'",
                ),
        )
        .arg(
            Arg::new("private_key")
                .short('k')
                .long("private-key")
                .required(true)
                .help("Path to encrypted private key")
                .long_help(
                    "Path to an Ed22519 Private Key File, in the MiniSign format. \
                    You will be prompted to enter the password to decrypt this file.",
                ),
        )
}

fn verify_subcommand() -> Command {
    Command::new("verify")
        .about("Verify the digital signature of a file")
        .arg(
            Arg::new("filepath")
                .required(true)
                .help("Path to the file being verified (see --help for details)")
                .long_help(
                    "The signature of a file is stored in a separate file which must be kept in the \
                    same directory as the original file. The signature file must end with \
                    a hexadecimal extension matching the key identifier of the corresponding \
                    public key. \n\nFor example, if the file being validated is at '/path/to/hashfile.txt' \
                    and the key id of the public key is '942505F94A549326', then the signature file \
                    must be at '/path/to/hashfile.txt.942505F94A549326'",
                ),
        )
        .arg(
            Arg::new("public_key")
                .short('k')
                .long("public-key")
                .required(true)
                .help("Path to public key")
                .long_help("Path to an Ed22519 Public Key File, in the MiniSign format."),
        )
}

fn genkey_subcommand() -> Command {
    Command::new("genkey")
        .about("Generate a new Ed22519 Public/Private keypair for signing and validating files")
        .arg(
            Arg::new("prefix")
                .short('p')
                .long("prefix")
                .required(true)
                .help("Prefix for new keypair (see --help for details)")
                .long_help(
                    "Generate a new public/private Ed22519 keypair using this prefix to create \
                    the filenames. E.g. if the prefix is 'mykey', the public \
                    key will be created at './mykey.pub' and the corresponding \
                    private key will be created at './mykey.key'. You will be prompted to \
                    enter a password to secure the private key.\n\nNote that in order to generate \
                    a new keypair with the same prefix, you have to explicitly delete or rename the old \
                    keypair before 'genkey' will allow you to create a new one.",
                ),
        )
}

/// Parse the command line arguments and return an `Arguments` struct
pub fn parse_cli() -> Result<HashMode, clap::error::Error> {
    let alg_arg = Arg::new("algorithm")
        .short('a')
        .long("alg")
        .required(true)
        .value_parser(value_parser!(HashAlg))
        .help("Algorithm to use")
        .long_help(
            "dkhash currently supports multiple hashing algorithms. Users are \
            encouraged to use more secure algorithms where possible, and although MD5 \
            and SHA1 are included for backwards compatibility purposes, users should \
            be aware that they are cryptographically broken and untrustworthy for more \
            than basic error detection.",
        );

    let args = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(dir_subcommand(&alg_arg))
        .subcommand(file_subcommand(&alg_arg))
        .subcommand(sign_subcommand())
        .subcommand(verify_subcommand())
        .subcommand(genkey_subcommand())
        .max_term_width(80)
        .get_matches();

    let matches: Arguments = Arguments::from_arg_matches(&args)?;

    #[cfg(target_os = "windows")]
    {
        if matches.path_string.ends_with('"') {
            error!("[*] Remove the terminal '\\' from the path");
            error!(
                "[!] Re-run with path ==>\n\t'{}'",
                &matches.path_string[..matches.path_string.len() - 1]
            );
            return Err(clap::Error::new(ErrorKind::InvalidValue));
        }
    }

    match args.subcommand_name() {
        Some("dir") => Ok(HashMode::RecursiveDir(matches)),
        Some("file") => Ok(HashMode::OneFile(matches)),
        Some("sign") => Ok(HashMode::SignFile(matches)),
        Some("verify") => Ok(HashMode::VerifyFile(matches)),
        Some("genkey") => Ok(HashMode::GenKeyPair(matches)),
        _ => Err(clap::Error::new(ErrorKind::UnknownArgument)),
    }
}
