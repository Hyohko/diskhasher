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

use {clap::Parser, diskhasher::*, regex::Regex, std::fs, std::path::Path, std::process};

/*
//#[clap(short,long)]
//logfile: Option<String>,
//#[clap(short,long)]
//success_log: Option<bool>,
*/

fn main() {
    let mut pool = create_threadpool().unwrap_or_else(|err| {
        println!("[-] ThreadPool error: {}", err);
        process::exit(1);
    });

    let args = Arguments::parse();

    println!("[+] Using the {:?} algorithm", args.algorithm);

    // Recursively enumerate directory
    let root_path = fs::canonicalize(Path::new(&args.directory)).unwrap_or_else(|_| {
        println!("[-] Could not canonicalize the path '{}'", args.directory);
        process::exit(1);
    });
    if !root_path.is_dir() {
        println!(
            "[-] Path '{}' is not a valid directory",
            root_path.display()
        );
        process::exit(1);
    }

    let hashfile_pattern = args
        .pattern
        .clone()
        .unwrap_or("NO_VALID_PATTERN".to_string());
    println!(
        "[+] Validating hashfile regular expression {:?}",
        hashfile_pattern
    );
    let hash_regex = Regex::new(&hashfile_pattern).unwrap_or_else(|_| {
        println!("[-] Invalid regular expression '{}'", hashfile_pattern);
        process::exit(1);
    });

    println!(
        "[+] Recursively listing all regular files in '{}'",
        root_path.display()
    );
    let all_files = recursive_dir(&root_path).unwrap_or_else(|_| {
        println!("[!] Unable to walk directory {}", root_path.display());
        process::exit(1);
    });

    let num_files: usize = start_hash_threads(&mut pool, all_files, &hash_regex, args).unwrap();

    // Wait for all threads to finish
    pool.join();
    hashcount_monitor(num_files);
    println!("[+] Done");
}
