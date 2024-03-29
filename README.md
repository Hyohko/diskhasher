# dkhash

A utility for calculating the checksums of all files on a given disk. If a checksum file is provided, then calculate only the checksums of the files listed and compare them against the give sums, reporting back any failures. For example:

```bash
./dkhash -d /path/to/folder -f md5sum_destination.txt -a md5 -l ./failures.log
```

This utility will spin up as many new threads as the processor will support to parallelize the computation of checksums.

## Preferred Build

The preferred build mode uses the Phusion Holy Build Box to build a cross-platform/"portable" binary. This script will pull down the latest Holy Build Box Docker container and execute the build process inside it. This has the advantage of linking against the oldest possible GLIBC that the HBB supports, and should work on anything later than CentOS 7 / Ubuntu 14.04. Execute the following script, which will automatically get the lastest HBB from the Docker hub:

```bash
cd /path/to/dkhash/
# Rust builds
./execute-hbb-build.sh rust release
./execute-hbb-build.sh rust debug
./execute-hbb-build.sh rust native

# C++ Builds
./execute-hbb-build.sh cpp release
./execute-hbb-build.sh cpp debug

./dkhash .....
```

# Rust

To build the project just using CARGO and not the Holy Build Box:

```bash
cd /path/to/dkhash/rs
cargo build --release
```

## Print the help/usage statement

```
$ ./dkhash -h
Recursive directory file hasher - computes cryptographic checksums for every
file in a directory. Supports a variety of hash algorithms, see --help for
details

Usage: dkhash <COMMAND>

Commands:
  dir     Recursively hash a single directory
  file    Compute the cryptographic checksum of a single file
  sign    Compute the Ed22519 digital signature of a single file
  verify  Validate the cryptographic checksum of a single file
  genkey  Generate a new Ed22519 Public/Private keypair for signing and
              validating files
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Print the help/usage statements for the **dir** command:

```
$ ./dkhash dir -h
Recursively hash a single directory

Usage: dkhash dir [OPTIONS] --alg <algorithm> <directory>

Arguments:
  <directory>  Path to the directory we want to validate

Options:
  -a, --alg <algorithm>
          Algorithm to use [possible values: md5, sha1, sha224, sha256, sha384,
          sha512, sha3-224, sha3-256, sha3-384, sha3-512]
  -f, --file-pattern <pattern>
          [Optional] Regex pattern used to identify hashfiles (e.g. md5sum*.txt)
  -s, --sort <sorting>
          File sorting order [possible values: inode-order, largest-first,
          smallest-first]
  -j, --jobs <jobs>
          [Optional] number of jobs (will be capped by number of cores)
  -l, --log <logfile>
          [Optional] File to log hashing results
  -g, --generate-hashfile <generate_hashfile>
          [Optional] create hashfile in a similar format to md5sum, etc.
  -x, --force
          Force computation of hashes even if hash pattern fails or is omitted
  -v, --verbose
          Print all results to stdout
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```

```
$ ./dkhash dir --help
Recursively hash a single directory

Usage: dkhash dir [OPTIONS] --alg <algorithm> <directory>

Arguments:
  <directory>
          dkhash will perform a cryptographic hash on every regular file in
          this directory and every one of its subdirectories. Symlinks and other
          non-file entities will be ignored

Options:
  -a, --alg <algorithm>
          dkhash currently supports multiple hashing algorithms. Users are
          encouraged to use more secure algorithms where possible, and although
          MD5 and SHA1 are included for backwards compatibility purposes, users
          should be aware that they are cryptographically broken and
          untrustworthy for more than basic error detection.

          Possible values:
          - md5:      MD5 (insecure)
          - sha1:     SHA1 (insecure)
          - sha224:   SHA224
          - sha256:   SHA256
          - sha384:   SHA384
          - sha512:   SHA512
          - sha3-224: SHA3-224
          - sha3-256: SHA3-256
          - sha3-384: SHA3-384
          - sha3-512: SHA3-512

  -f, --file-pattern <pattern>
          [Optional] This regular expression is used to identify hashfiles, i.e.
          files that were generated by md5sum or its equivalent for other hash
          algorithms. Each line in a hashfile should be formatted
                <hash_in_hexadecimal> <relative path to file from this hashfile>
           or
                <hash_in_hexadecimal> <absolute path to file>
          The parser will canonicalize all paths and validate that each file
          specified in the hashfile exists or print a relevant error message
          such as FileNotFound

  -s, --sort <sorting>
          [Optional] Depending on the size of the files in the directory, the
          user may want to see the largest files sorted first or the smallest.
          [Linux only] Inode-order hashing is the default method (ostensibly)
          for disk I/O speed especially on HDD drives to avoid thrashing the
          read/write heads above the platters

          Possible values:
          - inode-order:    Sort by inode order
          - largest-first:  Sort by largest first
          - smallest-first: Sort by smallest first

  -j, --jobs <jobs>
          For readability, the number of concurrently running threads performing
          file hashing is capped at either 12 threads or the max number of CPU
          cores available, whichever is smaller. The user may optionally run
          more jobs up to the max number of cores, but be warned that this may
          make the display unreadable.

  -l, --log <logfile>
          If provided, the logfile will record the hash results
          (success/failure) at this provided file location. If no directory is
          given as part of the file path, then this file will be written to the
          same directory as the dkhash executable.

  -g, --generate-hashfile <generate_hashfile>
          Writes a hashfile in the root directory as given by the --dir
          parameter, matching the format that md5sum, sha1sum, etc. use, e.g.
                <hash_hexstring> <relative_path_to_file_from_root>

  -x, --force
          If the --force option is set, then every regular file in the target
          directory will be hashed even if there is no corresponding entry in an
          hashfile, and no validation of hashes will be performed

  -v, --verbose
          Normally, when a hashfile pattern is set, only hash failures (ones
          that don't match a hashfile entry) is printed to STDOUT - if verbose
          is called, print successes and failures

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
## Print the help/usage statements for the **file** command:

```
$ ./dkhash file -h
Compute the cryptographic checksum of a single file

Usage: dkhash file --alg <algorithm> <filepath>

Arguments:
  <filepath>  Path to the file

Options:
  -a, --alg <algorithm>  Algorithm to use [possible values: md5, sha1, sha224,
                         sha256, sha384, sha512, sha3-224, sha3-256, sha3-384,
                         sha3-512]
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

```
$ ./dkhash file --help
Compute the cryptographic checksum of a single file

Usage: dkhash file --alg <algorithm> <filepath>

Arguments:
  <filepath>
          Compute the selected cryptographic checksum of the given file. If the
          file path given is not absolute, then assume it is in the local
          directory.

Options:
  -a, --alg <algorithm>
          dkhash currently supports multiple hashing algorithms. Users are
          encouraged to use more secure algorithms where possible, and although
          MD5 and SHA1 are included for backwards compatibility purposes, users
          should be aware that they are cryptographically broken and
          untrustworthy for more than basic error detection.

          Possible values:
          - md5:      MD5 (insecure)
          - sha1:     SHA1 (insecure)
          - sha224:   SHA224
          - sha256:   SHA256
          - sha384:   SHA384
          - sha512:   SHA512
          - sha3-224: SHA3-224
          - sha3-256: SHA3-256
          - sha3-384: SHA3-384
          - sha3-512: SHA3-512

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Digitally sign a file

```
$ ./dkhash sign -h
Compute the Ed22519 digital signature of a single file

Usage: dkhash sign --private-key <private_key> <filepath>

Arguments:
  <filepath>  Path to the file to be signed (see --help for details)

Options:
  -k, --private-key <private_key>  Path to encrypted private key
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

```
$ ./dkhash sign --help
Compute the Ed22519 digital signature of a single file

Usage: dkhash sign --private-key <private_key> <filepath>

Arguments:
  <filepath>
          After generating a hashfile, use this command to apply an Ed22519
          Digital Signature to the file. If no pre-existing public/private
          keypair exist, you must create one using the 'genkey' command.

          FILE EXTENSION EXAMPLE:

          If the file you are signing is at '/path/to/hashfile.txt', then your
          signature file will be have the key identifier number appended to it.
          If your key id is '942505F94A549326' and you are signing
          '/path/to/hashfile.txt', the signature file will be at
          '/path/to/hashfile.txt.942505F94A549326'

Options:
  -k, --private-key <private_key>
          Path to an Ed22519 Private Key File, in the MiniSign format. You will
          be prompted to enter the password to decrypt this file.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Validate the digital signature of a file

```
$ ./dkhash verify -h
Verify the digital signature of a file

Usage: dkhash verify --public-key <public_key> <filepath>

Arguments:
  <filepath>  Path to the file being verified (see --help for details)

Options:
  -k, --public-key <public_key>  Path to public key
  -h, --help                     Print help (see more with '--help')
  -V, --version                  Print version
```

```
$ ./dkhash verify --help
Verify the digital signature of a file

Usage: dkhash verify --public-key <public_key> <filepath>

Arguments:
  <filepath>
          The signature of a file is stored in a separate file which must be
          kept in the same directory as the original file. The signature file
          must end with a hexadecimal extension matching the key identifier of
          the corresponding public key.

          For example, if the file being validated is at '/path/to/hashfile.txt'
          and the key id of the public key is '942505F94A549326', then the
          signature file must be at '/path/to/hashfile.txt.942505F94A549326'

Options:
  -k, --public-key <public_key>
          Path to an Ed22519 Public Key File, in the MiniSign format.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Generate a new Ed22519 Private/Public keypair for signing

```
$ ./dkhash genkey -h
Generate a new Ed22519 Public/Private keypair for signing and validating files

Usage: dkhash genkey --prefix <prefix>

Options:
  -p, --prefix <prefix>  Prefix for new keypair (see --help for details)
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

```
$ ./dkhash genkey --help
Generate a new Ed22519 Public/Private keypair for signing and validating files

Usage: dkhash genkey --prefix <prefix>

Options:
  -p, --prefix <prefix>
          Generate a new public/private Ed22519 keypair using this prefix to
          create the filenames. E.g. if the prefix is 'mykey', the public key
          will be created at './mykey.pub' and the corresponding private key
          will be created at './mykey.key'. You will be prompted to enter a
          password to secure the private key.

          Note that in order to generate a new keypair with the same prefix, you
          have to explicitly delete or rename the old keypair before 'genkey'
          will allow you to create a new one.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

# C++

Print the help/usage statement:

```bash
$ ./dkhash -h
[+] ./dkhash
 - Recursively calculate the crypto hashes for a directory
Usage:
  ./dkhash [OPTION...]

  -d, --root-dir arg       Path to folder / disk drive
  -f, --hashfile-name arg  Name of the file(s) containing hashes
                           (multiple files are separated by commas)
  -a, --algorithm arg      Hash algorithm (md5, sha1, sha256)
  -t, --run-tests          Run hash function self-test modules
  -n, --no-osapi-hash      Force the usage of built-in algorithms
                           (not recommended)
  -l, --log arg            Path to logfile (optional)
  -s, --log-success        Record successful hashes in logfile
                           (optional)
  -v, --verbose            Print all hashes to the screen, including
                           successful hashes
  -h, --help               Print help message
  -x, --force              Force computing hashes on a directory if
                           no checksum file is entered
```

To build as statically-linked, default Release mode (runs on most NIX systems):

```bash
cd /path/to/dkhash/cpp
make

./dkhash .....
```

To build for Linux using CMAKE (may not work on all systems):

```bash
cd /path/to/dkhash/cpp
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make

./dkhash .....
```

To build on Windows requires CMake and the Windows Visual Studio 2019 development kit (just the compilers and libraries), and you'll need to do all this in the Developer Command Prompt for VS2019:

```cmd
cd C:\path\to\dkhash\cpp
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
msbuild .\dkhash.sln /P:Configuration=Release;Platform=x64

% to run %
.\Release\dkhash.exe ....
```

Optionally, a build script has been included for use in either CMD or PowerShell, which invokes the Developer Command Prompt script for loading all the necessary environment variables, and can be found at **C:\path\to\dkhash\cpp\winbuild.bat**