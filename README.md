# diskhasher

Print the help/usage statement:

```bash
$ ./diskhasher -h
[+] ./diskhasher
 - Recursively calculate the crypto hashes for a directory
Usage:
  ./diskhasher [OPTION...]

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

A utility for calculating the checksums of all files on a given disk. If a checksum file is provided, then calculate only the checksums of the files listed and compare them against the give sums, reporting back any failures. For example:

```bash
./diskhasher -d /path/to/folder -f md5sum_destination.txt -a md5 -l ./failures.log
```

This utility will spin up as many new threads as the processor will support to parallelize the computation of checksums.

The preferred build mode uses the Phusion Holy Build Box to build a cross-platform/"portable" binary. This script will pull down the latest Holy Build Box Docker container and execute the build process inside it. This has the advantage of linking against the oldest possible GLIBC that the HBB supports, and should work on anything later than CentOS 7 / Ubuntu 14.04. Execute the following script, which will automatically get the lastest HBB from the Docker hub:

```bash
cd /path/to/diskhasher/cpp
./execute-hbb-build.sh

./diskhasher .....
```

To build as statically-linked, default Release mode (runs on most NIX systems):

```bash
cd /path/to/diskhasher/cpp
make

./diskhasher .....
```

To build for Linux using CMAKE (may not work on all systems):

```bash
cd /path/to/diskhasher/cpp
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make

./diskhasher .....
```

To build on Windows requires CMake and the Windows Visual Studio 2019 development kit (just the compilers and libraries), and you'll need to do all this in the Developer Command Prompt for VS2019:

```cmd
cd C:\path\to\diskhasher\cpp
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
msbuild .\diskhasher.sln /P:Configuration=Release;Platform=x64

% to run %
.\Release\diskhasher.exe ....
```