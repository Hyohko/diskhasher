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

    ##################################
    Note to any future developer
    ##################################
    In writing this, we assume that:
    1) The hash checksum file is kept in the same directory where the files it references live -OR-
        it lives in the root of the directory we are checking
    2) The checksum file follows this format, with one hash/filename pair per line:
        <hexadecimal string hash> <filename>
        and that the hash is in lowercase and the file name is a relative path to the checksum file
    If this ever changes, this code will need to be updated.

    So far, this seems to be the output of the following command:
        $ find -type f \( -not -name "md5sum.txt" \) -exec md5sum '{}' \; > ~/md5sum.txt
    Some previous iterations of the hashfile used Powershell instead of BASH, so that
    output is WILDLY different. Hopefully they don't change their minds.
*/

#include "common.h"
#include "hash.h"
#include "cxxopts.hpp"

// Helper struct for pre-computing the file sizes, greatly speeding up
// std::sort's lambda function
typedef struct pathstruct
{
    fs::path path;
    std::string hash;
    size_t filesize;
    pathstruct(fs::path newpath, std::string newhash)
        : path(newpath), hash(newhash), filesize(fs::file_size(newpath)) {}
    // required for removing duplicates
    bool operator==(const pathstruct& other) const
    {
        return (path == other.path &&
                hash == other.hash &&
                filesize == other.filesize);
    }
}
pathstruct;

const std::string COMPUTE_ONLY("compute all hashes");

// CTRL-C signal handlers
static bool s_ctrl_c = false;
#ifdef _WIN32
BOOL WINAPI ctrl_c_handler(DWORD signum)
{
    std::cout << "[*] Terminating hashing threads, closing down gracefully..." << std::endl;
    stop_tasks();
    s_ctrl_c = true;
    return TRUE;
}
#else
void ctrl_c_handler([[maybe_unused]] int signum)
{
    std::cout << "[*] Terminating hashing threads, closing down gracefully..." << std::endl;
    stop_tasks();
    s_ctrl_c = true;
}
#endif

/**
 * @brief Display usage
 */
void print_usage()
{
    const char usage[] = "\n"
    "================================================================================\n"
    "  If no files were hashed during this run of DISKHASHER, validate all of\n"
    "  the checksum files in the directory. Each file in a checksum file must be the\n"
    "  the correct relative path to the checksum file itself. For example, using a\n"
    "  checksum file in the root of the directory, each sum has to look like this:\n\n"
    "      <checksum> ./path/to/first/file_a\n"
    "      <checksum> ./newpath/to/second/file_b\n\n"
    "  If the checksum files are co-located with their files, then simple filenames\n"
    "  will work just fine:\n\n"
    "      <checksum> file_a\n"
    "      <checksum> file_b\n\n"
    "  In the event that the checksum file uses absolute paths (like a mounted USB\n"
    "  drive), you'll need to pre-convert the paths to be correct (example of how to\n"
    "  do this is given using the 'sed' utility):\n\n"
    "      WRONG: /usbdrive/path/to/first/file_a\n"
    "      RIGHT: ./path/to/first/file_a\n"
    "         USING 'sed':  sed -i 's/\\/usbdrive/\\./g' /path/to/checksumfile\n\n"
    "================================================================================\n";
    std::cout << usage << std::endl;
}

/**
 * @brief Parse a checksum file / hashfile, split each line containing a cryptographic
 * checksum and a relative path to a file
 * @param filepath Absolute path to the checksum file
 * @return Vector of path / hash pairs contained in this checksum file
*/
std::vector<pathstruct> parse_hashfile(const fs::path& filepath)
{
	std::cout << "[+] Parsing hashfile " << filepath << std::endl;
    std::ifstream infile(filepath);
    std::vector<pathstruct> hashlist;
    std::string line;

    while (std::getline(infile, line))
    {
        std::istringstream iss(line);
        std::string hash, filename, word;
        if (!(iss >> hash >> filename)) {
			std::cerr << "[-] Could not parse line" << std::endl;
			break;
		} // error

        while (iss >> word)
        {
            filename += " ";
            filename += word;
        }

        if (filename.rfind("./", 0) == 0)
        {
            filename.erase(0,2);
        }
        fs::path target = filepath.parent_path() / filename;
        if(!fs::exists(target))
        {
            std::cerr << "[!] File " << target << " does not exist on disk" << std::endl;
        }
        else
        {
            hashlist.emplace_back(target, hash);
        }
    }
    infile.close();
    return hashlist;
}

/**
 * @brief Recursively walk the given directory
 * @param root_dir Root directory
 * @return Vector of absolute paths to every regular file in this directory
 * @note Will not traverse symlinks
*/
pathvector recursive_dirwalk(const fs::path& root_dir)
{
    pathvector all_files;
    for(auto& itEntry : fs::recursive_directory_iterator(root_dir))
    {
        if(s_ctrl_c)
        {
            break;
        }
        if(itEntry.is_regular_file())
        {
            all_files.emplace_back(itEntry.path());
        }
    }

    return all_files;
}


/**
 * @brief From the command line arguments get the root directory to hash, changing it
 * from a relative path to an absolute path
 * @param result Already-parsed command line arguments
 * @return Absolute path to the directory we are hashing
*/
fs::path get_root_dir(const cxxopts::ParseResult& result)
{
    fs::path root_path;
    if(result.count("d") || result.count("root-dir"))
    {
        root_path = result["d"].as<std::string>();
        if( !fs::exists(root_path) )
        {
            std::cerr << "[!] Path '" << root_path << "' does not exist" << std::endl;
            exit(1);
        }
        if(!fs::is_directory(root_path))
        {
            std::cerr << "[!] Path '" << root_path << "' is not a directory" << std::endl;
            exit(1);
        }
        if( root_path.is_relative() )
        {
            root_path = fs::absolute(root_path);
        }
        std::cout << "[+] Hashing " << root_path << std::endl;
    }
    else
    {
        std::cerr << "[!] Path required (-d || --root-dir)" << std::endl;
        exit(1);
    }
    return root_path;
}

/**
 * @brief From the command line arguments get the hash algorithm as an enum
 * @param result Already-parsed command line arguments
 * @return Algorithm to use in hashing
*/
HASHALG get_hashalg(const cxxopts::ParseResult& result)
{
    std::map<std::string, HASHALG> algs = {
            {"md5", MD5},
            {"sha1", SHA1},
            {"sha256", SHA256}
        };
    std::string algstr;
    if(result.count("a") || result.count("algorithm"))
    {
        algstr = result["a"].as<std::string>();
        // A more portable to_lower()
        std::transform(algstr.begin(), algstr.end(), algstr.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if(!algs.contains(algstr))
        {
            std::cerr << "[!] Must select 'md5', 'sha1', or 'sha256'" << std::endl;
            exit(1);
        }
        std::cout << "[+] Using algorithm '" << algstr << "'" << std::endl;
    }
    else
    {
            std::cerr << "[!] algorithm required (-a || --algorithm)" << std::endl;
            std::cerr << "[!] Must select 'md5', 'sha1', or 'sha256'" << std::endl;
            exit(1);
    }
    return algs[algstr];
}

/**
 * @brief Parse the command line prompt checksum file argument and get a list
 * of checksum files to match against during our search
 * @param result Already-parsed command line arguments
 * @result Vector of strings which are the file names of the checksum files
 */
strvector get_checksum_files(const cxxopts::ParseResult& result)
{
    strvector checksum_files;
    if(result.count("f") || result.count("hashfile-name"))
    {
        checksum_files = result["f"].as<strvector>();
        for(const std::string& s: checksum_files)
        {
            std::cout << "[*] Checksum file pattern '" << s << "'" << std::endl;
        }
    }
    else if(result.count("x") || result.count("force"))
    {
        // force compute-only
        std::cout << "[*] Calculating hashes without validating" << std::endl;
        checksum_files.emplace_back(COMPUTE_ONLY);
    }
    else
    {
        std::string response;
        std::cout << "[*] No checksum file provided" << std::endl;
        std::cout << "    Do you want to compute the hashes anyways? (Y/N) > ";

        while(!s_ctrl_c)
        {
            std::cin >> response;
            std::cout << std::endl;
            if ((response.rfind("Y", 0) == 0) || (response.rfind("y", 0) == 0))
            {
                checksum_files.emplace_back(COMPUTE_ONLY);
                break;
            }
            else if ((response.rfind("N", 0) == 0) || (response.rfind("n", 0) == 0))
            {
                std::cerr << "[!] Exiting..." << std::endl;
                exit(0);
            }
            std::cout << "    Invalid - Please enter 'yes' or 'no' to continue (Y/N) > ";
        }
    }
    return checksum_files;
}

/**
 * @brief Use the command line arguments to load hashes from a checksum file. If no checksum
 * file is passed in to the program, then prompt the user to see if a full hashing of the
 * target directory is desired, without validating hashes.
 * @param result The command line argument structure
 * @return Vector containing the target files in the checksum files with the expected hashes
 */
std::vector<pathstruct> load_hashes(const cxxopts::ParseResult& result)
{
    std::vector<pathstruct> all_hashes;
    fs::path root_dir = get_root_dir(result);
    strvector checksum_files = get_checksum_files(result);

    std::cout << "[+] Recursively walking " << root_dir << std::endl;
    pathvector all_files = recursive_dirwalk(root_dir);

    if(checksum_files.size() == 1 && checksum_files[0] == COMPUTE_ONLY)
    {
        std::cout << "[!] No checksum files given - no log files will be generated" << std::endl;
        std::for_each(all_files.begin(), all_files.end(), [&](const auto& path)
        {
            all_hashes.emplace_back(path, IGNORE_HASH_CHECK);
        });
    }
    else
    {
        for( const auto& p : all_files )
        {
            // Search the directory for all the checksum/hash files
            // and parse those files, storing the expected hashes
            if (std::find(checksum_files.begin(),
                        checksum_files.end(),
                        p.filename().string()) != checksum_files.end())
            {
                std::vector<pathstruct> hashes = parse_hashfile(p);
                all_hashes.insert(all_hashes.end(), hashes.begin(), hashes.end());
            }
        }
    }

    if(all_hashes.empty())
    {
        // Nothing to do
        std::cerr << "[-] No hashes found, check your 'hashfile-name' parameter" << std::endl;
        print_usage();
        exit(1);
    }

    std::cout << "[*] Sorting files by file size, smallest first" << std::endl;
    // Then, just in case, remove duplicate entries: 1) Sort  2) Erase Duplicates
    std::sort(all_hashes.begin(), all_hashes.end(), [](const pathstruct& a, const pathstruct& b) {
        return (a.filesize < b.filesize);
    });
    std::cout << "[*] Erasing duplicate entries, if any" << std::endl;
    all_hashes.erase(std::unique(all_hashes.begin(), all_hashes.end()), all_hashes.end());
    return all_hashes;
}

/**
 * @brief Parse command line args, and interpret some of them
 * @param argc Number of arguments
 * @param argv Argument list
 * @return The commandline arguments already parsed
 */
cxxopts::ParseResult parse_cmdline_args(int argc, const char* argv[])
{
std::cout << "[+] " << argv[0] << std::endl;

    cxxopts::Options options(argv[0], " - Recursively calculate the crypto hashes for a directory");
    bool run_tests;
    bool log_successes = false;

    options
      .set_width(70)
      .set_tab_expansion()
      .allow_unrecognised_options()
      .add_options()
      ("d, root-dir", "Path to folder / disk drive", cxxopts::value<std::string>())
      ("f, hashfile-name", "Name of the file(s) containing hashes (multiple files are separated by commas)", cxxopts::value<strvector>())
      ("a, algorithm", "Hash algorithm (md5, sha1, sha256)", cxxopts::value<std::string>())
      ("t, run-tests", "Run hash function self-test modules", cxxopts::value<bool>(run_tests))
      ("n, no-osapi-hash", "Force the usage of built-in algorithms (not recommended)", cxxopts::value<bool>())
      ("l, log", "Path to logfile (optional)", cxxopts::value<std::string>())
      ("s, log-success", "Record successful hashes in logfile (optional)", cxxopts::value<bool>(log_successes))
      ("v, verbose", "Print all hashes to the screen, including successful hashes", cxxopts::value<bool>())
      ("h, help", "Print help message")
      ("x, force", "Force computing hashes on a directory if no checksum file is entered", cxxopts::value<bool>())
    ;

    cxxopts::ParseResult result = options.parse(argc, argv);

    if(result.count("h") || result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if(run_tests)
    {
        run_hash_tests();
        exit(0);
    }

    if(result.count("l") || result.count("log"))
    {
        fs::path rel_logfile(fs::path(result["l"].as<std::string>()));
        set_log_path(fs::absolute(rel_logfile), log_successes);
    }

    return result;
}

/**
 * @brief main
 */
extern "C"
int main(int argc, const char* argv[])
{
    std::vector< std::future<pathpair> > tasks;
    cxxopts::ParseResult cmdline_args = parse_cmdline_args(argc, argv);
    bool use_osapi_hash = true;
    bool verbose = false;

    if(cmdline_args.count("v") || cmdline_args.count("verbose"))
    {
        verbose = true;
    }
    else
    {
        std::cout << "[!] Only displaying failed checksums, re-run with '-v' | '-verbose' to see all hashes" << std::endl;
    }

#ifdef _WIN32 // register signal handlers
    if (!SetConsoleCtrlHandler(ctrl_c_handler, TRUE))
    {
        std::cerr << "[-] Could not set control handler" << std::endl;
        exit(EXIT_FAILURE);
    }
#else
    std::signal(SIGINT, ctrl_c_handler);
    // Linux set ulimit to allow for a really huge disk
    // Get the current file limits for later on below.
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
        std::cerr << "[-] getrlimit() failed with errno=" << errno << std::endl;
        return 1;
    }
#endif // REGISTER SIGNAL HANDLERS

    if(cmdline_args.count("n") || cmdline_args.count("no-osapi-hash"))
    {
        std::cout << "[*] Forcing the use of built-in hashing algorithm" << std::endl;
        use_osapi_hash = false;
    }

    { // A scope for all_hashes
        auto hashalg = get_hashalg(cmdline_args);
        auto all_hashes = load_hashes(cmdline_args);
        size_t num_files = all_hashes.size();
        std::cout << "[+] Computing and checking " << num_files << " file hashes" << std::endl;
#ifndef _WIN32
        if((size_t)(limit.rlim_cur) < num_files || (size_t)(limit.rlim_max) < num_files)
        {
            // check for sudo
            if(geteuid() == 0)
            {
                limit.rlim_cur = num_files * 2;
                limit.rlim_max = num_files * 2;
                if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
                {
                    std::cerr << "[-] setrlimit() failed with errno=" << errno << std::endl;
                    return 1;
                }
            }
            else
            {
                set_hash_concurrency_limit(num_files);
            }
        }
#else
        // TODO: Windows RLIMIT-equivalent task here if necessary
#endif
        /*std::for_each(all_hashes.begin(), all_hashes.end(),
        [&](const pathstruct& s)
        {
            tasks.emplace_back(std::async(std::launch::async, hash_file_thread_func,
                                          s.path, hashalg, s.hash, use_osapi_hash));
        });*/
        // the lambda in std::for_each causes a double-free. Omit until later.
        for(const auto& s : all_hashes)
        {
            tasks.emplace_back(std::async(std::launch::async, hash_file_thread_func,
                                          s.path, hashalg, s.hash, use_osapi_hash));
        }
    }

    // Wait for and process results - the benefit of the std::sort() above is that, by sorting
    // on file size, we get results faster on the vast majority of the files. Less blocking
    // on big files in lieu of smaller ones.
    size_t numFiles = tasks.size();
    if(numFiles == 0)
    {
        std::cout << "[+] Done: No files to process" << std::endl << std::endl;
        close_log();
        return 0;
    }

    double progressAmt = (1.0 / (double)numFiles) * 100;
    double totalProgress = 0.0;
    size_t approxFivePct = numFiles / 20;
    size_t totalFilesHashed = 0;
    for(auto& f : tasks)
    {
        totalFilesHashed++;
        totalProgress += progressAmt;

        pathpair pair = f.get();
        if(pair.second == HASH_CANCELLED_STR || pair.second == HASH_FAILED_STR)
        {
            std::cout << "(" << (int)totalProgress << "%)[!] " << pair.second << " => " << pair.first << std::endl;
        }
        else
        {
            if(verbose)
            {
                std::cout << "(" << (int)totalProgress << "%)[+] file:  " << pair.first << std::endl;
                std::cout << "\tdigest:  " << pair.second << std::endl << std::endl;
            }
            else if(
                    (totalFilesHashed % approxFivePct) == 0 ||
                    totalFilesHashed == numFiles
                )
            {
                // For every five percent of files hashed, print a status report, and also
                // once the last file has been hashed
                std::cout << "(" << (int)totalProgress << "%)[+] " << totalFilesHashed << " files hashed" << std::endl;
            }
        }
    }

    std::cout << "[+] Done" << std::endl << std::endl;
    close_log();
    destroy_hash_concurrency_limit();
    return 0;
}