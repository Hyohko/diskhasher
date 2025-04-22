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
#include "filehash.h"
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
    bool operator==(const pathstruct &other) const
    {
        return (path == other.path &&
                hash == other.hash &&
                filesize == other.filesize);
    }
} pathstruct;

const std::string COMPUTE_ONLY("compute all hashes");

// CTRL-C signal handlers
static bool s_ctrl_c = false;
#ifdef _WIN32
BOOL WINAPI ctrl_c_handler(DWORD signum)
{
    spdlog::warn("[*] Terminating hashing threads, closing down gracefully...");
    stop_tasks();
    s_ctrl_c = true;
    return TRUE;
}
#else
void ctrl_c_handler([[maybe_unused]] int signum)
{
    spdlog::warn("[*] Terminating hashing threads, closing down gracefully...");
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
    "  If no files were hashed during this run of DKHASH, validate all of\n"
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
 * @brief Trim leading whitespace from a string.
 * @param s The string to trim.
 * @return Reference to the trimmed string.
 */
std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char c) {
        return !std::isspace<char>(c, std::locale::classic());
    }));
    return s;
}

/**
 * @brief Parse a checksum file / hashfile, split each line containing a cryptographic
 * checksum and a relative path to a file.
 * @param filepath Absolute path to the checksum file.
 * @return Vector of path / hash pairs contained in this checksum file.
 */
std::vector<pathstruct> parse_hashfile(const fs::path &filepath) {
    spdlog::info("[+] Parsing hashfile {}", filepath.string());
    std::ifstream infile(filepath);
    std::vector<pathstruct> hashlist;
    std::string line, hash, filename;
    size_t count = 0;

    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        if (!(iss >> hash)) {
            spdlog::error("[-] Could not parse line");
            continue;
        }

        std::getline(iss, filename);
        ltrim(filename);

        if (filename.starts_with("./")) {
            filename.erase(0, 2);
        }

        fs::path target = filepath.parent_path() / filename;
        if (!fs::exists(target)) {
            spdlog::error("[!] File {} does not exist on disk", target.string());
        } else {
            hashlist.emplace_back(target, hash);
        }

        if (++count % 500 == 0) {
            spdlog::info("[*] {} hashes parsed", count);
        }

        if (s_ctrl_c) {
            break;
        }
    }

    spdlog::info("[*] Total: {} hashes parsed", count);
    return hashlist;
}

/**
 * @brief Recursively walk the given directory.
 * @param root_dir Root directory.
 * @return Vector of absolute paths to every regular file in this directory.
 * @note Will not traverse symlinks.
 */
pathvector recursive_dirwalk(const fs::path &root_dir) {
    pathvector all_files;
    size_t count = 0;

    for (const auto &entry : fs::recursive_directory_iterator(root_dir)) {
        try {
            if (entry.is_regular_file()) {
                all_files.emplace_back(entry.path());
            }
        } catch (const fs::filesystem_error &e) {
            spdlog::error("[-] ({}) '{}' is not a regular file", e.what(), entry.path().string());
        }

        if (++count % 500 == 0) {
            spdlog::debug("[*] {} directory items enumerated", count);
        }

        if (s_ctrl_c) {
            break;
        }
    }

    spdlog::debug("[*] Total: {} directory items enumerated", count);
    return all_files;
}

/**
 * @brief Get the root directory to hash from command line arguments.
 * @param result Already-parsed command line arguments.
 * @return Absolute path to the directory we are hashing.
 */
fs::path get_root_dir(const cxxopts::ParseResult &result) {
    if (!(result.count("d") || result.count("root-dir"))) {
        spdlog::critical("[!] Path required (-d || --root-dir)");
        exit(1);
    }

    fs::path root_path = result["d"].as<std::string>();
    if (!fs::exists(root_path)) {
        spdlog::critical("[!] Path '{}' does not exist", root_path.string());
        exit(1);
    }

    if (!fs::is_directory(root_path)) {
        spdlog::critical("[!] Path '{}' is not a directory", root_path.string());
        exit(1);
    }

    if (root_path.is_relative()) {
        root_path = fs::absolute(root_path);
    }

    spdlog::info("[+] Hashing {}", root_path.string());
    return root_path;
}

/**
 * @brief Get the hash algorithm as an enum from command line arguments.
 * @param result Already-parsed command line arguments.
 * @return Algorithm to use in hashing.
 */
HASHALG get_hashalg(const cxxopts::ParseResult &result) {
    if (!(result.count("a") || result.count("algorithm"))) {
        spdlog::error("[!] Algorithm required (-a || --algorithm)");
        spdlog::error("[!] Must select 'md5', 'sha1', or 'sha256'");
        exit(1);
    }

    std::string algstr = result["a"].as<std::string>();
    std::transform(algstr.begin(), algstr.end(), algstr.begin(), ::tolower);

    static const std::map<std::string, HASHALG> algs = {
        {"md5", MD5}, {"sha1", SHA1},
#ifndef _WIN32
        {"sha224", SHA224},
#endif
        {"sha256", SHA256}, {"sha384", SHA384}, {"sha512", SHA512}};

    if (!algs.contains(algstr)) {
        spdlog::error("[!] Must select 'md5', 'sha1', or 'sha256'");
        exit(1);
    }

    spdlog::info("[+] Using algorithm '{}'", algstr);
    return algs.at(algstr);
}

/**
 * @brief Parse the command line checksum file argument and get a list of checksum files.
 * @param result Already-parsed command line arguments.
 * @return Vector of strings which are the file names of the checksum files.
 */
strvector get_checksum_files(const cxxopts::ParseResult &result) {
    if (result.count("f") || result.count("hashfile-name")) {
        strvector checksum_files = result["f"].as<strvector>();
        for (const auto &s : checksum_files) {
            spdlog::info("[*] Checksum file pattern '{}'", s);
        }
        return checksum_files;
    }

    if (result.count("x") || result.count("force")) {
        spdlog::info("[*] Calculating hashes without validating");
        return {COMPUTE_ONLY};
    }

    std::string response;
    std::cout << "[*] No checksum file provided\n"
              << "    Do you want to compute the hashes anyways? (Y/N) > ";

    while (!s_ctrl_c) {
        std::cin >> response;
        if (response.starts_with("Y") || response.starts_with("y")) {
            return {COMPUTE_ONLY};
        }
        if (response.starts_with("N") || response.starts_with("n")) {
            spdlog::error("[!] Exiting...");
            exit(0);
        }
        std::cout << "    Invalid - Please enter 'yes' or 'no' to continue (Y/N) > ";
    }

    return {};
}

/**
 * @brief Use the command line arguments to load hashes from a checksum file. If no checksum
 * file is passed in to the program, then prompt the user to see if a full hashing of the
 * target directory is desired, without validating hashes.
 * @param result The command line argument structure
 * @return Vector containing the target files in the checksum files with the expected hashes
 */
std::vector<pathstruct> load_hashes(const cxxopts::ParseResult &result)
{
    std::vector<pathstruct> all_hashes;
    fs::path root_dir = get_root_dir(result);
    strvector checksum_files = get_checksum_files(result);

    spdlog::info("[+] Recursively walking {}", root_dir.string());
    pathvector all_files = recursive_dirwalk(root_dir);

    if (checksum_files.size() == 1 && checksum_files[0] == COMPUTE_ONLY)
    {
        spdlog::warn("[!] No checksum files given - no log files will be generated");
        for (const auto &path : all_files)
        {
            if (s_ctrl_c)
            {
                break;
            }
            all_hashes.emplace_back(path, IGNORE_HASH_CHECK);
        }
    }
    else
    {
        for (const auto &p : all_files)
        {
            if (s_ctrl_c)
            {
                break;
            }
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

    if (s_ctrl_c)
    {
        all_hashes.clear();
        return all_hashes;
    }

    if (all_hashes.empty())
    {
        spdlog::error("[-] No hashes found, check your 'hashfile-name' parameter");
        print_usage();
        exit(1);
    }

    // Then, just in case, remove duplicate entries: 1) Sort  2) Erase Duplicates
    spdlog::info("[*] Sorting files by file size, smallest first");
    std::sort(all_hashes.begin(), all_hashes.end(), [](const pathstruct &a, const pathstruct &b)
              { return (a.filesize < b.filesize); });
    spdlog::info("[*] Erasing duplicate entries, if any");
    all_hashes.erase(std::unique(all_hashes.begin(), all_hashes.end()), all_hashes.end());
    return all_hashes;
}

/**
 * @brief Parse command line args, and interpret some of them
 * @param argc Number of arguments
 * @param argv Argument list
 * @return The commandline arguments already parsed
 */
cxxopts::ParseResult parse_cmdline_args(int argc, const char *argv[])
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
        ("x, force", "Force computing hashes on a directory if no checksum file is entered", cxxopts::value<bool>());

    cxxopts::ParseResult result = options.parse(argc, argv);

    if (result.count("h") || result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if (run_tests)
    {
        run_hash_tests();
        exit(0);
    }

    if (result.count("l") || result.count("log"))
    {
        fs::path rel_logfile(fs::path(result["l"].as<std::string>()));
        set_log_path(fs::absolute(rel_logfile), log_successes);
    }

    return result;
}

/**
 * @brief Start async tasks and get a vector of std::future for polling/awaiting
 * @param cmdline_args The command line arguments to the program
 * @param use_osapi_hash if True, attempt to use the built in Crypto module; if False, use the compiled in functions
 * @param print_debug Print all available debug statements
 * @return Vector of pending tasks that can be polled/awaited for results
 */
std::vector<std::future<pathpair>> start_tasks(const cxxopts::ParseResult &cmdline_args, bool use_osapi_hash, bool print_debug)
{
#ifndef _WIN32
    // Linux set ulimit to allow for a really huge disk
    // Get the current file limits for later on below.
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
        spdlog::critical("[-] getrlimit() failed with errno={} ({})", errno, std::strerror(errno));
        exit(1);
    }
    spdlog::debug("[+] Current limit on open files: {}", limit.rlim_cur);
    spdlog::debug("[+] Maximum limit on open files: {}", limit.rlim_max);
#endif // not _WIN32

    auto hashalg = get_hashalg(cmdline_args);
    auto all_hashes = load_hashes(cmdline_args);
    size_t num_files = all_hashes.size();
    spdlog::info("[+] Computing and checking {} file hashes", num_files);

#ifndef _WIN32
    // increase, if possible, the number of concurrent open files
    if ((size_t)(limit.rlim_cur) < num_files || (size_t)(limit.rlim_max) < num_files)
    {
        // check for sudo
        if (geteuid() == 0)
        {
            limit.rlim_cur = num_files * 2;
            limit.rlim_max = num_files * 2;
            if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
            {
                spdlog::critical("[-] setrlimit() failed with errno={}", errno);
                exit(1);
            }
        }
    }
    set_hash_concurrency_limit(std::min(num_files, limit.rlim_cur));
#endif

    std::vector<std::future<pathpair>> tasks;
    for (const auto &s : all_hashes)
    {
        if (s_ctrl_c)
        {
            tasks.clear();
            break;
        }
        tasks.emplace_back(std::async(std::launch::async, hash_file_thread_func,
                                      s.path, hashalg, s.hash, use_osapi_hash, print_debug));
    }
    return tasks;
}

/**
 * @brief Start async tasks and get a vector of std::future for polling/awaiting
 * @param tasks std::future vector of pending tasks to poll
 * @param numFiles number of tasks/files being hashed
 * @param verbose Print all available debug statements
 * @return Vector of pending tasks that can be polled/awaited for results
 */
void wait_on_tasks(std::vector<std::future<pathpair>> &tasks, size_t numFiles, bool verbose)
{
    double progressAmt = (1.0 / (double)numFiles) * 100;
    double totalProgress = 0.0;
    size_t approxFivePct = numFiles / 20;
    size_t totalFilesHashed = 0;

    spdlog::debug("[+] Polling tasks for completed hashes");
    for (auto &f : tasks)
    {
        pathpair pair;
        totalFilesHashed++;
        totalProgress += progressAmt;

        if (s_ctrl_c)
        {
            break;
        }

        if (!f.valid())
        {
            spdlog::warn("[*] Invalid task returned, check implementation");
            continue;
        }
        try
        {
            pair = f.get();
        }
        catch (const std::exception &e)
        {
            spdlog::warn("[!] Exception caught while attempting to retrieve path pair from std::future => {}", e.what());
            continue;
        }

        if (pair.second == HASH_CANCELLED_STR || pair.second == HASH_FAILED_STR)
        {
            if (verbose)
                spdlog::info("({}%)[!] {} => {}", (int)totalProgress, pair.second, pair.first.string());
        }
        else
        {
            if (verbose)
            {
                spdlog::info("({}%)[+] file:  {}\n\t\t\tdigest:  {}", (int)totalProgress, pair.first.string(), pair.second);
            }
            else if (
                (totalFilesHashed % approxFivePct) == 0 ||
                totalFilesHashed == numFiles)
            {
                // For every five percent of files hashed, print a status report, and also
                // once the last file has been hashed
                spdlog::info("({}%)[+] {} files hashed", (int)totalProgress, totalFilesHashed);
            }
        }
    }
}

/**
 * @brief main
 */
extern "C" int main(int argc, const char *argv[])
{
    // Create logger for the threads
    auto console = spdlog::stdout_color_mt(THREADLOGGER_STR);
    // Default logger - async console
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern(SPDLOG_PATTERN);

    cxxopts::ParseResult cmdline_args = parse_cmdline_args(argc, argv);
    bool use_osapi_hash = true;
    bool verbose = false;
    bool print_debug = false;

    if (cmdline_args.count("v") || cmdline_args.count("verbose"))
    {
        verbose = true;
        if (cmdline_args.count("v") >= 2)
        {
            spdlog::set_level(spdlog::level::debug); // Set global log level to debug
            print_debug = true;
        }
    }
    else
    {
        spdlog::warn("[!] Only displaying failed checksums, re-run with '-v' | '-verbose' to see all hashes");
    }

    if (cmdline_args.count("n") || cmdline_args.count("no-osapi-hash"))
    {
        spdlog::info("[*] Forcing the use of built-in hashing algorithm");
        use_osapi_hash = false;
    }

    // register Ctrl-C signal handlers
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(ctrl_c_handler, TRUE))
    {
        spdlog::critical("[-] Could not set control handler");
        exit(EXIT_FAILURE);
    }
#else
    std::signal(SIGINT, ctrl_c_handler);
#endif // REGISTER SIGNAL HANDLERS

    spdlog::info("[*] {} cores available for processing", std::thread::hardware_concurrency());

    auto tasks = start_tasks(cmdline_args, use_osapi_hash, print_debug);
    // Wait for and process results - the benefit of the std::sort() above is that, by sorting
    // on file size, we get results faster on the vast majority of the files. Less blocking
    // on big files in lieu of smaller ones.
    size_t numFiles = tasks.size();
    if (numFiles == 0)
    {
        spdlog::info("[+] Done: No files to process");
        close_log();
        return 0;
    }

    wait_on_tasks(tasks, numFiles, verbose);
    spdlog::info("[+] Done");
    close_log();
    destroy_hash_concurrency_limit();
    return 0;
}