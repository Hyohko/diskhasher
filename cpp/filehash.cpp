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

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#define SPDLOGGER 1

#include "common.h"
#include "filehash.h"
#include "hash.h"

static std::atomic_bool s_task_ended(false);
static bool s_log_successes = false;

std::shared_ptr<spdlog::logger> s_logfile;
bool s_logger_init = false;

std::unique_ptr<hash> create_hasher(HASHALG algorithm, const std::shared_ptr<spdlog::logger> &logger) {
    switch (algorithm) {
        case MD5: return std::make_unique<c_md5>(logger);
        case SHA1: return std::make_unique<c_sha1>(logger);
#ifndef _WIN32
        case SHA224: return std::make_unique<c_sha224>(logger);
#endif
        case SHA256: return std::make_unique<c_sha256>(logger);
        case SHA384: return std::make_unique<c_sha384>(logger);
        case SHA512: return std::make_unique<c_sha512>(logger);
        default: return nullptr;
    }
}

/**
 * @brief Atomically log the results of the hashing to stdout. If a log file has been opened
 * with set_log_path(), also log the results to file.
 * @param path Full/absolute path to the file being hashed
 * @param expected The expected hash of the file, if it's being checked. To skip this check,
 * pass IGNORE_HASH_CHECK instead
 * @param actual The actual hash as computed.
 */
static void log_result(const fs::path &path, const std::string &expected, const std::string &actual) {
    static const std::string ignored(IGNORE_HASH_CHECK);

    if (expected == ignored) {
        return;
    }

    if (actual != expected) {
        spdlog::error("[-] File '{}' failed checksum\n"
                      "\t\t\tExpected: '{}'\n"
                      "\t\t\tActual  : '{}'",
                      path.string(), expected, actual);
        if (s_logger_init) {
            s_logfile->error("[-] FAILURE =>\n\t"
                             "File     : {}\n\t"
                             "Expected : {}\n\t"
                             "Actual   : {}\n",
                             path.string(), expected, actual);
        }
    } else if (s_log_successes && s_logger_init) {
        s_logfile->info("[-] SUCCESS =>\n\t"
                        "File     : {}\n\t"
                        "Actual   : {}\n",
                        path.string(), actual);
    }
}

// concurrency semaphores
static std::atomic_bool s_sem_isset(false);
#ifdef _WIN32
static HANDLE sem_threads = NULL;
#else
static sem_t sem_threads;
#endif

///////////////////////////////////////////////////////////

void set_hash_concurrency_limit(unsigned int limit)
{
    spdlog::info("[+] Number of simultaneously opened files: {}", limit);
#ifdef _WIN32
    sem_threads = CreateSemaphoreW(NULL, 0, limit, NULL);
#else
    sem_init(&sem_threads, 0, limit);
#endif
    s_sem_isset = true;
}

static void sem_lock()
{
    if (s_sem_isset.load())
    {
#ifdef _WIN32
        if (NULL != sem_threads)
            WaitForSingleObject(sem_threads, INFINITE);
#else
        sem_wait(&sem_threads);
#endif
    }
}

static void sem_unlock()
{
    if (s_sem_isset.load())
    {
#ifdef _WIN32
        if (NULL != sem_threads)
            ReleaseSemaphore(sem_threads, 1, NULL);
#else
        sem_post(&sem_threads);
#endif
    }
}

void destroy_hash_concurrency_limit()
{
#ifdef _WIN32
    if (NULL != sem_threads)
        CloseHandle(sem_threads);
#else
    sem_destroy(&sem_threads);
#endif
    s_sem_isset = false;
}

void run_hash_tests()
{
    spdlog::info("[+] Running self tests using FIPS-180 test vectors");
    md5_self_test(1);
    sha1_self_test(1);
    sha224_self_test(1);
    sha256_self_test(1);
    sha384_self_test(1);
    sha512_self_test(1);
    spdlog::info("[+] Self test complete");
}

/*
    Why use POSIX open() vs fopen()? In linux, we have access to the O_DIRECT flag
    which hints at the kernel not to cache the read buffer but pass it straight
    through to the user space program. This may give a speed improvement since we are
    not attempting to write the hashed file to the disk. The most equivalent
    Windows flag (since we are reading files from front to back) is _O_SEQUENTIAL
*/
#include <fcntl.h> // POSIX Open
#ifdef _WIN32
#include <io.h>
#define open(a, b) _open((a), (b))
#define read(a, b, c) _read((a), (b), (c))
#define close(a) _close((a))
#define O_DIRECT (_O_SEQUENTIAL)
#else
/*
    Windows requires O_BINARY to open the file in binary mode, which is the default
    on POSIX systems.
*/
#define O_BINARY (0)
#endif

pathpair hash_file_thread_func(fs::path path, HASHALG algorithm, std::string expected, bool use_osapi_hashing, bool verbose) {
    const size_t READCHUNK_SIZE = 1024 * 1024 * 2; // 2 MB
    std::unique_ptr<hash> hasher;
    std::string hexdigest = HASH_FAILED_STR;
    int r_file = -1;

    auto local_logger = spdlog::get(THREADLOGGER_STR);
    local_logger->set_level(verbose ? spdlog::level::debug : spdlog::level::info);

#ifdef _WIN32
    std::unique_ptr<unsigned char[]> safeBuf(new unsigned char[READCHUNK_SIZE]);
#else
    const std::align_val_t ALIGN_SIZE = std::align_val_t(512);
    static auto del = [](unsigned char *p) { operator delete[](p, ALIGN_SIZE); };
    std::unique_ptr<unsigned char[], decltype(del)> safeBuf(new (ALIGN_SIZE) unsigned char[READCHUNK_SIZE]);
#endif

    unsigned char *buf = safeBuf.get();
    if (!buf) {
        local_logger->error("[-] Allocation failure");
        hexdigest = HASH_CANCELLED_STR;
        goto cleanup;
    }

    hasher = create_hasher(algorithm, local_logger);
    if (!hasher) {
        local_logger->error("Unsupported algorithm");
        hexdigest = HASH_FAILED_STR;
        goto cleanup;
    }

    use_osapi_hashing ? hasher->enable_osapi_hashing() : hasher->disable_osapi_hashing();

    sem_lock();
    r_file = open(path.string().c_str(), O_RDONLY | O_DIRECT | O_BINARY);
    if (r_file == -1) {
        local_logger->error("[-] OsErr: {} => File '{}' failed to open", std::strerror(errno), path.string());
        goto cleanup;
    }

    while (true) {
        if (s_task_ended.load()) {
            hexdigest = HASH_CANCELLED_STR;
            goto cleanup;
        }

        int bytes_read = read(r_file, buf, READCHUNK_SIZE);
        if (bytes_read == 0) { // EOF
            local_logger->debug("[*] End of file reached => {}", path.string());
            break;
        } else if (bytes_read == -1) { // ERROR
            local_logger->error("[-] errno {} => Failed to read from '{}'", std::strerror(errno), path.string());
            hexdigest = HASH_CANCELLED_STR;
            goto cleanup;
        }

        hasher->update(buf, bytes_read);
    }
    hexdigest = hasher->get_hash();
    log_result(path, expected, hexdigest);

cleanup:
    if (r_file != -1) {
        close(r_file);
    }
    sem_unlock();

    return {path, hexdigest};
}

void stop_tasks()
{
    spdlog::warn("[!] STOP ALL TASKS called");
    s_task_ended = true;
}

void set_log_path(const fs::path &path, bool log_successes)
{
    try
    {
        s_logfile = spdlog::basic_logger_mt<spdlog::async_factory>("async_file_logger", path.string());
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        spdlog::error("[-] Error: {} => File '{}' failed to open, no logging available for this run", ex.what(), path.string());
        return;
    }
    spdlog::info("[+] Logging results to {}", path.string());
    s_log_successes = log_successes;
    s_logger_init = true;
}

void close_log()
{
    s_logger_init = false;
    s_logfile.reset();
}