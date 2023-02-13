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

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include "common.h"
#include "hash.h"
#include "hashclass.h"
#include <spdlog/spdlog.h>

/**
 * @brief Atomically log the results of the hashing to stdout. If a log file has been opened
 * with set_log_path(), also log the results to file.
 * @param path Full/absolute path to the file being hashed
 * @param expected The expected hash of the file, if it's being checked. To skip this check,
 * pass IGNORE_HASH_CHECK instead
 * @param actual The actual hash as computed.
*/
static void log_result(const fs::path& path, const std::string& expected, const std::string& actual);

static std::atomic_bool s_task_ended(false);
static FILE* s_logfile = NULL;
static bool s_log_successes = false;
static std::mutex log_lock;

//concurrency semaphores
static std::atomic_bool s_sem_isset(false);
#ifdef _WIN32
static HANDLE sem_threads = NULL;
#else
static sem_t sem_threads;
#endif

///////////////////////////////////////////////////////////

void set_hash_concurrency_limit(unsigned int limit)
{
#ifdef _WIN32
    sem_threads = CreateSemaphoreW(NULL, 0, limit, NULL);
#else
    sem_init(&sem_threads, 0, limit);
#endif
    s_sem_isset = true;
}

static void sem_lock()
{
    if(s_sem_isset.load())
    {
#ifdef _WIN32
        if(NULL != sem_threads) WaitForSingleObject(sem_threads, INFINITE);
#else
        sem_wait(&sem_threads);
#endif
    }
}

static void sem_unlock()
{
    if(s_sem_isset.load())
    {
#ifdef _WIN32
        if(NULL != sem_threads) ReleaseSemaphore(sem_threads, 1, NULL);
#else
        sem_post(&sem_threads);
#endif
    }
}

void destroy_hash_concurrency_limit()
{
#ifdef _WIN32
    if(NULL != sem_threads) CloseHandle(sem_threads);
#else
    sem_destroy(&sem_threads);
#endif
    s_sem_isset = false;
}

void run_hash_tests()
{
    if(osapi_hashing_available())
    {
        spdlog::info("[+] OS API for hashing is available");
    }
    else
    {
        spdlog::info("[+] Running self tests using FIPS-180 test vectors");
        md5_self_test(1);
        sha1_self_test(1);
        sha256_self_test(1);
        spdlog::info("[+] Self test complete");
    }
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
#define open(a,b)   _open((a),(b))
#define read(a,b,c) _read((a),(b),(c))
#define close(a)    _close((a))
#define O_DIRECT    (_O_SEQUENTIAL)
#else
/*
    Windows requires O_BINARY to open the file in binary mode, which is the default
    on POSIX systems.
*/
#define O_BINARY    (0)
#endif
pathpair hash_file_thread_func(const fs::path& path, HASHALG algorithm, const std::string& expected, bool use_osapi_hashing)
{
    // Define this as needed (2 MB, currently)
    const size_t READCHUNK_SIZE = 1024 * 1024 * 2;
    std::unique_ptr<hash> hasher;
    std::string hexdigest;
    int r_file = -1;

    std::unique_ptr<unsigned char[]> safeBuf(new unsigned char[READCHUNK_SIZE]);
    unsigned char* buf = safeBuf.get();
    if(!buf)
    {
        std::cerr << "[-] Allocation failure" << std::endl;
        hexdigest = HASH_CANCELLED_STR;
        goto exit;
    }

    switch(algorithm)
    {
    case MD5:
        hasher = std::make_unique<c_md5>();
        break;
    case SHA1:
        hasher = std::make_unique<c_sha1>();
        break;
    case SHA256:
        hasher = std::make_unique<c_sha256>();
        break;
    }

    if(nullptr == safeBuf.get())
    {
        std::cerr << "[-] Allocation failure - hash object" << std::endl;
        hexdigest = HASH_FAILED_STR;
        goto exit;
    }

    use_osapi_hashing ? hasher->enable_osapi_hashing() : hasher->disable_osapi_hashing();

    sem_lock();
    r_file = open(path.string().c_str(), O_RDONLY | O_DIRECT | O_BINARY);
    if(-1 == r_file)
    {
        std::cerr << "[-] Error: " << std::strerror(errno) << " => File '" << path << "' failed to open" << std::endl;
        goto exit;
    }

    while ( 1 )
    {
        if(s_task_ended.load())
        {
            hexdigest = HASH_CANCELLED_STR;
            goto exit;
        }
        int bytes_read = read(r_file, buf, READCHUNK_SIZE);
        switch (bytes_read)
        {
        case 0: // EOF
            spdlog::debug("[*] End of file reached => {}", path.string());
            goto eof;
            break;
        case -1: // ERROR
            spdlog::error("[-] errno {} => Failed to read from '{}'", std::strerror(errno), path.string());
            hexdigest = HASH_FAILED_STR;
            goto exit;
            break;
        default:
            // More data to receive
            spdlog::debug("[*] More data to receive for => {}", path.string());
            break;
        }
        hasher->update(buf, bytes_read);
    }
eof:
    hexdigest = hasher->get_hash();
    log_result(path, expected, hexdigest);
exit:
    if(-1 != r_file)
    {
        close(r_file);
    }
    sem_unlock();

    return pathpair(path, hexdigest);
}

void stop_tasks()
{
    spdlog::warn("[!] STOP ALL TASKS called");
    s_task_ended = true;
}

void set_log_path(const fs::path& path, bool log_successes)
{
    log_lock.lock();
    s_logfile = fopen(path.string().c_str(), "w");
    if(!s_logfile)
    {
        spdlog::error("[-] Error: {} => File '{}' failed to open, no logging available for this run", std::strerror(errno), path.string());
        return;
    }
    spdlog::info("[+] Logging results to {}", path.string());
    s_log_successes = log_successes;
    log_lock.unlock();
}

void close_log()
{
    log_lock.lock();
    if(s_logfile)
    {
        fflush(s_logfile);
        fclose(s_logfile);
        s_logfile = NULL;
    }
    log_lock.unlock();
}

void log_result(const fs::path& path, const std::string& expected, const std::string& actual)
{
    static const std::string ignored(IGNORE_HASH_CHECK);
    if(expected == ignored)
    {
        return;
    }
    log_lock.lock();
    if(actual != expected)
    {
        spdlog::error("[-] File '{}' failed checksum\n" \
        "    Expected: '{}'\n" \
        "    Actual  : '{}'", path.string(), expected, actual);
        if(s_logfile)
        {
            fprintf(s_logfile, "[-] FAILURE =>\n\tFile     : %s\n\tExpected : %s\n\tActual   : %s\n", path.string().c_str(), expected.c_str(), actual.c_str());
            fflush(s_logfile);
        }
    }
    else if(s_log_successes)
    {
        if(s_logfile)
        {
            fprintf(s_logfile, "[+] SUCCESS =>\n\tFile     : %s\n\tActual   : %s\n", path.string().c_str(), actual.c_str());
            fflush(s_logfile);
        }
    }
    log_lock.unlock();
}