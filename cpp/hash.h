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

#pragma once

#include "common.h"

typedef enum
{
    MD5, SHA1, SHA256
} HASHALG;

/**
 * @brief Set limit on the number of hash threads that can run simultaneously
 * @param limit number of concurrent threads
*/
void set_hash_concurrency_limit(unsigned int limit);

/**
 * @brief Remove limit on the number of hash threads that can run simultaneously
 * @param limit number of concurrent threads
 * @note If set_limit above is called, you should call this just before program termination
*/
void destroy_hash_concurrency_limit();

/**
 * @brief Perform self tests on local hash functions
*/
void run_hash_tests();

/**
 * @brief Thread function for asynchronous hashing task (subject to concurrency limit)
 * @param path Full/absolute path to the file being hashed
 * @param algorithm The hash algorithm being used
 * @param expected The expected hash of the file, if it's being checked. To skip this check,
 * @param use_osapi_hashing If TRUE, try to force the use of the OS crypto API
*/
pathpair hash_file_thread_func(const fs::path& path, HASHALG algorithm, const std::string& expected, bool use_osapi_hashing);

/**
 * @brief When called, terminates all running tasks
*/
void stop_tasks();

/**
 * @brief Opens the log file for task logging
 * @param path The path to the log file
 * @param log_successes If true, then write successful hashes to the file in addition to failures
*/
void set_log_path(const fs::path& path, bool log_successes);

/**
 * @brief Flush and close the log file
*/
void close_log();