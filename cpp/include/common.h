/*
    DISKHASHER - 2023 by Hyohko

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

#ifdef _WIN32
#include <Windows.h>
#include <Bcrypt.h>
#else
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
// from C - CPP semaphores can't be intialized at runtime
#include <semaphore.h>
#endif

#include <atomic>
#include <csignal>
#include <cstring> // errno/strerror
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

// #define SPDLOG_PATTERN "[%H:%M:%S] [%n] [%^---%L---%$] [thread %t] %v"
#define SPDLOG_PATTERN      "[%H:%M:%S] [%^%=8l%$] %v"
#define THREADLOGGER_STR    "threadlogger"

namespace fs = std::filesystem;

typedef std::pair<std::string,std::uintmax_t> filepair;
typedef std::vector<filepair> filevector;
typedef std::vector<fs::path> pathvector;
typedef std::pair<fs::path,std::string> pathpair;
typedef std::vector<std::string> strvector;

#define HASH_CANCELLED_STR "---HASH CANCELLED---"
#define HASH_FAILED_STR "---HASH FAILED---"
#define IGNORE_HASH_CHECK "xx"

#include "indicators.hpp" // Progress bar
using namespace indicators;