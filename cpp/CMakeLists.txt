# DISKHASHER v0.1 - 2022 by Hyohko

##################################
#   GPLv3 NOTICE AND DISCLAIMER
##################################
#
# This file is part of DISKHASHER.
#
# DISKHASHER is free software: you can redistribute it
# and/or modify it under the terms of the GNU General
# Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# DISKHASHER is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General
# Public License along with DISKHASHER. If not, see
# <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 20)

project(diskhasher)

# dependency - spdlog
add_subdirectory(spdlog)

# Check for OS version
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(IS_LINUX FALSE)
    set(IS_WINDOWS TRUE)
endif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(IS_LINUX TRUE)
    set(IS_WINDOWS FALSE)
endif("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")

message(STATUS "CMAKE system ${CMAKE_SYSTEM_NAME}")

if(IS_LINUX)
    message(STATUS "Compiling for Linux")
    set(CMAKE_CXX_FLAGS "-Wall -g -Ofast -std=c++2a -fPIC -ffunction-sections \
                        -fdata-sections -frename-registers -flto -fopenmp \
                        -D_GLIBCXX_PARALLEL -Wl,--gc-sections -s -march=native")
endif (IS_LINUX)

if(IS_WINDOWS)
    message(STATUS "Compiling for Windows")
    #set(CMAKE_CXX_FLAGS "/Ox /incremental /GS- /Gy /fp:fast")
endif(IS_WINDOWS)

# Output
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
set(CMAKE_LEGACY_CYGWIN_WIN32 0)

set(SOURCES
    md5.c
    sha1.c
    sha256.c
    diskhasher.cpp
    hash.cpp
    hashclass.cpp
)

set(NIX_SOURCES
    kcapi-kernel-if.c
    kcapi-md.c
    kcapi-utils.c
)

if(IS_LINUX)
    add_executable(${CMAKE_PROJECT_NAME} ${SOURCES} ${NIX_SOURCES})
    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/spdlog/include)
    message(STATUS "Linking for Linux")
    find_package(Threads REQUIRED)
    target_link_libraries(${CMAKE_PROJECT_NAME} Threads::Threads spdlog)
endif(IS_LINUX)

if(IS_WINDOWS)
    add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/spdlog/include)
    message(STATUS "Linking for Windows")
    target_link_libraries(${CMAKE_PROJECT_NAME} Bcrypt spdlog)
endif(IS_WINDOWS)
