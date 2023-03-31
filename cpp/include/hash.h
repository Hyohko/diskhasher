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
// Kernel socket crypto
#ifndef _WIN32
#include "kcapi.h"
#endif

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class hash
 * @brief Pure Abstract Class - provides interface and generic functionality for hash algorithms
 * that extend/derive this class
 **/
class hash
{
private:
    std::shared_ptr<spdlog::logger> m_logger;
#ifdef _WIN32
    BCRYPT_ALG_HANDLE m_hAlg;
    BCRYPT_HASH_HANDLE m_hHash;
#else
    struct kcapi_handle *m_handle = NULL;
#endif

protected:
    bool m_isOsApi;
    size_t m_lenDigest = 0;        // set by derived classes
    unsigned char m_digestBuf[64]; // Largest possible digest

    /**
     * @brief Linux only - check to see if the Kernel Crypto API is installed and available
     * to user space
     * @return false if OS API crypto is not available
     * @note Static booleans prevent the internal logic from running more than once
     * to save time/space
     */
    virtual bool osapi_hashing_available();

    /**
     * @brief Start up the Operating System embedded hash API and acquire handles
     * @param hashname String indicating the name of the hash algorithm
     * @return bool - Function success
     */
#ifdef _WIN32
    virtual bool osapi_starts(LPCWSTR hashname);
#else
    virtual bool osapi_starts(const char *hashname);
#endif

    /**
     * @brief Update the hash state with data from the object being hashed
     * @param buf - Data fragment to be added to the hash object
     * @param ilen - Length of the data fragment
     * @return bool - Function success
     */
    virtual bool osapi_update(const unsigned char *buf, size_t ilen);

    /**
     * @brief Complete computation of the hash and save in object's digest buffer
     * @return bool - Function success
     * @note - After calling, all the hash handles are invalidated and this object cannot be reused.
     */
    virtual bool osapi_finish();

public:
    hash() = delete;
    hash(std::shared_ptr<spdlog::logger> logger);
    hash(const hash &) = delete;
    hash &operator=(const hash &) = delete;
    virtual ~hash();

    /**
     * @brief Turn on access to OS hashing algorithms if available
     */
    virtual void enable_osapi_hashing();

    /**
     * @brief Explicitly turn off OS hashing algorithms
     */
    virtual void disable_osapi_hashing();

    /**
     * @brief Update internal hash state with data to be hashed
     * @note Pure virtual function that subclasses must implement
     */
    virtual void update(const unsigned char *data, size_t ilen) = 0;

    /**
     * @brief Complete hashing and return message digest
     * @return std::string - Hexadecimal message digest in string form
     * @note Pure virtual function that subclasses must implement
     */
    virtual std::string get_hash() = 0;
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_md5
 * @brief MD5 subclass of hash class
 **/
class c_md5 : public hash
{
private:
    md5_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_MD5_ALGORITHM;
#else
    constexpr static char m_hashname[] = "md5";
#endif
    const static size_t m_md5Len = 16;

public:
    c_md5() = delete;
    c_md5(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_md5Len;
        osapi_starts(m_hashname);
        md5_starts(&m_ctx);
    }
    c_md5(const c_md5 &) = delete;
    c_md5 &operator=(const c_md5 &) = delete;
    virtual ~c_md5();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha1
 * @brief SHA1 subclass of hash class
 **/
class c_sha1 : public hash
{
private:
    sha1_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_SHA1_ALGORITHM;
#else
    constexpr static char m_hashname[] = "sha1";
#endif
    const static size_t m_sha1Len = 20;

public:
    c_sha1() = delete;
    c_sha1(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_sha1Len;
        osapi_starts(m_hashname);
        sha1_starts(&m_ctx);
    }
    c_sha1(const c_sha1 &) = delete;
    c_sha1 &operator=(const c_sha1 &) = delete;
    virtual ~c_sha1();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};

#ifndef _WIN32 // the BCRYPT Api does not support SHA224
///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha224
 * @brief SHA224 subclass of hash class
 **/
class c_sha224 : public hash
{
private:
    sha256_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_SHA224_ALGORITHM;
#else
    constexpr static char m_hashname[] = "sha224";
#endif
    const static size_t m_sha224Len = 28;

public:
    c_sha224() = delete;
    c_sha224(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_sha224Len;
        osapi_starts(m_hashname);
        sha256_starts(&m_ctx, 1); // sha224
    }
    c_sha224(const c_sha224 &) = delete;
    c_sha224 &operator=(const c_sha224 &) = delete;
    virtual ~c_sha224();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha256
 * @brief SHA256 subclass of hash class
 **/
class c_sha256 : public hash
{
private:
    sha256_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_SHA256_ALGORITHM;
#else
    constexpr static char m_hashname[] = "sha256";
#endif
    const static size_t m_sha256Len = 32;

public:
    c_sha256() = delete;
    c_sha256(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_sha256Len;
        osapi_starts(m_hashname);
        sha256_starts(&m_ctx, 0);
    }
    c_sha256(const c_sha256 &) = delete;
    c_sha256 &operator=(const c_sha256 &) = delete;
    virtual ~c_sha256();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha384
 * @brief SHA384 subclass of hash class
 **/
class c_sha384 : public hash
{
private:
    sha512_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_SHA384_ALGORITHM;
#else
    constexpr static char m_hashname[] = "sha384";
#endif
    const static size_t m_sha384Len = 48;

public:
    c_sha384() = delete;
    c_sha384(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_sha384Len;
        osapi_starts(m_hashname);
        sha512_starts(&m_ctx, 1);
    }
    c_sha384(const c_sha384 &) = delete;
    c_sha384 &operator=(const c_sha384 &) = delete;
    virtual ~c_sha384();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha512
 * @brief SHA512 subclass of hash class
 **/
class c_sha512 : public hash
{
private:
    sha512_context m_ctx;
#ifdef _WIN32
    LPCWSTR m_hashname = BCRYPT_SHA512_ALGORITHM;
#else
    constexpr static char m_hashname[] = "sha512";
#endif
    const static size_t m_sha512Len = 64;

public:
    c_sha512() = delete;
    c_sha512(std::shared_ptr<spdlog::logger> logger) : hash(logger)
    {
        m_lenDigest = m_sha512Len;
        osapi_starts(m_hashname);
        sha512_starts(&m_ctx, 0);
    }
    c_sha512(const c_sha512 &) = delete;
    c_sha512 &operator=(const c_sha512 &) = delete;
    virtual ~c_sha512();
    virtual void update(const unsigned char *data, size_t ilen);
    virtual std::string get_hash();
};