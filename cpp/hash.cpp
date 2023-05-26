/*
    DKHASH - 2023 by Hyohko

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

#include "common.h"
#include "hash.h"
#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#ifdef _WIN32
#define STATUS_UNSUCCESSFUL 0xC0000001
#define NT_SUCCESS(err) ((err) == 0)
#else
static FILE *dev_null = NULL;
static FILE fp_old;
/**
 * @brief Redirect writes to STDERR to /dev/null until enable_stderr() is called
 * @note Used to silence libkcapi error calls (which users have complained about)
 */
void disable_stderr()
{
    if (!dev_null)
        dev_null = fopen("/dev/null", "w");
    if (dev_null)
    {
        fp_old = *stderr;
        *stderr = *dev_null;
    }
}
/**
 * @brief Restores STDERR to original state, call after disable_stderr() is no longer needed
 * @note Used to silence libkcapi error calls (which users have complained about)
 */
void enable_stderr()
{
    if (dev_null)
    {
        *stderr = fp_old;
        fclose(dev_null);
        dev_null = NULL;
    }
}
#endif

/**
 * @brief Transform arbitrary binary data into a hex string
 * @param data Binary data
 * @param len Length of data
 * @return Hexadecimal string representing data
 */
static std::string hexStr(unsigned char *data, size_t len)
{
    std::stringstream ss;
    ss << std::hex;
    for (size_t i(0); i < len; ++i)
    {
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class hash
 * @brief Pure Abstract Class - provides interface and generic functionality for hash algorithms
 * that extend/derive this class
 **/

/**
 * @brief Linux only - check to see if the Kernel Crypto API is installed and available
 * to user space
 * @return false if OS API crypto is not available
 * @note Static booleans prevent the internal logic from running more than once
 * to save time/space
 */
bool hash::osapi_hashing_available()
{
#ifdef _WIN32
    return true;
#else
    static bool already_checked = false;
    static bool available = false;
    static std::mutex check_lock; // prevent race condition performing this check multiple times simultaneously

    check_lock.lock();
    if (!already_checked)
    {
        already_checked = true;
        struct kcapi_handle *handle = NULL;
        if (fs::exists("/proc/crypto"))
        {
            m_logger->info("[+] Checking for 'md5-generic' kernel driver");
            // KCAPI emits its own errors through stderr which has confused users of this utility. This call
            // is the most likely to fail, so we want to quash its verbosity by silencing stderr usage.
            disable_stderr();
            int ret = kcapi_md_init(&handle, "md5-generic", 0);
            enable_stderr();
            if (0 == ret)
            {
                available = true;
            }
            else
            {
                m_logger->warn("[!] 'md5-generic' missing, defaulting to 'md5' kernel driver");
                disable_stderr();
                ret = kcapi_md_init(&handle, "md5", 0);
                enable_stderr();
                if (0 == ret)
                {
                    available = true;
                }
                else
                {
                    m_logger->warn("[-] OS API hashing installed, but not accessible from user-space");
                }
            }
        }
        if (handle)
        {
            kcapi_md_destroy(handle);
        }
        if (!available)
        {
            m_logger->info("[*] Defaulting to built-in hashing");
        }
        else
        {
            m_logger->info("[*] OS API hashing is available");
        }
    }
    check_lock.unlock();
    return available;
#endif // _WIN32
}

#ifdef _WIN32
bool hash::osapi_starts(LPCWSTR hashname)
#else
bool hash::osapi_starts(const char *hashname)
#endif
{
    // m_logger->debug("[+] Initializing hash engine");
    if (!this->osapi_hashing_available())
        return false;
    if (!hashname)
    {
        m_logger->critical("[-] Missing hashname, check implementation");
        return false;
    }
#ifdef _WIN32
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0;
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&m_hAlg, hashname, NULL, 0)))
    {
        m_logger->critical("[-] WinError 0x{} returned by BCryptOpenAlgorithmProvider", hexStr((unsigned char *)&status, 4));
        return false;
    }

    if (!NT_SUCCESS(status = BCryptCreateHash(m_hAlg, &m_hHash, NULL, 0, NULL, 0, 0)))
    {
        m_logger->critical("[-] WinError 0x{} returned by BCryptCreateHash", hexStr((unsigned char *)&status, 4));
        BCryptCloseAlgorithmProvider(m_hAlg, 0);
        m_hAlg = NULL;
        return false;
    }
#else
    if (0 != kcapi_md_init(&m_handle, hashname, 0))
    {
        m_logger->critical("[-] Could not create OS API hash handle");
        return false;
    }
#endif
    return true;
}

/**
 * @brief Update the hash state with data from the object being hashed
 * @param buf - Data fragment to be added to the hash object
 * @param ilen - Length of the data fragment
 * @return bool - Function success
 */
bool hash::osapi_update(const unsigned char *buf, size_t ilen)
{
    if (!osapi_hashing_available())
        return false;
    if (!buf)
    {
        m_logger->critical("[-] NULL Pointer data buffer");
        return false;
    }
    if (0 == ilen)
    {
        m_logger->warn("[*] Warning - zero-length buffer passed to update");
    }
#ifdef _WIN32
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (NULL == m_hHash)
    {
        m_logger->critical("[-] Invalid hash handle, cannot update");
        return false;
    }
    if (!NT_SUCCESS(status = BCryptHashData(m_hHash, (PBYTE)buf, (ULONG)ilen, 0)))
    {
        m_logger->critical("[-] WinError 0x{} returned by BCryptHashData", hexStr((unsigned char *)&status, 4));
        return false;
    }
#else
    if (!m_handle)
    {
        m_logger->critical("[-] Invalid hash handle, cannot update");
        return false;
    }
    kcapi_md_update(m_handle, buf, ilen);
#endif
    return true;
}

/**
 * @brief Complete computation of the hash and save in object's digest buffer
 * @return bool - Function success
 * @note - After calling, all the hash handles are invalidated and this object cannot be reused.
 */
bool hash::osapi_finish()
{
    // m_logger->debug("[+] Finishing hash");
    if (!osapi_hashing_available())
        return false;
#ifdef _WIN32
    bool ret = true;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (NULL == m_hHash)
    {
        m_logger->critical("[-] Invalid hash handle, cannot finish");
        return false;
    }
    if (!NT_SUCCESS(status = BCryptFinishHash(m_hHash, m_digestBuf, (ULONG)m_lenDigest, 0)))
    {
        m_logger->critical("[-] WinError 0x{} returned by BCryptFinishHash", hexStr((unsigned char *)&status, 4));
        ret = false;
    }
    if (m_hAlg)
    {
        BCryptCloseAlgorithmProvider(m_hAlg, 0);
        m_hAlg = NULL;
    }
    if (m_hHash)
    {
        BCryptDestroyHash(m_hHash);
        m_hHash = NULL;
    }
    return ret;
#else
    if (!m_handle)
    {
        m_logger->critical("[-] Invalid hash handle, cannot finalize hash");
        return false;
    }
    kcapi_md_final(m_handle, (uint8_t *)m_digestBuf, m_lenDigest);
    if (m_handle)
    {
        kcapi_md_destroy(m_handle);
        m_handle = NULL;
    }
    return true;
#endif
}

/**
 * @brief ctor
 */
hash::hash(std::shared_ptr<spdlog::logger> logger)
{
    m_logger = logger;
#ifdef _WIN32
    m_hAlg = NULL;
    m_hHash = NULL;
    SecureZeroMemory(m_digestBuf, sizeof(m_digestBuf));
#else
    std::memset(m_digestBuf, 0, sizeof(m_digestBuf));
#endif
}

/**
 * @brief dtor
 */
hash::~hash()
{
#ifdef _WIN32
    if (m_hAlg)
    {
        BCryptCloseAlgorithmProvider(m_hAlg, 0);
        m_hAlg = NULL;
    }
    if (m_hHash)
    {
        BCryptDestroyHash(m_hHash);
        m_hHash = NULL;
    }
#else
    if (m_handle)
    {
        kcapi_md_destroy(m_handle);
        m_handle = NULL;
    }
#endif
}

/**
 * @brief Turn on access to OS hashing algorithms if available
 */
void hash::enable_osapi_hashing()
{
    m_isOsApi = osapi_hashing_available();
}

/**
 * @brief Explicitly turn off OS hashing algorithms
 */
void hash::disable_osapi_hashing()
{
    m_isOsApi = false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_md5
 * @brief MD5 subclass of hash class
 **/
c_md5::~c_md5()
{
    md5_free(&m_ctx);
}
void c_md5::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        md5_update(&m_ctx, data, ilen);
    }
}
std::string c_md5::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        md5_finish(&m_ctx, m_digestBuf);
        md5_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha1
 * @brief SHA1 subclass of hash class
 **/
c_sha1::~c_sha1()
{
    sha1_free(&m_ctx);
}
void c_sha1::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        sha1_update(&m_ctx, data, ilen);
    }
}
std::string c_sha1::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        sha1_finish(&m_ctx, m_digestBuf);
        sha1_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}

#ifndef _WIN32
///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha256
 * @brief SHA256 subclass of hash class
 **/
c_sha224::~c_sha224()
{
    sha256_free(&m_ctx);
}
void c_sha224::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        sha256_update(&m_ctx, data, ilen);
    }
}
std::string c_sha224::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        sha256_finish(&m_ctx, m_digestBuf);
        sha256_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha256
 * @brief SHA256 subclass of hash class
 **/
c_sha256::~c_sha256()
{
    sha256_free(&m_ctx);
}
void c_sha256::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        sha256_update(&m_ctx, data, ilen);
    }
}
std::string c_sha256::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        sha256_finish(&m_ctx, m_digestBuf);
        sha256_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha384
 * @brief SHA384 subclass of hash class
 **/
c_sha384::~c_sha384()
{
    sha512_free(&m_ctx);
}
void c_sha384::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        sha512_update(&m_ctx, data, ilen);
    }
}
std::string c_sha384::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        sha512_finish(&m_ctx, m_digestBuf);
        sha512_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * @class c_sha512
 * @brief SHA512 subclass of hash class
 **/
c_sha512::~c_sha512()
{
    sha512_free(&m_ctx);
}
void c_sha512::update(const unsigned char *data, size_t ilen)
{
    if (m_isOsApi)
    {
        osapi_update(data, ilen);
    }
    else
    {
        sha512_update(&m_ctx, data, ilen);
    }
}
std::string c_sha512::get_hash()
{
    if (m_isOsApi)
    {
        osapi_finish();
    }
    else
    {
        sha512_finish(&m_ctx, m_digestBuf);
        sha512_free(&m_ctx);
    }
    return hexStr(m_digestBuf, m_lenDigest);
}