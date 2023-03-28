/*
    This file has been modified from its original format, derived
    from mbedtls_sha256.h of the MBEDTLS cryptography project under
    version 3.0 of the GNU General Public License and is subject to that
    license's restrictions.
*/

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include <cstdio>
#include <cstdlib>
extern "C"
{
#endif

    /**
     * \brief          The SHA-256 context structure.
     *
     *                 The structure is used both for SHA-256 and for SHA-224
     *                 checksum calculations. The choice between these two is
     *                 made in the call to sha256_starts().
     */
    typedef struct sha256_context
    {
        uint32_t total[2];        /*!< The number of Bytes processed.  */
        uint32_t state[8];        /*!< The intermediate digest state.  */
        unsigned char buffer[64]; /*!< The data block being processed. */
        int is224;                /*!< If (1), calculate the 224 bit hash */
    } sha256_context;

    /**
     * \brief          This function initializes a SHA-256 context.
     *
     * \param ctx      The SHA-256 context to initialize. This must not be \c NULL.
     */
    void sha256_init(sha256_context *ctx);

    /**
     * \brief          This function clears a SHA-256 context.
     *
     * \param ctx      The SHA-256 context to clear. This may be \c NULL, in which
     *                 case this function returns immediately. If it is not \c NULL,
     *                 it must point to an initialized SHA-256 context.
     */
    void sha256_free(sha256_context *ctx);

    /**
     * \brief          This function clones the state of a SHA-256 context.
     *
     * \param dst      The destination context. This must be initialized.
     * \param src      The context to clone. This must be initialized.
     */
    void sha256_clone(sha256_context *dst,
                      const sha256_context *src);

    /**
     * \brief          This function starts a SHA-224 or SHA-256 checksum
     *                 calculation.
     *
     * \param ctx      The context to use. This must be initialized.
     * \param is224    This determines which function to use. This must be
     *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha256_starts(sha256_context *ctx, int is224);

    /**
     * \brief          This function feeds an input buffer into an ongoing
     *                 SHA-256 checksum calculation.
     *
     * \param ctx      The SHA-256 context. This must be initialized
     *                 and have a hash operation started.
     * \param input    The buffer holding the data. This must be a readable
     *                 buffer of length \p ilen Bytes.
     * \param ilen     The length of the input data in Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha256_update(sha256_context *ctx,
                      const unsigned char *input,
                      size_t ilen);

    /**
     * \brief          This function finishes the SHA-256 operation, and writes
     *                 the result to the output buffer.
     *
     * \param ctx      The SHA-256 context. This must be initialized
     *                 and have a hash operation started.
     * \param output   The SHA-224 or SHA-256 checksum result.
     *                 This must be a writable buffer of length \c 32 Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha256_finish(sha256_context *ctx,
                      unsigned char output[32]);

    /**
     * \brief          This function processes a single data block within
     *                 the ongoing SHA-256 computation. This function is for
     *                 internal use only.
     *
     * \param ctx      The SHA-256 context. This must be initialized.
     * \param data     The buffer holding one block of data. This must
     *                 be a readable buffer of length \c 64 Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int internal_sha256_process(sha256_context *ctx,
                                const unsigned char data[64]);

    /**
     * \brief          This function calculates the SHA-224 or SHA-256
     *                 checksum of a buffer.
     *
     *                 The function allocates the context, performs the
     *                 calculation, and frees the context.
     *
     *                 The SHA-256 result is calculated as
     *                 output = SHA-256(input buffer).
     *
     * \param input    The buffer holding the data. This must be a readable
     *                 buffer of length \p ilen Bytes.
     * \param ilen     The length of the input data in Bytes.
     * \param output   The SHA-224 or SHA-256 checksum result. This must
     *                 be a writable buffer of length \c 32 Bytes.
     * \param is224    Determines which function to use. This must be
     *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
     */
    int sha256(const unsigned char *input,
               size_t ilen,
               unsigned char output[32],
               int is224);

    /**
     * \brief          The SHA-224 checkup routine.
     *
     * \return         \c 0 on success.
     * \return         \c 1 on failure.
     */
    int sha224_self_test(int verbose);

    /**
     * \brief          The SHA-256 checkup routine.
     *
     * \return         \c 0 on success.
     * \return         \c 1 on failure.
     */
    int sha256_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* sha256.h */
