/*
    This file has been modified from its original format, derived
    from mbedtls_sha512.h of the MBEDTLS cryptography project under
    version 3.0 of the GNU General Public License and is subject to that
    license's restrictions.
*/

#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include <cstdio>
#include <cstdlib>
extern "C"
{
#endif

    /**
     * \brief          The SHA-512 context structure.
     *
     *                 The structure is used both for SHA-512 and for SHA-384
     *                 checksum calculations. The choice between these two is
     *                 made in the call to sha512_starts().
     */
    typedef struct sha512_context
    {
        uint64_t total[2];         /*!< The number of Bytes processed.  */
        uint64_t state[8];         /*!< The intermediate digest state.  */
        unsigned char buffer[128]; /*!< The data block being processed. */
        int is384;                 /*!< If (1), calculate the 384 bit hash */
    } sha512_context;

    /**
     * \brief          This function initializes a SHA-512 context.
     *
     * \param ctx      The SHA-512 context to initialize. This must not be \c NULL.
     */
    void sha512_init(sha512_context *ctx);

    /**
     * \brief          This function clears a SHA-512 context.
     *
     * \param ctx      The SHA-512 context to clear. This may be \c NULL, in which
     *                 case this function returns immediately. If it is not \c NULL,
     *                 it must point to an initialized SHA-512 context.
     */
    void sha512_free(sha512_context *ctx);

    /**
     * \brief          This function clones the state of a SHA-512 context.
     *
     * \param dst      The destination context. This must be initialized.
     * \param src      The context to clone. This must be initialized.
     */
    void sha512_clone(sha512_context *dst,
                      const sha512_context *src);

    /**
     * \brief          This function starts a SHA-384 or SHA-512 checksum
     *                 calculation.
     *
     * \param ctx      The context to use. This must be initialized.
     * \param is384    This determines which function to use. This must be
     *                 either \c 0 for SHA-512, or \c 1 for SHA-384.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha512_starts(sha512_context *ctx, int is384);

    /**
     * \brief          This function feeds an input buffer into an ongoing
     *                 SHA-512 checksum calculation.
     *
     * \param ctx      The SHA-512 context. This must be initialized
     *                 and have a hash operation started.
     * \param input    The buffer holding the data. This must be a readable
     *                 buffer of length \p ilen Bytes.
     * \param ilen     The length of the input data in Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha512_update(sha512_context *ctx,
                      const unsigned char *input,
                      size_t ilen);

    /**
     * \brief          This function finishes the SHA-512 operation, and writes
     *                 the result to the output buffer.
     *
     * \param ctx      The SHA-512 context. This must be initialized
     *                 and have a hash operation started.
     * \param output   The SHA-384 or SHA-512 checksum result.
     *                 This must be a writable buffer of length \c 64 Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int sha512_finish(sha512_context *ctx,
                      unsigned char output[64]);

    /**
     * \brief          This function processes a single data block within
     *                 the ongoing SHA-512 computation. This function is for
     *                 internal use only.
     *
     * \param ctx      The SHA-512 context. This must be initialized.
     * \param data     The buffer holding one block of data. This must
     *                 be a readable buffer of length \c 128 Bytes.
     *
     * \return         \c 0 on success.
     * \return         A negative error code on failure.
     */
    int internal_sha512_process(sha512_context *ctx,
                                const unsigned char data[128]);

    /**
     * \brief          This function calculates the SHA-384 or SHA-512
     *                 checksum of a buffer.
     *
     *                 The function allocates the context, performs the
     *                 calculation, and frees the context.
     *
     *                 The SHA-512 result is calculated as
     *                 output = SHA-512(input buffer).
     *
     * \param input    The buffer holding the data. This must be a readable
     *                 buffer of length \p ilen Bytes.
     * \param ilen     The length of the input data in Bytes.
     * \param output   The SHA-384 or SHA-512 checksum result. This must
     *                 be a writable buffer of length \c 64 Bytes.
     * \param is384    Determines which function to use. This must be
     *                 either \c 0 for SHA-512, or \c 1 for SHA-384.
     */
    int sha512(const unsigned char *input,
               size_t ilen,
               unsigned char output[64],
               int is384);

    /**
     * \brief          The SHA-384 checkup routine.
     *
     * \return         \c 0 on success.
     * \return         \c 1 on failure.
     */
    int sha384_self_test(int verbose);

    /**
     * \brief          The SHA-512 checkup routine.
     *
     * \return         \c 0 on success.
     * \return         \c 1 on failure.
     */
    int sha512_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* sha512.h */
