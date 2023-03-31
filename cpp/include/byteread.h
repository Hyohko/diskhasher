/*
    This file has been modified from its original format, derived
    from common.h of the MBEDTLS cryptography project under
    version 3.0 of the GNU General Public License and is subject to that
    license's restrictions.
*/

#ifndef _BYTEREAD_H_
#define _BYTEREAD_H_

/** Byte Reading Macros
 *
 * Given a multi-byte integer \p x, BYTE_n retrieves the n-th
 * byte from x, where byte 0 is the least significant byte.
 */
#define BYTE_0(x) ((uint8_t)((x)&0xff))
#define BYTE_1(x) ((uint8_t)(((x) >> 8) & 0xff))
#define BYTE_2(x) ((uint8_t)(((x) >> 16) & 0xff))
#define BYTE_3(x) ((uint8_t)(((x) >> 24) & 0xff))
#define BYTE_4(x) ((uint8_t)(((x) >> 32) & 0xff))
#define BYTE_5(x) ((uint8_t)(((x) >> 40) & 0xff))
#define BYTE_6(x) ((uint8_t)(((x) >> 48) & 0xff))
#define BYTE_7(x) ((uint8_t)(((x) >> 56) & 0xff))

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(data, offset) \
    (                               \
        ((uint32_t)(data)[(offset)] << 24) | ((uint32_t)(data)[(offset) + 1] << 16) | ((uint32_t)(data)[(offset) + 2] << 8) | ((uint32_t)(data)[(offset) + 3]))
#endif

/**
 * Put in memory a 32 bits unsigned integer in big-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_3(n);     \
        (data)[(offset) + 1] = BYTE_2(n); \
        (data)[(offset) + 2] = BYTE_1(n); \
        (data)[(offset) + 3] = BYTE_0(n); \
    }
#endif

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(data, offset) \
    (                               \
        ((uint32_t)(data)[(offset)]) | ((uint32_t)(data)[(offset) + 1] << 8) | ((uint32_t)(data)[(offset) + 2] << 16) | ((uint32_t)(data)[(offset) + 3] << 24))
#endif

/**
 * Put in memory a 32 bits unsigned integer in little-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_0(n);     \
        (data)[(offset) + 1] = BYTE_1(n); \
        (data)[(offset) + 2] = BYTE_2(n); \
        (data)[(offset) + 3] = BYTE_3(n); \
    }
#endif

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT16_LE
#define GET_UINT16_LE(data, offset) \
    (                               \
        ((uint16_t)(data)[(offset)]) | ((uint16_t)(data)[(offset) + 1] << 8))
#endif

/**
 * Put in memory a 16 bits unsigned integer in little-endian order.
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#ifndef PUT_UINT16_LE
#define PUT_UINT16_LE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_0(n);     \
        (data)[(offset) + 1] = BYTE_1(n); \
    }
#endif

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT16_BE
#define GET_UINT16_BE(data, offset) \
    (                               \
        ((uint16_t)(data)[(offset)] << 8) | ((uint16_t)(data)[(offset) + 1]))
#endif

/**
 * Put in memory a 16 bits unsigned integer in big-endian order.
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#ifndef PUT_UINT16_BE
#define PUT_UINT16_BE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_1(n);     \
        (data)[(offset) + 1] = BYTE_0(n); \
    }
#endif

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(data, offset) \
    (                               \
        ((uint64_t)(data)[(offset)] << 56) | ((uint64_t)(data)[(offset) + 1] << 48) | ((uint64_t)(data)[(offset) + 2] << 40) | ((uint64_t)(data)[(offset) + 3] << 32) | ((uint64_t)(data)[(offset) + 4] << 24) | ((uint64_t)(data)[(offset) + 5] << 16) | ((uint64_t)(data)[(offset) + 6] << 8) | ((uint64_t)(data)[(offset) + 7]))
#endif

/**
 * Put in memory a 64 bits unsigned integer in big-endian order.
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_7(n);     \
        (data)[(offset) + 1] = BYTE_6(n); \
        (data)[(offset) + 2] = BYTE_5(n); \
        (data)[(offset) + 3] = BYTE_4(n); \
        (data)[(offset) + 4] = BYTE_3(n); \
        (data)[(offset) + 5] = BYTE_2(n); \
        (data)[(offset) + 6] = BYTE_1(n); \
        (data)[(offset) + 7] = BYTE_0(n); \
    }
#endif

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(data, offset) \
    (                               \
        ((uint64_t)(data)[(offset) + 7] << 56) | ((uint64_t)(data)[(offset) + 6] << 48) | ((uint64_t)(data)[(offset) + 5] << 40) | ((uint64_t)(data)[(offset) + 4] << 32) | ((uint64_t)(data)[(offset) + 3] << 24) | ((uint64_t)(data)[(offset) + 2] << 16) | ((uint64_t)(data)[(offset) + 1] << 8) | ((uint64_t)(data)[(offset)]))
#endif

/**
 * Put in memory a 64 bits unsigned integer in little-endian order.
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n, data, offset)    \
    {                                     \
        (data)[(offset)] = BYTE_0(n);     \
        (data)[(offset) + 1] = BYTE_1(n); \
        (data)[(offset) + 2] = BYTE_2(n); \
        (data)[(offset) + 3] = BYTE_3(n); \
        (data)[(offset) + 4] = BYTE_4(n); \
        (data)[(offset) + 5] = BYTE_5(n); \
        (data)[(offset) + 6] = BYTE_6(n); \
        (data)[(offset) + 7] = BYTE_7(n); \
    }
#endif

#endif /* _BYTEREAD_H_ */