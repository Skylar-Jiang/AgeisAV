/* SPDX-License-Identifier: Apache-2.0
 * Research-only C translation of ppdeep 20260221 _spamsum.
 * Original implementation: Marcin Ulikowski, based on SpamSum by Andrew Tridgell.
 * See NATIVE_SSDEEP_NOTICE.md. No production loader selects this library.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

static const unsigned char fnv[64] = {
    0,19,38,57,12,31,50,5,24,43,62,17,36,55,10,29,
    48,3,22,41,60,15,34,53,8,27,46,1,20,39,58,13,
    32,51,6,25,44,63,18,37,56,11,30,49,4,23,42,61,
    16,35,54,9,28,47,2,21,40,59,14,33,52,7,26,45
};
static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

EXPORT int aegisav_ssdeep(const unsigned char *data, size_t length, char *out, size_t capacity) {
    if ((!data && length) || !out || capacity < 128 || length > 16u*1024u*1024u) return -1;
    uint32_t block = 3;
    while ((uint64_t)block * 64 < length) block *= 2;
    for (;;) {
        unsigned char window[7] = {0};
        uint32_t h1=0, h2=0, h3=0, rolling=0, q1=39, q2=39;
        unsigned cursor=0, n1=0, n2=0;
        char first[65], second[33], last1=0, last2=0;
        for (size_t i=0; i<length; ++i) {
            unsigned b = data[i];
            q1 = fnv[q1] ^ (b & 63);
            q2 = fnv[q2] ^ (b & 63);
            h2 = h2 - h1 + 7*b;
            h1 = h1 + b - window[cursor];
            window[cursor] = (unsigned char)b;
            cursor = (cursor + 1) % 7;
            h3 = (h3 << 5) ^ b;
            rolling = h1 + h2 + h3;
            if (rolling % block == block-1) {
                last1 = alphabet[q1];
                if (n1 < 63) { first[n1++] = last1; q1=39; last1=0; }
                if (rolling % (block*2) == block*2-1) {
                    last2 = alphabet[q2];
                    if (n2 < 31) { second[n2++] = last2; q2=39; last2=0; }
                }
            }
        }
        if (block > 3 && n1 < 32) { block /= 2; continue; }
        if (rolling) {
            first[n1++] = alphabet[q1];
            second[n2++] = alphabet[q2];
        } else {
            if (last1) first[n1++] = last1;
            if (last2) second[n2++] = last2;
        }
        first[n1]=0;
        second[n2]=0;
        int written = snprintf(out, capacity, "%u:%s:%s", block, first, second);
        return written >= 0 && (size_t)written < capacity ? written : -1;
    }
}
