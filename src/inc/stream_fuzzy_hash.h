#ifndef _STREAM_FUZZY_HASH_
#define _STREAM_FUZZY_HASH_

/*
 * Copyright (C) MESA 2015

 *
 */

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOTAL_LENGTH     0
#define EFFECTIVE_LENGTH 1
#define HASH_LENGTH      2

// typedef sfh_instance_t void*;
typedef struct
{
}sfh_instance_t;

/**
 * create a fuzzy hash handle and return it.
 * @return        [handle]
 */
sfh_instance_t * SFH_instance(unsigned long long origin_len);

/**
 * destroy context by a fuzzy hash handle.
 * @param handle  [handle]
 */
void SFH_release(sfh_instance_t * handle);

/**
 * Feed the function your data.
 * Call this function several times, if you have several parts of data to feed.
 * @param  handle [handle]
 * @param  data   [data that you want to fuzzy_hash]
 * @param  size   [data size]
 * @param  offset [offset]
 * @return        [return effective data length in current feed]
 */
unsigned int SFH_feed(sfh_instance_t * handle, const char* data, unsigned int size, unsigned long long offset);

/**
 * Obtain the fuzzy hash values.
 * @param  handle  [handle]
 * @param  result  [fuzzy hash result]
 *     Fuzzy hash result with offsets(in the square brackets, with colon splitted).
 *     eg. abc[1:100]def[200:300]
 * @param  size    [@result size]
 * @return         [return zero on success, non-zero on error]
 */
int SFH_digest(sfh_instance_t * handle, char* result, unsigned int size);

/**
 * Obtain certain length of fuzzy hash status.
 * @param  handle [handle]
 * @param  type   [length type]
     * TOTAL_LENGTH:Total length of data you have fed.
     *     Overlapped data will NOT count for 2 times.
     * EFFECTIVE_LENGTH:Length of data that involved in the calculation of hash.
     * HASH_LENGTH:Hash result length.
 * @return        [length value]
 */
unsigned long long SFH_status(sfh_instance_t * handle, int type);


#ifdef __cplusplus
}
#endif

#endif

