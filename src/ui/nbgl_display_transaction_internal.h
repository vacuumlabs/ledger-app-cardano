#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * Add a key-value pair to the transaction display linked list
 * Creates copies of both key and value strings, so caller's buffers can be freed immediately
 *
 * @param[in] key The key string (will be copied)
 * @param[in] key_len Length of key string (not including null terminator)
 * @param[in] value The value string (will be copied)
 * @param[in] value_len Length of value string (not including null terminator)
 * @return true on success, false on memory allocation failure
 */
bool tx_pairs_push(const char *key, size_t key_len,
                   const char *value, size_t value_len);

/**
 * Get the reusable temporary display buffer
 *
 * @return pointer to temporary buffer (512 bytes)
 */
char *tx_get_temp_display_buffer(void);
