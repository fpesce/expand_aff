#ifndef HASH_H
#define HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct hash_t hash_t;
typedef struct hash_idx_t hash_idx_t;

typedef struct hash_value_t
{
  uint32_t hash;
  uint32_t hash2;
  unsigned char hash2_set;
} hash_value_t;

typedef const void *(get_key_callback_fn_t) (const void *data);
typedef size_t(get_key_len_callback_fn_t) (const void *data);
typedef int (key_cmp_callback_fn_t) (const void *key1, const void *key2, size_t len);
typedef uint32_t (hash_callback_fn_t) (register const void *key, register size_t len);
typedef void (del_callback_fn_t) (void *data);

uint32_t hash_str_hash(register const void *opaque, register size_t len);
uint32_t hash_str_hash2(register const void *opaque, register size_t len);
hash_t *hash_make(size_t nel, size_t ffactor, get_key_callback_fn_t get_key, get_key_len_callback_fn_t get_key_len,
		  key_cmp_callback_fn_t key_cmp, del_callback_fn_t del, hash_callback_fn_t hash);
hash_t *hash_dbl_hashing_make(size_t nel, size_t ffactor, get_key_callback_fn_t get_key,
			      get_key_len_callback_fn_t get_key_len, key_cmp_callback_fn_t key_cmp, del_callback_fn_t del,
			      hash_callback_fn_t hash, hash_callback_fn_t hash2);
void hash_double_hashing_strategy(hash_t *hash, hash_callback_fn_t hash2);
void *hash_search(hash_t *hash, const void *key, size_t key_len, hash_value_t * hash_value);
void hash_remove(hash_t *hash, void *data, hash_value_t hash_value);
int hash_set(hash_t *hash, void *data, hash_value_t hash_value);
size_t hash_get_nel(const hash_t *hash);
void hash_delete(hash_t *hash);

extern hash_idx_t *hash_first(hash_t *hash);
extern hash_idx_t *hash_next(hash_idx_t *hi);
extern void hash_this(hash_idx_t *hi, const void **key, size_t *klen, void **val);

#endif /* HASH_H */
