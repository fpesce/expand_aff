/*
 * Copyright (C) 2011 François Pesce : francois.pesce (at) gmail (dot) com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#include "hash.h"

#define hashsize(n) ((size_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

static inline unsigned int MurmurHash2(const void *key, int len, unsigned int seed)
{
  /* 'm' and 'r' are mixing constants generated offline. */
  /* They're not really 'magic', they just happen to work well. */

  const unsigned int m = 0x5bd1e995;
  const int r = 24;
  unsigned int h;
  /* Mix 4 bytes at a time into the hash */
  const unsigned char *data = (const unsigned char *) key;

  /* Initialize the hash to a 'random' value */
  h = seed ^ len;

  while (len >= 4) {
    unsigned int k = *(unsigned int *) data;

    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    len -= 4;
  }

  /* Handle the last few bytes of the input array */
  switch (len) {
  case 3:
    h ^= data[2] << 16;
  case 2:
    h ^= data[1] << 8;
  case 1:
    h ^= data[0];
    h *= m;
  };

  /* Do a few final mixes of the hash to ensure the last few */
  /* bytes are well-incorporated. */
  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}

extern uint32_t hash_str_hash(register const void *opaque, register size_t len)
{
  return MurmurHash2(opaque, len, 0x1337cafe);
}

extern uint32_t hash_str_hash2(register const void *opaque, register size_t len)
{
  return MurmurHash2(opaque, len, 0xdeadbabe);
}

struct hash_t
{
  void ***table;
  size_t *filling_table;
  get_key_callback_fn_t *get_key;
  get_key_len_callback_fn_t *get_key_len;
  key_cmp_callback_fn_t *key_cmp;
  hash_callback_fn_t *hash;
  hash_callback_fn_t *hash2;
  del_callback_fn_t *del;

  off_t elt_size;
  size_t nel;
  size_t size;
  size_t ffactor;
  uint32_t mask;
  unsigned char power;
#define TYPE_NORMAL 0x00
#define TYPE_DBL_HASH 0x01
  unsigned char type;
};

extern hash_t *hash_make(size_t nel, size_t ffactor, get_key_callback_fn_t get_key, get_key_len_callback_fn_t get_key_len,
			 key_cmp_callback_fn_t key_cmp, del_callback_fn_t del, hash_callback_fn_t hash)
{
  hash_t *result;

  if (NULL == (result = malloc(sizeof(struct hash_t)))) {
    fprintf(stderr, "allocation error\n");
    return NULL;
  }

  result->get_key = get_key;
  result->get_key_len = get_key_len;
  result->key_cmp = key_cmp;
  result->hash = hash;
  result->hash2 = NULL;
  result->del = del;
  result->elt_size = 0;
  result->nel = 0;
  result->ffactor = ffactor;
  result->power = 0;
  result->type = TYPE_NORMAL;
  while (hashsize(result->power) < nel)
    result->power++;

  result->size = hashsize(result->power);
  result->mask = hashmask(result->power);

  if (NULL == (result->table = calloc(result->size, sizeof(void **)))) {
    fprintf(stderr, "allocation error nel: %u factor: %u.\n", (unsigned int) nel, (unsigned int) ffactor);
    return NULL;
  }

  if (NULL == (result->filling_table = calloc(result->size, sizeof(size_t)))) {
    fprintf(stderr, "allocation error nel: %u factor: %u.\n", (unsigned int) nel, (unsigned int) ffactor);
    return NULL;
  }

  return result;
}

extern hash_t *hash_dbl_hashing_make(size_t nel, size_t ffactor, get_key_callback_fn_t get_key,
				     get_key_len_callback_fn_t get_key_len, key_cmp_callback_fn_t key_cmp,
				     del_callback_fn_t del, hash_callback_fn_t hash, hash_callback_fn_t hash2)
{
  hash_t *result;

  result = hash_make(nel, ffactor, get_key, get_key_len, key_cmp, del, hash);
  if (NULL != result)
    hash_double_hashing_strategy(result, hash2);

  return result;
}

extern void hash_double_hashing_strategy(hash_t *hash, hash_callback_fn_t hash2)
{
  hash->hash2 = hash2;
  hash->type = TYPE_DBL_HASH;
}

extern void *hash_search(hash_t *hash, const void *key, size_t key_len, hash_value_t * hash_value)
{
  uint32_t key_hash;
  size_t i, nel, bucket;

  key_hash = hash->hash(key, key_len);

  if (NULL != hash_value) {
    hash_value->hash = key_hash;
    if (TYPE_DBL_HASH == hash->type)
      hash_value->hash2_set = 0;
  }

  bucket = key_hash & hash->mask;
  if (0 != (nel = hash->filling_table[bucket])) {
    for (i = 0; i < nel; i++) {
      if (key_len == hash->get_key_len(hash->table[bucket][i]))
	if (0 == (hash->key_cmp(key, hash->get_key(hash->table[bucket][i]), key_len)))
	  return hash->table[bucket][i];
    }
  }

  if (TYPE_DBL_HASH == hash->type) {
    if (16 > hash->power)
      hash_value->hash2 = key_hash >> 16;
    else
      hash_value->hash2 = hash->hash2(key, key_len);

    hash_value->hash2_set = 1;

    bucket = hash_value->hash2 & hash->mask;

    if (0 != (nel = hash->filling_table[bucket])) {
      for (i = 0; i < nel; i++) {
	if (key_len == hash->get_key_len(hash->table[bucket][i]))
	  if (0 == (hash->key_cmp(key, hash->get_key(hash->table[bucket][i]), key_len)))
	    return hash->table[bucket][i];
      }
    }
  }

  return NULL;
}

static inline int hash_rebuild(hash_t *hash)
{
  hash_t *tmp;
  size_t i, j;
  int rv;

  if (NULL ==
      (tmp =
       hash_make(hashsize(hash->power + 1), hash->ffactor, hash->get_key, hash->get_key_len, hash->key_cmp, hash->del, hash->hash))) {
    fprintf(stderr, "error calling hash_init\n");
    return -1;
  }

  tmp->hash2 = hash->hash2;
  tmp->type = hash->type;

  for (i = 0; i < hash->size; i++) {
    for (j = 0; j < hash->filling_table[i]; j++) {
      hash_value_t hash_value;

      hash_value.hash = hash->hash(hash->get_key(hash->table[i][j]), hash->get_key_len(hash->table[i][j]));
      if (TYPE_DBL_HASH == hash->type)
	hash_value.hash2_set = 0;

      if (0 != (rv = hash_set(tmp, hash->table[i][j], hash_value))) {
	fprintf(stderr, "error calling hash_set\n");
	return rv;
      }
    }
  }
  free(hash->filling_table);
  for (i = 0; i < hash->size; i++)
    if (NULL != hash->table[i])
      free(hash->table[i]);
  free(hash->table);
  hash->table = tmp->table;
  hash->filling_table = tmp->filling_table;
  hash->nel = tmp->nel;
  hash->size = tmp->size;
  hash->mask = tmp->mask;
  hash->power = tmp->power;
  free(tmp);

  return 0;
}

extern void hash_remove(hash_t *hash, void *data, hash_value_t hash_value)
{
  size_t nel, bucket, i, key_len;
  const void *key;

  if ((TYPE_DBL_HASH == hash->type) && (0 != hash_value.hash2_set))
    bucket = hash_value.hash2 & hash->mask;
  else
    bucket = hash_value.hash & hash->mask;

  key = hash->get_key(data);
  key_len = hash->get_key_len(data);
  if (0 != (nel = hash->filling_table[bucket])) {
    for (i = 0; i < nel; i++) {
      if (key_len == hash->get_key_len(hash->table[bucket][i]))
	if (0 == (hash->key_cmp(key, hash->get_key(hash->table[bucket][i]), key_len))) {
	  if (i != nel - 1) {
	    hash->table[bucket][i] = hash->table[bucket][nel - 1];
	    hash->table[bucket][nel - 1] = NULL;
	  }
	  else {
	    hash->table[bucket][i] = NULL;
	  }
	  hash->filling_table[bucket]--;
	  hash->nel--;
	  break;
	}
    }
  }
  else {
    fprintf(stderr, "try to remove something that is not here\n");
  }
}

extern int hash_set(hash_t *hash, void *data, hash_value_t hash_value)
{
  size_t nel, bucket;
  int rv;

  bucket = hash_value.hash & hash->mask;

  if ((0 == (nel = hash->filling_table[bucket]))
      && (NULL == hash->table[bucket])) {
    hash->table[bucket] = malloc(hash->ffactor * sizeof(void *));
  }
  else if ((TYPE_DBL_HASH == hash->type) && (nel >= (hash->ffactor - 1))) {
    if (0 == hash_value.hash2_set) {
      if (16 > hash->power)
	hash_value.hash2 = hash_value.hash >> 16;
      else
	hash_value.hash2 = hash->hash2(hash->get_key(data), hash->get_key_len(data));
    }
    bucket = hash_value.hash2 & hash->mask;
    nel = hash->filling_table[bucket];
    if (nel >= (hash->ffactor - 1)) {
      bucket = hash_value.hash & hash->mask;
      nel = hash->filling_table[bucket];
    }
    else if ((0 == nel) && (NULL == hash->table[bucket])) {
      hash->table[bucket] = malloc(hash->ffactor * sizeof(void *));
    }
  }

  hash->table[bucket][nel] = data;
  hash->filling_table[bucket]++;
  hash->nel++;

  if (hash->ffactor <= hash->filling_table[bucket]) {
    if (0 != (rv = hash_rebuild(hash))) {
      fprintf(stderr, "error calling hash_rebuild\n");
      return rv;
    }
  }

  return 0;
}

extern size_t hash_get_nel(const hash_t *hash)
{
  return hash->nel;
}

extern void hash_delete(hash_t *hash)
{
  size_t i, j;

  if(NULL != hash->del) {
  for (i = 0; i < hash->size; i++)
    if (NULL != hash->table[i]) {
      for (j = 0; j < hash->filling_table[i]; j++) {
        hash->del(hash->table[i][j]);
      }
      free(hash->table[i]);
    }
  } else {
    for (i = 0; i < hash->size; i++)
      if (NULL != hash->table[i])
	free(hash->table[i]);
  }
  free(hash->filling_table);
  free(hash->table);
  free(hash);
}

struct hash_idx_t
{
    hash_t *hash;
    size_t bucket;
    size_t element;		/* of a bucket */
};

extern hash_idx_t *hash_first(hash_t *hash)
{
  hash_idx_t *hi;

  hi = malloc(sizeof(struct hash_idx_t));
  if(NULL != hi) {
    hi->hash = hash;
    hi->bucket = 0;
    hi->element = 0;

    if (hash->filling_table[0] > 0)
      return hi;

    return hash_next(hi);
  } else {
    fprintf(stderr, "hash_first: allocation error\n");
  }

  return hi;
}

extern hash_idx_t *hash_next(hash_idx_t *hi)
{
  if ((0 != hi->hash->filling_table[hi->bucket])
      && (hi->element < (hi->hash->filling_table[hi->bucket] - 1))) {
    hi->element++;
    return hi;
  }
  else {
    hi->element = 0;
    for (hi->bucket += 1; hi->bucket < hi->hash->size; hi->bucket++) {
      if (0 != hi->hash->filling_table[hi->bucket])
	break;
    }
    if (hi->bucket < hi->hash->size)
      return hi;
  }
  free(hi);

  return NULL;
}

extern void hash_this(hash_idx_t *hi, const void **key, size_t *klen, void **val)
{
  if (key)
    *key = hi->hash->get_key(hi->hash->table[hi->bucket][hi->element]);
  if (klen)
    *klen = hi->hash->get_key_len(hi->hash->table[hi->bucket][hi->element]);
  if (val)
    *val = hi->hash->table[hi->bucket][hi->element];
}
