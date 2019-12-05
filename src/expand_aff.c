/*
 * Copyright (C) 2012  François Pesce
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 2; tab-width: 0 -*- */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <regex.h>
#include <sys/types.h>

#include "hash.h"
#include "list.h"
#include "mmap_wrapper.h"

#define OPTION_EXPAND 0x1
#define OPTION_TYPO_E 0x2

#define is_option_set(mask, option)  ((mask & option) == option)

#define set_option(mask, option, on)     \
    do {                                 \
        if (on)                          \
            mask |= option;             \
        else                             \
            mask &= ~option;            \
    } while (0)

#define MIN(a,b) (((a)<(b))?(a):(b))

/** This structure defines a replacement destination string. */
struct rep_dst_t
{
  char *dst;
  size_t dst_len;
};

typedef struct rep_dst_t rep_dst_t;

/**
 * This structure's goal is to define a typing error as small as possible.
 * In order to recursively generates all possible typing error on a single word
 * in the smallest possible memory area.
 */
struct typing_err_t
{
  const rep_dst_t *rep;
  unsigned char r_pos; /* the position of the string to replace. */
  unsigned char r_len; /* the length of the string to replace. */
};

typedef struct typing_err_t typing_err_t;

/** This structure holds a set of replacements possible for one string. */
struct rep_t
{
  /** String to replace. */
  char *src;
  /** Length of string to replace. */
  size_t src_len;
  /** List of possible replacements. */
  list_t *dsts;
};

typedef struct rep_t rep_t;

static const void *rep_get_key(const void *data)
{
  const rep_t *rep = data;

  return rep->src;
}

static size_t rep_get_key_len(const void *data)
{
  const rep_t *rep = data;

  return rep->src_len;
}

static void rep_cleanup(void *data)
{
  rep_dst_t *dst;
  rep_t *rep = data;

  while (NULL != list_first(rep->dsts)) {
    dst = list_get(list_first(rep->dsts));
    free(dst->dst);
    free(dst);
    list_cdr(rep->dsts);
  }
  list_delete(rep->dsts);
  list_release_container(rep->dsts);
  free(rep->src);
  free(rep);
}

static int str_key_cmp(const void *key1, const void *key2, size_t len)
{
  const char *str1 = key1;
  const char *str2 = key2;

  return strncmp(str1, str2, len);
}

/** This structure defines match pattern and corresponding affix. */
struct rule_t
{
  /** NULL means the prefix is preppended, the suffix is appended, otherwise, to_replace is rewritten upon. */
  char *to_replace;
  size_t to_replace_len;
  /** The affix to write. */
  char *replacement;
  size_t replacement_len;
  /** The regex that string must match to trigger this rule. */
  regex_t *to_match;
};

typedef struct rule_t rule_t;

struct affix_t
{
  /** List of rule_t. */
  list_t *rules;
  /** Can a su/prefix be applied with this pre/suffix.*/
  int combine:1;
  /** Type */
  int is_suffix:1;
};

typedef struct affix_t affix_t;

struct aff_conf_t
{
  /* store replacement in hash. */
  hash_t *reps;
  size_t longest_rep;
  /* maximum nb of changes for one exact same substring. */
  int max_dsts;
  int max_shift;
  affix_t *prefix[UCHAR_MAX];
  affix_t *suffix[UCHAR_MAX];
  unsigned char opt_mask;
  unsigned char typo_level;
};

typedef struct aff_conf_t aff_conf_t;

static inline affix_t *affix_make(int combine, int is_suffix)
{
  affix_t *result;

  result = malloc(sizeof(struct affix_t));

  if (NULL != result) {
    result->rules = list_make();
    if (is_suffix)
      result->is_suffix |= 0x1;
    else
      result->is_suffix &= 0x0;
    if (combine)
      result->combine |= 0x1;
    else
      result->combine &= 0x0;
  }

  return result;
}

static inline void rule_destroy(rule_t *rule)
{
  if (rule->to_match) {
    regfree(rule->to_match);
    free(rule->to_match);
  }
  if (rule->replacement)
    free(rule->replacement);
  if (rule->to_replace)
    free(rule->to_replace);

  free(rule);
}

static inline void affix_destroy(affix_t * affix)
{
  rule_t *rule;

  while (NULL != list_first(affix->rules)) {
    rule = list_get(list_first(affix->rules));
    rule_destroy(rule);
    list_cdr(affix->rules);
  }
  list_delete(affix->rules);
  list_release_container(affix->rules);
  free(affix);
}

static inline void aff_conf_destroy(aff_conf_t *aff_conf)
{
  unsigned char i;

  for (i = 0; i < UCHAR_MAX; i++) {
    if (NULL != (aff_conf->prefix)[i])
      affix_destroy((aff_conf->prefix)[i]);
    if (NULL != (aff_conf->suffix)[i])
      affix_destroy((aff_conf->suffix)[i]);
  }

  if (NULL != aff_conf->reps)
    hash_delete(aff_conf->reps);

  free(aff_conf);
}

#define REGEX_MAX_SZ 1024
static inline rule_t *rule_make(const char *line, size_t len, int is_suffix)
{
  char regex[REGEX_MAX_SZ];
  const char *ptr, *end, *limit;
  rule_t *result;

  if (len < 5) {
    fprintf(stderr, "invalid rule line (too small) [%.*s]\n", (int) len, line);
    return NULL;
  }
  limit = line + len;
  result = malloc(sizeof(struct rule_t));
  if (NULL != result) {
    ptr = &line[5];
    while (isspace(*ptr) && (ptr < limit))
      ptr++;

    if (ptr >= limit) {
      fprintf(stderr, "invalid rule line (nothing after rule name) [%.*s]\n", (int) len, line);
      free(result);
      return NULL;
    }

    end = ptr + 1;
    if ('0' == *ptr) {
      result->to_replace = NULL;
      result->to_replace_len = 0;
      end++;
    }
    else {
      end = ptr + 1;
      while (!isspace(*end) && (end < limit))
	end++;

      if (end >= limit) {
	fprintf(stderr, "invalid rule line (no end for replaced) [%.*s]\n", (int) len, line);
	free(result);
	return NULL;
      }

      result->to_replace_len = end - ptr;
      result->to_replace = strndup(ptr, result->to_replace_len);
      if (NULL == result->to_replace) {
	fprintf(stderr, "error calling strndup\n");
	free(result);
	return NULL;
      }
    }
    ptr = end;
    while (isspace(*ptr) && (ptr < limit))
      ptr++;

    if (ptr >= limit) {
      fprintf(stderr, "invalid rule line [%.*s] (nothing after replaced)\n", (int) len, line);
      if (NULL != result->to_replace)
	free(result->to_replace);
      free(result);
      return NULL;
    }

    end = ptr + 1;
    while (!isspace(*end) && (end < limit))
      end++;

    if (end >= limit) {
      fprintf(stderr, "invalid rule line (no end for replacement) [%.*s]\n", (int) len, line);
      if (NULL != result->to_replace)
	free(result->to_replace);
      free(result);
      return NULL;
    }
    result->replacement_len = end - ptr;
    result->replacement = strndup(ptr, result->replacement_len);
    if (NULL == result->replacement) {
      fprintf(stderr, "error calling strndup (for replacement)\n");
      if (NULL != result->to_replace)
	free(result->to_replace);
      free(result);
      return NULL;
    }

    ptr = end;
    while (isspace(*ptr) && (ptr < limit))
      ptr++;

    if (ptr >= limit) {
      fprintf(stderr, "invalid rule line [%.*s] (nothing after replaced)\n", (int) len, line);
      free(result->replacement);
      if (NULL != result->to_replace)
	free(result->to_replace);
      free(result);
      return NULL;
    }

    end = ptr + 1;
    while (!isspace(*end) && (end < limit))
      end++;

    result->to_match = malloc(sizeof(regex_t));
    if (is_suffix) {
      snprintf(regex, REGEX_MAX_SZ, "%.*s$", (int) (end - ptr), ptr);
    }
    else {
      snprintf(regex, REGEX_MAX_SZ, "^%.*s", (int) (end - ptr), ptr);
    }
    if (0 != regcomp(result->to_match, regex, REG_ICASE | REG_NOSUB | REG_NEWLINE)) {
      fprintf(stderr, "invalid regex [%s] line [%.*s]\n", regex, (int) len, line);
      free(result->replacement);
      if (NULL != result->to_replace)
	free(result->to_replace);
      free(result);
      return NULL;
    }
  }
  else {
    fprintf(stderr, "error calling calloc\n");
  }

  return result;
}

static inline affix_t *affix_build(mmap_wrapper_t *mw, const char *line, size_t len, size_t * idx, int is_suffix)
{
  affix_t *result;
  rule_t *rule;
  long int nb_rules, r;
  int rv;

  nb_rules = strtol(&line[8], NULL, 10);
  if ((LONG_MIN == nb_rules) || (LONG_MAX == nb_rules)) {
    fprintf(stderr, "invalid PFX line [%.*s]\n", (int) len, line);
    return NULL;
  }

  result = affix_make('Y' == line[6], 0);
  for (r = 0; r < nb_rules; r++) {
    rv = mmap_get_next(mw, idx, '\n');
    if (0 != rv) {
      fprintf(stderr, "error calling mmap_get_next in affix code idx: %u\n", (unsigned int) *idx);
      affix_destroy(result);
      return NULL;
    }
    line = mmap_get_line(mw, idx, &len, '\n');
    if (NULL == line) {
      fprintf(stderr, "error calling mmap_get_line in affix code idx: %u\n", (unsigned int) *idx);
      affix_destroy(result);
      return NULL;
    }
    rule = rule_make(line, len, is_suffix);
    if (NULL == rule) {
      fprintf(stderr, "error calling rule_make line [%.*s]\n", (int) len, line);
      affix_destroy(result);
      return NULL;
    }
    if (0 != list_cons(result->rules, rule)) {
      fprintf(stderr, "error calling list_cons line [%.*s]\n", (int) len, line);
      affix_destroy(result);
      return NULL;
    }
  }

  return result;
}

static inline aff_conf_t *aff_conf_make(const char *file)
{
  mmap_wrapper_t *mw;
  aff_conf_t *result;
  const char *line;
  size_t idx, len;
  int rv;
  unsigned char pos;

  rv = mmap_wrapper_init(&mw, file);
  if (0 != rv) {
    fprintf(stderr, "error calling mmap_wrapper_init on file %s\n", file);
    return NULL;
  }

  result = calloc(1, sizeof(struct aff_conf_t));
  if (NULL == result) {
    mmap_wrapper_delete(mw);
    fprintf(stderr, "error calling calloc\n");
    return NULL;
  }
  for (rv = mmap_get_head(mw, &idx); 0 == rv; rv = mmap_get_next(mw, &idx, '\n')) {
    line = mmap_get_line(mw, &idx, &len, '\n');
    if (NULL == line) {
      fprintf(stderr, "error calling mmap_get_line on file %s idx: %u\n", file, (unsigned int) idx);
      aff_conf_destroy(result);
      mmap_wrapper_delete(mw);
      return NULL;
    }
    if (0 == len)
      continue;

    if (0 == strncmp(line, "PFX", 3)) {
      if (len < 9) {
	fprintf(stderr, "too short PFX line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }
      pos = (unsigned char) line[4];
      (result->prefix)[pos] = affix_build(mw, line, len, &idx, 0);
      if (NULL == (result->prefix)[pos]) {
	fprintf(stderr, "invalid PFX line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }
    }
    else if (0 == strncmp(line, "SFX", 3)) {
      if (len < 9) {
	fprintf(stderr, "too short SFX line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }
      pos = (unsigned char) line[4];
      (result->suffix)[pos] = affix_build(mw, line, len, &idx, 1);
      if (NULL == (result->suffix)[pos]) {
	fprintf(stderr, "invalid SFX line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }
    }
    else if (0 == strncmp(line, "REP", 3)) {
      hash_value_t hash_value;
      const char *ptr, *end, *limit;
      rep_t *rep;
      rep_dst_t *rep_dst;
      long int nb_reps, r;

      if (len < 5) {
	fprintf(stderr, "too short REP line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }
      nb_reps = strtol(&line[4], NULL, 10);
      if ((LONG_MIN == nb_reps) || (LONG_MAX == nb_reps)) {
	fprintf(stderr, "invalid REP line [%.*s]\n", (int) len, line);
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }

      result->reps =
	hash_dbl_hashing_make((size_t) nb_reps, 3, rep_get_key, rep_get_key_len, str_key_cmp, rep_cleanup, hash_str_hash, hash_str_hash2);
      if (NULL == result->reps) {
	fprintf(stderr, "error calling hash_dbl_hashing_make\n");
	aff_conf_destroy(result);
	mmap_wrapper_delete(mw);
	return NULL;
      }

      for (r = 0; r < nb_reps; r++) {
	rv = mmap_get_next(mw, &idx, '\n');
	if (0 != rv) {
	  fprintf(stderr, "error calling mmap_get_next in affix code on file %s idx: %u\n", file, (unsigned int) idx);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	line = mmap_get_line(mw, &idx, &len, '\n');
	if (NULL == line) {
	  fprintf(stderr, "error calling mmap_get_line in affix code on file %s idx: %u\n", file, (unsigned int) idx);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	if (len < 7) {
	  fprintf(stderr, "too short REP line [%.*s]\n", (int) len, line);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	limit = line + len;
	ptr = &line[4];
	end = ptr + 1;
	while (!isspace(*end) && (end < limit))
	  end++;

	if (end >= limit) {
	  fprintf(stderr, "invalid REP line (no end for destination) [%.*s]\n", (int) len, line);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}

	rep_dst = malloc(sizeof(struct rep_dst_t));
	if (NULL == rep_dst) {
	  fprintf(stderr, "error calling malloc rep_dst\n");
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	rep_dst->dst_len = end - ptr;
	rep_dst->dst = strndup(ptr, rep_dst->dst_len);
	if (NULL == rep_dst->dst) {
	  fprintf(stderr, "error calling strndup for dst\n");
	  free(rep_dst);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	ptr = end;
	while (isspace(*ptr) && (ptr < limit))
	  ptr++;

	if (ptr >= limit) {
	  fprintf(stderr, "invalid rule line [%.*s] (nothing after destination)\n", (int) len, line);
	  free(rep_dst->dst);
	  free(rep_dst);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}

	end = ptr + 1;
	while (!isspace(*end) && (end < limit))
	  end++;

	/* Because we want to "create" bad words, so we use rep destination as source. */
	rep = hash_search(result->reps, ptr, end - ptr, &hash_value);
	if (NULL == rep) {
	  rep = malloc(sizeof(struct rep_t));
	  if (NULL == rep) {
	    fprintf(stderr, "error calling malloc rep\n");
	    free(rep_dst->dst);
	    free(rep_dst);
	    aff_conf_destroy(result);
	    mmap_wrapper_delete(mw);
	    return NULL;
	  }
	  rep->src_len = end - ptr;
	  if(rep->src_len > result->longest_rep)
	    result->longest_rep = rep->src_len;
	  rep->src = strndup(ptr, rep->src_len);
	  if (NULL == rep->src) {
	    fprintf(stderr, "error calling strndup rep->src\n");
	    free(rep_dst->dst);
	    free(rep_dst);
	    aff_conf_destroy(result);
	    mmap_wrapper_delete(mw);
	    return NULL;
	  }
	  rep->dsts = list_make();
	  if (NULL == rep->dsts) {
	    fprintf(stderr, "error calling list_make\n");
	    free(rep_dst->dst);
	    free(rep_dst);
	    aff_conf_destroy(result);
	    mmap_wrapper_delete(mw);
	    return NULL;
	  }
	  if (0 != hash_set(result->reps, rep, hash_value)) {
	    fprintf(stderr, "error calling hash_set\n");
	    free(rep_dst->dst);
	    free(rep_dst);
	    aff_conf_destroy(result);
	    mmap_wrapper_delete(mw);
	    return NULL;
	  }
	}
	if (0 != list_cons(rep->dsts, rep_dst)) {
	  fprintf(stderr, "error calling hash_set\n");
	  free(rep_dst->dst);
	  free(rep_dst);
	  aff_conf_destroy(result);
	  mmap_wrapper_delete(mw);
	  return NULL;
	}
	if(rep_dst->dst_len > (end - ptr)) {
	  if(result->max_shift < (rep_dst->dst_len - (end - ptr)))
	    result->max_shift = rep_dst->dst_len - (end - ptr);
	}

	if(result->max_dsts < list_get_nb_cells(rep->dsts))
	  result->max_dsts = list_get_nb_cells(rep->dsts);
      }
    }
  }

  mmap_wrapper_delete(mw);

  return result;
}

#define DIC_NB_WRD_AVG 65536
struct wrd_t {
  char *s;
  size_t len;
};
typedef struct wrd_t wrd_t;

static const void *wrd_get_key(const void *data)
{
  const wrd_t *wrd = data;

  return wrd->s;
}

static size_t wrd_get_key_len(const void *data)
{
  const wrd_t *wrd = data;

  return wrd->len;
}

static void wrd_cleanup(void *data)
{
  wrd_t *wrd = data;

  free(wrd->s);
  free(wrd);
}

static inline int gen_typing_errors(const aff_conf_t *aff_conf, hash_t *dbl_kill, const wrd_t *wrd, const typing_err_t *typing_err, size_t nb_errs, unsigned char deep)
{
  hash_value_t hash_value;
  typing_err_t *local;
  wrd_t *new, *hit;
  size_t nb_local, idx, i;
  int nb_gens, rv, shift;

  if(0 == deep)
    return 0;

  nb_gens = 0;
  local = malloc((nb_errs - 1) * sizeof(struct typing_err_t));
  if(NULL == local) {
    fprintf(stderr, "error calling local = malloc\n");
    return -1;
  }
  new = malloc(sizeof(struct wrd_t));
  if(NULL == new) {
    fprintf(stderr, "error calling new = malloc\n");
    free(local);
    return -1;
  }
  new->s = malloc((wrd->len + (aff_conf->max_shift * nb_errs)) * sizeof(char));
  if(NULL == new->s) {
    fprintf(stderr, "error calling new->s = malloc\n");
    free(new);
    free(local);
    return -1;
  }
  for(i = 0; i < nb_errs; i++) {
    memset(local, 0, (nb_errs - 1) * sizeof(struct typing_err_t));
    nb_local = 0;
    /*
     * We select an error, then invalidate every similar error and shifts
     * necessary positions, and recurse.
     */
    new->len = wrd->len + ((typing_err[i].rep)->dst_len - typing_err[i].r_len);
    memcpy(new->s, wrd->s, typing_err[i].r_pos);
    memcpy(new->s + typing_err[i].r_pos, (typing_err[i].rep)->dst, (typing_err[i].rep)->dst_len);
    memcpy(new->s + typing_err[i].r_pos + (typing_err[i].rep)->dst_len, wrd->s + typing_err[i].r_pos + typing_err[i].r_len, wrd->len - (typing_err[i].r_pos + typing_err[i].r_len));
    new->s[new->len] = '\0';
    shift = (typing_err[i].rep)->dst_len - typing_err[i].r_len;
    for(idx = 0; idx < nb_errs; idx++) {
      if((typing_err[idx].r_pos + typing_err[idx].r_len) < typing_err[i].r_pos) {
	memcpy(&(local[nb_local]), &(typing_err[idx]), sizeof(struct typing_err_t));
	nb_local++;
      } else if(typing_err[idx].r_pos > (typing_err[i].r_pos + (typing_err[i].rep)->dst_len)) {
	memcpy(&(local[nb_local]), &(typing_err[idx]), sizeof(struct typing_err_t));
	local[nb_local].r_pos += shift;
	nb_local++;
      }
    }
    hit = hash_search(dbl_kill, new->s, new->len, &hash_value);
    if(NULL == hit) {
      fprintf(stdout, "%.*s\n", (int) new->len, new->s);
      nb_gens++;
      if(0 != nb_local) {
	rv = gen_typing_errors(aff_conf, dbl_kill, new, local, nb_local, deep - 1);
	if(-1 == rv) {
	  fprintf(stderr, "error calling gen_typing_errors\n");
	  free(new->s);
	  free(new);
	  free(local);
	  return -1;
	}
	nb_gens += rv;
      }
    }
  }
  free(new->s);
  free(new);
  free(local);

  return nb_gens;
}

static inline int aff_process_dictionary(const aff_conf_t *aff_conf, const char *dictionary)
{
  hash_value_t hash_value;
  mmap_wrapper_t *mw;
  hash_t *dbl_kill;
  hash_idx_t *hi;
  affix_t *pfx, *sfx;
  wrd_t *wrd, *new, *pfxmatch, *sfxmatch;
  const char *line, *limit, *prefix, *suffix, *end;
  size_t idx, len, wrdlen;
  int rv;

  rv = mmap_wrapper_init(&mw, dictionary);
  if (0 != rv) {
    fprintf(stderr, "error calling mmap_wrapper_init on file %s\n", dictionary);
    return -1;
  }
  dbl_kill = hash_dbl_hashing_make(DIC_NB_WRD_AVG, 7, wrd_get_key, wrd_get_key_len, str_key_cmp, wrd_cleanup, hash_str_hash, hash_str_hash2);
  if(NULL == dbl_kill) {
    mmap_wrapper_delete(mw);
    fprintf(stderr, "error calling mmap_wrapper_init on file %s\n", dictionary);
    return -1;
  }
  for (rv = mmap_get_head(mw, &idx); 0 == rv; rv = mmap_get_next(mw, &idx, '\n')) {
    line = mmap_get_line(mw, &idx, &len, '\n');
    if (NULL == line) {
      fprintf(stderr, "error calling mmap_get_line on file %s idx: %u\n", dictionary, (unsigned int) idx);
      hash_delete(dbl_kill);
      mmap_wrapper_delete(mw);
      return -1;
    }
    end = memchr(line, '/', len);
    if(NULL != end) {
      wrdlen = end - line;
    } else {
      wrdlen = len;
    }
    wrd = hash_search(dbl_kill, line, wrdlen, &hash_value);
    if(NULL == wrd) {
      wrd = malloc(sizeof(struct wrd_t));
      if (NULL == wrd) {
	fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
	hash_delete(dbl_kill);
	mmap_wrapper_delete(mw);
	return -1;
      }
      wrd->s = strndup(line, wrdlen);
      if (NULL == wrd->s) {
	fprintf(stderr, "%s(%d): error calling strndup\n", __FUNCTION__, __LINE__);
	free(wrd);
	hash_delete(dbl_kill);
	mmap_wrapper_delete(mw);
	return -1;
      }
      wrd->len = wrdlen;
      if(0 != hash_set(dbl_kill, wrd, hash_value)) {
	fprintf(stderr, "error calling hash_set (wrd) line [%.*s]\n", (int) len, line);
	free(wrd->s);
	free(wrd);
	hash_delete(dbl_kill);
	mmap_wrapper_delete(mw);
	return -1;
      }
      /* Display new word. */
      fprintf(stdout, "%.*s\n", (int) wrd->len, wrd->s);
    }
    if(is_option_set(aff_conf->opt_mask, OPTION_EXPAND) && (NULL != end)) {
      limit = line + len;
      /* apply suffix alone. */
      for(suffix = end + 1; suffix < limit; suffix++) {
	sfx = aff_conf->suffix[(unsigned char) *suffix];
	if(NULL != sfx) {
	  cell_t *cell;
	  rule_t *rule;

	  for(cell = list_first(sfx->rules); (NULL != cell); cell = list_next(cell)) {
	    rule = list_get(cell);
	    if(0 == regexec(rule->to_match, wrd->s, 0, 0, 0)) {
	      /* Match, apply rule, exit */
	      new = malloc(sizeof(struct wrd_t));
	      if (NULL == new) {
		fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
		hash_delete(dbl_kill);
		mmap_wrapper_delete(mw);
		return -1;
	      }
	      new->len = (wrd->len - rule->to_replace_len) + rule->replacement_len;
	      new->s = malloc((new->len + 1) * sizeof(char));
	      if (NULL == new->s) {
		fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
		free(new);
		hash_delete(dbl_kill);
		mmap_wrapper_delete(mw);
		return -1;
	      }
	      snprintf(new->s, new->len + 1, "%.*s%.*s", (int) (wrd->len - rule->to_replace_len), wrd->s, (int) rule->replacement_len, rule->replacement);
	      sfxmatch = hash_search(dbl_kill, new->s, new->len, &hash_value);
	      if(NULL == sfxmatch) {
		if(0 != hash_set(dbl_kill, new, hash_value)) {
		  fprintf(stderr, "error calling hash_set (new) line [%.*s]\n", (int) len, line);
		  fprintf(stderr, "error calling mmap_get_line on file %s idx: %u\n", dictionary, (unsigned int) idx);
		  free(new->s);
		  free(new);
		  hash_delete(dbl_kill);
		  mmap_wrapper_delete(mw);
		  return -1;
		}
		fprintf(stdout, "%.*s\n", (int) new->len, new->s);
		sfxmatch = new;
	      } else {
		free(new->s);
		free(new);
	      }
	    }
	  }
	}
      }
      for(prefix = end + 1; prefix < limit; prefix++) {
	/* apply prefix alone. */
	pfx = aff_conf->prefix[(unsigned char) *prefix];
	if(NULL != pfx) {
	  cell_t *cell;
	  rule_t *rule;

	  for(cell = list_first(pfx->rules); (NULL != cell); cell = list_next(cell)) {
	    rule = list_get(cell);
	    if(0 == regexec(rule->to_match, wrd->s, 0, 0, 0)) {
	      /* Match, apply rule, exit */
	      new = malloc(sizeof(struct wrd_t));
	      if (NULL == new) {
		fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
		hash_delete(dbl_kill);
		mmap_wrapper_delete(mw);
		return -1;
	      }
	      new->len = (wrd->len - rule->to_replace_len) + rule->replacement_len;
	      new->s = malloc((new->len + 1) * sizeof(char));
	      if (NULL == new->s) {
		fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
		free(new);
		hash_delete(dbl_kill);
		mmap_wrapper_delete(mw);
		return -1;
	      }
	      snprintf(new->s, new->len + 1, "%.*s%.*s", (int) rule->replacement_len, rule->replacement, (int) (wrd->len - rule->to_replace_len), wrd->s + rule->to_replace_len);
	      pfxmatch = hash_search(dbl_kill, new->s, new->len, &hash_value);
	      if(NULL == pfxmatch) {
		if(0 != hash_set(dbl_kill, new, hash_value)) {
		  fprintf(stderr, "error calling hash_set (new) line [%.*s]\n", (int) len, line);
		  fprintf(stderr, "error calling mmap_get_line on file %s idx: %u\n", dictionary, (unsigned int) idx);
		  free(new->s);
		  free(new);
		  hash_delete(dbl_kill);
		  mmap_wrapper_delete(mw);
		  return -1;
		}
		fprintf(stdout, "%.*s\n", (int) new->len, new->s);
		pfxmatch = new;
	      } else {
		free(new->s);
		free(new);
	      }

	      /* apply prefix x suffix where possible. */
	      if(0x1 & pfx->combine) {
		for(suffix = end + 1; suffix < limit; suffix++) {

		  sfx = aff_conf->suffix[(unsigned char) *suffix];
		  if(NULL != sfx) {
		    cell_t *cellsfx;
		    rule_t *rulesfx;

		    for(cellsfx = list_first(sfx->rules); (NULL != cellsfx); cellsfx = list_next(cellsfx)) {
		      rulesfx = list_get(cellsfx);
		      if(0 == regexec(rulesfx->to_match, pfxmatch->s, 0, 0, 0)) {
			/* Match, apply rule, exit */
			new = malloc(sizeof(struct wrd_t));
			if (NULL == new) {
			  fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
			  hash_delete(dbl_kill);
			  mmap_wrapper_delete(mw);
			  return -1;
			}
			new->len = (pfxmatch->len - rulesfx->to_replace_len) + rulesfx->replacement_len;
			new->s = malloc((new->len + 1) * sizeof(char));
			if (NULL == new->s) {
			  fprintf(stderr, "%s(%d): error calling malloc\n", __FUNCTION__, __LINE__);
			  free(new);
			  hash_delete(dbl_kill);
			  mmap_wrapper_delete(mw);
			  return -1;
			}
			snprintf(new->s, new->len + 1, "%.*s%.*s", (int) (pfxmatch->len - rulesfx->to_replace_len), pfxmatch->s, (int) rulesfx->replacement_len, rulesfx->replacement);
			sfxmatch = hash_search(dbl_kill, new->s, new->len, &hash_value);
			if(NULL == sfxmatch) {
			  if(0 != hash_set(dbl_kill, new, hash_value)) {
			    fprintf(stderr, "error calling hash_set (new) line [%.*s]\n", (int) len, line);
			    free(new->s);
			    free(new);
			    hash_delete(dbl_kill);
			    mmap_wrapper_delete(mw);
			    return -1;
			  }
			  fprintf(stdout, "%.*s\n", (int) new->len, new->s);
			} else {
			  free(new->s);
			  free(new);
			}
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }

  if(is_option_set(aff_conf->opt_mask, OPTION_TYPO_E)) {
    for(hi = hash_first(dbl_kill); NULL != hi; hi = hash_next(hi)) {
      void *val;
      wrd_t *wrd;
      typing_err_t *typing_err;
      size_t i, j, nb_errs;

      /*
	 char *s;
	 size_t len;
	 */

      hash_this(hi, NULL, NULL, &val);
      wrd = val;
      /* Because we can't have more than sum (i = 0 to n) of i's modifications. */
      nb_errs = aff_conf->max_dsts * (wrd->len * (wrd->len + 1)) / 2; /* should be x'd by max rep for 1 same str here. */
      typing_err = calloc(nb_errs, sizeof(struct typing_err_t));
      if (NULL == typing_err) {
	fprintf(stderr, "%s(%d): error calling calloc\n", __FUNCTION__, __LINE__);
	hash_delete(dbl_kill);
	mmap_wrapper_delete(mw);
	return -1;
      }
      nb_errs = 0;
      for(j = MIN(aff_conf->longest_rep, wrd->len); j > 0; j--) {
	for(i = 0; i < (wrd->len - j); i++) {
	  rep_t *rep;

	  rep = hash_search(aff_conf->reps, wrd->s + i, j, &hash_value);
	  if (NULL != rep) {
	    cell_t *cell;

	    for(cell = list_first(rep->dsts); (NULL != cell); cell = list_next(cell)) {
	      /* propose the replacement */
	      typing_err[nb_errs].rep = list_get(cell);
	      typing_err[nb_errs].r_pos = i;
	      typing_err[nb_errs].r_len = j;
	      nb_errs++;
	    }
	  }
	}
      }
      if(0 != nb_errs) {
	rv = gen_typing_errors(aff_conf, dbl_kill, wrd, typing_err, nb_errs, aff_conf->typo_level);
	if(-1 == rv) {
	  fprintf(stderr, "error calling gen_typing_errors\n");
	  free(typing_err);
	  hash_delete(dbl_kill);
	  mmap_wrapper_delete(mw);
	  return -1;
	}
      }
      free(typing_err);
    }
  }

  hash_delete(dbl_kill);
  mmap_wrapper_delete(mw);

  return 0;
}

static inline void usage(const char *argv_0, struct option *long_options)
{
  int i;

  fprintf(stdout, "myspell dictionary expanding experiment\n");
  fprintf(stdout, "Usage: %s [OPTIONS] file.aff file.dic\n", argv_0);
  fprintf(stdout, "Expand file.dic using the aff file for valid as well as invalid modifications.\n");
  fprintf(stdout, "\n");
  for (i = 0; NULL != long_options[i].name; i++) {
    fprintf(stdout, "-%c,\t--%s\t", long_options[i].val, long_options[i].name);
    if (0 == strcmp("help", long_options[i].name)) {
      fprintf(stdout, "\tDisplay this usage");
    } else if (0 == strcmp("expand", long_options[i].name)) {
      fprintf(stdout, "Use AFF rules to generates valid words");
    } else if (0 == strcmp("typo-level", long_options[i].name)) {
      fprintf(stdout, "Maximum number of concurrent errors per word in typo mode (default=2)");
    } else if (0 == strcmp("typo", long_options[i].name)) {
      fprintf(stdout, "\tGenerates invalid words using common mistakes defined in AFF");
    }
    fprintf(stdout, "\n");
  }
}

int main(int argc, char **argv)
{
  static struct option long_options[] = {
    {"expand", 0, NULL, 'e'},
    {"help", 0, NULL, 'h'},
    {"typo-level", 1, NULL, 'l'},
    {"typo", 0, NULL, 't'},
    {NULL, 0, NULL, 0}
  };
  aff_conf_t *aff_conf;
  long int tmp;
  int c, rv;
  unsigned char opt_mask, typo_level;

  opt_mask = 0x00;
  typo_level = 2;
  while (1) {
    int option_index = 0;

    c = getopt_long(argc, argv, "l:teh", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'e':
	set_option(opt_mask, OPTION_EXPAND, 1);
	break;
      case 'h':
	usage(argv[0], long_options);
	return 0;
      case 'l':
	tmp = strtol(optarg, NULL, 10);
	if ((0 > tmp) || (UCHAR_MAX < tmp)) {
	  fprintf(stderr, "invalid level");
	  usage(argv[0], long_options);
	  return -1;
	}
	typo_level = tmp;
	break;
      case 't':
	set_option(opt_mask, OPTION_TYPO_E, 1);
	break;
      default:
	fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
	usage(argv[0], long_options);
	return -1;
    }
  }

  if ((argc - optind) < 2) {
    fprintf(stderr, "%s requires two parameters, which are [file.aff] [file.dic]\n", argv[0]);
    usage(argv[0], long_options);
    return -1;
  }

  aff_conf = aff_conf_make(argv[optind]);
  if (NULL == aff_conf) {
    fprintf(stderr, "error calling aff_conf_make\n");
    return -1;
  }
  aff_conf->opt_mask = opt_mask;
  aff_conf->typo_level = typo_level;

  rv = aff_process_dictionary(aff_conf, argv[optind + 1]);
  if(0 != rv) {
    fprintf(stderr, "error calling aff_process_dictionary\n");
    return -1;
  }
  aff_conf_destroy(aff_conf);

  return 0;
}
