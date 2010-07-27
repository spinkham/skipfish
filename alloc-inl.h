/*
   skipfish - error-checking, memory-zeroing alloc routines
   --------------------------------------------------------

   Note: when DEBUG_ALLOCATOR is set, a horribly slow but pedantic
   allocation tracker is used. Don't enable this in production.

   Author: Michal Zalewski <lcamtuf@google.com>

   Copyright 2009, 2010 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 */

#ifndef _HAVE_ALLOC_INL_H
#define _HAVE_ALLOC_INL_H

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"

#define ALLOC_CHECK_SIZE(_s) do { \
    if ((_s) > MAX_ALLOC) \
      FATAL("bad alloc request: %u bytes", (_s)); \
  } while (0)

#define ALLOC_CHECK_RESULT(_r,_s) do { \
    if (!(_r)) \
      FATAL("out of memory: can't allocate %u bytes", (_s)); \
  } while (0)


#define ALLOC_MAGIC   0xFF00
#define ALLOC_C(_ptr) (((u16*)(_ptr))[-3])
#define ALLOC_S(_ptr) (((u32*)(_ptr))[-1])

static inline void* __DFL_ck_alloc(u32 size) {
  void* ret;

  if (!size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + 6);
  ALLOC_CHECK_RESULT(ret, size);

  ret += 6;

  ALLOC_C(ret) = ALLOC_MAGIC;
  ALLOC_S(ret) = size;

  return memset(ret, 0, size);
}


static inline void* __DFL_ck_realloc(void* orig, u32 size) {
  void* ret;
  u32   old_size = 0;

  if (!size) {
    if (orig) free(orig - 6);
    return NULL;
  }

  if (orig) {
    if (ALLOC_C(orig) != ALLOC_MAGIC) ABORT("Bad alloc canary");
    old_size = ALLOC_S(orig);
    orig -= 6;
  }

  ALLOC_CHECK_SIZE(size);
  ret = realloc(orig, size + 6);
  ALLOC_CHECK_RESULT(ret, size);

  ret += 6;

  ALLOC_C(ret) = ALLOC_MAGIC;
  ALLOC_S(ret) = size;

  if (size > old_size)
    memset(ret + old_size, 0, size - old_size);

  return ret;
}


static inline void* __DFL_ck_strdup(u8* str) {
  void* ret;
  u32   size;

  if (!str) return NULL;

  size = strlen((char*)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + 6);
  ALLOC_CHECK_RESULT(ret, size);

  ret += 6;

  ALLOC_C(ret) = ALLOC_MAGIC;
  ALLOC_S(ret) = size;

  return memcpy(ret, str, size);
}


static inline void* __DFL_ck_memdup(u8* mem, u32 size) {
  void* ret;

  if (!mem || !size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + 6);
  ALLOC_CHECK_RESULT(ret, size);
  
  ret += 6;

  ALLOC_C(ret) = ALLOC_MAGIC;
  ALLOC_S(ret) = size;

  return memcpy(ret, mem, size);
}


static inline void __DFL_ck_free(void* mem) {
  if (mem) {
    if (ALLOC_C(mem) != ALLOC_MAGIC) ABORT("Bad alloc canary");
    free(mem - 6);
  }
}


#ifndef DEBUG_ALLOCATOR

/* Non-debugging mode - straightforward aliasing. */

#define ck_alloc        __DFL_ck_alloc
#define ck_realloc      __DFL_ck_realloc
#define ck_strdup       __DFL_ck_strdup
#define ck_memdup       __DFL_ck_memdup
#define ck_free         __DFL_ck_free

#else

/* Debugging mode - include additional structures and support code. */

#define ALLOC_BUCKETS 1024

struct __AD_trk_obj {
  void *ptr;
  char *file, *func;
  u32 line;
};


extern struct __AD_trk_obj* __AD_trk[ALLOC_BUCKETS];
extern u32 __AD_trk_cnt[ALLOC_BUCKETS];

#define __AD_H(_ptr) (((((u32)(long)(_ptr)) >> 16) ^ ((u32)(long)(_ptr))) % \
                     ALLOC_BUCKETS)

/* Adds a new entry to the list of allocated objects. */

static inline void __AD_alloc_buf(void* ptr, const char* file, const char* func,
                                   u32 line) {
  u32 i, b;

  if (!ptr) return;

  b = __AD_H(ptr);

  for (i=0;i<__AD_trk_cnt[b];i++)
    if (!__AD_trk[b][i].ptr) {
      __AD_trk[b][i].ptr = ptr;
      __AD_trk[b][i].file = (char*)file;
      __AD_trk[b][i].func = (char*)func;
      __AD_trk[b][i].line = line;
      return;
    }

  __AD_trk[b] = __DFL_ck_realloc(__AD_trk[b],
    (__AD_trk_cnt[b] + 1) * sizeof(struct __AD_trk_obj));

  __AD_trk[b][__AD_trk_cnt[b]].ptr = ptr;
  __AD_trk[b][__AD_trk_cnt[b]].file = (char*)file;
  __AD_trk[b][__AD_trk_cnt[b]].func = (char*)func;
  __AD_trk[b][__AD_trk_cnt[b]].line = line;
  __AD_trk_cnt[b]++;

}


/* Removes entry from the list of allocated objects. */

static inline void __AD_free_buf(void* ptr, const char* file, const char* func,
                                 u32 line) {
  u32 i, b;

  if (!ptr) return;

  b = __AD_H(ptr);

  for (i=0;i<__AD_trk_cnt[b];i++)
    if (__AD_trk[b][i].ptr == ptr) {
      __AD_trk[b][i].ptr = 0;
      return;
    }

  WARN("ALLOC: Attempt to free non-allocated memory in %s (%s:%u)",
       func, file, line);

}


/* Does a final report on all non-deallocated objects. */

static inline void __AD_report(void) {
  u32 i, b;

  fflush(0);

  for (b=0;b<ALLOC_BUCKETS;b++)
    for (i=0;i<__AD_trk_cnt[b];i++)
      if (__AD_trk[b][i].ptr)
        WARN("ALLOC: Memory never freed, created in %s (%s:%u)",
             __AD_trk[b][i].func, __AD_trk[b][i].file, __AD_trk[b][i].line);

}


/* Simple wrappers for non-debugging functions: */

static inline void* __AD_ck_alloc(u32 size, const char* file, const char* func,
                                  u32 line) {
  void* ret = __DFL_ck_alloc(size);
  __AD_alloc_buf(ret, file, func, line);
  return ret;
}


static inline void* __AD_ck_realloc(void* orig, u32 size, const char* file,
                                    const char* func, u32 line) {
  void* ret = __DFL_ck_realloc(orig, size);
  __AD_free_buf(orig, file, func, line);
  __AD_alloc_buf(ret, file, func, line);
  return ret;
}


static inline void* __AD_ck_strdup(u8* str, const char* file, const char* func,
                                   u32 line) {
  void* ret = __DFL_ck_strdup(str);
  __AD_alloc_buf(ret, file, func, line);
  return ret;
}


static inline void* __AD_ck_memdup(u8* mem, u32 size, const char* file,
                                   const char* func, u32 line) {
  void* ret = __DFL_ck_memdup(mem, size);
  __AD_alloc_buf(ret, file, func, line);
  return ret;
}


static inline void __AD_ck_free(void* ptr, const char* file,
                                const char* func, u32 line) {
  __AD_free_buf(ptr, file, func, line);
  __DFL_ck_free(ptr);
}


/* Populates file / function / line number data to *_d wrapper calls: */

#define ck_alloc(_p1) \
  __AD_ck_alloc(_p1, __FILE__, __FUNCTION__, __LINE__)
#define ck_realloc(_p1, _p2) \
  __AD_ck_realloc(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)
#define ck_strdup(_p1) \
  __AD_ck_strdup(_p1, __FILE__, __FUNCTION__, __LINE__)
#define ck_memdup(_p1, _p2) \
  __AD_ck_memdup(_p1, _p2, __FILE__, __FUNCTION__, __LINE__)
#define ck_free(_p1) \
  __AD_ck_free(_p1, __FILE__, __FUNCTION__, __LINE__)

#endif /* ^!DEBUG_ALLOCATOR */

#endif /* ! _HAVE_ALLOC_INL_H */
