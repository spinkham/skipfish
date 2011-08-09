/*

   skipfish - various string manipulation helpers
   ----------------------------------------------

   Some modern operating systems still ship with no strcasestr() or memmem()
   implementations in place, for reasons beyond comprehension. This file
   includes a simplified version of these routines, copied from NetBSD, plus
   several minor, custom string manipulation macros and inline functions.

   The original NetBSD code is licensed under a BSD license, as follows:

   Copyright (c) 1990, 1993
   The Regents of the University of California.  All rights reserved.

   This code is derived from software contributed to Berkeley by
   Chris Torek.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the University nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.

 */

#ifndef _HAVE_STRING_INL_H
#define _HAVE_STRING_INL_H

#include <ctype.h>
#include <string.h>

#include "types.h"


/* Macros for easy string prefix matching */

#define prefix(_long, _short) \
  strncmp((char*)(_long), (char*)(_short), strlen((char*)(_short)))

#define case_prefix(_long, _short) \
  strncasecmp((char*)(_long), (char*)(_short), strlen((char*)(_short)))


/* Modified NetBSD strcasestr() implementation (rolling strncasecmp). */

static inline u8* inl_strcasestr(const u8* haystack, const u8* needle) {
  register u8 c, sc;
  register u32 len;

  if (!haystack || !needle) return 0;

  if ((c = *needle++)) {

    c = tolower(c);
    len = strlen((char*)needle);

    do {
      do {
        if (!(sc = *haystack++)) return 0;
      } while (tolower(sc) != c);
    } while (strncasecmp((char*)haystack, (char*)needle, len));

    haystack--;

  }

  return (u8*)haystack;

}


/* Modified NetBSD memmem() implementation (rolling memcmp). */

static inline void* inl_memmem(const void* haystack, u32 h_len,
                               const void* needle, u32 n_len) {
  register u8* sp = (u8*)haystack;
  register u8* pp = (u8*)needle;
  register u8* eos = sp + h_len - n_len;

  if (!(haystack && needle && h_len && n_len)) return 0;

  while (sp <= eos) {
    if (*sp == *pp)
      if (memcmp(sp, pp, n_len) == 0) return sp;
    sp++;
  }

  return 0;

}


/* Distance-limited strstr. */

static inline u8* inl_findstr(const u8* haystack, const u8* needle, u32 max_len) {
  register u8 c, sc;
  register u32 len;

  if (!haystack || !needle) return 0;
  max_len++;

  if ((c = *needle++)) {

    len = strlen((char*)needle);

    do {
      do {
        if (!(sc = *haystack++) || !max_len--) return 0;
      } while (sc != c);
    } while (strncmp((char*)haystack, (char*)needle, len));

    haystack--;

  }

  return (u8*)haystack;

}




/* String manipulation macros for operating on a dynamic buffer. */

#define NEW_STR(_buf_ptr, _buf_len) do { \
    (_buf_ptr) = ck_alloc(1024); \
    (_buf_len) = 0; \
  } while (0)

#define ADD_STR_DATA(_buf_ptr, _buf_len, _str) do { \
    u32 _sl = strlen((char*)_str); \
    if ((_buf_len) + (_sl) + 1 > ALLOC_S(_buf_ptr)) { \
      u32 _nsiz = ((_buf_len) + _sl + 1024) >> 10 << 10; \
      (_buf_ptr)  = ck_realloc(_buf_ptr, _nsiz); \
    } \
    memcpy((_buf_ptr) + (_buf_len), _str, _sl + 1); \
    (_buf_len) += _sl; \
  } while (0)

#define TRIM_STR(_buf_ptr, _buf_len) do { \
    (_buf_ptr) = ck_realloc(_buf_ptr, _buf_len + 1); \
    (_buf_ptr)[_buf_len] = 0; \
  } while (0)


/* Simple base64 encoder */

static inline u8* b64_encode(u8* str, u32 len) {

  const u8 b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789+/";

  u8 *ret, *cur;

  ret = cur = ck_alloc((len + 3) * 4 / 3 + 1);

  while (len > 0) {

    if (len >= 3) {
      u32 comp = (str[0] << 16) | (str[1] << 8) | str[2];

      *(cur++) = b64[comp >> 18];
      *(cur++) = b64[(comp >> 12) & 0x3F];
      *(cur++) = b64[(comp >> 6) & 0x3F];
      *(cur++) = b64[comp & 0x3F];

      len -= 3;
      str += 3;

    } else if (len == 2) {
      u32 comp = (str[0] << 16) | (str[1] << 8);

      *(cur++) = b64[comp >> 18];
      *(cur++) = b64[(comp >> 12) & 0x3F];
      *(cur++) = b64[(comp >> 6) & 0x3D];
      *(cur++) = '=';

      len -= 2;
      str += 2;

    } else {
      u32 comp = (str[0] << 16);;

      *(cur++) = b64[comp >> 18];
      *(cur++) = b64[(comp >> 12) & 0x3F];
      *(cur++) = '=';
      *(cur++) = '=';

      len--;
      str++;

    }

  }

  *cur = 0;
  return ret;

}

#endif /* !_HAVE_STRING_INL_H */
