/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include "afl-qemu-common.h"
#include "tcg.h"

void HELPER(afl_entry_routine)(CPUArchState *env) {

  afl_forkserver(ENV_GET_CPU(env));

}

void HELPER(afl_compcov_16)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

}

void HELPER(afl_compcov_32)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

    INC_AFL_AREA(idx + 2);
    if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

      INC_AFL_AREA(idx + 1);
      if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

    }

  }

}

void HELPER(afl_compcov_64)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  register uintptr_t idx = cur_loc;

  if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000)) {

    INC_AFL_AREA(idx + 6);
    if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000)) {

      INC_AFL_AREA(idx + 5);
      if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000)) {

        INC_AFL_AREA(idx + 4);
        if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000)) {

          INC_AFL_AREA(idx + 3);
          if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

            INC_AFL_AREA(idx + 2);
            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

              INC_AFL_AREA(idx + 1);
              if ((arg1 & 0xff00) == (arg2 & 0xff00)) { INC_AFL_AREA(idx); }

            }

          }

        }

      }

    }

  }

}

void HELPER(afl_cmplog_8)(target_ulong cur_loc, target_ulong arg1,
                          target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;
  // if (!__afl_cmp_map->headers[k].cnt)
  //  __afl_cmp_map->headers[k].cnt = __afl_cmp_counter++;

  __afl_cmp_map->headers[k].shape = 0;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_16)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;
  // if (!__afl_cmp_map->headers[k].cnt)
  //  __afl_cmp_map->headers[k].cnt = __afl_cmp_counter++;

  __afl_cmp_map->headers[k].shape = 1;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_32)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 3;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

void HELPER(afl_cmplog_64)(target_ulong cur_loc, target_ulong arg1,
                           target_ulong arg2) {

  register uintptr_t k = (uintptr_t)cur_loc;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 7;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = arg1;
  __afl_cmp_map->log[k][hits].v1 = arg2;

}

#include <sys/mman.h>

static int area_is_mapped(void *ptr, size_t len) {

  char *p = ptr;
  char *page = (char *)((uintptr_t)p & ~(sysconf(_SC_PAGE_SIZE) - 1));

  int r = msync(page, (p - page) + len, MS_ASYNC);
  if (r < 0) return errno != ENOMEM;
  return 1;

}

void HELPER(afl_cmplog_rtn)(CPUArchState *env) {

#if defined(TARGET_X86_64)

  void *ptr1 = g2h(env->regs[R_EDI]);
  void *ptr2 = g2h(env->regs[R_ESI]);

#elif defined(TARGET_I386)

  target_ulong *stack = g2h(env->regs[R_ESP]);

  if (!area_is_mapped(stack, sizeof(target_ulong) * 2)) return;

  // when this hook is executed, the retaddr is not on stack yet
  void *    ptr1 = g2h(stack[0]);
  void *    ptr2 = g2h(stack[1]);

#else

  // stupid code to make it compile
  void *ptr1 = NULL;
  void *ptr2 = NULL;
  return;

#endif

  if (!area_is_mapped(ptr1, 32) || !area_is_mapped(ptr2, 32)) return;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
  uintptr_t k = (uintptr_t)env->eip;
#else
  uintptr_t k = 0;
#endif

  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 31;

  hits &= CMP_MAP_RTN_H - 1;
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v0,
                   ptr1, 32);
  __builtin_memcpy(((struct cmpfn_operands *)__afl_cmp_map->log[k])[hits].v1,
                   ptr2, 32);

}



void HELPER(afl_fncov)(target_ulong fn_loc){

  if(afl_area_ctrl[0]) return;

  if(fn_loc < afl_start_code || fn_loc > afl_end_code)
    return;

  fn_loc = (fn_loc >> 4) ^ (fn_loc << 8);
  fn_loc &= (MAP_SIZE - 1);

  register uintptr_t idx = fn_loc;
  idx += (COV_FN - 1) * MAP_SIZE;
  INC_AFL_AREA(idx);

}


static const u8 distance_class_lookup8[9] = {

  [0]         = 1,
  [1]         = 2,
  [2]         = 4,
  [3]         = 8,
  [4]         = 16,
  [5]         = 32,
  [6]         = 64,
  [7 ... 8]   = 128

};



void HELPER(afl_cmpcov_8)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {
  
  if(afl_area_ctrl[0]) return;

  register uintptr_t idx = (afl_path_cksum >> 1) ^ cur_loc;

  u8 distance = distance_class_lookup8[__builtin_popcountll(arg1 ^ arg2)];

  idx += (COV_LAST - 1) * MAP_SIZE;

  afl_area_ptr[idx] |= distance;

}



static const u8 distance_class_lookup16[17] = {

  [0]           = 1,
  [1 ... 2]     = 2,
  [3 ... 4]     = 4,
  [5 ... 6]     = 8,
  [7 ... 8]     = 16,
  [9 ... 10]    = 32,
  [11 ... 12]   = 64,
  [13 ... 16]   = 128

};


void HELPER(afl_cmpcov_16)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {
  
  if(afl_area_ctrl[0]) return;

  register uintptr_t idx = (afl_path_cksum >> 1) ^ cur_loc;

  idx += (COV_LAST - 1) * MAP_SIZE;

  u8 distance = distance_class_lookup16[__builtin_popcountll(arg1 ^ arg2)];

  afl_area_ptr[idx] |= distance;
  
}


static const u8 distance_class_lookup32[33] = {

  [0]           = 1,
  [1 ... 2]     = 2,
  [3 ... 4]     = 4,
  [5 ... 8]     = 8,
  [9 ... 12]    = 16,
  [13 ... 16]   = 32,
  [17 ... 24]   = 64,
  [25 ... 32]   = 128

};


void HELPER(afl_cmpcov_32)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  if(afl_area_ctrl[0]) return;

  register uintptr_t idx = (afl_path_cksum >> 1) ^ cur_loc;

  idx += (COV_LAST - 1) * MAP_SIZE;

  u8 distance = distance_class_lookup32[__builtin_popcountll(arg1 ^ arg2)];

  afl_area_ptr[idx] |= distance;
  
}



static const u8 distance_class_lookup64[65] = {

  [0]           = 1,
  [1 ... 4]     = 2,
  [5 ... 8]     = 4,
  [9 ... 16]    = 8,
  [17 ... 24]   = 16,
  [25 ... 36]   = 32,
  [37 ... 48]   = 64,
  [49 ... 64]   = 128

};



void HELPER(afl_cmpcov_64)(target_ulong cur_loc, target_ulong arg1,
                            target_ulong arg2) {

  if(afl_area_ctrl[0]) return;

  register uintptr_t idx = (afl_path_cksum >> 1) ^ cur_loc;

  idx += (COV_LAST - 1) * MAP_SIZE;

  u8 distance = distance_class_lookup64[__builtin_popcountll(arg1 ^ arg2)];

  afl_area_ptr[idx] |= distance;

}



// void HELPER(afl_memcov)(target_ulong cur_pc, target_ulong mem_loc) {


//   if(afl_area_ctrl[0]) return;
  
//   cur_pc  = (cur_pc >> 4) ^ (cur_pc << 8);
//   cur_pc &= MAP_SIZE - 1;


//   u8 offset = (mem_loc >> 7) & 0x7;
//   mem_loc = ((mem_loc >> 3) & 0xffffff80) | (mem_loc & 0x7f);
//   mem_loc &= MAP_SIZE - 1;

//   register uintptr_t idx = (cur_pc >> 1) ^ mem_loc;
//   idx &= (MAP_SIZE - 1);
//   idx += MAP_SIZE * (COV_LAST - 1);


//   afl_area_ptr[idx] |= (1 << offset);

// }