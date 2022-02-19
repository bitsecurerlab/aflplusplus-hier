/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.2.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include "../../mcts.h"
#include <math.h>
/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(tb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(env); \
    } \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)


/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;
static unsigned char _afl_area_ptr_ctrl = 0;
static unsigned char *afl_area_ptr_ctrl = &_afl_area_ptr_ctrl;


/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUArchState*);

void afl_maybe_log_edge(abi_ulong, abi_ulong);
void afl_maybe_log_call(abi_ulong, abi_ulong);
void afl_maybe_log_ma(abi_ulong, abi_ulong, int);
void afl_maybe_log_mw(abi_ulong, abi_ulong, abi_ulong);
void afl_maybe_log_brcond(abi_ulong, abi_ulong, abi_ulong, abi_ulong);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);


/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};


/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/


/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = (unsigned char *)shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    afl_area_ptr_ctrl = afl_area_ptr;
    afl_area_ptr += 1; 

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUArchState *env) {

  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      // path_cksum = 0;

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}


#define N_GRAM 16
static u8 path_top = 15;
static abi_ulong path_snap[N_GRAM];
static abi_ulong path_cksum = 0;

/* The equivalent of the tuple logging routine from afl-as.h. */

void afl_maybe_log_edge(abi_ulong next_pc, abi_ulong cur_loc) {

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if ( ((cur_loc > afl_end_code || cur_loc < afl_start_code) && (next_pc > afl_end_code || next_pc < afl_start_code)))
    return;

  /* Looks like QEMU always maps to fixed locations, so we can skip this:
     cur_loc -= afl_start_code; */

  /* Instruction addresses may be aligned. Let's mangle the value to get
     something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  next_pc = (next_pc >> 4) ^ (next_pc << 8);
  next_pc &= MAP_SIZE - 1;

  
  abi_ulong edge = (cur_loc >> 1) ^ next_pc;
  path_cksum ^= edge;
  path_top = (path_top + 1) % N_GRAM;
  path_cksum ^= path_snap[path_top];
  path_snap[path_top] = edge;


  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (!afl_area_ptr || cur_loc >= afl_inst_rms || next_pc >= afl_inst_rms) return;

  abi_ulong index;
  index = (cur_loc >> 1) ^ next_pc;
  index &= (MAP_SIZE - 1);
  index += MAP_SIZE * (N_ONE - 1);
  if(afl_area_ptr[index] < 255)
    afl_area_ptr[index] ++;

  


  //  // n16
  // index = path_cksum;
  // index &= (MAP_SIZE - 1);
  // index += MAP_SIZE * (N_LAST - 1);

  // if(afl_area_ptr[index] < 255)
  //   afl_area_ptr[index] ++;
  
}



void afl_maybe_log_call(abi_ulong target, abi_ulong pc){


  if(*afl_area_ptr_ctrl) return;

  if (target > afl_end_code || target < afl_start_code)
    return;

  /* Looks like QEMU always maps to fixed locations, so we can skip this:
     cur_loc -= afl_start_code; */

  /* Instruction addresses may be aligned. Let's mangle the value to get
     something quasi-uniform. */


  target = (target >> 4) ^ (target << 8);
  target &= (MAP_SIZE - 1);
  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (!afl_area_ptr || target >= afl_inst_rms) return;

  abi_ulong index;
  // index = (cc >> 1) ^ pc;
  index = target;
  index &= (MAP_SIZE - 1);
  index += MAP_SIZE * (N_CTX - 1);

  if(afl_area_ptr[index] < 255)
    afl_area_ptr[index] ++;
}





void afl_maybe_log_ma(abi_ulong mem_loc, abi_ulong cur_loc, int rw) {

  if(*afl_area_ptr_ctrl) return;

  if(cur_loc > afl_end_code || cur_loc < afl_start_code)
    return;

  /* Looks like QEMU always maps to fixed locations, so we can skip this:
     cur_loc -= afl_start_code; */

  /* Instruction addresses may be aligned. Let's mangle the value to get
     something quasi-uniform. */


  // abi_ulong _mem_loc = mem_loc;
  // abi_ulong _cur_loc = cur_loc;


  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  // mem_loc  = (mem_loc >> 4) ^ (mem_loc << 8);
  u8 offset = (mem_loc >> 7) & 0x7;
  mem_loc = ((mem_loc >> 3) & 0xffffff80) | (mem_loc & 0x7f);

  mem_loc &= HALF_MAP_SIZE - 1;
  if(rw) 
    mem_loc += HALF_MAP_SIZE; 
  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (!afl_area_ptr || mem_loc >= afl_inst_rms) return;

  abi_ulong index;
  index = (cur_loc >> 1) ^ mem_loc ;
  index &= (MAP_SIZE - 1);
  index += MAP_SIZE * (N_LAST - 1);

  // fprintf(stderr, "^^^0x%x: [2] 0x%x 0x%x | 0x%x 0x%x\n", index, _cur_loc, cur_loc, _mem_loc, mem_loc);

  // if(afl_area_ptr[index] < 255)
    // afl_area_ptr[index] ++;
  afl_area_ptr[index] |= (1 << offset);

}








const u64 m1  = 0x5555555555555555; //binary: 0101...
const u64 m2  = 0x3333333333333333; //binary: 00110011..
const u64 m4  = 0x0f0f0f0f0f0f0f0f; //binary:  4 zeros,  4 ones ...
const u64 m8  = 0x00ff00ff00ff00ff; //binary:  8 zeros,  8 ones ...
const u64 m16 = 0x0000ffff0000ffff; //binary: 16 zeros, 16 ones ...
const u64 m32 = 0x00000000ffffffff; //binary: 32 zeros, 32 ones
const u64 h01 = 0x0101010101010101; //the sum of 256 to the power of 0,1,2,3...


static inline u8 popcount(u64 x){
    x -= (x >> 1) & m1;             //put count of each 2 bits into those 2 bits
    x = (x & m2) + ((x >> 2) & m2); //put count of each 4 bits into those 4 bits 
    x = (x + (x >> 4)) & m4;        //put count of each 8 bits into those 8 bits 
    return (x * h01) >> 56;         //returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24) + ... 
}


static const u8 distance_class_lookup8[65] = {

  [0]           = 1,
  [1]           = 2,
  [2]           = 4,
  [3 ... 4]     = 8,
  [5 ... 8]     = 16,
  [9 ... 16]    = 32,
  [17 ... 32]   = 64,
  [33 ... 64]   = 128
  // [49 ... 64]   = 128

};



void afl_maybe_log_mw(abi_ulong pc, abi_ulong mem_loc, abi_ulong val){
  if(*afl_area_ptr_ctrl) return;

  if (pc > afl_end_code || pc < afl_start_code) return;

  u8 distance = distance_class_lookup8[popcount(val)];

  abi_ulong index = path_cksum ^ (mem_loc >> 2);
  index &= (MAP_SIZE - 1);
  index += (MAP_SIZE * (N_LAST - 1));

  // fprintf(stderr, "0x%x 0x%x %llu\n", pc, mem_loc, val);
  // fprintf(stderr, "  0x%x 0x%x %u\n", path_cksum, index, distance);

  if(afl_area_ptr)
    afl_area_ptr[index] |= distance;

}



/*
typedef enum {
    // non-signed 
    TCG_COND_NEVER  = 0 | 0 | 0 | 0,
    TCG_COND_ALWAYS = 0 | 0 | 0 | 1,
    TCG_COND_EQ     = 8 | 0 | 0 | 0,
    TCG_COND_NE     = 8 | 0 | 0 | 1,
    // signed 
    TCG_COND_LT     = 0 | 0 | 2 | 0,
    TCG_COND_GE     = 0 | 0 | 2 | 1,
    TCG_COND_LE     = 8 | 0 | 2 | 0,
    TCG_COND_GT     = 8 | 0 | 2 | 1,
    // unsigned 
    TCG_COND_LTU    = 0 | 4 | 0 | 0,
    TCG_COND_GEU    = 0 | 4 | 0 | 1,
    TCG_COND_LEU    = 8 | 4 | 0 | 0,
    TCG_COND_GTU    = 8 | 4 | 0 | 1,
} TCGCond;

*/


static inline void calc_flag_and_distance(abi_ulong cond, abi_ulong v1, abi_ulong v2, u8* flag, u8* distance){
  switch(cond & 6){
    case 0:{    // non-signed, eq/ne
      if(v1 == v2) *flag = 1;
      else *flag = 0;
      break;
    }
    case 2: {  // signed
      abi_long s1 = (abi_long) v1;
      abi_long s2 = (abi_long) v2;
      if((cond & 8) == 0){  // lt/ge   
        if(s1 < s2) *flag = 0;
        else *flag = 1;
      }
      else{                 // le/gt
        if (s1 <= s2) *flag = 0;
        else *flag = 1;
      }
      break;
    }
    default:{  // unsigned
      if ((cond & 8) == 0){    // ltu/geu
        if (v1 < v2) *flag = 0;
        else *flag =1;
      }
      else{                    // leu/gtu
        if(v1 <= v2) *flag = 0;
        else *flag = 1;
      }
      break;
    }
  }

  *distance = distance_class_lookup8[__builtin_popcountll(v1 ^ v2)];
}


void afl_maybe_log_brcond(abi_ulong pc, abi_ulong cond, abi_ulong c1, abi_ulong c2){

  if(*afl_area_ptr_ctrl) return;
  // if(pc < afl_start_code || pc > afl_end_code) return;

  u8 distance;
  u8 flag;
  
  calc_flag_and_distance(cond, c1, c2, &flag, &distance);

  pc  = (pc >> 4) ^ (pc << 8);

  abi_ulong index = (path_cksum >> 1) ^ pc;
  // abi_ulong index = pc;
  index &= (HALF_MAP_SIZE - 1);
  if(flag) index += HALF_MAP_SIZE;
  // 
  index = 0;
  distance = 128;
  ///
  index += (MAP_SIZE * (N_LAST - 1));

  if(afl_area_ptr)
    afl_area_ptr[index] |= distance;
    
}

// void afl_maybe_log_brcond(abi_ulong pc, abi_ulong cond, abi_ulong c1, abi_ulong c2){

//   if(*afl_area_ptr_ctrl) return;
//   // if(pc < afl_start_code || pc > afl_end_code) return;

//   u8 distance = distance_class_lookup8[__builtin_popcountll(c1 ^ c2)];
  

//   pc  = (pc >> 4) ^ (pc << 8);

//   abi_ulong index = (path_cksum >> 1) ^ pc;
//   index &= (MAP_SIZE - 1);
//   index += (MAP_SIZE * (N_LAST - 1));

//   if(afl_area_ptr)
//     afl_area_ptr[index] |= distance;
    
// }





/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    //do not cache for dynamically generated code
    if((t.pc >= afl_start_code) && (t.pc <= afl_end_code)){
      tb_find_slow(env, t.pc, t.cs_base, t.flags);
    }

  }

  close(fd);

}

