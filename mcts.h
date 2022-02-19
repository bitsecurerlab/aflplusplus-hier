
#include "types.h"
#include "config.h"
#include "kbtree.h"


#define MCTS_SCHEDULE

#define RLEVEL 3


typedef enum {
    N_NULL = 0,
    N_CTX  = 1,
    N_ONE  = 2,
    N_LAST = 3, //SIXTEEN
    N_INFI = 4
} n_gram_t;


struct queue_entry {

  u32 id;

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      fuzz_level,                     /* Number of fuzzing iterations     */
      edge_cksum,
      exec_cksum;                     /* Checksum of the execution trace  */
  
//   u64 exec_hval;

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth,                          /* Path depth                       */
      n_fuzz;                         /* Number of fuzz, does not overflow */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  u8* trace;

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100,       /* 100 elements ahead               */
                     *local_next;
};




typedef struct queue_cluster{
    u32 id,
        volumn;
    
    double new_paths; //added new paths in current iteration

    u64 queue_cycle;
    struct queue_entry *queue,
                       *queue_top,
                       *queue_cur;
} queue_cluster_t;



typedef struct mcts_node{
    
    u32 id;
    n_gram_t n_cov_level;

    double base_score, fuzz_score, v_score;

    double acc_w;

    double reward;
    u64 visit_times;
    u64    fuzz_level;

    u64 n_seeds;

    u8  *exec_trace, *fuzz_trace;
    u32 min_fuzz_byte;

    struct mcts_node *parent;
    
    void *children;

    queue_cluster_t *queue_cluster;

} mcts_node_t;



typedef struct mcts_key{
    u8* bits;
    mcts_node_t* node;
} mcts_key_t;


typedef struct trace_map{
    u32 exec_map[MAP_SIZE * (N_INFI - 1)];
    u8  step_exec_map[MAP_SIZE * (N_INFI - 1)];
    u8 fuzz_map[MAP_SIZE * (N_INFI - 1)];
    u8 fuzz_mark[MAP_SIZE * (N_INFI - 1)];
    // u32 counts[RLEVEL];
    double weights[N_INFI - 1];
} trace_map_t;



typedef struct mcts_tree{
    trace_map_t* trace_map;
    u32 n_tnodes[N_INFI],
        n_fuzzed_tnodes[N_INFI],
        _rlevel;
    
    u64 mutation_times;

    mcts_node_t *root,
                *leaf_cur,
                *node_maybe_new;
                // *pending;
    u8 new_node;

    u64 t[11];  // time log
    u64 b[6];   // bitmap log
} mcts_tree_t;






mcts_tree_t* new_tree(void);

void delete_tree(mcts_tree_t* );

n_gram_t add_to_tree(mcts_tree_t* , struct queue_entry*, u8* );

void update_trace_map(mcts_tree_t*, u8*);

struct queue_entry* next_queue_cur(mcts_tree_t*, double);
