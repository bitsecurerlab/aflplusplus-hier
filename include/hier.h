
#include "types.h"
#include "config.h"
#include "common.h"


typedef struct hier_node{

    u32 id;
    x_cov_t cov_level;

    double base_score; // rareness of the features covered by the node 
    double fuzz_score; // fuzzzing reward, related to rareness of features covered by test cases/seeds that are generated from the node

    u64 n_fuzz;  // times of be selected

    u64 n_seeds; // number of seeds

    u8  *exec_trace, *fuzz_trace;

    struct hier_node *parent;

    void *children;

    struct queue_entry* the_seed;  //bottom-level node containing the real seed

    u64 times_wo_finds;

} hier_node_t;



typedef struct hier_key{
    u8* bits;
    u32 size;
    hier_node_t* node;
} hier_key_t;



typedef struct hier_tree{
    u32 n_nodes[COV_INFI],
        n_fuzzed_nodes[COV_INFI];

    hier_node_t *root,
                *leaf_cur;

    u8 has_new_node;

    u32 n_bits[COV_INFI],
        n_fuzzed_bits[COV_INFI];   // bitmap log
} hier_tree_t;



typedef struct hier_sched{

    u16* step_exec_map;  // feature frequence for the current fuzzing round
    u64* exec_map;       // global feature frequece for all fuzzing rounds

    u32 map_size;
    u8   n_cov_level;
    double c_param;

    u32 current_entry;
    u64 current_queue_cycle;
    u64 current_wo_finds;

    hier_tree_t* tree;

    u64 t[3];

    u8 need_update;

} hier_sched_t;


hier_sched_t* new_hier_sched(uint32_t);

void delete_hier_sched(hier_sched_t* );


// cluster a new seed for the multi-level coverage 
void do_clustering(hier_sched_t* , struct queue_entry*, u8* );

void update_feature_freq(hier_sched_t*, u8*);

void update_wo_finds(hier_sched_t*, bool);


// seed scheduling
struct queue_entry* choose_next_seed(hier_sched_t* );
