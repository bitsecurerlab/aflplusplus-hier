#include <stdio.h>
#include <math.h>

#include "afl-fuzz.h"
#include "kbtree.h"


#define hier_key_cmp(n1, n2) (memcmp((n1).bits, (n2).bits, (n1).size))

KBTREE_INIT(hier, hier_key_t, hier_key_cmp)



static inline u64 next_p2_fast(u64 val) {

    u64 v = val;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;

    v += (v == 0);

    return v;

} 



static inline void minimize_bits_fast(u8* dst, u8* src, u32 size){

    u64* ptr = (u64*)src;
    u32 i;
    u8 v;
    u64 s;
    for(i = 0; i < (size >> 3); i++){
        v = 0;
        s = ptr[i];
        if(unlikely(s)){
            if(s & 0xff)               v |= 1;
            if(s & 0xff00)             v |= 2;
            if(s & 0xff0000)           v |= 4;
            if(s & 0xff000000)         v |= 8;
            if(s & 0xff00000000)       v |= 16;
            if(s & 0xff0000000000)     v |= 32;
            if(s & 0xff000000000000)   v |= 64;
            if(s & 0xff00000000000000) v |= 128;
        }
        dst[i] = v;
    }
}




hier_node_t* new_node(hier_tree_t*, x_cov_t, hier_node_t*);

hier_tree_t* new_tree();


hier_sched_t* new_hier_sched(u32 map_size){
    hier_sched_t* sched = (hier_sched_t *)ck_alloc(sizeof(hier_sched_t));

    sched->map_size = map_size;
    sched->n_cov_level = AFL_N_MULTI_LEVEL_COV;
    sched->c_param = AFL_HIER_SCHED_PARAM;

    sched->step_exec_map = (u16 *)ck_alloc(map_size * sched->n_cov_level * sizeof(u16));
    sched->exec_map = (u64 *)ck_alloc(map_size * sched->n_cov_level * sizeof(u64));

    sched->tree = new_tree();

    return sched;
}


void delete_tree(hier_tree_t* );


void delete_hier_sched(hier_sched_t* sched){

    ck_free(sched->step_exec_map);
    ck_free(sched->exec_map);
    delete_tree(sched->tree);

    ck_free(sched);

}



void update_base_score(hier_sched_t*, hier_node_t* );



void do_clustering(hier_sched_t* sched, struct queue_entry* queue, u8* trace_bits){

    hier_tree_t* tree = sched->tree;
    hier_node_t* cur = tree->root;
    kbtree_t(hier)* map;
    hier_key_t k, *k_p = &k, *p;
    hier_node_t *nx;
    x_cov_t i;

    u64 start_us = get_cur_time_us();

    u32 size = sched->map_size;
    u32 k_size;

    for(i = COV_NULL + 1; i <= COV_LAST; i++){

        u8* bits;
        if(i == COV_LAST) {
            k_size = size;
            bits = (u8*)ck_alloc(k_size);
            memcpy(bits, trace_bits + size * (i - 1), size);
        }
        else{
            k_size = (size >> 3);
            bits = (u8*)ck_alloc(k_size);
            minimize_bits_fast(bits, trace_bits + size * (i - 1), size);
        }

        k_p->bits = bits;
        k_p->size = k_size;
        map = (kbtree_t(hier) *)cur->children;
        p = kb_getp(hier, map, k_p);
        if(!p){
            nx = new_node(tree, i, cur);
            nx->exec_trace = bits;
            update_base_score(sched, nx);
            k_p->node = nx;
            p = kb_putp(hier, map, k_p);
        }
        else { ck_free(bits); }

        cur = p->node;

    }
    // assert(cur->n_cov_level == N_LAST)
    struct queue_entry* q = cur->the_seed;
    if(!q) { 
        cur->the_seed = queue; 
        do{
            cur->n_seeds++;
            cur= cur->parent;
        }while(cur);
    }
    else if(q->len > queue->len) {
        cur->the_seed = queue;
    }

    // fprintf(stderr, "new_seed: %d\n", queue->id);
    sched->t[1] += (get_cur_time_us() - start_us);

}



void update_feature_freq(hier_sched_t* sched, u8* trace_bits){
    u32 i;
    u16* se_map = sched->step_exec_map;
    u8* bytes = trace_bits;
    u64 start_us = get_cur_time_us();

    for(i = 0; i < sched->map_size * sched->n_cov_level; i++){

        if(bytes[i]) { se_map[i] += 1; }

    }

    sched->t[2] += (get_cur_time_us() - start_us);
}




inline void update_wo_finds(hier_sched_t* sched, bool no_find){
    hier_node_t* nx = sched->tree->leaf_cur;
    while(nx){
        if(no_find) { nx->times_wo_finds ++; }
        else { nx->times_wo_finds = 0; }
        nx = nx->parent;
    }
}


inline hier_node_t* best_leaf_node(hier_tree_t*, double);


void update_reward(hier_sched_t* sched);



struct queue_entry* choose_next_seed(hier_sched_t* sched){

    u64 start_us = get_cur_time_us();
    update_reward(sched);

    hier_node_t* nx = best_leaf_node(sched->tree, sched->c_param);

    struct queue_entry* q = nx->the_seed;
    
    sched->current_entry = q->id;
    nx = nx->parent;  // edge level
    sched->current_queue_cycle = nx->n_fuzz;
    sched->current_wo_finds = nx->times_wo_finds;

    sched->t[0] += (get_cur_time_us() - start_us);

    return q;
}



hier_node_t* new_node(hier_tree_t* tree, x_cov_t cov, hier_node_t* parent){

    hier_node_t* nx = (hier_node_t*)ck_alloc(sizeof(hier_node_t));

    nx->id = tree->n_nodes[cov];
    nx->cov_level = cov;
    nx->parent = parent;
    nx->n_fuzz = 1;

    if(nx->cov_level != COV_LAST) {
        nx->children = (void*)kb_init(hier, KB_DEFAULT_SIZE);
    }

    tree->n_nodes[0]++;
    if(cov > COV_NULL && cov < COV_INFI){
        tree->n_nodes[cov]++;
        u8* buf = (u8*)ck_alloc(MAP_SIZE * sizeof(u8));
        nx->fuzz_trace = buf;
    }

    tree->has_new_node = 1;
    
    return nx;
}


void delete_node(hier_node_t* node){

    ck_free(node->fuzz_trace);

    kbtree_t(hier) *map; 
    if(node->children){
        kbitr_t itr;
        hier_key_t *p;
        map = (kbtree_t(hier) *)node->children;
        kb_itr_first(hier, map, &itr);
        for(; kb_itr_valid(&itr); kb_itr_next(hier, map, &itr)){
            p = &kb_itr_key(hier_key_t, &itr);
            free(p->bits);
            delete_node(p->node);
        }
        kb_destroy(hier, map);
    }

    ck_free(node);
}


hier_tree_t* new_tree(){

    hier_tree_t* tree = (hier_tree_t*) ck_alloc(sizeof(hier_tree_t));
    tree->root = new_node(tree, COV_NULL, NULL);
    return tree;
}



static void report_tree(hier_tree_t* tree){
    u32 i;
    char* tags[COV_LAST + 1] = {" total", "    fn", /*"    n0",*/ "  edge", /*"    n2", "   n4", "   n8"*/ "  last"};
    printf("final tree (#nodes, #bytes):\n");
    printf("  %s:\t %u(%u)\n", tags[0], tree->n_nodes[0], tree->n_fuzzed_nodes[0]);
    for(i=COV_NULL+1; i <= COV_LAST; i++){
        printf("  %s:\t %u(%u)\t %u(%u)\n", tags[i], tree->n_nodes[i], tree->n_fuzzed_nodes[i], tree->n_bits[i], tree->n_fuzzed_bits[i]);
    }
    printf("total seeds: %llu\n", tree->root->n_seeds);
}


void delete_tree(hier_tree_t* tree){
    report_tree(tree);
    delete_node(tree->root);
    ck_free(tree);
}





inline double calc_distance(u8* bitmap, u32 size) {

    u32 i;
    u8 byte;
    u8 distance;
    // u8 min_distance = 128;
    u32 sum = 0;
    u32 num = 0;

    for(i = 0; i < size; i++ ) {

        byte = bitmap[i];

        if(unlikely(byte)) {

            if(byte & 2)        { distance = 1; }
            else if(byte & 4)   { distance = 2; }
            else if(byte & 8)   { distance = 4; }
            else if(byte & 16)  { distance = 8; }
            else if(byte & 32)  { distance = 16; }
            else if(byte & 64)  { distance = 32; }
            else if(byte & 128) { distance = 64; }
            else                { distance = 0; }       //ignore byte & 1 
            sum += distance;
            num += 1;
        }

    }
    
    double avg_distance = (double)num / sum;
    return avg_distance;
}




void update_base_score(hier_sched_t* sched, hier_node_t* node) {

    u32 map_size = sched->map_size;

    u8* etrace = node->exec_trace;

    if(node->cov_level == COV_LAST) {

        node->base_score = calc_distance(etrace, map_size);

    }
    else{

        u16* step_emap = sched->step_exec_map + map_size * (node->cov_level - 1);
        u64* emap = sched->exec_map + map_size * (node->cov_level - 1);

        double score = 0; 

        u32 i, j, k;
        u8 val;
        u64 cnt;
        u64 num = 0;


        for(i = 0; i < (map_size >> 3); i++){
            val = etrace[i];
            for(j = 0; j < 8; j++){
                k = i * 8 + j;
                if(val & (1 << j)){
                    cnt = emap[k] + step_emap[k];
                    score += ((double) 1.0) / pow(cnt, 2);
                    num++;
                }
            }
        }

        score = sqrt(score / num);

        node->base_score = score;
    }

    node->fuzz_score = 1.0;

}



void update_score(hier_sched_t* sched){

    hier_tree_t* tree = sched->tree;
    if(!tree->leaf_cur) return;

    u32 map_size = sched->map_size;

    u8  *etrace;
    u16 *step_map;
    u64 *emap;

    double score1;
    double score2 = 1.0;
    double score2x;

    u32 i, j, k;
    u8  val;
    u64 num1;
    u64 num2 = 0;

    u64 cnt, min_cnt;

    hier_node_t* nx;

    for(nx = tree->leaf_cur; nx->cov_level < COV_INFI && nx->cov_level > COV_NULL; nx = nx->parent){

        min_cnt = ((u64)-1) >> 1;

        step_map = sched->step_exec_map + map_size * (nx->cov_level - 1);
        emap = sched->exec_map + map_size * (nx->cov_level - 1);

        score2x = 0;

        if(nx->cov_level == COV_LAST) {
            if(sched->need_update){
                for(i = 0; i < map_size; i++) {
                    if(step_map[i]) {  
                        cnt = emap[i];
                        min_cnt = MIN(min_cnt, cnt); 
                    }
                }
            }
        }
        else{ 
            etrace = nx->exec_trace;
            score1 = 0;
            num1 = 0;
            for(i = 0; i < (map_size >> 3); i++){
                val = etrace[i];
                for(j = 0; j < 8; j++){
                    k = i * 8 + j;

                    cnt = emap[k];

                    if(val & (1 << j)){
                        score1 += ((double) 1.0) / pow(cnt, 2);
                        num1++;
                    }

                    if(sched->need_update && step_map[k]){
                        min_cnt = MIN(min_cnt, cnt);
                    }
                }
            }

            score1 = sqrt(score1 / num1);
            nx->base_score = score1;

        }

        score2x = ((double)1.0) / next_p2_fast(min_cnt);
        score2 *= score2x;
        num2 += 1;
        nx->fuzz_score = (nx->fuzz_score + pow(score2, 1.0 / num2)) / 2;  
    }

}




hier_node_t* best_child(hier_tree_t* tree, hier_node_t* node, double c_param){

    double score, cur_best_score = -1;
    hier_node_t *cur=NULL, *nx;
    hier_key_t *p;
    kbitr_t itr;
    kbtree_t(hier) *map; 
    map = (kbtree_t(hier) *)node->children;
    kb_itr_first(hier, map, &itr);

    u64 factor = tree->root->n_fuzz;

    for(; kb_itr_valid(&itr); kb_itr_next(hier, map, &itr)){
        p = &kb_itr_key(hier_key_t, &itr);
        nx = p->node;
        double s1 = nx->base_score;
        double s2 = nx->fuzz_score;
        double s3 = c_param * sqrt((double)nx->n_seeds / node->n_seeds) * sqrt(log((double)node->n_fuzz) / nx->n_fuzz);
        score = factor * s1 * (s2 + s3) ;
        // fprintf(stderr, "    #%d score: %f (%f, %f, %f) (%llu %llu) (%llu, %llu)\n", nx->id, score, s1, s2, s3, nx->n_seeds, node->n_seeds, nx->n_fuzz, node->n_fuzz);
        if( (score > cur_best_score) || (score == cur_best_score && nx->n_fuzz < cur->n_fuzz)){
            cur_best_score = score;
            cur = nx;
            // fprintf(stderr, "  cur best child: #%d, %f\n", cur->id, cur_best_score);
        }
        
    }
    // fprintf(stderr, "best child: #%d, best score: %f\n\n", cur->id, cur_best_score);
    return cur;
}



inline hier_node_t* best_leaf_node(hier_tree_t* tree, double c_param){

    hier_node_t* cur = tree->root;
    while(cur->cov_level != COV_LAST){
        cur = best_child(tree, cur, c_param);
    }
    tree->leaf_cur = cur;
    return cur;

}



void update_reward(hier_sched_t* sched){

    u64* bytes = sched->exec_map;
    u16* step_bytes = sched->step_exec_map;

    u32 i;
    u16 val;

    hier_tree_t* tree = sched->tree;
    hier_node_t *nx = tree->leaf_cur;

    while(nx){
        if(nx->n_fuzz == 1){
            tree->n_fuzzed_nodes[nx->cov_level]++;
            tree->n_fuzzed_nodes[0]++;
        }
        nx->n_fuzz++;
        nx = nx->parent;
    }

    for(i = 0; i < sched->map_size * sched->n_cov_level ; i++){
        val = step_bytes[i];
        if(val) { 
            bytes[i] += val; // = MIN(100000, bytes[i] + val);
            sched->need_update = 1;
        }
    }
   
    update_score(sched);

    if(sched->need_update) {
        memset(step_bytes, 0, sched->map_size * sched->n_cov_level * sizeof(u16));
        sched->need_update = 0;
    }

    if(tree->has_new_node){
        report_tree(tree);
        tree->has_new_node = 0;
    }
    
}

