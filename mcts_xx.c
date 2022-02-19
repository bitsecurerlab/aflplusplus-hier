

#include <stdio.h>
#include <math.h>

#include "debug.h"
#include "mcts.h"



#define mcts_key_cmp(n1, n2) (memcmp((n1).bitmap, (n2).bitmap, (MAP_SIZE >> 3)))

KBTREE_INIT(mcts, mcts_key_t, mcts_key_cmp)


static u8 read_bit(u8* bits, u32 i){
  return (bits[i>>3] & (128 >> (i & 7))) ? 1 : 0 ;
}



#define FF(_b)  (0xff << ((_b) << 3))
#define FFFF(_b)  (0xff << ((_b) << 4))


static u32 count_bits(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


static u32 count_bytes(u8* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}


static u32 count_words(u16* mem, u32 size) {

  u32* ptr = (u32*)mem;
  u32  i   = (size >> 1);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FFFF(0)) ret++;
    if (v & FFFF(1)) ret++;

  }

  return ret;

}


static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 128 >> (i & 7);
    i++;

  }

}



void update_trace_cnt(mcts_tree_t* tree, u8* trace_bits){

    u16* trace_counts = tree->trace_counts;
    u32 i;
    for(i= 0; i < tree->_rlevel * MAP_SIZE; i++){
        if(trace_bits[i] && trace_counts[i] < 1000){
            trace_counts[i] += 1;
        }
    }
}


void reset_trace_cnt(mcts_tree_t* tree){
    memset(tree->trace_counts, 0, tree->_rlevel * 2 * MAP_SIZE);
}







static queue_cluster_t* new_queue_cluster(mcts_tree_t* tree){
    queue_cluster_t* new = (queue_cluster_t*)malloc(sizeof(queue_cluster_t));
    memset(new, 0, sizeof(queue_cluster_t));
    new->id = tree->nums[N_LAST];
    return new;
}



static mcts_node_t* new_node(mcts_tree_t* tree, n_gram_t n, mcts_node_t* parent){
    mcts_node_t* nx = (mcts_node_t*) malloc(sizeof(mcts_node_t));
    memset(nx, 0, sizeof(mcts_node_t));

    nx->n_gram_level = n;
    nx->parent = parent;
    // nx->reward = 0;
    // nx->visit_times = 0;
    nx->id = tree->nums[0];  
    // nx->n_fuzz = 0;  
    // nx->base_scores = 0;

    if(nx->n_gram_level == N_LAST){
        // nx->children = NULL;
        nx->queue_cluster = new_queue_cluster(tree);
    }else{
        nx->children  = (void*) kb_init(mcts, KB_DEFAULT_SIZE);
        // nx->queue_cluster = NULL;
    }    
    
    tree->nums[0]++;
    if(nx->n_gram_level > N_NULL && nx->n_gram_level < N_INFI){
        tree->nums[nx->n_gram_level]++;
    }

    // nx->bitmap = NULL;
    // nx->new_next = NULL;
    return nx;
}

static void delete_node(mcts_node_t* node){

    // printf("deleting_node %llx\n", node);  
    if(node->queue_cluster){
        free(node->queue_cluster);
        // node->queue_cluster = NULL;
    }
    kbtree_t(mcts) *map; 
    if(node->children){
        kbitr_t itr;
        mcts_key_t *p;
        map = (kbtree_t(mcts) *)node->children;
        kb_itr_first(mcts, map, &itr);
        for(; kb_itr_valid(&itr); kb_itr_next(mcts, map, &itr)){
            p = &kb_itr_key(mcts_key_t, &itr);
            free(p->bitmap);
            // kb_delp(mcts, map, p);
            delete_node(p->node);
        }
        // printf("destory map: %llx of %llx\n", map, node);
        kb_destroy(mcts, map);
    }

    // printf("delete_node %llx, -> %llx\n", node, node->parent);
    if(!node->parent){
        //only root need free
        free(node);
    }
    // printf("complete delete_node %llx\n", node);

}



mcts_tree_t* new_tree(void){
    mcts_tree_t* tree = (mcts_tree_t*)malloc(sizeof(mcts_tree_t));

    memset(tree, 0, sizeof(mcts_tree_t));

    tree->_rlevel = 3;

    tree->trace_counts = (u16*)malloc(sizeof(u16) * tree->_rlevel * MAP_SIZE);
    reset_trace_cnt(tree);

    mcts_node_t* root = new_node(tree, N_NULL, NULL);
    root->n_fuzz = 1;
    tree->root = root;

    return tree;
}


static void report_tree(mcts_tree_t* tree){
    u32 i;
    char* tags[N_INFI] = {" total", "   ctx", /*"    n0",*/ "    n1", /*"    n2", "   n4", "   n8"*/ "    ma"};
    printf("final tree (#nodes):\n");
    for(i=N_NULL; i < N_INFI; i++){
        printf("  %s\t: %u(%u)\n", tags[i], tree->nums[i], tree->fuzzed[i]);
    }

}


void delete_tree(mcts_tree_t* tree){
    report_tree(tree);
    // printf("delete tree\n");
    delete_node(tree->root);
    free(tree->trace_counts);
    tree->node_cur = NULL;
    free(tree);
    // printf("finish delete tree\n");
}



n_gram_t add_to_tree(mcts_tree_t* tree, struct queue_entry* queue, u8* trace_bits){

    // printf("add_to_tree %d\n", queue->id);
    mcts_node_t* cur = tree->root;
    kbtree_t(mcts)* map;
    mcts_key_t k, *k_p = &k, *p;
    mcts_node_t *nx;
    n_gram_t i, ret=N_INFI;
    u32 size = (MAP_SIZE >> 3);
    for(i = N_NULL + 1; i < N_INFI; i++){
        u8* bitmap = (u8*)malloc(size * sizeof(u8));
        memset(bitmap, 0, size);
        minimize_bits(bitmap, trace_bits + MAP_SIZE * (i - 1));
        k_p->bitmap = bitmap;
        map = (kbtree_t(mcts) *)cur->children;
        p = kb_getp(mcts, map, k_p);
        if(!p){
            ret = MIN(ret, i);
            nx = new_node(tree, i, cur);
            nx->bitmap = bitmap;
            k_p->node = nx;
            p = kb_putp(mcts, map, k_p);
            
            if(!tree->pending){
                tree->pending = nx;
            }
            else{
                nx->new_next = tree->pending;
                tree->pending = nx;
            }
            // cur = nx;
        }
        else{
            free(bitmap);
        }
        cur = p->node;
    }
    // assert(cur->n_gram_level == N_LAST)
    queue_cluster_t* cur_cluster = cur->queue_cluster;

    if(cur_cluster->queue_top){
        cur_cluster->queue_top->local_next = queue;
        cur_cluster->queue_top = queue;
    }
    else{
        cur_cluster->queue = cur_cluster->queue_top = cur_cluster->queue_cur = queue;
    }
    queue->local_next = NULL;

    cur_cluster->volumn++;

    if(tree->node_cur){
        tree->node_cur->queue_cluster->new_paths += pow(2, N_INFI - ret);
    }

    // printf("finish add_to_tree\n");

    return ret;
}



static mcts_node_t* best_child(mcts_node_t* node, double c_param){
    // printf("best child of %llx\n", (u64)node);
    double score, cur_best_score = 0;
    mcts_node_t *cur=NULL, *nx;
    mcts_key_t *p;
    kbitr_t itr;
    kbtree_t(mcts) *map; 
    map = (kbtree_t(mcts) *)node->children;
    kb_itr_first(mcts, map, &itr);
    u32 i = 0, k = 0;
    for(; kb_itr_valid(&itr); kb_itr_next(mcts, map, &itr)){
        p = &kb_itr_key(mcts_key_t, &itr);
        nx = p->node;
        
        score = nx->base_score;
        score += MIN(1, ((double)(nx->reward + 0) / (nx->visit_times + 1)));
        score += (c_param * sqrt( (1 + log((double)(node->visit_times + 1))) / (nx->visit_times + 1)));
        if(score >= cur_best_score){
            cur_best_score = score;
            cur = nx;
            k = i;
        }
        i++;
        // if(p->n_gram_level == N_LAST){
        //     // printf("**queue_cur: %llx, queue: %llx, queue_top: %llx\n", p->queue_cluster->queue_cur, p->queue_cluster->queue, p->queue_cluster->queue_top);
        // }
    }
    printf("best score: %f(%f), best child %d (%d/%d, n_fuzz:%llu)\n", 
        cur_best_score, cur->base_score, cur->id, k+1, i, cur->n_fuzz);  
    return cur;
}


static mcts_node_t* best_leaf_node(mcts_node_t* root, double c_param){
    // printf("best_leaf_node of %llx\n", (u64)root);
    mcts_node_t* cur = root;
    while(cur->n_gram_level != N_LAST){
        cur = best_child(cur, c_param);
    }
    return cur;
}



static void update_base_score(mcts_tree_t* tree){
    mcts_node_t *prev,
                *cur = tree->pending,
                *parent;
    double score;
    u32 i, base, word_cnts[N_LAST];
    u16 cnt;
    for(i = 0; i < N_LAST; i++){
        word_cnts[i] = count_words(tree->trace_counts + MAP_SIZE * i, MAP_SIZE);
        printf("word_cnts[%u]: %u\n", i, word_cnts[i]);
    }

    while(cur){
        score = 0;
        base = MAP_SIZE * (cur->n_gram_level - 1);
        for(i = 0; i < MAP_SIZE; i++){
            if(read_bit(cur->bitmap, i)){
                cnt = tree->trace_counts[base + i];
                // printf("[%d]cnt: %d  ", i, cnt);
                score += ((double)1 / cnt);
            }
        }
        score /= word_cnts[cur->n_gram_level - 1];
        cur->_base_scores[0] = score;
        cur->base_score = score + cur->_base_scores[1] / (1 + cur->pending_children);
        // printf("+update base score: %f to %u,%u\n", cur->base_score, cur->id, cur->n_gram_level);
        parent = cur->parent;
        if(parent){
            parent->pending_children++;
            parent->_base_scores[1] += cur->base_score;
        }
        prev = cur;
        cur = cur->new_next;
        prev->new_next = NULL;
    }
    tree->pending = NULL;

    cur = tree->node_cur;
    double new_score;
    while(cur){
        // parent = NULL;
        // if(!cur->n_fuzz){
        //     new_score = (cur->_base_scores[1] / (1 + cur->pending_children));
        //     parent = cur->parent;
        //     if(parent){
        //         parent->pending_children--;
        //         parent->_base_scores[1] += (new_score - cur->base_score);
        //     }
        //     cur->base_score = new_score;
        // }
     
        new_score = cur->_base_scores[1] / (1 + cur->pending_children);
        // new_score += cur->_base_scores[0] / pow(2, 1+cur->n_fuzz);
        new_score += cur->_base_scores[0] / pow(2 + cur->n_fuzz, 3);
        parent = cur->parent;
        if(!cur->n_fuzz){
            if(parent){
                if(new_score == 0){
                    parent->pending_children--;
                }
                parent->_base_scores[1] += (new_score - cur->base_score);
            }
        }
        cur->base_score = new_score;
        // printf("-update base score: %f to %u,%u\n", cur->base_score, cur->id, cur->n_gram_level);
        cur = parent;
    }
}



static void update_reward_1(mcts_tree_t* tree){
    static u32 factor = 0;
    mcts_node_t *nx = tree->node_cur;
    
    // if(nx){
        queue_cluster_t* qc = nx->queue_cluster;
        u64 new_paths = qc->new_paths / pow(2, N_INFI - N_ONE),
            mutation_times = qc->mutation_times;
        if(!factor){
            u32 cands[5] = {10000, 1000, 100, 10, 1};
            u32 i;
            for(i=0;i<5;i++){
                factor = cands[i];
                if((new_paths + 1) * factor < mutation_times) break;
            }
        }
        u64 r = new_paths * factor;
        printf("update reward: %llu, %llu, @%x\n", r, mutation_times, qc);
        do{
            if(!nx->n_fuzz){
                tree->fuzzed[nx->n_gram_level]++;
                tree->fuzzed[0]++;
            }
            nx->n_fuzz++;
            nx->reward += r;
            nx->visit_times += mutation_times;
            nx = nx->parent;
        }while(nx);

        qc->new_paths = 0;
        qc->mutation_times = 0;
    // }
    
}


static void update_reward_2(mcts_tree_t* tree){
    mcts_node_t *nx = tree->node_cur;
    queue_cluster_t* qc = nx->queue_cluster;
    u64 mutation_times = qc->mutation_times;
    double r = 0.0;
    u8* bitmap;
    u32 i, base, mul = 1;
    u32 cnt, word_cnt;
    while(nx && nx->n_gram_level != N_NULL){
        if(nx->n_gram_level != N_NULL){
            double rx = 0;
            word_cnt = 0;
            base = MAP_SIZE * (nx->n_gram_level - 1);
            printf("%u, %u\n", count_words(tree->trace_counts + base, MAP_SIZE), count_bits(nx->bitmap, MAP_SIZE>>3));
            for(i = 0; i < MAP_SIZE; i++){
                cnt = tree->trace_counts[base + i];
                if(cnt){
                    // printf("[%u] %u  ", i, cnt);
                    word_cnt ++;
                    if(!read_bit(nx->bitmap, i)){
                        // printf("[%u] %u (%u)   ", i, cnt, count_bits(nx->bitmap, MAP_SIZE>>3));
                        rx += (double)1.0 / cnt; 
                    }
                }
            }
            r += rx * (1 << (N_LAST - nx->n_gram_level));
            mul = 1 << (N_INFI - nx->n_gram_level);
            mul -= 1;
            double rm = r / mul;
            printf("\nupdate reward %f (%f, %f)\n", rm, rx, r);
            nx->reward = rm;
        }
        else{
            nx->reward += r;
        }
        if(!nx->n_fuzz){
            tree->fuzzed[nx->n_gram_level]++;
            tree->fuzzed[0]++;
        }
        nx->n_fuzz++;
        nx->visit_times += mutation_times;
        nx = nx->parent;
    }
    qc->new_paths = 0;
    qc->mutation_times = 0;

}

static void update_reward_3(mcts_tree_t* tree){
    mcts_node_t *nx = tree->node_cur;
    queue_cluster_t* qc = nx->queue_cluster;
    u64 mutation_times = qc->mutation_times;
    double r = 0.0;
    u8* bitmap;
    u32 i, base, mul = 1;
    u32 cnt, word_cnt;
    while(nx && nx->n_gram_level != N_NULL){
        if(nx->n_gram_level != N_NULL){
            double rx = 0;
            word_cnt = 0;
            base = MAP_SIZE * (nx->n_gram_level - 1);
            printf("%u, %u\n", count_words(tree->trace_counts + base, MAP_SIZE), count_bits(nx->bitmap, MAP_SIZE>>3));
            for(i = 0; i < MAP_SIZE; i++){
                cnt = tree->trace_counts[base + i];
                if(cnt){
                    // printf("[%u] %u  ", i, cnt);
                    word_cnt ++;
                        // printf("[%u] %u (%u)   ", i, cnt, count_bits(nx->bitmap, MAP_SIZE>>3));
                    rx += (double)1.0 / cnt; 
 
                }
            }
            rx /= word_cnt;
            r += rx * (1 << (N_LAST - nx->n_gram_level));
            mul = 1 << (N_INFI - nx->n_gram_level);
            mul -= 1;
            double rm = r / mul;
            printf("\nupdate reward %f (%f, %f)\n", rm, rx, r);
            nx->reward = rm;
        }
        else{
            nx->reward += r;
        }
        if(!nx->n_fuzz){
            tree->fuzzed[nx->n_gram_level]++;
            tree->fuzzed[0]++;
        }
        nx->n_fuzz++;
        nx->visit_times += mutation_times;
        nx = nx->parent;
    }
    qc->new_paths = 0;
    qc->mutation_times = 0;

}





struct queue_entry* next_queue_cur(mcts_tree_t* tree, double c_param){

    static u32 num = 0;

    if(num){
        update_base_score(tree);
        update_reward_1(tree);
        reset_trace_cnt(tree);
    }    
    // update_reward_x(tree);
    report_tree(tree);
    mcts_node_t* nx = best_leaf_node(tree->root, c_param);
    queue_cluster_t* qc = nx->queue_cluster;
    printf("%u' next_queue_cluster_cur %u of %u, %u nodes \n", num, qc->id+1, tree->nums[N_LAST], tree->nums[0]);
    num++;
    // printf("queue_cur: %llx, queue: %llx, queue_top: %llx\n", qc->queue_cur, qc->queue, qc->queue_top);

    tree->node_cur = nx;

    struct queue_entry* q = nx->queue_cluster->queue_cur;
    if(!q){
        q = nx->queue_cluster->queue;
    }
    nx->queue_cluster->queue_cur = q->local_next;
    
    return q;
}

