#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "../types.h" 
#include "../alloc-inl.h"

// #define multi_printf(tag, array, n) ({ \
//     u8* _tmp; \
//     int _i; \
//     int _len = snprintf(NULL, 0, (tag), (array)[0]);\
//     int _total_len = _len * (n) + 1;\
//     _tmp = ck_alloc(_len * (n) + 1); \
//     _len = 0; \
//     for(_i=0;_i<(n);_i++){ \
//         _len += snprintf(_tmp + _len, _total_len - _len, (tag), (array)[_i]); \
//     } \
//     _tmp; \
// })

int main(){
    char tag[] = "%u ";
    u32 arrayx[] = {302, 395, 725, 1501, 3457};

    // u8 str[1024];
    // int i;
    // int k=0;
    // for(i=0;i<5;i++){
    //     k += snprintf(str+k, 1024-k, tag, arrayx[i]);
    // }
    // // int k = snprintf(str, 1024, tag, arrayx[0]);
    // // printf("%u, %s\n", k, str);
    // // k = snprintf(str + k, 1023, tag, arrayx[1]);
    // printf("%u, %s\n", k, str);

    // printf("%u %lu\n", array[0], sizeof(array));
    u8* str = multi_printf(tag, arrayx, 5);
    printf("%d\n%s\n", sizeof(str), str);
    // // do{ 
    //     u8 _tmp[1024]; 
    //     int _i; 
    //     int _k=0; 
    //     for(_i=0;_i<(2);_i++){ 
    //         _k += snprintf(_tmp+k, 1024-k, tag, arrayx[_i]); 
    //     } 
    //     printf("%u\n%s\n", _k, _tmp); 
    // // }while(0);
}

