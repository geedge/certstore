#include <stdint.h>
#include <string.h>
#include "rt_string.h"

const char *
try_val_to_str_idx(const unsigned int val, const struct value_string *vs, int *idx)
{
    int  i = 0;
    if (idx == NULL){
        goto finish;
    }

    if(vs) {
        while (vs[i].strptr) {
            if (vs[i].value == val) {
                *idx = i;
                return(vs[i].strptr);
            }
            i++;
        }
    }

finish:
    *idx = -1;
    return NULL;
}

const char*
val_to_str(const unsigned int val, const struct value_string *vs)
{
    int ignore_me;

    return try_val_to_str_idx(val, vs, &ignore_me);
}

