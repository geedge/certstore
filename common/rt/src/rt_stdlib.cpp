
#include <stdlib.h>
#include <string.h>
#include "rt_common.h"
#include "rt_stdlib.h"

void *kmalloc(int s,
                        int flags,
                        int __attribute__((__unused__)) node)
{
    void *p;

    if(likely((p = malloc(s)) != NULL)){
        if(flags & MPF_CLR)
            memset(p, 0, s);
    }

    return p;
}

void kfree(void *p)
{
    if(likely(p != NULL)){
        free(p);
    }

    p = NULL;
}

