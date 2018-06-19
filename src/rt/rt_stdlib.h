#ifndef __RT_STDLIB_H__
#define __RT_STDLIB_H__

#include <stdlib.h>

/** memory flags */
#define MPF_CLR         (1 << 0)      /** Clear it after allocated */

extern void kfree(void *p);

void *kmalloc(int s, int flags,  int __attribute__((__unused__)) node);


#endif

