#ifndef __UTIL_STRING_H__
#define __UTIL_STRING_H__

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifndef STRLEN
#define STRLEN(STR) ((int)strlen((const char *)STR))
#endif

#ifndef ISALNUM
#define ISALNUM(S) (isalnum((const char)S))
#endif

#ifndef STRCMP
#define STRCMP(S,D) (strcmp((const char *)S, (const char *)D))
#endif

#ifndef STRSTR
#define STRSTR(D,S) (strstr((const char *)D,(const char *)S))
#endif

#ifndef STRNCMP
#define STRNCMP(S,D,L) (strncmp((const char *)S, (const char *)D, L))
#endif

#ifndef STRCAT
#define STRCAT(D,S) (strcat((char *)D, (const char *)S))
#endif

#ifndef FOREVER
#define FOREVER for(;;)
#endif

typedef struct atomic {
  volatile int counter;
} atomic_t;

struct value_string {
    unsigned int value;
    const char *strptr;
};

extern const char*
val_to_str(const unsigned int val, const struct value_string *vs);

typedef struct{
#define ATOMIC64_SIZE sizeof(long long)
    int64_t counter;
}atomic64_t;

#define ATOMIC_INIT(i)	{ (i) }

#define atomic_read(v)	(*(volatile int *)&(v)->counter)
#define atomic64_read(v)	(*(volatile int64_t *)&(v)->counter)

#define atomic_add(x, y) (__sync_add_and_fetch((&(((atomic_t *)x)->counter)), (y)))
#define atomic64_add(x, y) (__sync_add_and_fetch((&(((atomic64_t *)x)->counter)), (y)))
#define atomic64_sub(x, y) (__sync_sub_and_fetch((&(((atomic64_t *)x)->counter)), (y)))

#define atomic64_inc(x)  (atomic64_add((x), 1))
#define atomic64_dec(x) (atomic64_sub((x), 1))

static inline void atomic64_set(atomic64_t *v, int64_t val)
{
    v->counter = val;
}

#endif
