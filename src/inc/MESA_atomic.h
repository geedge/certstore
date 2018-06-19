#ifndef _MESA_ATOMIC_H_
#define _MESA_ATOMIC_H_


#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
typedef unsigned long MESA_ATOMIC_T;
#define MESA_ATOMIC_SET(v, i)	__sync_lock_test_and_set((&v), i)
#define MESA_ATOMIC_READ(v)		__sync_or_and_fetch((&v), 0)
#define MESA_ATOMIC_INC(v) 		__sync_add_and_fetch((&v),1)
#define MESA_ATOMIC_DEC(v) 		__sync_sub_and_fetch((&v),1)
#define MESA_ATOMIC_ADD(v,add) 	__sync_add_and_fetch((&v),(add))
#define MESA_ATOMIC_SUB(v,sub) 	__sync_sub_and_fetch((&v),(sub))
#else 
#include <alsa/iatomic.h>
typedef atomic_t	MESA_ATOMIC_T;
#define MESA_ATOMIC_SET(v, i)	atomic_set((&v), i)
#define MESA_ATOMIC_READ(v) 	atomic_read((&v))
#define MESA_ATOMIC_INC(v) 		atomic_inc((&v))
#define MESA_ATOMIC_DEC(v) 		atomic_dec((&v))
#define MESA_ATOMIC_ADD(v, add) atomic_add((add),(&v))
#define MESA_ATOMIC_SUB(v, sub) 	atomic_sub((sub),(&v))
#endif 


#ifdef __tilegx__
#include <arch/atomic.h>
typedef int	MESA_ATOMIC_T;
#define MESA_ATOMIC_SET(v, i)	arch_atomic_exchange((&v), i)
#define MESA_ATOMIC_READ(v) 	arch_atomic_or((&v), 0)
#define MESA_ATOMIC_INC(v) 		arch_atomic_add((&v), 1)
#define MESA_ATOMIC_DEC(v) 		arch_atomic_sub((&v), 1)
#define MESA_ATOMIC_ADD(v, add) arch_atomic_add((&v), add)
#define MESA_ATOMIC_SUB(v, sub) 	arch_atomic_sub((&v), sub)
#endif


#endif

