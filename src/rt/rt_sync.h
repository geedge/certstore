/*
*   sync.h
*   Created by Tsihang <qihang@semptian.com>
*   1 June, 2015
*   Func: System startup synchronous operation interface of SPASR
*   Personal.Q
*/


#ifndef __SYSTEM_SYNC_H__
#define __SYSTEM_SYNC_H__

#include <pthread.h>

#define rt_pthread_attr pthread_attr_t
#define rt_pthread  pthread_t
#define rt_mutex pthread_mutex_t
#define rt_mutex_attr pthread_mutexattr_t
#define rt_mutex_init(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define rt_mutex_lock(mut) pthread_mutex_lock(mut)
#define rt_mutex_trylock(mut) pthread_mutex_trylock(mut)
#define rt_mutex_unlock(mut) pthread_mutex_unlock(mut)
#define rt_mutex_destroy(mut) pthread_mutex_destroy(mut)

#define INIT_MUTEX(name)\
    rt_mutex name = PTHREAD_MUTEX_INITIALIZER;

#endif

