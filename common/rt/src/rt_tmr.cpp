/*************************************************************************
	> File Name: rt_tmr.c
	> Author:
	> Mail:
	> Created Time: 2018年09月19日 星期三 15时57分58秒
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>

#include "rt_stdlib.h"
#include "rt_sync.h"
#include "rt_string.h"
#include "rt_common.h"

static int init;

enum {
    ALLOWED,
    FORBIDDEN
};

enum tmr_type{
	TMR_PERIODIC, 
	TMR_ASHOT
};

enum tmr_status{
	TMR_STOPPED, 
	TMR_STARTED
};

struct tmr_task{
    rt_pthread pid;

    rt_pthread_attr *attr;

    void * (*routine)(void *);
};

struct rt_timer_t{

#define TMR_INVALID  -1

    int module;

    /** unique id */
    uint32_t uid;

    /** Make sure that allocate desc member with malloc like function. */
    char *desc;

    /** in ms */
    int64_t interval;

    int64_t curr_ticks;

    enum tmr_type type;

    enum tmr_status status;

    void (*routine)(uint32_t uid, int argc, char **argv);

    int argc;

    char **argv;

    int recycle;
};

struct rt_timer_t *_this;

static volatile atomic64_t  g_sys_cur_ticks = ATOMIC_INIT(0);

struct rt_timer_t  *
tmr_set(uint32_t uid,
        void (*proc)(struct rt_timer_t *t))
{
    uid = uid;

     if(likely(proc))
           proc(_this);

    return _this;
}

static void tmr_enable(struct rt_timer_t *t)
{
    t->status = TMR_STARTED;
}

static void tmr_disable(struct rt_timer_t *t)
{
    t->status = TMR_STOPPED;
}

void tmr_start(uint32_t uid)
{
    tmr_set(uid, tmr_enable);
}

void tmr_stop(uint32_t uid)
{
    tmr_set(uid, tmr_disable);
}

static void tmr_handler(int __attribute__((__unused__))sig)
{
    int64_t old_ticks = 0;

    old_ticks = atomic64_add(&g_sys_cur_ticks, 1);
    if (likely(_this->status == TMR_STARTED)){
        if (likely(old_ticks >= _this->curr_ticks)) {
            _this->routine(_this->uid, _this->argc, _this->argv);
        if (likely(TMR_ASHOT == _this->type))
            _this->status= TMR_STOPPED;
        else
            _this->curr_ticks = old_ticks + _this->interval;
        }
    }
}

static void realtimer_init()
{
    static struct itimerval tmr;

    signal(SIGALRM, tmr_handler);
    tmr.it_interval.tv_sec = 1;
    tmr.it_interval.tv_usec = 0;
    tmr.it_value.tv_sec = 1;
    tmr.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &tmr, NULL);

}

static void
tmr_default_routine(uint32_t uid, int __attribute__((__unused__))argc,
                    char __attribute__((__unused__))**argv)
{
    static int count[2] = {0};

    count[uid%2] ++;
    printf ("default timer [%u, %d] routine has occured\n", uid, count[uid%2]);
}

static __rt_always_inline__ void *
tmr_alloc()
{
    struct rt_timer_t *t;

    t = (struct rt_timer_t *)kmalloc(sizeof(struct rt_timer_t), MPF_CLR, -1);
    if(likely(t)){
        t->uid = TMR_INVALID;
        t->routine = tmr_default_routine;
        t->interval = 3; //tmr_internal_trans(3);
        t->recycle = ALLOWED;
        t->type = TMR_ASHOT;
        t->status = TMR_STOPPED;
    }
    return t;
}

static void *
tmr_daemon(void __attribute__((__unused__))*pv_par )
{
    FOREVER{
        sleep(86400);
    }
    return NULL;
}

uint32_t tmr_create(int module,
                const char *desc,
                void (*routine)(uint32_t, int, char **), int argc, char **argv, int sec)
{
    uint32_t uid = -1;

    if(unlikely(!desc)){
        goto finish;
    }

    _this = (struct rt_timer_t *)tmr_alloc();
    if(unlikely(!_this)){
        goto finish;
    }

    _this->module = module;
    _this->desc = strdup(desc);
    _this->curr_ticks = 0;
    _this->interval = sec;
    _this->routine = routine ? routine : tmr_default_routine;
    _this->type = TMR_PERIODIC;
    _this->uid = uid = 1;
    _this->recycle = ALLOWED;
    _this->status = TMR_STOPPED;
    _this->argc = argc;
    _this->argv = argv;

    if(likely(init == 0)){
        struct tmr_task *task = (struct tmr_task*)kmalloc(sizeof(struct tmr_task), MPF_CLR, -1);
        if (likely(task)){
            if (pthread_create(&task->pid, task->attr, tmr_daemon, NULL)){
    			goto finish;
    		}
    		if (pthread_detach(task->pid)){
    			goto finish;
    		}
        }
        init = 1;
        realtimer_init();
    }

finish:
    return uid;
}

