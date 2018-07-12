/*************************************************************************
	> File Name: rd_lock.h
	> Author:
	> Mail:
	> Created Time: 2018年07月05日 星期四 11时02分03秒
 ************************************************************************/

#ifndef _RD_LOCK_H
#define _RD_LOCK_H

#include "hiredis.h"

struct rd_lock_scb{
    int  m_validityTime;
    sds  m_resource;
    sds  m_val;
};

void rd_lock_init();

void rd_lock_fini();

int rd_mutex_lock(const char *resource, const int ttl,
                 struct rd_lock_scb *mtx, struct redisContext *c);

int rd_mutex_unlock(struct rd_lock_scb *mtx, struct redisContext *c);

#endif
