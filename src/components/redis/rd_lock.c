/*************************************************************************
	> File Name: rd_lock.c
	> Author:
	> Mail:
	> Created Time: 2018年07月05日 星期四 11时01分39秒
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>

#include "rd_lock.h"
#include "rt_string.h"

struct rd_RedLock{
    float m_clockDriftFactor;
    sds   m_unlockScript;
    int   m_retryCount;
    int   m_retryDelay;
};

static struct rd_RedLock redlock = {
    .m_clockDriftFactor = 0.01,
    .m_unlockScript = NULL,
    .m_retryCount = 0,
    .m_retryDelay = 0,
};

struct rd_RedLock *mutx_redlock()
{
    return &redlock;
}

static char *
get_unique_lockid()
{
    int i = 0;
    char *s = NULL;
	char value[10] = "0123456789";
    unsigned char buffer[20];

    struct timeval t1;
    gettimeofday(&t1, NULL);
    srand(t1.tv_usec * t1.tv_sec);

    for (int i = 0; i < 20; ++i) {
        buffer[i] = value[rand() % 10];
	}
    //获取20byte的随机数据
    s = sdsempty();
    for (i = 0; i < 20; i++) {
        s = sdscatprintf(s, "%02X", buffer[i]);
    }

    return s;
}

static int
rd_lock_instance(redisContext *c, const char *resource,
                 const char *val, const int ttl)
{
    int xret = 0;
    redisReply *reply;

    reply = (redisReply *)redisCommand(c, "set %s %s px %d nx", resource, val, ttl);
    if (NULL == reply)
        goto finish;

    //printf("Set return: %s [null == fail, OK == success]\n", reply->str);

    if (reply->str && STRCMP(reply->str, "OK") == 0) {
        xret = 1;
    }
    freeReplyObject(reply);

finish:
    return xret;
}

static char **convertToSds(int count, char** args)
{
    int j;
    char **sds = (char**)malloc(sizeof(char*)*count);
    for(j = 0; j < count; j++)
        sds[j] = sdsnew(args[j]);
    return sds;
}

redisReply *rd_command_argv(redisContext *c, int argc, char **inargv)
{
    redisReply *reply = NULL;

    char **argv;
    argv = convertToSds(argc, inargv);

    size_t *argvlen;
    argvlen = (size_t *)malloc(argc * sizeof(size_t));

    for (int j = 0; j < argc; j++)
        argvlen[j] = sdslen(argv[j]);

    reply = (redisReply *)redisCommandArgv(c, argc, (const char **)argv, argvlen);
    if (reply) {
        //printf("RedisCommandArgv return: %lld\n", reply->integer);
    }
    free(argvlen);
    sdsfreesplitres(argv, argc);
    return reply;
}

int rd_mutex_unlock(struct rd_lock_scb *mtx, struct redisContext *c)
{
    int argc = 5;
    struct rd_RedLock *redlock = mutx_redlock();

    char *unlockScriptArgv[] = {(char*)"EVAL",
                                redlock->m_unlockScript,
                                (char*)"1",
                                (char*)mtx->m_resource,
                                (char*)mtx->m_val};

    redisReply *reply = rd_command_argv(c, argc, unlockScriptArgv);
    if (reply) {
        freeReplyObject(reply);
    }

    if (reply->integer){
        sdsfree(mtx->m_resource);
        sdsfree(mtx->m_val);
    }
    return 0;
}

/* redis lock*/
int rd_mutex_lock(const char *resource, const int ttl,
                 struct rd_lock_scb *mtx, struct redisContext *c)
{
    struct rd_RedLock *redlock = mutx_redlock();

    char *val = NULL;
    int retryCount =0, xret = 0;

    val = get_unique_lockid();
    if (!val) {
        return xret;
    }
    mtx->m_resource = sdsnew(resource);
    mtx->m_val = val;
    retryCount  = redlock->m_retryCount;

    do {
        int n = 0;
        int startTime = (int)time(NULL) * 1000;

        if (c == NULL || c->err) {
            goto finish;
        }

        if (rd_lock_instance(c, resource, val, ttl)) {
            n++;
        }

        int drift = (ttl * redlock->m_clockDriftFactor) + 2;
        int validityTime = ttl - ((int)time(NULL) * 1000 - startTime) - drift;
        //printf("The resource validty time is %d, n is %d\n",
        //       validityTime, n);

        if (n > 0 && validityTime > 0) {
            mtx->m_validityTime = validityTime;
            xret = 1;
            goto finish;
        } else {
            printf("The resource validty time is %d, n is %d\n",
               validityTime, n);
        }
        // Wait a random delay before to retry
        int delay = rand() % redlock->m_retryDelay + floor(redlock->m_retryDelay / 2);
        printf("[Test] delay = %d\n", delay);
        usleep(delay * 1000);
        retryCount--;
    } while (retryCount > 0);

finish:
    return xret;
}

void rd_lock_init()
{
    struct rd_RedLock *rdlock = mutx_redlock();

    rdlock->m_unlockScript       = sdsnew("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end");
    rdlock->m_retryCount = 3;
    rdlock->m_retryDelay = 10;
    rdlock->m_clockDriftFactor = 0.01;

    return;
}

