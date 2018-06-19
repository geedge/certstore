/*
*   rt_time.c
*   Created by fengweihao
*   30 May, 2018
*   Func: Time Component
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include "rt_time.h"

struct tm *rt_localtime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

uint64_t rt_time_s(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec  + tv.tv_usec/1000/1000);    /** CST timestamp */
};

uint64_t rt_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000  + tv.tv_usec/1000);
}

uint64_t rt_time_ns()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 * 1000   + tv.tv_usec);
}

int rt_tms2str(uint64_t ts, const char *tm_form, char *date, size_t len)
{
    struct tm *tm = NULL;

    assert(date);
    /** Convert ts to localtime with local time-zone */
    tm = localtime((time_t *)&ts);
    return (int)strftime(date, len - 1, tm_form, tm);
}

int rt_curr_tms2str(const char *tm_form, char *date, size_t len)
{
    return rt_tms2str(time(NULL), tm_form, date, len);
}

