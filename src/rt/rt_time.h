#ifndef __RT_TM_H__
#define __RT_TM_H__

struct tm *rt_localtime(time_t timep, struct tm *result);
int rt_tms2str(uint64_t ts, const char *tm_form, char *date, size_t len);
int rt_curr_tms2str(const char *tm_form, char *date, size_t len);

u_int64_t rt_time_s(void);
u_int64_t rt_time_ms(void);
u_int64_t rt_time_ns();

#endif
