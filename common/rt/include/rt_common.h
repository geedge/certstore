#ifndef __RT_COMMON_H__
#define __RT_COMMON_H__

#include <assert.h>
#define EVAL_TM_STYLE   "%Y-%m-%d"

/** Alway treated the expr as true */
#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif

/** Alway treated the expr as false */
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#define	__rt_always_inline__	__attribute__((always_inline)) inline

#define CHECK_OR_EXIT(condition, fmt, ...)                                                                          \
do { if(!(condition)) { mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, fmt, ##__VA_ARGS__); exit(EXIT_FAILURE);   }  } while(0) \


#endif
