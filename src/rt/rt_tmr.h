/*************************************************************************
	> File Name: rt_tmr.h
	> Author:
	> Mail:
	> Created Time: 2018年09月19日 星期三 15时58分04秒
 ************************************************************************/

#ifndef _RT_TMR_H
#define _RT_TMR_H

#define RT_TMR_ADVANCED

extern void tmr_start(uint32_t uid);
extern void tmr_stop(uint32_t uid);

/**
* routine: must be a reentrant function.
* An unknown error ocurrs if a thread-safe function called as a routione.
*/
extern uint32_t tmr_create(int module,
                const char *desc,
                void (*routine)(uint32_t, int, char **), int argc, char **argv, int sec);

#endif

