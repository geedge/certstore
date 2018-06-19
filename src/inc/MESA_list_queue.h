#ifndef _MESA_LIST_QUEUE_H_
#define _MESA_LIST_QUEUE_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
	MESA_list 第三版，
	1-增加线程安全特性;
	2-隐藏内部结构, 更安全、接口更简洁;
	3-调用者无需自行管理节点结构，使用更方便;
*/

#define MESA_LIST_QUEUE_VERSION_MACRO (20160308)
extern const unsigned int MESA_LIST_QUEUE_VERSION_INT;

#define MESA_LIST_OP_PLACE_HEAD		(0x1)
#define MESA_LIST_OP_PLACE_TAIL		(0x2)

#define MESA_list_GET					(0x1)
#define MESA_list_JOIN					(0x2)

#define MESA_list_BOLCK				(0x4)
#define MESA_list_NONBOLCK				(0x8)

#define MESA_list_JOIN_BLOCK			(MESA_list_JOIN|MESA_list_BOLCK)
#define MESA_list_JOIN_NONBLOCK		(MESA_list_JOIN|MESA_list_NONBOLCK)
#define MESA_list_GET_BLOCK			(MESA_list_GET|MESA_list_BOLCK)
#define MESA_list_GET_NONBLOCK			(MESA_list_GET|MESA_list_NONBOLCK)

typedef void * MESA_lqueue_head;
typedef int (* MESA_lqueue_cb_t)(void *data, long data_len, void *arg);

/* All of the following functions return value */
typedef enum{
	MESA_QUEUE_RET_OK 				=   0, /* success */
	MESA_QUEUE_RET_COMMON_ERR		= -1, /* general、undefined errors */
	MESA_QUEUE_RET_ARG_ERR			= -2, /* invalid args */
	MESA_QUEUE_RET_NUM_FULL 			= -3, /* queue number full */
	MESA_QUEUE_RET_MEM_FULL			= -4, /* queue memory full */
	MESA_QUEUE_RET_QEMPTY			= -5, /* queue empty */
	MESA_QUEUE_RET_LEN_ERR			= -6, /* length error */
	MESA_QUEUE_RET_CANT_GET_LOCK 	= -7, /* can't get lock in non-block mode */
	MESA_QUEUE_RET_GET_LOCK_TMOUT	= -8, /* get lock timeout */
}MESA_queue_errno_t;

/*
	args description:
	[IN]
    		thread_safe : 1:create thread safe queue; 0:without thread safe insurance.
    		max_item_num: maximum queue items of the queue, 0 means infinity.	     
*/
MESA_lqueue_head MESA_lqueue_create(int thread_safe, long max_item_num);

/* 
	attention:
	The follow two functions is get some value of queue in a moment,
	however, the value you got is not exactly,
	because it's maybe changed immediately by other thread when this functions is return.
*/
long MESA_lqueue_get_mem_used(MESA_lqueue_head head);
long MESA_lqueue_get_count(MESA_lqueue_head head);


/* 
	args description:
	[IN]:
		lq_head : the handler of MESA_lqueue.

	[OUT]:
		data	    : receive buffer.

	[IN && OUT]:
		data_len: 
			is value-result argument, like "addrlen of recvfrom(2)",
			the caller should initialize the size of the 'data', 
			will modified on return to indicate the actual size of the queue item.

*/
int MESA_lqueue_read_head(MESA_lqueue_head lq_head, void *data, long *data_len);
int MESA_lqueue_get_head(MESA_lqueue_head lqhead, void *data, long *data_len);

/*
    if return value of "cb" is 0, the behaviour is like MESA_lqueue_read_head(),
    else if return value of "cb" is not 0, the behaviour is like MESA_lqueue_get_head().
*/
int MESA_lqueue_detect_get_head(MESA_lqueue_head lq_head, MESA_lqueue_cb_t cb, void *data, long *data_len, void *cb_arg);
int MESA_lqueue_get_tail(MESA_lqueue_head lq_head, void *data, long *data_len);

int MESA_lqueue_join_head(MESA_lqueue_head lq_head, const void *data, long data_len);
int MESA_lqueue_join_tail(MESA_lqueue_head lq_head, const void *data, long data_len);


/* these functions features same with above no "try",
   except shall return immediately, in other word is "Non-block mode"! 
 */
int MESA_lqueue_try_read_head(MESA_lqueue_head lq_head, void *data, long *data_len);
int MESA_lqueue_try_get_head(MESA_lqueue_head lq_head, void *data, long *data_len);
int MESA_lqueue_try_get_tail(MESA_lqueue_head lq_head, void *data, long *data_len);
int MESA_lqueue_try_join_head(MESA_lqueue_head lq_head, const void *data, long data_len);
int MESA_lqueue_try_join_tail(MESA_lqueue_head lq_head, const void *data, long data_len);


void MESA_lqueue_destroy(MESA_lqueue_head head, MESA_lqueue_cb_t cb, void *cb_arg);

const char *MESA_lqueue_strerror(MESA_queue_errno_t error_num);

#ifdef __cplusplus
}
#endif

#endif

