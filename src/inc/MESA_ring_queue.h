#ifndef __MESA_RING_QUEUE_H_
#define __MESA_RING_QUEUE_H_ 1

#ifdef __cplusplus
extern "C"
{
#endif

typedef void * MESA_ring_queue_head;

#define MESA_RING_QUEUE_VERSION_MACRO		(20160708)
extern const unsigned int MESA_RING_QUEUE_VERSION_INT;

/* All of the following functions return value */
typedef enum{
	MESA_RQUEUE_RET_OK 				=  0, /* success */
	MESA_RQUEUE_RET_COMMON_ERR		= -1, /* general、undefined errors */
	MESA_RQUEUE_RET_ARG_ERR			= -2, /* invalid args */
	MESA_RQUEUE_RET_NUM_FULL 		= -3, /* queue number full */
	MESA_RQUEUE_RET_MEM_FULL		= -4, /* queue memory full */
	MESA_RQUEUE_RET_QEMPTY			= -5, /* queue empty */
	MESA_RQUEUE_RET_LEN_ERR			= -6, /* length error */
	MESA_RQUEUE_RET_CANT_GET_LOCK 	= -7, /* can't get lock in non-block mode */
	MESA_RQUEUE_RET_GET_LOCK_TMOUT	= -8, /* get lock timeout */
}MESA_ring_queue_errno_t;


/*
	args description:
	[IN]
    		thread_safe : 1:create thread safe queue; 0:without thread safe insurance.
    		max_item_num: maximum queue items of the queue, must more than zero.	     
*/
MESA_ring_queue_head MESA_ring_queue_born(void);


enum MESA_rq_opt{
	RQO_THREAD_SAFE = 0, /* must be int, 1:create ring qqueue with thread safe features, default is 1 */ 
	RQO_RING_ELEMENT_NUM,	/* must be unsigned int, defalut is 1000. */
	RQO_PRE_ALLOC_BUF_LEN,    /* must be unsigned int, 预先分配每个item的内存, 以后只用memcpy */
	RQO_MULTI_THREAD_LOCK_FREE, /* must be int, default is 0, conflict with RQO_THREAD_SAFE */
};

/*
	to set features of specified MESA_ring_queue_headhandle.
		opt_type: option type, refer to enum MESA_htable_opt;
		opt_val : option value, depend on opt type;
		opt_len : opt_val size, depend on opt type;
	
	return value:
		0 :success;
		<0:error;
*/
int MESA_ring_queue_set_opt(MESA_ring_queue_head rq, enum MESA_rq_opt opt_type, void *opt_val, int opt_len);


/*
	Construct ring queue and ready to running.

	return value:
		0 : success;
		<0: error.
*/
int MESA_ring_queue_mature(MESA_ring_queue_head rq);



int MESA_ring_queue_get_count(MESA_ring_queue_head head);

/* 
	args description:
	[IN]:
		lq_head : the handler of MESA_ring_queue.

	[OUT]:
		data	    : receive buffer.

	[IN && OUT]:
		data_len: 
			is value-result argument, like "addrlen of recvfrom(2)",
			the caller should initialize the size of the 'data', 
			will modified on return to indicate the actual size of the queue item.

*/
int MESA_ring_queue_read(MESA_ring_queue_head rq_head, void *data, int *data_len);
int MESA_ring_queue_get(MESA_ring_queue_head rqhead, void *data, int *data_len);
int MESA_ring_queue_join(MESA_ring_queue_head rq_head, const void *data, int data_len);


/* these functions features same with above no "try",
   except shall return immediately, in other word is "Non-block mode"! 
 */
int MESA_ring_queue_try_read(MESA_ring_queue_head rq_head, void *data, int *data_len);
int MESA_ring_queue_try_get(MESA_ring_queue_head rqhead, void *data, int *data_len);
int MESA_ring_queue_try_join(MESA_ring_queue_head rq_head, const void *data, int data_len);


typedef int (* MESA_rqueue_cb_t)(void *data, long data_len, void *arg);
void MESA_ring_queue_destroy(MESA_ring_queue_head rq_head, MESA_rqueue_cb_t cb, void *cb_arg);
const char *MESA_ring_queue_strerror(MESA_ring_queue_errno_t error_num);

#ifdef __cplusplus
}
#endif

#endif

