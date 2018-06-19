#ifndef __MESA_HTABLE_H_
#define __MESA_HTABLE_H_
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

/*
 * general purpose hash table implementation.
 *
 * xiang hong
 * 2002-07-28
 *History:
 * 2012-03-23 zhengchao add thread safe option and link expire feature;
 * 2014-01-27 lijia add reentrant feature.
 */
#define MESA_HTABLE_VERSION_MACRO	(20170104)
extern const unsigned int MESA_HTABLE_VERSION_INT;

#define MESA_HASH_DEBUG			(0)

#define COMPLEX_KEY_SWITCH		(1)

#define ELIMINATE_TYPE_NUM			(1)
#define ELIMINATE_TYPE_TIME			(2)
#define ELIMINATE_TYPE_MANUAL		(3) /* delete oldest item by manual */

typedef void * MESA_htable_handle;


#define HASH_MALLOC(_n_)		malloc(_n_)
#define HASH_FREE(_p_)			free(_p_)


#ifndef uchar
#define uchar	unsigned char
#endif
#ifndef uint
#define uint	unsigned int
#endif

/* eliminate algorithm */
#define HASH_ELIMINATE_ALGO_FIFO		(0) /* by default */
#define HASH_ELIMINATE_ALGO_LRU		(1)

/*
 * hash key compare function prototype, see hash_key_comp().
 * return value:
 *      0:key1 and key2 are equal;
 *  other:key1 and key2 not equal. 
 */
typedef int key_comp_fun_t(const uchar * key1, uint size1, const uchar * key2, uint size2);

/*
 * hash key->index computing function prototype, see hash_key2index().
 */
typedef uint key2index_fun_t(const MESA_htable_handle table, const uchar * key, uint size);

typedef void MESA_htable_data_free_cbfun_t(void *data);

typedef int MESA_htable_expire_notify_cbfun_t(void *data, int eliminate_type);

typedef uchar* MESA_htable_complex_key_dup_cbfun_t(const uchar *key, uint key_size);

typedef void MESA_htable_complex_key_free_cbfun_t(uchar *key, uint key_size);

typedef long hash_cb_fun_t(void *data, const uchar *key, uint size, void *user_arg);

/*
 *	thread_safe: 0:create hash table without thread safe features; 
 *                positive:the bigger number has more performance, less collide, but less timeout accuracy.
 *                         max number is 1024.
 *   recursive: 0:can't recursive call MESA_htable_xxx series function
 *			  1:can recursive call MESA_htable_xxx series function.
 * 	hash_slot_size: how big do you want the table to be, must be 2^N;
 *   max_elem_num: the maximum elements of the HASH-table,0 means infinite;
 * 	key_comp: hash key compare function, use default function if NULL;
 *			suggest implement by yourself.
 *  key2index: hash key->index computing function, use default function if NULL;
 *			suggest use MESA_htable built-in function.
 *  data_free: release resources function;
 *  data_expire_with_condition: 
 *		if expire_time > 0 and data_expire_with_condition != NULL, 
 *			then call this function when an element expired, and give the reason by the 'type' 
 *		if expire_time > 0 and	data_expire_with_condition is NULL, 
 *			eliminate the item immediately;
 *				args:
 *					data: pointer to attached data;
 *					type: item eliminate reason, ELIMINATE_TYPE_NUM or ELIMINATE_TYPE_TIME;
 *				return value of 'data_expire_with_condition':
 *					1: the item can be eliminated;
 *					0: the item can't be eliminated, renew the item.
 *  eliminate_type: the algorithm of elimanate a expired element, 0:FIFO; 1:LRU.
 *  expire_time: the element expire time in second, 0 means infinite.
 */
typedef struct{
	unsigned int thread_safe;
	int recursive;
	unsigned int hash_slot_size;
	unsigned int max_elem_num;
	int eliminate_type;
	int expire_time;
	key_comp_fun_t * key_comp; 
	key2index_fun_t * key2index;
	void (* data_free)(void *data);
	int (*data_expire_with_condition)(void *data, int eliminate_type);
#if COMPLEX_KEY_SWITCH	
	uchar* (*complex_key_dup)(const uchar *key, uint key_size);
	void (* complex_key_free)(uchar *key, uint key_size);
#endif	
}MESA_htable_create_args_t;


/* All of the following functions return value */
typedef enum{
	MESA_HTABLE_RET_OK 				=  0, /* success */
	MESA_HTABLE_RET_COMMON_ERR		= -1, /* general、undefined errors */
	MESA_HTABLE_RET_ARG_ERR			= -2, /* invalid args */
	MESA_HTABLE_RET_NUM_FULL 		= -3, /* htable number full */
	MESA_HTABLE_RET_QEMPTY			= -4, /* htable empty */
	MESA_HTABLE_RET_DUP_ITEM			= -5, /* duplicate item */
	MESA_HTABLE_RET_NOT_FOUND		= -6, /* not found item */
	MESA_HTABLE_RET_LEN_ERR			= -7, /* length error */
	MESA_HTABLE_RET_CANT_GET_LOCK 	= -8, /* can't get lock in non-block mode */
	MESA_HTABLE_RET_GET_LOCK_TMOUT	= -9, /* get lock timeout */
}MESA_htable_errno_t;

/*
 * You should never use this API to create a hash table, use MESA_htable_born() instead.
 * name: MESA_htable_create
 *	functionality: allocats memory for hash slots, and initialize hash structure;
 * param:
 *	args: argments set;
 *	args_len: length of argment set;
 * returns:
 * 	NULL 	: error;
 * 	Non-NULL : success;
 */
MESA_htable_handle MESA_htable_create(const MESA_htable_create_args_t *args, int args_struct_len);

/*
 * get total number of HASH element.
*/
unsigned int MESA_htable_get_elem_num(const MESA_htable_handle table);

/*
 * name: MESA_htable_destroy
 * functionality: cleans up hash structure, frees memory occupied;
 * param:
 * 	table: who is the victim;
 * 	func: callback function to clean up data attached to hash items, has higher priority level than MESA_htable_data_free_cbfun_t in initialization.

 * returns:
 * 	always returns 0;
 */
int MESA_htable_destroy(MESA_htable_handle table, void (* func)(void *));

/*
 * name: MESA_htable_add
 * functionality: adds item to table, call hash_expire() if elem_count gets
 * 	bigger than threshold_hi, and adjust threshold;
 * param:
 * 	table: to which table do you want to add;
 * 	key: what is the label;
 * 	size: how long is the label;
 * 	data: what data do you want to attach;
 * returns:
 *	>0: success,return hash elems' linklist size;
 *	 0: success.
 *   <0: error, refer to MESA_htable_errno_t.
 */
int MESA_htable_add(MESA_htable_handle table, const uchar * key, uint size, const void *data);

/*
	TODO,
	sturct hash_status{
		uint hlist_max;
		uint hlist_max_slot_index;
		uint cur_index_hlist_num;
		uint hash_value;
	};

	新增MESA_htable_add_feedback(MESA_htable_handle table, const uchar * key, uint size, const void *data, sturct hash_status *hstat);
	用于返回HASH表的一些关键信息,
	
*/

#if 0
/*
 * name: hash_add_with_expire
 * functionality: adds item to table, than call hash_expire() on its list
 * param:
 * 	table: to which table do you want to add;
 * 	key: what is the label;
 * 	size: how long is the label;
 * 	data: what data do you want to attach;
 * returns:
 *	>0 success,return hash elems' linklist size
 * 	-1, duplicates found and can't add this one;
 * 	-2, memory failure;
 */
int MESA_hash_add_with_expire_v3(MESA_htable_inner_t * table, uchar * key, uint size, void * data);

#endif


/*
 * name: MESA_htable_del
 * functionality: deletes item from table.
 * param:
 * 	table: from which table do you want to delete;
 * 	key  : what is the label;
 * 	size : how long is the label;
 * 	func : callback function to clean up data attached to hash items,
 	       if this pointer is NULL will call "data_free" in MESA_hash_create(),
 * returns:
 * 	0 : success;
 * 	<0: error, refer to MESA_htable_errno_t.
 */
int MESA_htable_del(MESA_htable_handle table, const uchar * key, uint size,
                                void (* func)(void *));
/*
	TODO:
	新增MESA_htable_del_with_hash(MESA_htable_handle table, const uchar * key, uint size, uint hash_value,
                                void (* func)(void *));
	删除时带入之前的hash_value, 减少一次hash计算开销, 
*/


/*
 * name: MESA_htable_del_oldest_manual
 * functionality: deletes oldest item from table.
 * param:
 * 	table: from which table do you want to delete;
 * 	func : callback function to clean up data attached to hash items,
 	       if this pointer is NULL will call "data_free" in MESA_hash_create(),
 *   batch_num: delete oldest items.      
 * returns:
 * 	0, do nothing ;
 * 	>0, delete items;
 */
int MESA_htable_del_oldest_manual(MESA_htable_handle table, void (* func)(void *), int batch_num);
                                
/*
 * name: MESA_htable_search
 * functionality: selects item from table;
 * param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *MESA_htable_search(const MESA_htable_handle table, const uchar * key, uint size);

/*
 * name: MESA_htable_search_cb
 * functionality: selects item from table, and then call 'cb', reentrant;
 * in param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *  cb   : call this function when found the attached data;
 *  arg  : the argument of "cb" function.
 * out param:
 *  cb_ret: the return value of the function "cb".
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *MESA_htable_search_cb(const MESA_htable_handle table, const uchar * key, uint size,
                                                  hash_cb_fun_t *cb, void *arg, long *cb_ret);

/*
 * name: MESA_htable_iterate
 * functionality: iterates each hash item;
 * params:
 * 	table: what table is to be iterated;
 * 	func: what do you want to do to each attached data item;
 * returns:
 * 	0: iterates all items;
 * -1: error;
 */
int MESA_htable_iterate(MESA_htable_handle table, 
			void (* func)(const uchar * key, uint size, void * data, void *user), void * user);


/*
 * name: MESA_htable_iterate_bytime
 * functionality: iterates each hash item by your demand;
 *				note:
 *				if 'thread_safe' more than one, this function is not correct.
 * params:
 * 	table: what table is to be iterated;
 *	iterate_type: 1: newest item first; 2: oldest item first;
 * 	iterate_cb: what do you want to do to each attached data item;
 *			return value of iterate_cb:
 *				 refer to ITERATE_CB_RET_xxx;
 * returns:
 * 	0: iterates all items;
 *	-1: uncomplete break.
 *   -2: error;
 */
#define ITERATE_CB_RET_CONTINUE_FLAG			(0) 	    /* default, like MESA_htable_iterate() */ 
#define ITERATE_CB_RET_BREAK_FLAG				(1<<1) /* break iterate, return from MESA_htable_iterate_bytime() immediately */
#define ITERATE_CB_RET_DEL_FLAG				(1<<2) /* del this item, like but faster than call MESA_htable_del() */
#define ITERATE_CB_RET_REVERSE_FLAG			(1<<3) /* if the item is newest item, it will become the oldest item, and vice versa */
#define ITERATE_CB_RET_REMOVE_BUT_NOT_FREE	(1<<4) /* only remove the item from Hash table, but don't free the attached data, be careful */

#define ITERATE_TYPE_NEWEST_FIRST					(1)
#define ITERATE_TYPE_OLDEST_FIRST					(2)
int MESA_htable_iterate_bytime(MESA_htable_handle table, int iterate_type,
		int (*iterate_cb)(const uchar * key, uint size, void * data, void *user), void * user);

/* 
	args:
		print_switch:
			0: disable print message;
			1: enable  print message;
*/
void MESA_htable_print_crtl(MESA_htable_handle table, int print_switch);


/*
	Create a htable handle and Alloc memory, and set default option,
	but can't running before call MESA_htable_mature().
	
	return value:
		not NULL: success.
		NULL    : error.
*/
MESA_htable_handle MESA_htable_born(void);

/* 
	MESA_htable option definition.
*/
enum MESA_htable_opt{
	MHO_THREAD_SAFE = 0, /* must be int, 1:create hash table with thread safe features, default is 0 */ 
	MHO_MUTEX_NUM,	/* must be int, valid only if MHO_THREAD_SAFE is not zero, max value is 1024, defalut is 1. the bigger number has more performance and less mutex collide, but less timeout accuracy */
	MHO_HASH_SLOT_SIZE, /* must be unsigned int, default is 1048576. */
	MHO_HASH_MAX_ELEMENT_NUM, /* must be unsigned int, defalut is 0, means infinite */
	MHO_EXPIRE_TIME, /* must be int, defalut is 0, means infinite */
	MHO_ELIMIMINATE_TYPE, /* must be int, valid only if MHO_EXPIRE_TIME is not zero. HASH_ELIMINATE_ALGO_FIFO or HASH_ELIMINATE_ALGO_LRU, defalut HASH_ELIMINATE_ALGO_FIFO */
	MHO_CBFUN_KEY_COMPARE, /* must be key_comp_fun_t, hash key compare function, use default function if NULL */ 
	MHO_CBFUN_KEY_TO_INDEX, /* must be key2index_fun_t, hash key->index computing function, use default function if NULL */
	MHO_CBFUN_DATA_FREE, /* must be MESA_htable_data_free_cbfun_t, release resources function */
	/*  data_expire_notify, must be MESA_htable_expire_notify_cbfun_t, 
	 *		if expire_time > 0 and data_expire_notify != NULL, 
	 *			then call this function when an element expired, and give the reason by the 'type' 
	 *		if expire_time > 0 and	data_expire_notify is NULL, 
	 *			eliminate the item immediately;
	 *				args:
	 *					data: pointer to attached data;
	 *					type: item eliminate reason, ELIMINATE_TYPE_NUM or ELIMINATE_TYPE_TIME;
	 *				return value of 'data_expire_with_condition':
	 *					1: the item can be eliminated;
	 *					0: the item can't be eliminated, renew the item.
	 */
 	MHO_CBFUN_DATA_EXPIRE_NOTIFY,
 	MHO_CBFUN_COMPLEX_KEY_DUP,  /* must be MESA_htable_complex_key_dup_cbfun_t, if key store in a complex struct, caller must be implement this duplicate function.  */
 	MHO_CBFUN_COMPLEX_KEY_FREE,  /* must be MESA_htable_complex_key_free_cbfun_t, if key store in a complex struct, caller must be implement this duplicate function.  */
	MHO_AUTO_UPDATE_TIME, /* must be int, create a background thread used to update current_time instead of time(NULL). 1:enable; 0:disable; default value is 0; */
	MHO_SCREEN_PRINT_CTRL, /* must be int, 1:enable screen print; 0:disable screen print; default is 1. */
	MHO_HASH_LIST_COLLIDE_THRESHOLD, /* must be int, write log when hash collide number more than this, default is 100, 0 means infinite. */
	MHO_HASH_LOG_FILE, /* must be char * with EOF, default is "./hash_list_collide.log", opt_len is strlen(optval) */
	MHO_HASH_SEARCH_MAX_TIMES, /* must be int, max compare items in once MESA_htable_search()  */
	MHO_HASH_SEARCH_AVG_TIMES,  /* must be double, average compare items in all previous MESA_htable_search()  */
	__MHO_MAX_VAL, /* caller can't use this definition, it's value maybe changed in next version!! */
};


/*
	to set features of specified MESA_htable handle.
		opt_type: option type, refer to enum MESA_htable_opt;
		opt_val : option value, depend on opt type;
		opt_len : opt_val size, depend on opt type;
	
	return value:
		0 :success;
		<0:error;
*/
int MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, void *opt_val, int opt_len);

/*
	to get features of specified MESA_htable handle.
		opt_type: option type, refer to enum MESA_htable_opt;
		opt_val : option value, depend on opt type;
		opt_len : value-result argument, opt_val size, depend on opt type;
	
	return value:
		0 :success;
		<0:error;
*/
int MESA_htable_get_opt(MESA_htable_handle api_table, enum MESA_htable_opt opt_type, void *opt_val, int *opt_len);

/*
	Construct htable and ready to running.

	return value:
		0 : success;
		<0: error.
*/
int MESA_htable_mature(MESA_htable_handle table);


#ifdef __cplusplus
}
#endif

#endif	/* _LIB_HASH_H_INCLUDED_ */


