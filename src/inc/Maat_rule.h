
/*
*****************Maat Network Flow Rule Manage Framework********
*	Maat is the Goddess of truth and justice in ancient Egyptian concept.
*	Her feather was the measure that determined whether the souls (considered 
*	to reside in the heart) of the departed would reach the paradise of afterlife
*	successfully.
*	Author: zhengchao@iie.ac.cn,MESA
*	Version 2018-09-25 foreign key and rule tags.
*	NOTE: MUST compile with G++
*	All right reserved by Institute of Infomation Engineering,Chinese Academic of Science 2014~2018
*********************************************************
*/
#ifndef H_MAAT_RULE_H_INCLUDE
#define H_MAAT_RULE_H_INCLUDE
#ifndef __cplusplus
#error("This file should be compiled with C++ compiler")
#endif
#include "stream.h"
enum MAAT_CHARSET
{
	CHARSET_NONE=0,
	CHARSET_GBK,
	CHARSET_BIG5,
	CHARSET_UNICODE,
	CHARSET_UTF8,	// 4
	CHARSET_BIN,	//5
	CHARSET_UNICODE_ASCII_ESC,		// Unicode Escape format, prefix backslash-u hex, e.g. "\u627;"
	CHARSET_UNICODE_ASCII_ALIGNED,//Unicode Escape format, prefix backslash-u with 4 bytes aligned, e.g. "\u0627"
	CHARSET_UNICODE_NCR_DEC,		//SGML Numeric character reference,decimal base, e.g. "&#1575;"
	CHARSET_UNICODE_NCR_HEX,		//SGML Numeric character reference,hexdecimal base, e.g. "&#x627;"
	CHARSET_URL_ENCODE_GB2312,		//URL encode with GB2312, e.g. the chinese word "china" was encoded to %D6%D0%B9%FA
	CHARSET_URL_ENCODE_UTF8		//11, URL encode with UTF8,e.g. the chinese word "china" was encoded to %E4%B8%AD%E5%9B%BD
};
enum MAAT_ACTION
{
	MAAT_ACTION_BLOCK=0,
	MAAT_ACTION_MONIT,
	MAAT_ACTION_WHITE
};
enum MAAT_POS_TYPE
{
	MAAT_POSTYPE_EXPR=0,
	MAAT_POSTYPE_REGEX
};
typedef	void*	scan_status_t;
typedef	void*	stream_para_t;
typedef	void*	Maat_feather_t;


#define	MAX_SERVICE_DEFINE_LEN			128
#define	MAX_HUGE_SERVICE_DEFINE_LEN		(1024*4)
struct Maat_rule_t
{
	int		config_id;
	int		service_id;
	char	do_log;
	char 	do_blacklist;
	char	action;
	char	reserved;
	int		serv_def_len;
	char 	service_defined[MAX_SERVICE_DEFINE_LEN];
};
#define	MAAT_RULE_UPDATE_TYPE_FULL	1
#define	MAAT_RULE_UPDATE_TYPE_INC	2
typedef void Maat_start_callback_t(int update_type,void* u_para);
typedef void Maat_update_callback_t(int table_id,const char* table_line,void* u_para);
typedef void Maat_finish_callback_t(void* u_para);





//--------------------HITTING DETAIL DESCRIPTION BEGIN

#define	MAAT_MAX_HIT_RULE_NUM		8
#define MAAT_MAX_EXPR_ITEM_NUM		8
#define	MAAT_MAX_HIT_POS_NUM		8
#define	MAAT_MAX_REGEX_GROUP_NUM	8

//NOTE position buffer as hitting_regex_pos and hit_pos,are ONLY valid before next scan or Maat_stream_scan_string_end
struct regex_pos_t
{
	int group_num;
	int hitting_regex_len;
	const char* hitting_regex_pos;
	int grouping_len[MAAT_MAX_REGEX_GROUP_NUM];
	const char* grouping_pos[MAAT_MAX_REGEX_GROUP_NUM];
};
struct str_pos_t
{
	int hit_len;
	const char* hit_pos;
};
struct sub_item_pos_t
{
	enum MAAT_POS_TYPE ruletype;
	int hit_cnt;
	union
	{
		struct regex_pos_t	regex_pos[MAAT_MAX_HIT_POS_NUM];
		struct str_pos_t substr_pos[MAAT_MAX_HIT_POS_NUM];
	};
};

struct Maat_region_pos_t
{
	
	int region_id;
	int sub_item_num;
	struct sub_item_pos_t sub_item_pos[MAAT_MAX_EXPR_ITEM_NUM];	
};

struct Maat_hit_detail_t
{
	int config_id;//set <0 if half hit;
	int hit_region_cnt;
	struct Maat_region_pos_t region_pos[MAAT_MAX_HIT_RULE_NUM];	
};
//--------------------HITTING DETAIL DESCRIPTION END

//Abondon interface ,left for compatible.
Maat_feather_t Maat_summon_feather(int max_thread_num,
								const char* table_info_path,
								const char* ful_cfg_dir,
								const char* inc_cfg_dir,
								void*logger);//MESA_handle_logger
//Abondon interface ,left for compatible. 
Maat_feather_t Maat_summon_feather_json(int max_thread_num,
									const char* table_info_path,
									const char* json_rule,
									void* logger);

Maat_feather_t Maat_feather(int max_thread_num,const char* table_info_path,void* logger);
int Maat_initiate_feather(Maat_feather_t feather);

enum MAAT_INIT_OPT
{
	MAAT_OPT_SCANDIR_INTERVAL_MS=1,	//VALUE is interger, SIZE=sizeof(int). DEFAULT:1,000 milliseconds.
	MAAT_OPT_EFFECT_INVERVAL_MS,	//VALUE is interger, SIZE=sizeof(int). DEFAULT:60,000 milliseconds.
	MAAT_OPT_FULL_CFG_DIR,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_INC_CFG_DIR,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_JSON_FILE_PATH,		//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_STAT_ON,				//VALUE is NULL, SIZE is 0. MAAT_OPT_STAT_FILE_PATH must be set. Default: stat OFF.
	MAAT_OPT_PERF_ON,				//VALUE is NULL, SIZE is 0. MAAT_OPT_STAT_FILE_PATH must be set. Default: stat OFF.
	MAAT_OPT_STAT_FILE_PATH,		//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. DEFAULT: no default.
	MAAT_OPT_SCAN_DETAIL,			//VALUE is interger *, SIZE=sizeof(int). 0: not return any detail;1: return  hit pos, not include regex grouping.
									//  2 return hit pos and regex grouping pos;DEFAULT:0
	MAAT_OPT_INSTANCE_NAME,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1, no more than 11 bytes.DEFAULT: MAAT_$tableinfo_path$.
	MAAT_OPT_DECRYPT_KEY,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. No DEFAULT.
	MAAT_OPT_REDIS_IP,				//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. No DEFAULT.
	MAAT_OPT_REDIS_PORT,			//VALUE is a unsigned short or a signed int, host order, SIZE= sizeof(unsigned short) or sizeof(int). No DEFAULT.
	MAAT_OPT_REDIS_INDEX,			//VALUE is interger *, 0~15, SIZE=sizeof(int). DEFAULT: 0.
	MAAT_OPT_CMD_AUTO_NUMBERING,	//VALUE is a interger *, 1 or 0, SIZE=sizeof(int). DEFAULT: 1.
	MAAT_OPT_DEFERRED_LOAD,			//VALUE is NULL,SIZE is 0.  Default: Deffered initialization OFF.
	MAAT_OPT_CUMULATIVE_UPDATE_OFF,	//VALUE is NULL,SIZE is 0.  Default: CUMMULATIVE UPDATE ON.
	MAAT_OPT_LOAD_VERSION_FROM,		//VALUE is a long long, SIZE=sizeof(long long). Default: Load the Latest. Only valid in redis mode, and maybe failed for too old. 
									//This option also disables background update.
	MAAT_OPT_ENABLE_UPDATE,			//VALUE is interger, SIZE=sizeof(int). 1: Enabled, 0:Disabled.  DEFAULT: Backgroud update is enabled. Runtime setting is allowed.
	MAAT_OPT_ACCEPT_TAGS,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. Format is a JSON, e.g.{"tags":[{"tag":"location","value":"Beijing/ChaoYang/Huayan/22A"},{"tag":"isp","value":"telecom"}]}
	MAAT_OPT_FOREIGN_CONT_DIR,		//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. Specifies a local diretory to store foreign content. Default: []table_info_path]_files
 	MAAT_OPT_FOREIGN_CONT_LINGER		//VALUE is interger *, SIZE=sizeof(int). Greater than 0: delete after VALUE seconds; 0: delete foreign content right after the notification callbacks;  Less than 0: NEVER delete. Default: 0.
 };
//return -1 if failed, return 0 on success;
int Maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size);
enum MAAT_STATE_OPT
{
	MAAT_STATE_VERSION=1,			//Get current maat version. VALUE is long long, SIZE=sizeof(long long). 
	MAAT_STATE_LAST_UPDATING_TABLE	//Query at Maat_finish_callback_t to determine whether this table is the last one to update. VALUE is interger, SIZE=sizeof(int), 1:yes, 0: no
};
int Maat_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size);

void Maat_burn_feather(Maat_feather_t feather);

//return table_id(>=0) if success,otherwise return -1;
int Maat_table_register(Maat_feather_t feather,const char* table_name);
//return 1 if success,otherwise return -1 incase invalid table_id or registed function number exceed 32;
int Maat_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,//MAAT_RULE_UPDATE_TYPE_*,u_para
									Maat_update_callback_t *update,//table line ,u_para
									Maat_finish_callback_t *finish,//u_para
									void* u_para);

enum MAAT_SCAN_OPT
{
	MAAT_SET_SCAN_DISTRICT=1,		//VALUE is a const char*,SIZE= strlen(string).DEFAULT: no default.
	MAAT_SET_SCAN_LAST_REGION		//VALUE is NULL, SIZE=0. This option indicates that the follow scan is the last region of current scan cobination.
};
//return 0 if success, return -1 when failed;
int Maat_set_scan_status(Maat_feather_t feather,scan_status_t* mid,enum MAAT_SCAN_OPT type,const void* value,int size);

//Return hit rule number, return -1 when error occurs,return -2 when hit current region
//mid MUST set to NULL before fist call
int Maat_scan_intval(Maat_feather_t feather,int table_id
						,unsigned int intval
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num);
int Maat_scan_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num);
int Maat_scan_proto_addr(Maat_feather_t feather,int table_id
						,struct ipaddr* addr,unsigned short int proto
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t *mid,int thread_num);
int Maat_full_scan_string(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int* found_pos,int rule_num
						,scan_status_t* mid,int thread_num);
//hite_detail could be NULL if unconcern
int Maat_full_scan_string_detail(Maat_feather_t feather,int table_id
						,enum MAAT_CHARSET charset,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
						,int* detail_ret,scan_status_t* mid,int thread_num);

stream_para_t Maat_stream_scan_string_start(Maat_feather_t feather,int table_id,int thread_num);
int Maat_stream_scan_string(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int* found_pos,int rule_num
									,scan_status_t* mid);
//hited_detail could be NULL if unconcern
int Maat_stream_scan_string_detail(stream_para_t* stream_para
									,enum MAAT_CHARSET charset,const char* data,int data_len
									,struct Maat_rule_t*result,int rule_num,struct Maat_hit_detail_t *hit_detail,int detail_num
									,int* detail_ret,scan_status_t* mid);
void Maat_stream_scan_string_end(stream_para_t* stream_para);

stream_para_t Maat_stream_scan_digest_start(Maat_feather_t feather,int table_id,unsigned long long total_len,int thread_num);
int Maat_stream_scan_digest(stream_para_t* stream_para
									,const char* data,int data_len,unsigned long long offset
									,struct Maat_rule_t*result,int rule_num
									,scan_status_t* mid);
void Maat_stream_scan_digest_end(stream_para_t* stream_para);

int Maat_similar_scan_string(Maat_feather_t feather,int table_id
						,const char* data,int data_len
						,struct Maat_rule_t*result,int rule_num
						,scan_status_t* mid,int thread_num);

void Maat_clean_status(scan_status_t* mid);
enum MAAT_RULE_OPT
{
	MAAT_RULE_SERV_DEFINE	//VALUE is a char* buffer,SIZE= buffer size. 
};
int Maat_read_rule(Maat_feather_t feather, const struct Maat_rule_t* rule, enum MAAT_RULE_OPT type, void* value, int size);
#endif	//	H_MAAT_RULE_H_INCLUDE

