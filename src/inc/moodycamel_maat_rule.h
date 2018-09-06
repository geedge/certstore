/*************************************************************************
	> File Name: moodycamel_maat_rule.h
	> Author:
	> Mail:
	> Created Time: 2018年09月04日 星期二 16时55分54秒
 ************************************************************************/

#ifndef _MOODYCAMEL_MAAT_RULE_H
#define _MOODYCAMEL_MAAT_RULE_H

typedef	void*	Maat_feather_t;

enum MAAT_INIT_OPT
{
	MAAT_OPT_SCANDIR_INTERVAL_MS=1,	//VALUE is interger, SIZE=sizeof(int). DEFAULT:1,000 milliseconds.
	MAAT_OPT_EFFECT_INVERVAL_MS,	//VALUE is interger, SIZE=sizeof(int). DEFAULT:60,000 milliseconds.
	MAAT_OPT_FULL_CFG_DIR,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_INC_CFG_DIR,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_JSON_FILE_PATH,		//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1.DEFAULT: no default.
	MAAT_OPT_STAT_ON,				//VALUE is  NULL,SIZE is 0. MAAT_OPT_STAT_FILE_PATH must be set. Default: stat OFF.
	MAAT_OPT_PERF_ON,				//VALUE is NULL,SIZE is 0. MAAT_OPT_STAT_FILE_PATH must be set. Default: stat OFF.
	MAAT_OPT_STAT_FILE_PATH,		//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. DEFAULT: no default.
	MAAT_OPT_SCAN_DETAIL,			//VALUE is interger *, SIZE=sizeof(int). 0: not return any detail;1: return  hit pos, not include regex grouping;
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
	MAAT_OPT_ENABLE_UPDATE			//VALUE is interger, SIZE=sizeof(int). 1: Enabled, 0:Disabled.  DEFAULT: Backgroud update is enabled. Runtime setting is allowed.
};

enum MAAT_STATE_OPT
{
	MAAT_STATE_VERSION=1,			//Get current maat version. VALUE is long long, SIZE=sizeof(long long).
	MAAT_STATE_LAST_UPDATING_TABLE	//Query at Maat_finish_callback_t to determine whether this table is the last one to update. VALUE is interger, SIZE=sizeof(int), 1:yes, 0: no
};


typedef void Maat_start_callback_t(int update_type,void* u_para);
typedef void Maat_update_callback_t(int table_id,const char* table_line,void* u_para);
typedef void Maat_finish_callback_t(void* u_para);

Maat_feather_t Maat_inter_feather(int max_thread_num,const char* table_info_path,void* logger);

int Maat_inter_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size);

int Maat_inter_initiate_feather(Maat_feather_t feather);

int Maat_inter_table_register(Maat_feather_t feather,const char* table_name);

int Maat_inter_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,
									Maat_update_callback_t *update,
									Maat_finish_callback_t *finish,
									void* u_para);
int Maat_inter_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size);

void Maat_inter_burn_feather(Maat_feather_t feather);

#endif

