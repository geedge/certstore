/*************************************************************************
	> File Name: moodycamel_maat_rule.cpp
	> Author:
	> Mail:
	> Created Time: 2018年09月04日 星期二 16时56分42秒
 ************************************************************************/

#include<iostream>

using namespace std;

#include <Maat_rule.h>

extern "C" Maat_feather_t maat_feather(int max_thread_num,const char* table_info_path,void* logger);
extern "C" int maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size);
extern "C" int maat_initiate_feather(Maat_feather_t feather);
extern "C" int maat_table_register(Maat_feather_t feather,const char* table_name);
extern "C" void matt_burn_feather(Maat_feather_t feather);
extern "C" int maat_inter_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,
									Maat_update_callback_t *update,
									Maat_finish_callback_t *finish,
									void* u_para);
extern "C" int maat_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size);

extern "C" MAAT_PLUGIN_EX_DATA maat_plugin_get_EX_data(Maat_feather_t feather, int table_id, const char* key);

extern "C" int maat_plugin_EX_register(Maat_feather_t feather, int table_id,
							Maat_plugin_EX_new_func_t* new_func,
							Maat_plugin_EX_free_func_t* free_func,
							Maat_plugin_EX_dup_func_t* dup_func,
							Maat_plugin_EX_key2index_func_t* key2index_func,
							long argl, void *argp);

Maat_feather_t maat_feather(int max_thread_num,const char* table_info_path,void* logger)
{
	return Maat_feather(max_thread_num, table_info_path, logger);
}

int maat_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size)
{
	return Maat_set_feather_opt(feather, type, value, size);
}

int maat_initiate_feather(Maat_feather_t feather)
{
	return Maat_initiate_feather(feather);
}

int maat_table_register(Maat_feather_t feather,const char* table_name)
{
	return Maat_table_register(feather, table_name);
}

int maat_inter_table_callback_register(Maat_feather_t feather,short table_id,
									   Maat_start_callback_t *start,
									   Maat_update_callback_t *update,
									   Maat_finish_callback_t *finish,
									   void* u_para)
{
	return Maat_table_callback_register(feather, table_id, start, update, finish, u_para);
}


int maat_plugin_EX_register(Maat_feather_t feather, int table_id,
							Maat_plugin_EX_new_func_t* new_func,
							Maat_plugin_EX_free_func_t* free_func,
							Maat_plugin_EX_dup_func_t* dup_func,
							Maat_plugin_EX_key2index_func_t* key2index_func,
							long argl, void *argp)
{
	return Maat_plugin_EX_register(feather,table_id,new_func,free_func,dup_func,key2index_func,argl,argp);
}

MAAT_PLUGIN_EX_DATA maat_plugin_get_EX_data(Maat_feather_t feather, int table_id, const char* key)
{
	return  Maat_plugin_get_EX_data(feather, table_id, key);
}

int maat_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size)
{
	return  Maat_read_state(feather, type, value, size);
}

void matt_burn_feather(Maat_feather_t feather)
{
	return Maat_burn_feather(feather);
}


