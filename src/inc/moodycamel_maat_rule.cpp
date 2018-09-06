/*************************************************************************
	> File Name: moodycamel_maat_rule.cpp
	> Author:
	> Mail:
	> Created Time: 2018年09月04日 星期二 16时56分42秒
 ************************************************************************/

#include<iostream>

using namespace std;

#include "Maat_rule.h"

extern "C" Maat_feather_t Maat_inter_feather(int max_thread_num,const char* table_info_path,void* logger);
extern "C" int Maat_inter_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size);
extern "C" int Maat_inter_initiate_feather(Maat_feather_t feather);
extern "C" int Maat_inter_table_register(Maat_feather_t feather,const char* table_name);
extern "C" void Maat_inter_burn_feather(Maat_feather_t feather);
extern "C" int Maat_inter_table_callback_register(Maat_feather_t feather,short table_id,
									Maat_start_callback_t *start,
									Maat_update_callback_t *update,
									Maat_finish_callback_t *finish,
									void* u_para);
extern "C" int Maat_inter_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size);

Maat_feather_t Maat_inter_feather(int max_thread_num,const char* table_info_path,void* logger)
{
	return Maat_feather(max_thread_num, table_info_path, logger);
}

int Maat_inter_set_feather_opt(Maat_feather_t feather,enum MAAT_INIT_OPT  type,const void* value,int size)
{
	return Maat_set_feather_opt(feather, type, value, size);
}

int Maat_inter_initiate_feather(Maat_feather_t feather)
{
	return Maat_initiate_feather(feather);
}

int Maat_inter_table_register(Maat_feather_t feather,const char* table_name)
{
	return Maat_table_register(feather, table_name);
}

int Maat_inter_table_callback_register(Maat_feather_t feather,short table_id,
									   Maat_start_callback_t *start,
									   Maat_update_callback_t *update,
									   Maat_finish_callback_t *finish,
									   void* u_para)
{
	return Maat_table_callback_register(feather, table_id, start, update, finish, u_para);
}

int Maat_inter_read_state(Maat_feather_t feather, enum MAAT_STATE_OPT  type, void* value, int size)
{
	return  Maat_read_state(feather, type, value, size);
}

void Maat_inter_burn_feather(Maat_feather_t feather)
{
	return Maat_burn_feather(feather);
}



