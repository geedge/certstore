/*************************************************************************
	> File Name: moodycamel_field_stat2.cpp
	> Author:
	> Mail:
	> Created Time: 2018年07月03日 星期二 16时48分52秒
 ************************************************************************/

#include<iostream>
#include "field_stat2.h"

using namespace std;

extern "C" screen_stat_handle_t FS_internal_create_handle(void);
extern "C" int FS_internal_set_para(screen_stat_handle_t handle, enum FS_option  type,const void* value,int size);
extern "C" void FS_internal_start(screen_stat_handle_t handle);
extern "C" int FS_internal_register(screen_stat_handle_t handle,enum field_dsp_style_t style,
						 			enum field_calc_algo calc_type,const char* name);
extern "C" int FS_internal_operate(screen_stat_handle_t handle,int id,int id2,int column_id,enum field_op op,long long value);

screen_stat_handle_t FS_internal_create_handle(void)
{
	return FS_create_handle();
}

int FS_internal_set_para(screen_stat_handle_t handle, enum FS_option  type,const void* value,int size)
{
	return FS_set_para(handle, type, value, size);
}

void FS_internal_start(screen_stat_handle_t handle)
{
	FS_start(handle);
}

int FS_internal_register(screen_stat_handle_t handle,enum field_dsp_style_t style,
						 enum field_calc_algo calc_type,const char* name)
{
	return FS_register(handle, style, calc_type, name);
}

int FS_internal_operate(screen_stat_handle_t handle,int id,int id2,int column_id,enum field_op op,long long value)
{
	int ret = -1;

	ret = FS_operate(handle, id, column_id, op, value);
	if (ret < 0)
		goto finish;

	if (id2 < 0)
		goto finish;

	ret = FS_operate(handle, id2, 0, op, value);
finish:
		return ret;
}

