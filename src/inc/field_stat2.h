#ifndef H_SCREEN_STAT_H_INCLUDE
#define H_SCREEN_STAT_H_INCLUDE
#include <stdio.h>

#ifndef __cplusplus
#error("This file should be compiled with C++ compiler")
#endif

enum field_dsp_style_t
{
	FS_STYLE_FIELD=0,
	FS_STYLE_COLUMN,
	FS_STYLE_LINE,
	FS_STYLE_STATUS
};
enum field_calc_algo
{
	FS_CALC_CURRENT=0,
	FS_CALC_SPEED
};
enum field_op
{
	FS_OP_ADD=1,
	FS_OP_SET
};


typedef	void* screen_stat_handle_t;

enum FS_option
{
	OUTPUT_DEVICE,		//VALUE is a const char*, indicate a  file path string, SIZE = strlen(string+'\0')+1.DEFAULT:output to stdout.
	PRINT_MODE,			//VALUE is an interger,1:Rewrite ,2: Append. SIZE=4,DEFALUT:REWRITE.
	STAT_CYCLE,			//VALUE is an interger idicate interval seconds of every output, SIZE=4 ,DEFUALT:2 seconds.
	PRINT_TRIGGER,		//VALUE is an interger,1:Do print,0: Don't print.SIZE=4.DEFAULT:1.
	CREATE_THREAD,		//VALUE is an interger,1: Create a print thread,0:not create,output by call passive_output function,
						//and the STAT_CYCLE is meaningless.SIZE=4,DEFAULT:0.
	ID_INVISBLE,		//value is field_id/status_id/column_id, not output this string, SIZE=4,DEFAULT: shutdown NO one.
	FLUSH_BY_DATE,		//value is 1(ture) or 0(false),SIZE=4,DEFAULT: Do not flush by date.
	APP_NAME,			//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. DEFAULT is "?".
	STATS_SERVER_IP, 	//VALUE is a const char*, MUST end with '\0', SIZE= strlen(string+'\0')+1. No DEFAULT.
	STATS_SERVER_PORT, 	//VALUE is a unsigned short or a signed int, host order, SIZE= sizeof(unsigned short) or sizeof(int). No DEFAULT.
	MAX_STAT_FIELD_NUM		//VALUE is an interger, SIZE=sizeof(int), DEFAULT:1024.
};

//Always success.
screen_stat_handle_t FS_create_handle(void);

int FS_set_para(screen_stat_handle_t handle, enum FS_option  type,const void* value,int size);
void FS_start(screen_stat_handle_t handle);
void FS_stop(screen_stat_handle_t* handle);

//return field_id/line_id/column_id greater than zero if success,return an interger less than zero if failed.
//should NOT include "|:\n\r.\t<>[]#!@"or space in the parameter name.
//Runtime rregister column is NOT allowed.
int FS_register(screen_stat_handle_t handle,enum field_dsp_style_t style,enum field_calc_algo calc_type,const char* name);

//numerator_id and denominator_id must be column/field/status style.
//scaling: negative value: zoom in; positive value: zoom out;
int FS_register_ratio(screen_stat_handle_t handle,int numerator_id,int denominator_id,int scaling,enum field_dsp_style_t style,enum field_calc_algo calc_type,const char* name);

//id: when id's type is FIELD , column_id is ignore.
int FS_operate(screen_stat_handle_t handle,int id,int column_id,enum field_op op,long long value);

void FS_passive_output(screen_stat_handle_t handle);

#endif

