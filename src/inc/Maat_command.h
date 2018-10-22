#ifndef H_MAAT_COMMAND_H_INCLUDE
#define H_MAAT_COMMAND_H_INCLUDE
#ifndef __cplusplus
#error("This file should be compiled with C++ compiler")
#endif
#include "Maat_rule.h"
enum MAAT_OPERATION
{
	MAAT_OP_DEL=0,
	MAAT_OP_ADD,
	MAAT_OP_RENEW_TIMEOUT	//Rule expire time is changed to now+cmd->expire_after
};
 
enum MAAT_REGION_TYPE
{
	REGION_EXPR,
	REGION_IP,
	REGION_INTERVAL,
	REGION_DIGEST,
	REGION_SIMILARITY
};
enum MAAT_EXPR_TYPE
{	
	EXPR_TYPE_STRING=0,
	EXPR_TYPE_AND,
	EXPR_TYPE_REGEX,
	EXPR_TYPE_OFFSET
};
enum MAAT_MATCH_METHOD
{	
	MATCH_METHOD_SUB=0,
	MATCH_METHOD_RIGHT,
	MATCH_METHOD_LEFT,
	MATCH_METHOD_COMPLETE
};

enum MAAT_CASE_TYPE
{
	UNCASE_PLAIN=0,
	CASE_HEXBIN,
	CASE_PLAIN
};
enum MAAT_ADDR_TYPE
{
	ADDR_TYPE_IPv4=4,
	ADDR_TYPE_IPv6=6
};
enum MAAT_ADDR_DIRECTION
{
	ADDR_DIR_DOUBLE=0,
	ADDR_DIR_SINGLE=1
};
struct Maat_rgn_str_t
{
	const char *keywords;
	const char *district;// optional for expr_plus, otherwise set to NULL.
	enum MAAT_EXPR_TYPE expr_type;
	enum MAAT_MATCH_METHOD match_method;
	enum MAAT_CASE_TYPE hex_bin;
};
struct Maat_rgn_addr_t
{
	enum MAAT_ADDR_TYPE addr_type;
	const char* src_ip;
	const char* mask_src_ip;
	const char* dst_ip;
	const char* mask_dst_ip;
	unsigned short src_port;
	unsigned short mask_src_port;
	unsigned short dst_port;
	unsigned short mask_dst_port;
	unsigned short protocol;
	enum MAAT_ADDR_DIRECTION direction;
};
struct Maat_rgn_intv_t
{
	unsigned int low_boundary;
	unsigned int up_boundary;
};
struct Maat_rgn_digest_t
{
	unsigned long long orgin_len;
	const char* digest_string;
	short confidence_degree;
};
struct Maat_rgn_sim_t
{
	char* target;
	short threshold;// 1~100
};
struct Maat_region_t
{
	const char* table_name;
	int region_id;	//If MAAT_OPT_CMD_AUTO_NUMBERING==1, maat will assigned one. Or users must appoint a unique number.
	enum MAAT_REGION_TYPE region_type;
	union
	{
		struct Maat_rgn_str_t expr_rule;
		struct Maat_rgn_addr_t ip_rule;
		struct Maat_rgn_intv_t interval_rule;
		struct Maat_rgn_digest_t digest_rule;
		struct Maat_rgn_sim_t similarity_rule;
	};
};
struct Maat_group_t
{
	int region_num;
	int group_id;	//If MAAT_OPT_CMD_AUTO_NUMBERING==1, maat will assigned one. Or users must assign a unique number.
	struct Maat_region_t *regions;	
};
struct Maat_cmd_t
{
	//This Struct MUST alloced by Maat_create_cmd(), then released by Maat_free_cmd(). 
	struct Maat_rule_t compile; // for MAAT_OP_DEL, only compile.config_id is necessary.
	int group_num;				// for MAAT_OP_DEL, set to 0.
	int expire_after;			//expired after $expire_after$ seconds, set to 0 for never timeout.
	int label_id;					//>0, to be indexed and quried by Maat_cmd_select; =0 not index
	struct Maat_group_t* groups;// Add regions with Maat_add_region2cmd 
};	
struct Maat_line_t
{
	const char* table_name;
	const char* table_line;
	int rule_id;		// for MAAT_OP_DEL, only rule_id and table_name are necessary.
	int label_id;
	int expire_after;	//expired after $timeout$ seconds, set to 0 for never timeout.
};
struct Maat_cmd_t* Maat_create_cmd(const struct Maat_rule_t* rule, int group_num);
int Maat_cmd_set_opt(struct Maat_cmd_t* cmd, enum MAAT_RULE_OPT type, const char* val, int size);
//input: which_group 0~group_num
//input: region can be freed after added.
void Maat_add_region2cmd(struct Maat_cmd_t* cmd,int which_group,const struct Maat_region_t* region);

void Maat_free_cmd(struct Maat_cmd_t* cmd);
int Maat_format_cmd(struct Maat_cmd_t* cmd, char* buffer, int size);
//Input string of REGION_EXPR and REGION_SIMILARITY need to be escapeed.
char* Maat_str_escape(char* dst,int size,const char*src);

//Deletion failed due to not complete synchronize with Redis.
//To make sure the delete command is excecuted, user should try again after MAAT_OPT_SCANDIR_INTERVAL_MS ms.
//Returns nubmer of successfully updated rule.
//The following functions are NOT thread safe.
int Maat_cmd(Maat_feather_t feather,struct Maat_cmd_t* cmd,enum MAAT_OPERATION op);

//pipeline model
int Maat_cmd_append(Maat_feather_t feather,struct Maat_cmd_t* cmd,enum MAAT_OPERATION op);

//Return nubmer of successfully updated rule.
//Return -1 for failed.
int Maat_cmd_commit(Maat_feather_t feather);


int Maat_cmd_set_group(Maat_feather_t feather, int group_id, const struct Maat_region_t* region, enum MAAT_OPERATION op);

//Returns nubmer of successfully updated rule.
//Return -1 for failed.
int Maat_cmd_set_line(Maat_feather_t feather,const struct Maat_line_t* line_rule, enum MAAT_OPERATION op);
int Maat_cmd_set_lines(Maat_feather_t feather,const struct Maat_line_t** line_rule, int line_num ,enum MAAT_OPERATION op);
int Maat_cmd_set_file(Maat_feather_t feather,const char* key, const char* value, size_t size, enum MAAT_OPERATION op);

//Return the value of key after the increment.
//If the key does not exist, it is set to 0 before performing the operation.
long long Maat_cmd_incrby(Maat_feather_t feather,const char* key, int increment);
int Maat_cmd_select(Maat_feather_t feather, int label_id, int * output_ids, unsigned int size);
int Maat_cmd_flushDB(Maat_feather_t feather);
#endif

