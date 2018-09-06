#ifndef _GRAM_INDEX_ENGINE_
#define _GRAM_INDEX_ENGINE_

#ifdef __cplusplus
extern "C" {
#endif

#define GIE_INSERT_OPT 0
#define GIE_DELETE_OPT 1
#define GIE_INPUT_FORMAT_SFH 1
#define GIE_INPUT_FORMAT_PLAIN 0


typedef struct 
{
	/* data */
}GIE_handle_t;


typedef struct 
{
	unsigned int id;
	unsigned int sfh_length;//size of fuzzy_hash
	short operation;//GIE_INSERT_OPT or GIE_DELETE_OPT.if operation is GIE_DELETE_OPT, only id is needed;
	short cfds_lvl;
	char * sfh;
	void * tag;
}GIE_digest_t;


typedef struct 
{
	unsigned int id;
	short cfds_lvl;
	void * tag;
}GIE_result_t;


typedef struct 
{
	unsigned int gram_value;
	//unsigned int htable_num;
	unsigned int position_accuracy;
	short format; //if format==GIE_INPUT_FORMAT_SFH, means the input string is a GIE_INPUT_FORMAT_SFH string 
	                //else id format==PALIN, means the input string is common string
	short ED_reexamine;//if ED_reexamine==1, calculate edit distance to verify the final result
}GIE_create_para_t;


GIE_handle_t * GIE_create(const GIE_create_para_t * para);


int GIE_update(GIE_handle_t * handle, GIE_digest_t ** digests, int size);


//return actual matched result count
//return 0 when matched nothing;
//return -1 when error occurs;
int GIE_query(GIE_handle_t * handle, const char * data, int data_len, GIE_result_t * results, int result_size);

void GIE_destory(GIE_handle_t * handle);
int GIE_string_similiarity(const char *str1, int len1, const char *str2, int len2);
int GIE_sfh_similiarity(const char *sfh1, int len1, const char *sfh2, int len2);

#ifdef __cplusplus
}
#endif
#endif
