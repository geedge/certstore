#ifndef _MESA_LIST_COUNT_H_
#define _MESA_LIST_COUNT_H_

typedef struct MESA_list_count{
	struct MESA_list_count	*nextele;
	struct MESA_list_count	*preele;
	void *quiddity;
}MESA_list_count_t;

#ifdef __cplusplus
extern "C"
{
#endif

void MESA_list_count_init_head(struct MESA_list_count *head);
long MESA_list_count_get_count(const struct MESA_list_count *head);
int  MESA_list_count_is_empty(const struct MESA_list_count *head);
void MESA_list_count_add(struct MESA_list_count *head, struct MESA_list_count *new_list);
void MESA_list_count_add_tail(struct MESA_list_count *head, struct MESA_list_count *new_list);
void MESA_list_count_del(struct MESA_list_count *head, struct MESA_list_count *del_list);
void MESA_list_count_move(struct MESA_list_count *head, struct MESA_list_count *list);
void MESA_list_count_move_tail(struct MESA_list_count *head, struct MESA_list_count *list);
struct MESA_list_count *MESA_list_count_join_n(struct MESA_list_count *head, struct MESA_list_count *op_place, struct MESA_list_count *new_obj);
struct MESA_list_count *MESA_list_count_join_p(struct MESA_list_count *head, struct MESA_list_count *new_obj, struct MESA_list_count *op_place);

#ifdef __cplusplus
}
#endif

#endif

