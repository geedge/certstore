#ifndef _MESA_LIST_H_
#define _MESA_LIST_H_

typedef struct MESA_list{
	struct MESA_list	*nextele;
	struct MESA_list	*preele;
	void *quiddity;
}MESA_list_t;


#ifdef __cplusplus
extern "C"
{
#endif

#define MESA_LIST_VERSION_MACRO  (20150529)
extern const unsigned int MESA_LIST_VERSION_INT;

void MESA_list_init_head(struct MESA_list *head);
int  MESA_list_is_empty(const struct MESA_list *head);
void MESA_list_add(struct MESA_list *head, struct MESA_list *new_list);
void MESA_list_add_tail(struct MESA_list *head, struct MESA_list *new_list);
void MESA_list_del(struct MESA_list *head, struct MESA_list *del_list);
void MESA_list_move(struct MESA_list *head, struct MESA_list *list);
void MESA_list_move_tail(struct MESA_list *head, struct MESA_list *list);
struct MESA_list *MESA_list_join_n(struct MESA_list *head, struct MESA_list *op_place, struct MESA_list *new_obj);
struct MESA_list *MESA_list_join_p(struct MESA_list *head, struct MESA_list *new_obj, struct MESA_list *op_place);

#ifdef __cplusplus
}
#endif

#endif

