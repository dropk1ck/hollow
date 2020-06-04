#ifndef __UTIL_H
#define __UTIL_H

struct map {
    char *text;
    unsigned long start;
    unsigned long end;
    int is_r;
    int is_w;
    int is_x;
};

// singly-linked lists
typedef struct list_node {
    void *data;
    struct list_node *next;
} list_node;


list_node *list_create(void *data);
list_node *list_insert_end(list_node *list, void *data);
list_node *parse_maps(int pid);
void parse_map(char *buf, struct map *map);

#endif  // __UTIL_H