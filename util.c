#include "util.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


void parse_map(char *buf, struct map *map) {
    char *addrs;
    char *perms;
    char *start_addr, *end_addr;

    map->text = strdup(buf);
    addrs = strtok(buf, " ");
    if (!addrs) {
        printf("could not parse addresses from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    perms = strtok(NULL, " ");
    if (!perms) {
        printf("could not parse permissions from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    start_addr = strtok(addrs, "-");
    if (!start_addr) {
        printf("could not parse start address from maps! line was:\n%s\n", buf);
        exit(-1);
    }
    
    end_addr = strtok(NULL, "-");
    if (!end_addr) {
        printf("could not parse end address from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    map->start = strtoul(start_addr, NULL, 16);
    map->end = strtoul(end_addr, NULL, 16);
    if (perms[0] == 'r') { map->is_r = 1; }
    if (perms[1] == 'w') { map->is_w = 1; }
    if (perms[2] == 'x') { map->is_x = 1; }
}


list_node *list_create(void *data) {
    list_node *ln = malloc(sizeof(list_node));
    if (ln != NULL) {
        ln->next = NULL;
        ln->data = data;
    }
    return ln;
}


list_node *list_insert_end(list_node *list, void *data) {
    list_node *new_node = list_create(data);
    if (new_node != NULL) {
        // find the last element in the list
        while (list->next != NULL) {
            list = list->next;
        }
        
        list->next = new_node;
    }
    return new_node;
}


list_node *parse_maps(int pid) {
    list_node *maps_list = NULL;
    char procpath[1024];
    char buf[1024];
    FILE* vmmap;

    // open /proc/[pid]/maps
    memset(procpath, 0, sizeof(procpath));
    snprintf(procpath, sizeof(procpath), "/proc/%d/maps", pid);
    vmmap = fopen(procpath, "r");
    if (!vmmap) {
        perror("fopen");
        return NULL;
    }

    // TODO: this could fail for many reasons (e.g. path was a symlink and real path is different),
    //       improve someday
    while(fgets(buf, sizeof(buf), vmmap) != NULL) {
        struct map *map;

        map = malloc(sizeof(struct map));
        memset(map, 0, sizeof(map)); 
        parse_map(buf, map);

        if (maps_list == NULL) {
            maps_list = list_create(map);
        }
        else {
            list_insert_end(maps_list, map);
        }
    }

    return maps_list;
}