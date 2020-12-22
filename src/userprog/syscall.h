#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "kernel/list.h"

struct process_file {
	struct file* ptr; 
	int fd;
	struct list_elem elem;
};
struct mapping
  {
    struct list_elem elem;      /* List element. */
    int handle;                 /* Mapping id. */
    struct file *file;          /* File. */
    uint8_t *base;              /* Start of memory mapping. */
    size_t page_cnt;            /* Number of pages mapped. */
  };

void syscall_init (void);
void clean_all_files(struct list* files);

#endif /* userprog/syscall.h */
