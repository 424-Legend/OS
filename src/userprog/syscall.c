#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
//#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
int exec_process(char *file_name);
void exit_process(int status);
void * is_valid_addr(const void *vaddr);
struct process_file* search_fd(struct list* files, int fd);
void clean_single_file(struct list* files, int fd);
// void clean_all_files(struct list* files); // declear in syscall.h used by another c files


int syscall_exec(char *file_name);
int syscall_wait(tid_t child_tid);
int syscall_creat(char *name,off_t initial_size);
int syscall_remove(struct intr_frame *f);
int syscall_open(char *name);
int syscall_filesize(int fd);
int syscall_read(int size,void *buffer,int fd);
int syscall_write(int size, void *buffer, int fd);
void syscall_seek(int fd, int pos);
int syscall_tell(int fd);
void syscall_close(int fd);
void syscall_halt(void);
static void unmap(struct mapping *m);
static int syscall_mmap(int fd,void * addr);
static struct mapping * lookup_mapping (int handle);
static int sys_munmap(int mapping); 
static struct mapping * lookup_mapping (int handle);


void pop_stack(int *esp, int *a, int offset){
	int *tmp_esp = esp;
	*a = *((int *)is_valid_addr(tmp_esp + offset));
}
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  	int *p = f->esp;
	is_valid_addr(p);

  	int system_call = *p;
	switch (system_call)
	{
		case SYS_HALT: shutdown_power_off(); break;
		case SYS_EXIT: {
			int status;
			pop_stack(f->esp, &status, 1);
			exit_process(status);
			break;}
		case SYS_EXEC: {
			char *file_name;
			pop_stack(f->esp, &file_name, 1);
			f->eax = syscall_exec(file_name); 
			break;
		}
		case SYS_WAIT:{
			tid_t child_tid;
			pop_stack(f->esp, &child_tid, 1);
			f->eax = syscall_wait(child_tid); 
			break;
		} 
		case SYS_CREATE:{
			off_t initial_size;
			char *name;
			pop_stack(f->esp, &initial_size, 5);
			pop_stack(f->esp, &name, 4);
			if (!is_valid_addr(name)) 
				f->eax = -1;
			else	
				f->eax = syscall_creat(name,initial_size); 
			break;
		}
		case SYS_REMOVE: f->eax = syscall_remove(f); break;
		case SYS_OPEN: {
			char *name;

			pop_stack(f->esp, &name, 1);
			if (!is_valid_addr(name))
				f->eax = -1;	
			else
				f->eax = syscall_open(name); 
			break;}
		case SYS_FILESIZE: {
			int fd;
			pop_stack(f->esp, &fd, 1);
			f->eax = syscall_filesize(fd); 
			break;
		}
		case SYS_READ: {
			int size;
			void *buffer;
			int fd;
			pop_stack(f->esp, &size, 7);
			pop_stack(f->esp, &buffer, 6);
			pop_stack(f->esp, &fd, 5);
			f->eax = syscall_read(size,buffer,fd); 
			break;
		}
		case SYS_WRITE: {
			int size;
			void *buffer;
			int fd;
			pop_stack(f->esp, &size, 7);
			pop_stack(f->esp, &buffer, 6);
			pop_stack(f->esp, &fd, 5);

			f->eax = syscall_write(size,buffer,fd); 
			break;
		}
		case SYS_SEEK: {
			int fd;
			int pos;
			pop_stack(f->esp, &fd, 5);
			pop_stack(f->esp, &pos, 4);
			syscall_seek(fd, pos); 
			break;
		}
		case SYS_TELL: {
			int fd;
			pop_stack(f->esp, &fd, 1);
			f->eax = syscall_tell(fd); 
			break;
		}
		case SYS_CLOSE: {
			int fd;
			pop_stack(f->esp, &fd, 1);
			syscall_close(fd); 
			break;
		}
		case SYS_MMAP : {
			int fd;
			int pos;
			pop_stack(f->esp, &fd, 4);
			pop_stack(f->esp, &pos, 5);
			f->eax = syscall_mmap(fd,pos);
			break; 
		}
		case SYS_MUNMAP : {
			int fd; 
			pop_stack(f->esp, &fd, 1);
			f->eax = sys_munmap(fd);
			break;
		}

		default:
		printf("Default %d\n",*p);
	}
}


int
exec_process(char *file_name)
{
	int tid;
	lock_acquire(&filesys_lock);
	char * name_tmp = malloc (strlen(file_name)+1);
	strlcpy(name_tmp, file_name, strlen(file_name) + 1);

	char *tmp_ptr;
	name_tmp = strtok_r(name_tmp, " ", &tmp_ptr);

	struct file *f = filesys_open(name_tmp);  // check whether the file exists. critical to test case "exec-missing"

	if (f == NULL)
	{
		lock_release(&filesys_lock);
		tid = -1;
	}
	else
	{
		file_close(f);
		lock_release(&filesys_lock);
		tid = process_execute(file_name);
	}
	return tid;
}

void
exit_process(int status)
{
	struct child_process *cp;
	struct thread *cur_thread = thread_current();

	enum intr_level old_level = intr_disable();
	for (struct list_elem *e = list_begin(&cur_thread->parent->list_of_children_processes); e != list_end(&cur_thread->parent->list_of_children_processes); e = list_next(e))
	{
		cp = list_entry(e, struct child_process, child_elem);
		if (cp->tid == cur_thread->tid)
		{
			
			cp->if_waited = true;
			cp->exit_status = status;
		}
	}
	cur_thread->exit_status = status;
	intr_set_level(old_level);

	thread_exit();
}

void *
is_valid_addr(const void *vaddr)
{
	void *page_ptr = NULL;
	if (!is_user_vaddr(vaddr) || !(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr)))
	{
		exit_process(-1);
		return 0;
	}
	return page_ptr;
}

  /* Find fd and return process file struct in the list,
  if not exist return NULL. */
struct process_file *
search_fd(struct list* files, int fd)
{
	struct process_file *proc_f;
	for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e))
	{
		proc_f = list_entry(e, struct process_file, elem);
		if (proc_f->fd == fd)
			return proc_f;
	}
	return NULL;
}

  /* close and free specific process files
  by the given fd in the file list. Firstly,
  find fd in the list, then remove it. */
void
clean_single_file(struct list* files, int fd)
{
	struct process_file *proc_f = search_fd(files,fd);
	if (proc_f != NULL){
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
    	free(proc_f);
	}
}

  /* close and free all process files in the file list */
void
clean_all_files(struct list* files)
{
	struct process_file *proc_f;
	while(!list_empty(files))
	{
		proc_f = list_entry (list_pop_front(files), struct process_file, elem);
		file_close(proc_f->ptr);
		list_remove(&proc_f->elem);
		free(proc_f);
	}
}

int
syscall_exec(char *file_name)
{
	
	if (!is_valid_addr(file_name)){
		return -1;
	}
		

	return exec_process(file_name);
}

int
syscall_wait(tid_t child_tid)
{
	return process_wait(child_tid);
}

static char *
copy_in_string (const char *us)
{
  char *ks;
  char *upage;
  size_t length;

  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  length = 0;
  for (;;)
    {
      upage = pg_round_down (us);
      if (!page_lock (upage, false))
        goto lock_error;

      for (; us < upage + PGSIZE; us++)
        {
          ks[length++] = *us;
          if (*us == '\0')
            {
              page_unlock (upage);
              return ks;
            }
          else if (length >= PGSIZE)
            goto too_long_error;
        }

      page_unlock (upage);
    }

 too_long_error:
  page_unlock (upage);
 lock_error:
  palloc_free_page (ks);
  thread_exit ();
}

int
syscall_creat(char *name,off_t initial_size)
{
	char *kfile = copy_in_string (name);
  bool ok;
  lock_acquire (&filesys_lock);
  ok = filesys_create (kfile, initial_size);
  lock_release (&filesys_lock);
	// printf("%x\n",ok);
  palloc_free_page (kfile);
  return ok;
}
 
int
syscall_remove(struct intr_frame *f) 
{
	int ret;
	char *name;

	pop_stack(f->esp, &name, 1);
	if (!is_valid_addr(name))
		ret = -1;

	lock_acquire(&filesys_lock);
	if (filesys_remove(name) == NULL)
		ret = false;
	else
		ret = true;
	lock_release(&filesys_lock);

	return ret;
}

int
syscall_open(char *name)
{
	int ret;
	lock_acquire(&filesys_lock);
	struct file *fptr = filesys_open(name);
	lock_release(&filesys_lock);

	if (fptr == NULL)
		ret = -1;
	else
	{
		struct process_file *pfile = malloc(sizeof(*pfile));
		pfile->ptr = fptr;
		pfile->fd = thread_current()->fd_count;
		thread_current()->fd_count++;
		list_push_back(&thread_current()->opened_files, &pfile->elem);
		ret = pfile->fd;
	}
	return ret;
}
 
int 
syscall_filesize(int fd)
{
	int ret;

	lock_acquire(&filesys_lock);
	ret = file_length (search_fd(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	return ret;
}
static struct process_file *
lookup_fd (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->opened_files); e != list_end (&cur->opened_files);
       e = list_next (e))
    {
      struct process_file *pf;
      pf = list_entry (e, struct process_file, elem);
      if (pf->fd == handle)
        return pf;
    }

  thread_exit ();
}
int
syscall_read(int size,void *udst_,int handle)
{
uint8_t *udst = udst_;
struct process_file  *pf;
int bytes_read = 0;

  pf = lookup_fd(handle);
  if(handle != 1 && pf == NULL)
	return -1;
	// if(size==0&&pf==0){
	// 	fclose(pf);
	// 	return 0;
	// }

  while (size >0)
    {
      /* How much to read into this page? */
      size_t page_left = PGSIZE - pg_ofs (udst);
      size_t read_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Read from file into page. */
      if (handle != 1) 
        {
          if (!page_lock (udst, true))
            thread_exit ();
          lock_acquire (&filesys_lock);
          retval = file_read (pf->ptr, udst, read_amt);
          lock_release (&filesys_lock);
          page_unlock (udst);
        }
      else
        {
          size_t i;

          for (i = 0; i < read_amt; i++)
            {
              char c = input_getc ();
              if (!page_lock (udst, true))
                thread_exit ();
              udst[i] = c;
              page_unlock (udst);
            }
          bytes_read = read_amt;
        }

      /* Check success. */
      if (retval < 0)
        {
          if (bytes_read == 0)
            bytes_read = -1;
          break;
        }
      bytes_read += retval;
      if (retval != (off_t) read_amt)
        {
          /* Short read, so we're done. */
          break;
        }
      /* Advance. */
      udst += retval;
      size -= retval;
    }
	
  return bytes_read;
	// int ret;
	// size_t page_left = PGSIZE - pg_ofs (udst);
    // size_t read_amt = size < page_left ? size : page_left;
    // off_t retval;
	// if (!is_valid_addr(buffer))
	// 	ret = -1;

	// if (fd == 0)
	// {
	// 	int i;
	// 	uint8_t *buffer = buffer;
	// 	for (i = 0; i < size; i++)
	// 		buffer[i] = input_getc();
	// 	ret = size;
	// }
	// else
	// {
	// 	struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
	// 	if (pf == NULL)
	// 		ret = -1;
	// 	else
	// 	{
	// 		lock_acquire(&filesys_lock);
	// 		ret = file_read(pf->ptr, buffer, size);
	// 		lock_release(&filesys_lock);
	// 	}
	// }

	// return ret;
}

int
syscall_write(int size, void *buffer, int fd)
{

	int ret;

	if (!is_valid_addr(buffer))
		return -1;
		
	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	else
	{
		enum intr_level old_level = intr_disable();
		struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
		intr_set_level (old_level);
		lock_acquire(&filesys_lock);
		if (pf == NULL){
			ret = -1;
			lock_release(&filesys_lock);
		}
		else
		{
			ret = file_write(pf->ptr, buffer, size);
		lock_release(&filesys_lock);
		}
	}
	return ret;
}

void
syscall_seek(int fd, int pos)
{
	lock_acquire(&filesys_lock);
	file_seek(search_fd(&thread_current()->opened_files, pos)->ptr, fd);
	lock_release(&filesys_lock);
}

int
syscall_tell(int fd)
{
	int ret;
	lock_acquire(&filesys_lock);
	ret = file_tell(search_fd(&thread_current()->opened_files, fd)->ptr);
	lock_release(&filesys_lock);

	return ret;
}

void
syscall_close(int fd)
{
	lock_acquire(&filesys_lock);
	clean_single_file(&thread_current()->opened_files, fd);
	lock_release(&filesys_lock);
}

/* Binds a mapping id to a region of memory and a file. */
/* Remove mapping M from the virtual address space,
   writing back any pages that have changed. */
static void
unmap1 (struct mapping *m)
{
/* add code here */
  list_remove(&m->elem);
  for(int i = 0; i < m->page_cnt; i++)
  {
    //Pages written by the process are written back to the file...
    if (pagedir_is_dirty(thread_current()->pagedir, m->base + (PGSIZE * i)))
    {
      lock_acquire(&filesys_lock);
      file_write_at(m->file, m->base + (PGSIZE * i), PGSIZE, (PGSIZE * i)); // Check 3rd parameter
      lock_release(&filesys_lock);
    }
  }
  for(int i = 0; i < m->page_cnt; i++)
  {
    page_deallocate(m->base + (PGSIZE * i));
  }
}

static int 
syscall_mmap(int fd,void * addr){
	// printf("fd : %d\n",fd);
	// printf("add : %x\n",addr);
	struct process_file *pf = search_fd(&thread_current()->opened_files,fd);
	struct mapping *m = malloc(sizeof *m);
	size_t offset;
	off_t length;

	if(m == NULL || addr == NULL || pg_ofs(addr) != 0){
		return -1;
	}
	//printf("fd : %d\n",pf->fd);
	m->handle = thread_current()->fd_count ++;
	lock_acquire(&filesys_lock);
	m->file = file_reopen(pf->ptr);
	lock_release(&filesys_lock);
	if(m->file == NULL){
		// printf("add : %x\n",addr);
		free(m);
		return -1;
	}
	m->base = addr;
	m->page_cnt = 0;
	// printf("add : %x\n",addr);
	list_push_front(&thread_current ()->mappings, &m->elem);
	offset = 0;
	lock_acquire(&filesys_lock);
	length = file_length(m->file);
	// printf("%d\n",length);
	lock_release(&filesys_lock);

	while(length > 0){
		struct page *p = page_allocate ((uint8_t *) addr + offset, false);
      if (p == NULL)
        {
          unmap1 (m);
          return -1;
        }
      p->private = false;
      p->file = m->file;
      p->file_offset = offset;
      p->file_bytes = length >= PGSIZE ? PGSIZE : length;
      offset += p->file_bytes;
      length -= p->file_bytes;
      m->page_cnt++;
	}
	return m->handle;
}

static struct mapping *
lookup_mapping (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->mappings); e != list_end (&cur->mappings);
       e = list_next (e))
    {
      struct mapping *m = list_entry (e, struct mapping, elem);
      if (m->handle == handle)
        return m;
    }

  thread_exit ();
}


/* Munmap system call. */
static int
sys_munmap (int mapping)
{
/* add code here */
  unmap1(lookup_mapping(mapping));
  return 0;
}