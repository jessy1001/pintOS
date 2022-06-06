#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
// #include "lib/kernel/bitmap.h"
// #include "filesys/filesys.c"
#include <bitmap.h>
#include "threads/palloc.h"
#include "filesys/file.h"
// #include "devices/"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(char* file);
int wait(pid_t);
int open(const char* file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *bubber, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void check_address(void* addr);


//이외 추가함수
static struct file *find_file_by_fd(int fd);
int add_file_to_fdt (struct file *file);
void remove_file_from_fdt(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	/*내가 추가 */
	lock_init(&filesys_lock);
}

/* The main system call interface 
syscall_handler() 가 제어권을 얻을 때 
system call number는 rax에 있고 인자는 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달된다.*/
void
syscall_handler (struct intr_frame *f UNUSED) {	//syscall-entry.S에서 kernel stack에 push 한 애들을 encapsulate한 interrupt frame
	int syscall_num;

	// check_address(f->rsp); //이걸 여기다 해주는 게 아닌 것 같은데...??
	syscall_num = f->R.rax;

	switch(syscall_num){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi); //exit을 부를 때 rdi에 아마 int status가 있을 것이다
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1)
				exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;

		default:
			exit(-1);
			break;
	}
	/*retrieve system call number and any system call arguments,
	carry out appropriate actions */


	/* make system call handler call system call using sc number
	check validation of pointers in parameter list
	copy arguments on the user stack into kernel
	save return value of syscall at eax(rax) register
	 */

	// printf ("system call!\n");
	// thread_exit ();
}

/* 1. null pointer
   2. pointer to kernel virtual address space
   3. pointer to unmapped virtual memory */
void check_address(void* addr){
	struct thread* cur = thread_current();

	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

/* 현재 프로세스의 fd테이블에 파일 추가*/
int add_file_to_fdt (struct file *file){
	struct thread *cur = thread_current();
	struct file **fdt = cur->fd_table;

	//fd의 위치가 제한 범위를 넘지 않고, fdtable
	while (cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx]){
		cur -> fd_idx ++;
	}
	//fdt이 가득 찼다면
	if (cur->fd_idx >= FDCOUNT_LIMIT)
		return -1;
	//해당 자리에 파일 배치
	fdt[cur->fd_idx] = file;
	return cur->fd_idx;

}

void remove_file_from_fdt(int fd){
	struct thread *cur = thread_current();

	//Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;
	cur->fd_table[fd] = NULL;
	
}

static struct file *find_file_by_fd(int fd){
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	return cur->fd_table[fd];
}

/* -------------syscall--------------*/
/* 핀토스 종료 */
void halt(void){
	power_off();
}

tid_t fork(const char* thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status); // Process Termination Message
	thread_exit();
}

tid_t exec(char *file){
	check_address(file);

	int file_size = strlen(file) + 1;//  '\0'까지 복사해주기 위해서
	char *fn_copy = palloc_get_page(PAL_ZERO);
	
	if (fn_copy == NULL){
		exit(-1);
	}
	strlcpy(fn_copy, file, file_size); //
	if (process_exec(fn_copy) == -1){
		return -1;

	}
	/*'This never returns if successful.*/
	NOT_REACHED();
	return 0;
}
/* clones the current process as 'name', returns the new process's tid or TID_error*/


/* 요청받은 파일을 생성한다. 만약 파일 주소가 유효하지 않다면 종료*/
bool create(const char* file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

/*-------------------file------------------------- */

/* 요청받은 파일이름의 파일을 제거 */
bool remove(const char* file){
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file){
	check_address(file);
	// lock_acquire(&file_rw_lock);
	struct file *fileobj = filesys_open(file);
	if (fileobj == NULL)
		return -1;
	
	int fd = add_file_to_fdt(fileobj);

	//fdtable이 가득 찼다면
	if (fd == -1)
		file_close(fileobj);
	// lock_release(&file_rw_lock);
	return fd;
}

/* fd인자를 받아 파일 크기 리턴*/
int filesize(int fd){
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}


int read(int fd, void *buffer, unsigned size){
	check_address(buffer); //buffer 시작 주소 체크
	check_address(buffer + size - 1); //buffer 끝 주소도 유저 영역 내에 있는지 체크
	int read_count;
	unsigned char *buf = buffer;
	struct file *fileobj = find_file_by_fd(fd);

	if (fileobj == NULL)
		return -1;
	
	if (fd == 0){ // STDIN
		char key;
		for (int read_count = 0; read_count < size; read_count++){
			key = input_getc();
			*buf++ = key; //buf에 key 넣고 buf += 1
			if (key == '\0'){ //엔터
				break;
			}
		}
	} 
	else if (fd == 1){ //STDOUT
		return -1;
	}
	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(find_file_by_fd(fd), buffer, size);
		lock_release(&filesys_lock);
	}
	
	return read_count;
}
/* write (size) bytes from (buffer) to the open file (fd) */
int write(int fd, const void* buffer, unsigned size){
	check_address(buffer);
	int write_count;
	struct file *fileobj = find_file_by_fd(fd);

	if (fileobj == NULL)
		return -1;

	if(fd == 1){//STDOUT: "write to the console"
		putbuf(buffer, size); //print (size) bytes from (buffer) to console
		write_count = size;
	}
	else if (fd == 0){ //STDIN
		return -1;
	}
	else {
		lock_acquire(&filesys_lock);
		write_count = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_count;
}
/* Changes the next byte to be read or written in open file fd to position,*/
void seek(int fd, unsigned position){

	if (fd < 2) return;
	
	struct file *fileobj = find_file_by_fd(fd);
	check_address(fileobj); //이거 안해도됨...?
	//fileobj->pos = position; 아니 내장함수 있음
	file_seek(fileobj, position);
}

/* Returns the position of the next byte to be read or written in open file fd(=offset)*/
unsigned tell(int fd){
	if (fd < 2) return;
	struct file *fileobj = find_file_by_fd(fd);
	check_address(fileobj); //이거 안해도 됨????
	return file_tell(fileobj);
}

/*열린 파일을 닫는 시스템콜: 파일을 닫고 fd 제거 */
void close(int fd){
	if (fd < 2) return;
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return;
	remove_file_from_fdt(fd);
	file_close(fd);
}

