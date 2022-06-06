#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed_point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* mlfq */
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* sleep 상태의 스레드들을 저장하는 리스트 */
static struct list sleep_list;
/* ready list에서 맨 처음으로 awake할 스레드의 tick 값 */
static struct list all_list;
static int64_t next_tick_to_awake;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

// mlfqs로 인한 추가
int load_avg;

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&sleep_list); // sleep 스레드들을 연결해놓은 리스트를 초기화한다.
	list_init (&all_list);
	next_tick_to_awake = INT64_MAX;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);
	load_avg = LOAD_AVG_DEFAULT;

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {	
	struct thread *t = thread_current (); // thread 유효성 검사

	/* Update statistics. */
	if (t == idle_thread)	
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns(idle은 priority가 0이니까...?).  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Project 2: System Call */
	struct thread *parent;
	parent = thread_current();
	list_push_back(&parent->child_list, &t->child_elem);

	/* ---Project 2: system call--- */
	t->fd_table = palloc_get_multiple(PAL_ZERO, FDT_PAGES);
	if (t->fd_table == NULL)
		return TID_ERROR;
	t->fd_idx = 2; //0은 stdin, 1은 stdout에 이미 할당
	t->fd_table[0] = 0; //stdin자리에 1배정
	t->fd_table[1] = 1; //stdout자리에 2배정 (is the 1 and 2 fd's?)
	
	t->stdin_count = 1;
	t->stdout_count = 1;

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread; //이거 언제 실행? function(aux)의 wrapper로 실행.
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;


	/* Add to run queue. */
	thread_unblock (t);
	
	// Thread unblock 후, 현재 실행중인 thread와 우선순위 비교 
	// running_thread_priority < new_thread_priority
	// priority = 새로 들어오는 스레드의 priority
	// thread_get_priority = Running 상태의 스레드의 priority
	// if (priority > thread_get_priority()){
	// 	thread_yield();
	// }
	test_max_priority();
	

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
// unblock = 1) 우선순위 순으로 ready list에 넣고 2) 상태를 ready로 바꿔줌
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	// 우선순위 정렬되어 삽입되도록 수정
	list_insert_ordered (&ready_list, &t->elem, cmp_priority, NULL);
	// list_push_back (&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		// 우선순위 정렬되어 삽입되도록 수정
		list_insert_ordered (&ready_list, &curr->elem, cmp_priority, NULL);
		// list_push_back (&ready_list, &curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}
// cmp_priority()
// 첫 번째 인자의 우선순위가 높으면 1을 반환, 두 번째 인자의 우선순위가 높으면 0을 반환
bool
cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	struct thread *A;
	struct thread *B;

	A = list_entry(a, struct thread, elem);
	B = list_entry(b, struct thread, elem);

	if (A->priority > B->priority){

		return 1;
	} 
	return 0;

}
// test_max_priority()
// 현재 수행 중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링
void
test_max_priority(void) {
	//예외처리
	if(list_empty(&ready_list)){
		return;
	}

	struct thread *t;
	struct list_elem* max = list_begin(&ready_list);

	t = list_entry(max, struct thread, elem);

	if (t->priority > thread_get_priority())
		thread_yield();
	
	
}


/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {

	if(thread_mlfqs)	// mlfqs에서는 priority를 임의로 변경 못함 ->비활성화
		return;
	thread_current ()->origin_priority = new_priority;
	refresh_priority(); // 현 thread의 donations 리스트에 따라 우선순위 갱신
	test_max_priority();// 우선순위를 갱신한 경우에도 확인 필요

}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {

	
	enum intr_level old_level;
	old_level = intr_disable();
	struct thread *t = thread_current();
	thread_current()->nice = nice;
	mlfqs_priority(t);
	test_max_priority();
	intr_set_level(old_level);
	// 현재 스레드 nice값 변경
	// nice값 변경 후, 현재 스레드 우선순위 재계산
	// 우선순위에 의해 scheduling
	// 인터럽트를 비활성화 하는 이유? : 
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {

	enum intr_level old_level;
	old_level = intr_disable();
	int nice = thread_current()->nice;
	intr_set_level(old_level);

	return nice; // return값 nice로 받아야하는 것을 놓침!
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {

	enum intr_level old_level;
	old_level = intr_disable();
	int load_avg_value = fp_to_int_round(mult_mixed(load_avg, 100));
	intr_set_level(old_level);
	return load_avg_value; //return값을 load_avg_value로 정의하고 받아야하는 것을 놓침!
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	
	
	enum intr_level old_level;
	old_level = intr_disable();
	struct thread *t = thread_current();
	int recent_cpu = fp_to_int_round(mult_mixed(t->recent_cpu, 100));
	intr_set_level(old_level);
	return recent_cpu; //return값을 recent_cpu로 정의하고 받아야하는 것을 놓침!
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
// 인자 - thread_func *function : kernel이 실행할 함수, void *aux : sync를 위한 semaphore 등
// ensures that function that was run exits!!
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *); //thread내 intr_frame 구조체
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	
	/* project 1 donations */
	t->origin_priority = priority;
	list_init(&t->donors);
	t->wait_on_lock = NULL;

	/* project 1 mlfqs */
	t->nice = NICE_DEFAULT;
	t->recent_cpu = RECENT_CPU_DEFAULT;
	if(t != idle_thread) {
		list_push_back(&all_list, &t->all_elem);
	}

	/* project 2 */
	list_init(&t->child_list);
	sema_init(&t->wait_sema, 0);
	sema_init(&t->fork_sema, 0);
	sema_init(&t->free_sema, 0);
	t->running = NULL;
	// t -> exit_status = 0;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
//tf로 들어온 값들을 실제 CPU register에 넣어주기???
//이때 tf는 userstack일 수도, thread 구조체일수도
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n" //stack pointer rsp
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_remove(&curr->all_elem);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

// 1) ticks = 자야할 시각(이 시각이 지나야 깨서도 running 상태로 갈 수 있음)
// 2) next_tick_to_awake = 스레드들 중에서 자야할 최소 시각
//    ex) 1,2,3 스레드 중에서 자야할 최소시각이 적은 스레드의 ticks값으로 갱신해준다
void update_next_tick_to_awake(int64_t ticks){
	next_tick_to_awake = (next_tick_to_awake>ticks) ? ticks : next_tick_to_awake;
} 

int64_t get_next_tick_to_awake(void) {
	return next_tick_to_awake;
}

void thread_sleep(int64_t ticks){
	/* 현재 실행되고 있는 스레드에 대한 작업이므로. */
	struct thread* cur = thread_current();

	/* 인터럽트 disable*/
	enum intr_level old_level;
	ASSERT(!intr_context());
	old_level = intr_disable(); // 스레드를 list에 추가해주는 일은 인터럽트가 걸리면 안 된다.	

	ASSERT(cur != idle_thread);  // idle thread라면 종료.

	cur->wakeup_tick = ticks;						// wakeup_tick 업데이트
	update_next_tick_to_awake(cur->wakeup_tick); 	// next_tick_to_awake 업데이트(새로 들어온 것이 더 작은값인지 확인)
	list_push_back (&sleep_list, &cur->elem);		// sleep_list에 끝에 추가

	/* 스레드를 sleep 시킨다. */
	thread_block();

	/* 인터럽트 원복 */
	intr_set_level(old_level);
}

void thread_awake(int64_t ticks){
	struct list_elem* cur = list_begin(&sleep_list); //리스트의 처음 원소
	struct thread* t;
	next_tick_to_awake = INT64_MAX; // 초기화를 해주기 위해서는 MAX값으로 초기값 설정해줘야한다.


	/* sleep list의 끝까지 순환한다. */
	while(cur != list_end(&sleep_list)){ // list_end는 꼬리를 반환
		t = list_entry(cur, struct thread, elem); // list 원소를 스레드 구조체의 주소로 바꿔주고 포인터로 정의된 t에 주소값을 넣어준다

		if (ticks >= t->wakeup_tick){  // 깨울 시간이 지났다
			cur = list_remove(&t->elem); // 스레드 구조체의 elem를 제거하고 cur에 넣어줌
			thread_unblock(t);           // status를 unblock상태로 바꿔준다.
		}
		else{  // 아직 안 깨워도 된다 : 다음 쓰레드로 넘어간다.
			cur = list_next(cur);
			update_next_tick_to_awake(t->wakeup_tick);  // next_tick이 바뀌었을 수 있으므로 업데이트해준다.
		}
	}
}

void donate_priority(void){
	// thread_current()의 wait_on_lock의 holder의 -> donors를 훑자
	// struct thread *t = thread_current();

	/*
	 현재 스레드가 기다리고 있는 lock과 연결된 모든 스레드들을 훑은다
	 priority를 lock을 보유하고 있는 thread에게 기부
	 nested(연결된, 연쇄적인) lock을 고려 -> 해당 lock과 관련있는 모든 thread들에게 기부
	 하나의 스레드가 복수개의 lock을 획득해야하는 경우 lock acquire이 반복 실행 -> 이 함수도 반보길행
	 nested depth = 8로 제한
	*/
	struct thread *t = thread_current();
	for(int i = 0; i<8 ; i++) {
		if (t->wait_on_lock == NULL){	//훑은 스레드가 원하는 lock이 없다면 중지
			break;
		}		
		t->wait_on_lock->holder->priority = t->priority;
		t = t->wait_on_lock->holder;
	}
}


/*
스레드의 우선순위가 변경 되었을 때, donation을 고려하여 우선순위를 다시 결정하는 함수 
현재 스레드의 우선순위를 기부받기 전의 우선순위로 변경
가장 우선순위가 높은 donations 리스트의 thread와 현재 thread의 우선순위를 비교하여 높은 값을 현재 thread의 우선순위로 설정
*/
void refresh_priority(void){
	struct thread  *t = thread_current();

	t->priority = t->origin_priority;
	if(!list_empty(&t->donors)) {
		int max_prio = list_entry(list_begin(&t->donors), struct thread, d_elem)->priority;
		if (t->priority < max_prio){
			t->priority = max_prio;
		}
	}
}

/*
lock을 해지했을 때, donations 리스트에서 해당 엔트리를 삭제하기 위한 함수
현재 thread의 donations 리스트를 확인하여 해지할 lock을 보유하고 있는 엔트리를 삭제
*/

void remove_with_lock(struct lock *lock){ // 해제되는 lock을 인자로 받음


	struct thread *t = thread_current();
	struct list_elem *e;		//donation elem
	for (e = list_begin (&t->donors); e != list_end (&t->donors); e = list_next (e)){
		struct thread *t = list_entry(e, struct thread, d_elem);
		if (lock == t->wait_on_lock){
			list_remove(&t->d_elem);
		}

	}

}

// donors 우선순위 비교도 따로 구현해줘야한다. 
// list_elem으로 받으면 문제점 
// -> list_elem은 현재 값을 담고 있고, 여기서는 새로운 값을 담기 때문에 갱신이 되버려서 문제가 된다.

bool
cmp_donors_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	struct thread *donors_A;
	struct thread *donors_B;

	donors_A = list_entry(a, struct thread, d_elem);
	donors_B = list_entry(b, struct thread, d_elem);

	if (donors_A->priority > donors_B->priority){

		return 1;
	} 
	return 0;

}

void mlfqs_priority (struct thread *t){

	if(t == idle_thread)
		return;
	t->priority =  fp_to_int(add_mixed(div_mixed(t->recent_cpu, -4) , PRI_MAX - t->nice*2));
 // t->recent_cpu -4로 놓고 sub로 써버렸음
 // priority는 정수기 때문에 fp_to_int를 해줘야하는데 안해줌
}

void mlfqs_recent_cpu(struct thread *t){
	if(t == idle_thread)
		return;
	t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg,2),add_mixed(mult_mixed(load_avg,2),1)), t->recent_cpu), t->nice);
} // add_fp, add_mixed 구분하지 못했음

void mlfqs_load_avg(void){

	int ready_threads;
	if (thread_current() == idle_thread){
		ready_threads = list_size(&ready_list); 
	}
	else{
		ready_threads = list_size(&ready_list) + 1;
	}

	load_avg = add_fp(mult_fp(div_fp(int_to_fp(59), int_to_fp(60)), load_avg), mult_mixed(div_fp(int_to_fp(1),int_to_fp(60)), ready_threads));
	
	if (load_avg < 0){
		load_avg = LOAD_AVG_DEFAULT;
	}
	//load_avg(system값이라 idle일 때도 실행) 값을 바꿔주는 것을 생각하지 못했음
}


// idle 조건 넣을 때, ASSERT로 사용했었는데 -> 프로세스 종료되버려서 무조건 if문 써야한다.
void mlfqs_increment(void){

	struct thread *t = thread_current();
	if(t != idle_thread){
		t->recent_cpu = add_mixed(t->recent_cpu,1); 
	}
} 

/* ready, sleep, current 스레드의 리스트를 받아서 동작 시켜주는 코드*/
// 이 코드는 현재 test case에서는 통과를 한다 -> 현재 테스트에서는 lock을 요청하는 부분이 없는 것 같다 (그래서 통과하는듯)
// lock_acquire() -> sema_down(watiers 리스트에 들어감) -> block -> schedule -> launch(running <-> block) -> 따로 list에 안들어감
// 따라서 watiers를 고려하지 않았기 때문에 recent_cpu가 다시 계산이 되지 않고 -> 처리되지 않는 스레드가 발생한다!

// void mlfqs_recalc(void){

// 	struct list_elem *e;
// 	struct thread *t_c = thread_current();
	
// 	if(t_c != idle_thread){
// 		mlfqs_priority(t_c);
// 		mlfqs_recent_cpu(t_c);
// 	}	

		
// 	for (e = list_begin (&ready_list); e != list_end (&ready_list); e = list_next (e)){
// 		struct thread *t_r = list_entry(e, struct thread, elem);
// 			mlfqs_priority(t_r);
// 			mlfqs_recent_cpu(t_r);
		
// 		}


// 	for (e = list_begin (&sleep_list); e != list_end (&sleep_list); e = list_next (e)){
// 		struct thread *t_s = list_entry(e, struct thread, elem);
// 			mlfqs_priority(t_s);
// 			mlfqs_recent_cpu(t_s);
// 		}
// 	return;


// }


/* thread 생성시 all list를 생성하여 관리한다 */
// 이렇게 하면 어떤 thread들도 누락되지 않고 계산될 수 있다.
// 1) all_list 선언 2) all_list list 초기화 3) curr 스레드 종료 시, list에서 삭제 4) mlfqs_recal(all list) 계산함수 구현 
// 문제가 있다면 -> all list를 삭제해줘야하는데
// 이 부분은 schedule()함수 호출이 되고, curr 스레드가 종료 된다면 curr->status == THREAD_DYING 조건문 안에
// all_list에서 삭제 해주면 된다. 
void mlfqs_recalc(void)
{
	struct list_elem *e;
	for(e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)){
		mlfqs_recent_cpu(list_entry(e, struct thread, all_elem));
		mlfqs_priority(list_entry(e, struct thread, all_elem));
	}

}