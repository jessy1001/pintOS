threads_SRC  = threads/init.c		# Main program.
threads_SRC += threads/thread.c		# Thread management core.
threads_SRC += threads/interrupt.c	# Interrupt core.
threads_SRC += threads/intr-stubs.S	# Interrupt stubs.
threads_SRC += threads/synch.c		# Synchronization.
threads_SRC += threads/palloc.c		# Page allocator.
threads_SRC += threads/malloc.c		# Subpage allocator.
threads_SRC += threads/start.S		# Startup code.
threads_SRC += threads/mmu.c		    # Memory management unit related things.
<<<<<<< HEAD
threads_SRC += threads/fixed_point.c #부동소수점 연산 헤더
=======
threads_SRC += threads/fixed_point.c	
>>>>>>> d8240afe8c4871f5c2284927748749fd5f57f530
