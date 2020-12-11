/* * * * * * * * * * * * * * * * * * * * * 
* Syscall file for LAB2 PDS
* This file contain the "exit()" syscall
* used to terminate a process.
*
*
*
*
* * * * * * * * * * * * * * * * * * * * */

#include <types.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <lib.h>
#include <syscall.h>
#include <proc.h>
#include <clock.h>
#include <copyinout.h>
#include <thread.h>
#include <kern/fcntl.h>
#include <vm.h>
#include <vfs.h>
#include <addrspace.h>
#include <current.h>
#include <cdefs.h> /* for __DEAD */
#include <mips/trapframe.h>
#include <synch.h>
#include <test.h>
#include <kern/wait.h>
#if OPT_SHELL

extern struct tableOpenFile TabFile;

void
sys__exit(int status)
{
	struct proc *p = curproc;
	/*Let's create the error code in a linux fashion:*/
	p->p_status = _MKWAIT_EXIT(status);
	proc_remthread(curthread);
	V(p->p_sem);
	if(p ->wnohang)
		proc_destroy(p);
	thread_exit();
	panic("thread_exit returned\n");

}

int
sys_waitpid(pid_t pid, userptr_t statusp, int options,pid_t* retval)
{
	*retval = -1;
	int flg = 0;
	/*Here we assume that pid can be only positive: no concept of group id*/
	if (pid <= 0){
		return ENOSYS;
	}
	if(pid >= PID_MAX || pid >= MAX_PROC || pid == curproc->p_pid || pid == curproc->parent_p_pid)
		return ECHILD;
	struct proc *p = proc_search_pid(pid);
	int s,s1;
	if(options!=0) //TO DO: Gestire le opzioni
		if(options!= WNOHANG && options != WUNTRACED && options != (WNOHANG||WUNTRACED) )
			return EINVAL;
	if (p==NULL){
		return ESRCH;
	}
	if( (options & WNOHANG) == WNOHANG){
		flg = 1;
		p->wnohang = 1;
	}
	if(!flg)
		s = proc_wait(p);
	else
		s = 0;
	if (statusp!=NULL)
	{
	int result = copyout(&s, (userptr_t) statusp, sizeof(int));

	if(result)
		return result;
	if(copyin((userptr_t) statusp,&s1, sizeof(int)))
		kprintf("bruh...2\n");

	//memcpy(ret, &pid, sizeof(int));
	}
	*retval = pid;
	return 0;
}

int
sys_getpid(pid_t* retval)
{
  KASSERT(curproc != NULL);
  *retval = curproc->p_pid;
  return 0;
}

static void
call_enter_forked_process(void *tfv, unsigned long dummy) {
  struct trapframe *tf = (struct trapframe *)tfv;
  (void)dummy;
  enter_forked_process(tf); 
 
  panic("enter_forked_process returned (should not happen)\n");
}

int sys_fork(struct trapframe *ctf,pid_t* retval) {

	struct trapframe *tf_child;
	struct proc *newp;
	int result;

	KASSERT(curproc != NULL);

	newp = proc_create_runprogram(curproc->p_name);
	if (newp == NULL) {
		return ENOMEM;
	}
	as_copy(curproc->p_addrspace, &(newp->p_addrspace));
	if(newp->p_addrspace == NULL){
		proc_destroy(newp); 
		return ENOMEM; 
	}

	proc_file_table_copy(curproc, newp);
	tf_child = kmalloc(sizeof(struct trapframe));
	if(tf_child == NULL){
		proc_destroy(newp);
		return ENOMEM; 
	}
	memcpy(tf_child, ctf, sizeof(struct trapframe));

	/* TO BE DONE: linking parent/child, so that child terminated 
		on parent exit */
	newp->parent_p_pid = curproc->p_pid;
	result = thread_fork(
			curthread->t_name, newp,
			call_enter_forked_process, 
			(void *)tf_child, (unsigned long)0/*unused*/);

	if (result){
		proc_destroy(newp);
		kfree(tf_child);
		return ENOMEM;
  }

 
	*retval = newp->p_pid;
  return  0;
}

struct lock* exec_lk = NULL;
static 
void sys_exec_init(){
	if (exec_lk == NULL)
		exec_lk = lock_create("Exec_lock");
}

int sys_execv(char *progname, char *args[]){
	
	struct addrspace *as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;
	int argc=0;
	int i = 0,len,j,k;
	struct addrspace * old_as;
	sys_exec_init();
	lock_acquire(exec_lk);
	char* garbage = kmalloc( (ARG_MAX+1));
	char* path_name = kmalloc( (PATH_MAX+1));
	size_t size = 0;
	int end = 0;
	result = copyinstr((userptr_t)progname, path_name, PATH_MAX, &size);
	if(result){
		kfree(path_name);
		kfree(garbage);
		lock_release(exec_lk);
		return result;

	}	


	i = 0;
	{
		/* switch every args from user to kernel space: control if they are ok */
		result = copyinstr((userptr_t)args, garbage, ARG_MAX, &size);
		if (result){
			kfree(path_name);
			kfree(garbage);
			lock_release(exec_lk);
			return result;
		}
		while (!end)
		{
			size = 0;
			if(args[i] == NULL){
				break;
			}
			result = copyinstr((userptr_t)args[i], garbage, ARG_MAX, &size);
				if (result){
					kfree(path_name);
					kfree(garbage);
					lock_release(exec_lk);
					return result;
				}
			i++;
			if(size == 0)
				end = 1;


		}
		argc = i;
	}
	/* No need it anymore */ 
	kfree(garbage);
	vaddr_t topstack[argc];
	/* a pointer is 4 bytes long in our architecture */
	char nullbytes[4];
	for (i = 0; i < 4 ; i++)
		nullbytes[i] = 0x00;
	/*argv will containt the args to be copied into the stack */
	if (argc > 300){
		kfree(path_name);
		lock_release(exec_lk);
		return E2BIG;
	}

	char** argv = (char **) kmalloc(argc * sizeof (char *));
	/* memory is full */
	if (!argv) {
		kfree(path_name);
		lock_release(exec_lk);
	   	return ENOMEM;
	}

	int tot_len = 0;
	/* looping through the arguments to copy into the new array: thery are safe for sure */
	for (i = 0;i < argc; i++) {
		/*4 bytes padding*/
	len = strlen(args[i]) + 4 - (strlen(args[i]) % 4); 
	tot_len+=len;
	/*Problem: passed more than arg max bytes */

	if(tot_len>= ARG_MAX){
		for (k = 0;k < i; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		lock_release(exec_lk);
		return E2BIG;
	}
	
	argv[i] = (char *) kmalloc(len);

	/* can't allocate arg[i] */
	if (!argv[i]) {
		for (k = 0;k < i; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		lock_release(exec_lk);
		return ENOMEM;
	}

	/* Put '\0' in each of the spots. */
	for (j = 0; j < len; j++)
	    argv[i][j] = '\0';

	/* copy the arguments into argv. Also copyin can be used
	 Can't fail: we already tested args*/
	memcpy(argv[i], args[i], strlen(args[i]));
	}

	/* Here in argv there are all the arguments 4-bytes aligned. */


	/* Open the file. */
	result = vfs_open(path_name, O_RDONLY, 0, &v);
	if (result) {
		for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		lock_release(exec_lk);
		return result;
	}
	/* We are in a running prcoess */
	KASSERT(proc_getas() != NULL);
	old_as = curproc->p_addrspace;
	/* Create a new address space. */
	as = as_create();
	if (as == NULL) {
		vfs_close(v);
		int k;
		for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		lock_release(exec_lk);
		return ENOMEM;
	}

	/* Switch to it and activate it. */
	proc_setas(as);
	as_activate();

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
		for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		proc_setas(old_as);
		vfs_close(v);
		lock_release(exec_lk);
		return result;
	}
	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(as, &stackptr);
	if (result) {
		for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		kfree(path_name);
		proc_setas(old_as);
		vfs_close(v);
		lock_release(exec_lk);
		return result;
	}
	/* Done with it */

	kfree(path_name);
	/* Copy arguments from the kernel to the users stack. */

	size_t actual;
	
	/* Looping through the array to copy the arguments into the stack.
	The stack is bottom up, so we start with the last argument of argv */

	for (i = argc - 1; i >= 0; i--) {
	len = strlen(argv[i]) + 4 - (strlen(argv[i]) % 4);

	// Decrement the stack pointer to copy in the arguments.
	stackptr -= len;
	// copy the arguments into the stack and free them from argv.
	result = copyoutstr(argv[i],(userptr_t) stackptr,len,&actual);
	if(result != 0){
	    for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		lock_release(exec_lk);
	    return result;
	}
	// save the stack address of the arguments in the original order.
	topstack[argc - i - 1] = stackptr;
	}
	// decrement the stack pointer and add 4 null bytes of padding.
	stackptr -= 4;
	
	result  = copyoutstr(nullbytes,(userptr_t) stackptr,4,&actual);
	if(result != 0){
	    for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		lock_release(exec_lk);
	    return result;
	}

	// writing the addresses of the arguments in the stack, into the stack.
	for (i = 0; i < argc; i++) {
	stackptr -= 4;
	result  = copyout((void*)&topstack[i],(userptr_t) stackptr,4);
	if(result != 0){
	    for (k = 0;k < argc; k++) {
			kfree(argv[k]);
		}
		kfree(argv);
		lock_release(exec_lk);
	    return result;
	}
	}

	for (k = 0;k < argc; k++) {
			kfree(argv[k]);
	}
	as_destroy(old_as);
	kfree(argv);
	lock_release(exec_lk);

	/* Warp to user mode. */

	enter_new_process(argc /*argc*/, (userptr_t) stackptr/*userspace addr of argv*/,
			  NULL /*userspace addr of environment*/,
			  stackptr, entrypoint);

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
}
#endif
