

#include <types.h>
#include <kern/stattypes.h>
#include <kern/unistd.h>
#include <kern/errno.h>
#include <clock.h>
#include <syscall.h>
#include <current.h>
#include <lib.h>
#include <vm.h>

#include <copyinout.h>
#include <vnode.h>
#include <vfs.h>

#include <synch.h>
#include <uio.h>
#include <kern/fcntl.h>

#if OPT_SHELL
#include <kern/stat.h>
#include <kern/seek.h>
#include <copyinout.h>

/* system open file table */

struct tableOpenFile TabFile;

int sys_chdir(const char *pathname, int32_t *retval)
{
  char *path = kmalloc(sizeof(char) * PATH_MAX);
  size_t len;
  int result;

  if (pathname == NULL)
  {
    kfree(path);
    *retval = -1;
    return EFAULT;
  }

  result = copyinstr((userptr_t)pathname, path, PATH_MAX, &len);
  if(result)
  {
    kfree(path);
    *retval = -1;
    return result;
  }
  result = vfs_chdir(path);
  if (result)
  {
    kfree(path);
    *retval = -1;
    return result;
  }
  kfree(path);
  *retval = 0;
  return 0;
}

int sys__getcwd(char *buf, size_t buflen, int32_t *retval)
{
  struct iovec iov;
  struct uio ku;
  int result;
  size_t size;

  if (buflen <= 0)
  {
    *retval = -1;
    return EINVAL;
  }

  if (buf == NULL)
  {
    *retval = -1;
    return EFAULT;
  }

  char *name = kmalloc(sizeof(char) * buflen);

  uio_kinit(&iov, &ku, name, buflen, 0, UIO_READ);
  result = vfs_getcwd(&ku);
  if (result)
  {
    kfree(name);
    *retval = -1;
    return result;
  }

  result = copyoutstr((const void *)name, (userptr_t)buf, buflen, &size);
  if(result)
  {
    kfree(name);
    *retval = -1;
    return result; 
  }

  *retval = buflen - ku.uio_resid;
  kfree(name);
  return 0;
}
/* struct proc *p may be not null due to the integration of console ( Open of stdin/out/err )
 classic call in arch/mips/syscall/syscall.c struct proc*p is always NULL */
int sys_open(struct proc *p, userptr_t path, int openflags, mode_t mode, int32_t *retval)
{

  int result, fd, i, pos = -1;
  struct vnode *v = NULL;
  struct openfile *of = NULL;
  char *kpath = kmalloc(sizeof(char) * PATH_MAX);
  size_t len;

  if (path == NULL)
  {
    *retval = -1;
    kfree(kpath);
    return EFAULT;
  }

  if (p == NULL)
  {
    if ((openflags & O_ACCMODE) >= 3 || (openflags & 0xFFFFFF80) != 0)
    {
      *retval = -1;
      kfree(kpath);
      return EINVAL;
    }
    p = curproc;
    result = copyinstr(path, kpath, PATH_MAX, &len);
    if(result)
    {
      *retval = -1;
      return result;
    }
    result = vfs_open((char *)kpath, openflags, mode, &v);
  }
  else
  {
    result = vfs_open((char *)path, openflags, mode, &v);
  }

  if (result)
  {
    *retval = -1;
    kfree(kpath);
    return result;
  }

  lock_acquire(TabFile.lk);

  for (i = 0; i < SYSTEM_OPEN_MAX; i++)
  {
    if (TabFile.systemFileTable[i].vn == v)
    {
      pos = i;
      break;
    }
    if (TabFile.systemFileTable[i].vn == NULL && pos == -1)
    {
      pos = i;
    }
  }

  for (fd = 0; fd < OPEN_MAX; fd++)
  {
    if (p->fileTable[fd] == NULL)
      break;
  }

  if (pos == -1 || fd == OPEN_MAX)
  {
    *retval = -1;
    vfs_close(v);
    kfree(kpath);
    lock_release(TabFile.lk);
    if (pos == -1)
      return ENFILE;
    if (fd == OPEN_MAX)
      return EMFILE;
  }

  of = &TabFile.systemFileTable[pos];

  if (TabFile.systemFileTable[pos].vn == NULL)
  {
    of->vn = v;
    of->countRef = 0;
    of->reader = 0;
    of->writer = 0;
    of->lk_reader = lock_create("lk_reader");
    of->lk_writer = lock_create("lk_writer");
  }

  TabFile.systemFileTable[pos].countRef++;

  p->fileTable[fd] = kmalloc(sizeof(struct fileTableEntry));
  p->fileTable[fd]->of = of;
  p->fileTable[fd]->offset = 0;
  p->fileTable[fd]->flags = openflags;
  p->fileTable[fd]->fd = fd;
  p->fileTable[fd]->fteCnt = 1;
  p->fileTable[fd]->fte_lock = lock_create("fte_lock");
  *retval = fd;
  kfree(kpath);
  lock_release(TabFile.lk);
  return 0;
}

int sys_close(int fd, int32_t *retval)
{

  struct openfile *of = NULL;
  struct fileTableEntry *fte = NULL;
  struct vnode *vn;

  if (fd < 0 || fd >= OPEN_MAX)
  {
    *retval = -1;
    return EBADF;
  }

  fte = curproc->fileTable[fd];
  if (fte == NULL)
  {
    *retval = -1;
    return EBADF;
  }

  lock_acquire(curproc->close_lk);
  lock_acquire(fte->fte_lock);
  lock_release(curproc->close_lk);

  of = curproc->fileTable[fd]->of;
  curproc->fileTable[fd] = NULL;

  fte->fteCnt--;
  if (fte->fteCnt == 0)
  {
    lock_destroy(fte->fte_lock);
    kfree(fte);
    lock_acquire(TabFile.lk);
    of->countRef--;
    if (of->countRef == 0)
    {
      vn = of->vn;
      of->vn = NULL;
      lock_destroy(of->lk_reader);
      lock_destroy(of->lk_writer);
      vfs_close(vn);
    }
    *retval = 0;
    lock_release(TabFile.lk);
    return 0;
  }

  lock_release(fte->fte_lock);
  *retval = 0;
  return 0;
}

int sys_lseek(int fd, off_t pos, int whence, int64_t *retval)
{
  struct stat stats;
  off_t offset;
  mode_t result;

  if (fd < 0 || fd >= OPEN_MAX)
  {
    *retval = -1;
    return EBADF;
  }

  lock_acquire(curproc->close_lk);

  if (curproc->fileTable[fd] == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  lock_acquire(curproc->fileTable[fd]->fte_lock);

  lock_release(curproc->close_lk);

  VOP_GETTYPE(curproc->fileTable[fd]->of->vn, &result);
  if (result == _S_IFCHR || result == _S_IFBLK)
  {
    *retval = -1;
    lock_release(curproc->fileTable[fd]->fte_lock);
    return ESPIPE;
  }

  switch (whence)
  {
  case SEEK_SET:
    offset = pos;
    break;

  case SEEK_CUR:
    offset = curproc->fileTable[fd]->offset + pos;
    break;

  case SEEK_END:
    VOP_STAT(curproc->fileTable[fd]->of->vn, &stats);
    offset = stats.st_size + pos;
    break;

  default:
    *retval = -1;
    lock_release(curproc->fileTable[fd]->fte_lock);
    return EINVAL;
    break;
  }

  if (offset < 0)
  {
    *retval = -1;
    lock_release(curproc->fileTable[fd]->fte_lock);
    return EINVAL;
  }

  curproc->fileTable[fd]->offset = offset;
  *retval = offset;
  lock_release(curproc->fileTable[fd]->fte_lock);
  return 0;
}

int sys_dup2(int oldfd, int newfd, int32_t *retval)
{
  struct fileTableEntry *fte = NULL;
  int result;

  if (oldfd < 0 || oldfd >= OPEN_MAX || newfd < 0 || newfd >= OPEN_MAX)
  {
    *retval = -1;
    return EBADF;
  }

  lock_acquire(curproc->close_lk);

  fte = curproc->fileTable[oldfd];
  if (fte == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  lock_acquire(fte->fte_lock);

  lock_release(curproc->close_lk);

  if (curproc->fileTable[newfd] != NULL)
  {
    if (oldfd == newfd)
    {
      *retval = oldfd;
      lock_release(fte->fte_lock);
      return 0;
    }

    result = sys_close(newfd, retval);
    if (result)
    {
      lock_release(fte->fte_lock);
      return result;
    }
  }

  fte->fteCnt++;
  curproc->fileTable[newfd] = fte;

  *retval = newfd;
  lock_release(fte->fte_lock);
  return 0;
}

int sys_write(int fd, userptr_t buf_ptr, size_t size, int32_t *retval)
{

  struct iovec iov;
  struct uio ku;
  off_t offset;
  struct stat *stats = NULL;
  int nwrite, result;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd >= OPEN_MAX)
  {
    *retval = -1;
    return EBADF;
  }

  lock_acquire(curproc->close_lk);

  if (curproc->fileTable[fd] == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  if (buf_ptr == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EFAULT;
  }

  of = curproc->fileTable[fd]->of;
  if (of == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  if ((curproc->fileTable[fd]->flags & O_ACCMODE) == O_RDONLY)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  if (curproc->fileTable[fd]->flags & O_APPEND)
  {
    VOP_STAT(of->vn, stats);
    offset = stats->st_size;
  }
  else
  {
    offset = curproc->fileTable[fd]->offset;
  }
  vn = of->vn;
  if (vn == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  lock_acquire(curproc->fileTable[fd]->fte_lock);

  lock_release(curproc->close_lk);

  lock_acquire(of->lk_writer);

  kbuf = kmalloc(size);
  result = copyin(buf_ptr, kbuf, size);
  if(result)
  {
    *retval = -1;
    kfree(kbuf);
    lock_release(of->lk_writer);
    lock_release(curproc->fileTable[fd]->fte_lock);
    return result;
  }
  uio_kinit(&iov, &ku, kbuf, size, offset, UIO_WRITE);
  result = VOP_WRITE(vn, &ku);

  if (result)
  {
    *retval = -1;
    kfree(kbuf);
    lock_release(of->lk_writer);
    lock_release(curproc->fileTable[fd]->fte_lock);
    return result;
  }
  kfree(kbuf);
  curproc->fileTable[fd]->offset = ku.uio_offset;
  nwrite = size - ku.uio_resid;
  *retval = nwrite;
  lock_release(of->lk_writer);
  lock_release(curproc->fileTable[fd]->fte_lock);
  return 0;
}

int sys_read(int fd, userptr_t buf_ptr, size_t size, int32_t *retval)
{

  struct iovec iov;
  struct uio ku;
  off_t offset;
  int nread, result;
  struct vnode *vn;
  struct openfile *of;
  void *kbuf;

  if (fd < 0 || fd >= OPEN_MAX)
  {
    *retval = -1;
    return EBADF;
  }

  lock_acquire(curproc->close_lk);

  if (curproc->fileTable[fd] == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  if (buf_ptr == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EFAULT;
  }
  of = curproc->fileTable[fd]->of;
  offset = curproc->fileTable[fd]->offset;

  if (of == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  if ((curproc->fileTable[fd]->flags & O_ACCMODE) == O_WRONLY)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  vn = of->vn;
  if (vn == NULL)
  {
    *retval = -1;
    lock_release(curproc->close_lk);
    return EBADF;
  }

  lock_acquire(curproc->fileTable[fd]->fte_lock);
  lock_release(curproc->close_lk);
  lock_acquire(of->lk_reader);
  of->reader++;
  if (of->reader == 1)
  {
    lock_acquire(of->lk_writer);
  }
  lock_release(of->lk_reader);

  kbuf = kmalloc(size);
  uio_kinit(&iov, &ku, kbuf, size, offset, UIO_READ);
  result = VOP_READ(vn, &ku);

  if (result)
  {
    *retval = -1;
    kfree(kbuf);
    lock_acquire(of->lk_reader);
    of->reader--;
    if (of->reader == 0)
    {
      lock_release(of->lk_writer);
    }
    lock_release(of->lk_reader);
    lock_release(curproc->fileTable[fd]->fte_lock);
    return result;
  }
  curproc->fileTable[fd]->offset = ku.uio_offset;
  nread = size - ku.uio_resid;
  if(nread != 0)
  {
    result = copyout(kbuf, buf_ptr, nread);
    if(result)
    {
      *retval = -1;
    }
    else
    {
      *retval = nread;
    }
  }
  else
  {
    result = 0;
    *retval = 0;
  }
  

  kfree(kbuf);
  lock_acquire(of->lk_reader);
  of->reader--;
  if (of->reader == 0)
  {
    lock_release(of->lk_writer);
  }
  lock_release(of->lk_reader);
  lock_release(curproc->fileTable[fd]->fte_lock);
  return result;
}

int sys_remove(userptr_t pathname, int32_t *retval)
{
  char name[NAME_MAX + 1];
  size_t len;
  //From user ptr to kernel space
  int result;
  *retval = -1; 
  result = copyinstr(pathname, name, NAME_MAX, &len);
  if (result)
  {
    return result;
  }

  result = vfs_remove(name);
  if (result)
  {
    return result; 
  }
  *retval = 0;
  return 0;
}
#endif
