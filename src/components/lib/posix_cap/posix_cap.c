#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <time.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <cos_component.h>
#include <cos_defkernel_api.h>
#include <llprint.h>
#include <posix.h>
#include <ps_list.h>
#include <memmgr.h>
#include <contigmem.h>

static struct ps_lock stdout_lock;

ssize_t
write_bytes_to_stdout(const char *buf, size_t count)
{
	size_t i;
	for (i = 0; i < count; i++) printc("%c", buf[i]);
	return count;
}

ssize_t
cos_write(int fd, const void *buf, size_t count)
{
	/* You shouldn't write to stdin anyway, so don't bother special casing it */
	if (fd == 1 || fd == 2) {
		ps_lock_take(&stdout_lock);
		write_bytes_to_stdout((const char *) buf, count);
		ps_lock_release(&stdout_lock);
		return count;
	} else {
		printc("fd: %d not supported!\n", fd);
		assert(0);
	}
}

ssize_t
cos_writev(int fd, const struct iovec *iov, int iovcnt)
{
	if (fd == 1 || fd == 2) {
		ps_lock_take(&stdout_lock);
		int i;
		ssize_t ret = 0;
		for (i=0; i<iovcnt; i++) {
			ret += write_bytes_to_stdout((const void *)iov[i].iov_base, iov[i].iov_len);
		}
		ps_lock_release(&stdout_lock);
		return ret;
	} else {
		printc("fd: %d not supported!\n", fd);
		assert(0);
	}
}

long
cos_ioctl(int fd, int request, void *data)
{
	/* musl libc does some ioctls to stdout, so just allow these to silently go through */
	if (fd == 1 || fd == 2) return 0;

	printc("ioctl on fd(%d) not implemented\n", fd);
	assert(0);
	return 0;
}

ssize_t
cos_brk(void *addr)
{
	// printc("brk not implemented\n");
	/* Unsure if the below comment is accurate. We return 0, so doesn't brk "succeed"? */
	/* musl libc tries to use brk to expand heap in malloc. But if brk fails, it
	   turns to mmap. So this fake brk always fails, force musl libc to use mmap */
	return 0;
}

void *
cos_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret=0;
	// printc("mmap sz:%luKB(%luMB)\n", length/1024, length/1024/1024);

	if (addr != NULL) {
		printc("parameter void *addr is not supported!\n");
		errno = ENOTSUP;
		return MAP_FAILED;
	}
	if (fd != -1) {
		printc("file mapping is not supported!\n");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	addr = (void *)contigmem_alloc((length / PAGE_SIZE));
	if (!addr){
		ret = (void *) -1;
	} else {
		memset(addr, 0, length);
		ret = addr;
	}

	if (ret == (void *)-1) {  /* return value comes from man page */
		printc("mmap() failed!\n");
		/* This is a best guess about what went wrong */
		errno = ENOMEM;
	}
	return ret;
}

int
cos_munmap(void *start, size_t length)
{
	printc("munmap not implemented\n");
	errno = ENOSYS;
	return -1;
}

int
cos_madvise(void *start, size_t length, int advice)
{
	/* We don't do anything with the advice from madvise, but that isn't really a problem */
	return 0;
}

void *
cos_mremap(void *old_address, size_t old_size, size_t new_size, int flags)
{
	printc("mremap not implemented\n");
	errno = ENOSYS;
	return (void*) -1;
}

int
cos_mprotect(void *addr, size_t len, int prot)
{
	/* Musl uses this at thread create time */
	printc("mprotect not implemented\n");
	return 0;
}

void
libc_posixcap_initialization_handler()
{
	ps_lock_init(&stdout_lock);
	libc_syscall_override((cos_syscall_t)(void*)cos_write, __NR_write);
	libc_syscall_override((cos_syscall_t)(void*)cos_writev, __NR_writev);
	libc_syscall_override((cos_syscall_t)(void*)cos_ioctl, __NR_ioctl);
	libc_syscall_override((cos_syscall_t)(void*)cos_brk, __NR_brk);
	libc_syscall_override((cos_syscall_t)(void*)cos_munmap, __NR_munmap);
	libc_syscall_override((cos_syscall_t)(void*)cos_madvise, __NR_madvise);
	libc_syscall_override((cos_syscall_t)(void*)cos_mremap, __NR_mremap);
	libc_syscall_override((cos_syscall_t)(void*)cos_mprotect, __NR_mprotect);
	libc_syscall_override((cos_syscall_t)(void*)cos_mmap, __NR_mmap);
}
