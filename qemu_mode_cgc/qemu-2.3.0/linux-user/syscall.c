/*
 *  Linux syscalls
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#define _ATFILE_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/swap.h>
#include <linux/capability.h>
#include <signal.h>
#include <sched.h>
#ifdef __ia64__
int __clone2(int (*fn)(void *), void *child_stack_base,
             size_t stack_size, int flags, void *arg, ...);
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/times.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/statfs.h>
#include <utime.h>
#include <sys/sysinfo.h>
//#include <sys/user.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/wireless.h>
#include <linux/icmp.h>
#include "qemu-common.h"
#ifdef CONFIG_TIMERFD
#include <sys/timerfd.h>
#endif
#ifdef TARGET_GPROF
#include <sys/gmon.h>
#endif
#ifdef CONFIG_EVENTFD
#include <sys/eventfd.h>
#endif
#ifdef CONFIG_EPOLL
#include <sys/epoll.h>
#endif
#ifdef CONFIG_ATTR
#include "qemu/xattr.h"
#endif
#ifdef CONFIG_SENDFILE
#include <sys/sendfile.h>
#endif

#define termios host_termios
#define winsize host_winsize
#define termio host_termio
#define sgttyb host_sgttyb /* same as target */
#define tchars host_tchars /* same as target */
#define ltchars host_ltchars /* same as target */

#include <linux/termios.h>
#include <linux/unistd.h>
#include <linux/cdrom.h>
#include <linux/hdreg.h>
#include <linux/soundcard.h>
#include <linux/kd.h>
#include <linux/mtio.h>
#include <linux/fs.h>
#if defined(CONFIG_FIEMAP)
#include <linux/fiemap.h>
#endif
#include <linux/fb.h>
#include <linux/vt.h>
#include <linux/dm-ioctl.h>
#include <linux/reboot.h>
#include <linux/route.h>
#include <linux/filter.h>
#include <linux/blkpg.h>
#include "linux_loop.h"
#include "uname.h"

#include "qemu.h"

#include "randvals.h"


//erro no of cgc syscall
// #define EBADF       1
// #define EFAULT      2
// #define EINVAL      3
// #define ENOMEM      4
// #define ENOSYS      5
// #define EPIPE       6


#define CLONE_NPTL_FLAGS2 (CLONE_SETTLS | \
    CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)

//#define DEBUG

//#include <linux/msdos_fs.h>
#define VFAT_IOCTL_READDIR_BOTH   _IOR('r', 1, struct linux_dirent [2])
#define VFAT_IOCTL_READDIR_SHORT  _IOR('r', 2, struct linux_dirent [2])


#undef _syscall0
#undef _syscall1
#undef _syscall2
#undef _syscall3
#undef _syscall4
#undef _syscall5
#undef _syscall6

#define _syscall0(type,name)    \
static type name (void)     \
{         \
  return syscall(__NR_##name);  \
}

#define _syscall1(type,name,type1,arg1)   \
static type name (type1 arg1)     \
{           \
  return syscall(__NR_##name, arg1);  \
}

#define _syscall2(type,name,type1,arg1,type2,arg2)  \
static type name (type1 arg1,type2 arg2)    \
{             \
  return syscall(__NR_##name, arg1, arg2);  \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
static type name (type1 arg1,type2 arg2,type3 arg3)   \
{               \
  return syscall(__NR_##name, arg1, arg2, arg3);    \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4)  \
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4)      \
{                   \
  return syscall(__NR_##name, arg1, arg2, arg3, arg4);      \
}

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,  \
      type5,arg5)             \
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{                   \
  return syscall(__NR_##name, arg1, arg2, arg3, arg4, arg5);    \
}


#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,  \
      type5,arg5,type6,arg6)          \
static type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, \
                  type6 arg6)             \
{                   \
  return syscall(__NR_##name, arg1, arg2, arg3, arg4, arg5, arg6);  \
}


#define __NR_sys_uname __NR_uname
#define __NR_sys_getcwd1 __NR_getcwd
#define __NR_sys_getdents __NR_getdents
#define __NR_sys_getdents64 __NR_getdents64
#define __NR_sys_getpriority __NR_getpriority
#define __NR_sys_rt_sigqueueinfo __NR_rt_sigqueueinfo
#define __NR_sys_syslog __NR_syslog
#define __NR_sys_tgkill __NR_tgkill
#define __NR_sys_tkill __NR_tkill
#define __NR_sys_futex __NR_futex
#define __NR_sys_inotify_init __NR_inotify_init
#define __NR_sys_inotify_add_watch __NR_inotify_add_watch
#define __NR_sys_inotify_rm_watch __NR_inotify_rm_watch

#if defined(__alpha__) || defined (__ia64__) || defined(__x86_64__) || \
    defined(__s390x__)
#define __NR__llseek __NR_lseek
#endif

/* Newer kernel ports have llseek() instead of _llseek() */
#if defined(TARGET_NR_llseek) && !defined(TARGET_NR__llseek)
#define TARGET_NR__llseek TARGET_NR_llseek
#endif




#if defined(TARGET_NR__llseek) && defined(__NR_llseek)
_syscall5(int, _llseek,  uint,  fd, ulong, hi, ulong, lo,
          loff_t *, res, uint, wh);
#endif



#if defined(TARGET_NR_futex) && defined(__NR_futex)
_syscall6(int,sys_futex,int *,uaddr,int,op,int,val,
          const struct timespec *,timeout,int *,uaddr2,int,val3)
#endif


/* ARM EABI and MIPS expect 64bit types aligned even on pairs or registers */
#ifdef TARGET_ARM
static inline int regpairs_aligned(void *cpu_env) {
    return ((((CPUARMState *)cpu_env)->eabi) == 1) ;
}
#elif defined(TARGET_MIPS)
static inline int regpairs_aligned(void *cpu_env) { return 1; }
#elif defined(TARGET_PPC) && !defined(TARGET_PPC64)
/* SysV AVI for PPC32 expects 64bit parameters to be passed on odd/even pairs
 * of registers which translates to the same as ARM/MIPS, because we start with
 * r3 as arg1 */
static inline int regpairs_aligned(void *cpu_env) { return 1; }
#else
static inline int regpairs_aligned(void *cpu_env) { return 0; }
#endif

#define ERRNO_TABLE_SIZE 1200

/* target_to_host_errno_table[] is initialized from
 * host_to_target_errno_table[] in syscall_init(). */
static uint16_t target_to_host_errno_table[ERRNO_TABLE_SIZE] = {
};

/*
 * This list is the union of errno values overridden in asm-<arch>/errno.h
 * minus the errnos that are not actually generic to all archs.
 */
static uint16_t host_to_target_errno_table[ERRNO_TABLE_SIZE] = {
    [EIDRM]   = TARGET_EIDRM,
    [ECHRNG]    = TARGET_ECHRNG,
    [EL2NSYNC]    = TARGET_EL2NSYNC,
    [EL3HLT]    = TARGET_EL3HLT,
    [EL3RST]    = TARGET_EL3RST,
    [ELNRNG]    = TARGET_ELNRNG,
    [EUNATCH]   = TARGET_EUNATCH,
    [ENOCSI]    = TARGET_ENOCSI,
    [EL2HLT]    = TARGET_EL2HLT,
    [EDEADLK]   = TARGET_EDEADLK,
    [ENOLCK]    = TARGET_ENOLCK,
    [EBADE]   = TARGET_EBADE,
    [EBADR]   = TARGET_EBADR,
    [EXFULL]    = TARGET_EXFULL,
    [ENOANO]    = TARGET_ENOANO,
    [EBADRQC]   = TARGET_EBADRQC,
    [EBADSLT]   = TARGET_EBADSLT,
    [EBFONT]    = TARGET_EBFONT,
    [ENOSTR]    = TARGET_ENOSTR,
    [ENODATA]   = TARGET_ENODATA,
    [ETIME]   = TARGET_ETIME,
    [ENOSR]   = TARGET_ENOSR,
    [ENONET]    = TARGET_ENONET,
    [ENOPKG]    = TARGET_ENOPKG,
    [EREMOTE]   = TARGET_EREMOTE,
    [ENOLINK]   = TARGET_ENOLINK,
    [EADV]    = TARGET_EADV,
    [ESRMNT]    = TARGET_ESRMNT,
    [ECOMM]   = TARGET_ECOMM,
    [EPROTO]    = TARGET_EPROTO,
    [EDOTDOT]   = TARGET_EDOTDOT,
    [EMULTIHOP]   = TARGET_EMULTIHOP,
    [EBADMSG]   = TARGET_EBADMSG,
    [ENAMETOOLONG]  = TARGET_ENAMETOOLONG,
    [EOVERFLOW]   = TARGET_EOVERFLOW,
    [ENOTUNIQ]    = TARGET_ENOTUNIQ,
    [EBADFD]    = TARGET_EBADFD,
    [EREMCHG]   = TARGET_EREMCHG,
    [ELIBACC]   = TARGET_ELIBACC,
    [ELIBBAD]   = TARGET_ELIBBAD,
    [ELIBSCN]   = TARGET_ELIBSCN,
    [ELIBMAX]   = TARGET_ELIBMAX,
    [ELIBEXEC]    = TARGET_ELIBEXEC,
    [EILSEQ]    = TARGET_EILSEQ,
    [ENOSYS]    = TARGET_ENOSYS,
    [ELOOP]   = TARGET_ELOOP,
    [ERESTART]    = TARGET_ERESTART,
    [ESTRPIPE]    = TARGET_ESTRPIPE,
    [ENOTEMPTY]   = TARGET_ENOTEMPTY,
    [EUSERS]    = TARGET_EUSERS,
    [ENOTSOCK]    = TARGET_ENOTSOCK,
    [EDESTADDRREQ]  = TARGET_EDESTADDRREQ,
    [EMSGSIZE]    = TARGET_EMSGSIZE,
    [EPROTOTYPE]  = TARGET_EPROTOTYPE,
    [ENOPROTOOPT] = TARGET_ENOPROTOOPT,
    [EPROTONOSUPPORT] = TARGET_EPROTONOSUPPORT,
    [ESOCKTNOSUPPORT] = TARGET_ESOCKTNOSUPPORT,
    [EOPNOTSUPP]  = TARGET_EOPNOTSUPP,
    [EPFNOSUPPORT]  = TARGET_EPFNOSUPPORT,
    [EAFNOSUPPORT]  = TARGET_EAFNOSUPPORT,
    [EADDRINUSE]  = TARGET_EADDRINUSE,
    [EADDRNOTAVAIL] = TARGET_EADDRNOTAVAIL,
    [ENETDOWN]    = TARGET_ENETDOWN,
    [ENETUNREACH] = TARGET_ENETUNREACH,
    [ENETRESET]   = TARGET_ENETRESET,
    [ECONNABORTED]  = TARGET_ECONNABORTED,
    [ECONNRESET]  = TARGET_ECONNRESET,
    [ENOBUFS]   = TARGET_ENOBUFS,
    [EISCONN]   = TARGET_EISCONN,
    [ENOTCONN]    = TARGET_ENOTCONN,
    [EUCLEAN]   = TARGET_EUCLEAN,
    [ENOTNAM]   = TARGET_ENOTNAM,
    [ENAVAIL]   = TARGET_ENAVAIL,
    [EISNAM]    = TARGET_EISNAM,
    [EREMOTEIO]   = TARGET_EREMOTEIO,
    [ESHUTDOWN]   = TARGET_ESHUTDOWN,
    [ETOOMANYREFS]  = TARGET_ETOOMANYREFS,
    [ETIMEDOUT]   = TARGET_ETIMEDOUT,
    [ECONNREFUSED]  = TARGET_ECONNREFUSED,
    [EHOSTDOWN]   = TARGET_EHOSTDOWN,
    [EHOSTUNREACH]  = TARGET_EHOSTUNREACH,
    [EALREADY]    = TARGET_EALREADY,
    [EINPROGRESS] = TARGET_EINPROGRESS,
    [ESTALE]    = TARGET_ESTALE,
    [ECANCELED]   = TARGET_ECANCELED,
    [ENOMEDIUM]   = TARGET_ENOMEDIUM,
    [EMEDIUMTYPE] = TARGET_EMEDIUMTYPE,
#ifdef ENOKEY
    [ENOKEY]    = TARGET_ENOKEY,
#endif
#ifdef EKEYEXPIRED
    [EKEYEXPIRED] = TARGET_EKEYEXPIRED,
#endif
#ifdef EKEYREVOKED
    [EKEYREVOKED] = TARGET_EKEYREVOKED,
#endif
#ifdef EKEYREJECTED
    [EKEYREJECTED]  = TARGET_EKEYREJECTED,
#endif
#ifdef EOWNERDEAD
    [EOWNERDEAD]  = TARGET_EOWNERDEAD,
#endif
#ifdef ENOTRECOVERABLE
    [ENOTRECOVERABLE] = TARGET_ENOTRECOVERABLE,
#endif
};

static inline int host_to_target_errno(int err)
{
    if(host_to_target_errno_table[err])
        return host_to_target_errno_table[err];
    return err;
}

static inline int target_to_host_errno(int err)
{
    if (target_to_host_errno_table[err])
        return target_to_host_errno_table[err];
    return err;
}

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1)
        return -host_to_target_errno(errno);
    else
        return ret;
}

static inline int is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

char *target_strerror(int err)
{
    if ((err >= ERRNO_TABLE_SIZE) || (err < 0)) {
        return NULL;
    }
    return strerror(target_to_host_errno(err));
}

static inline int host_to_target_sock_type(int host_type)
{
    int target_type;

    switch (host_type & 0xf /* SOCK_TYPE_MASK */) {
    case SOCK_DGRAM:
        target_type = TARGET_SOCK_DGRAM;
        break;
    case SOCK_STREAM:
        target_type = TARGET_SOCK_STREAM;
        break;
    default:
        target_type = host_type & 0xf /* SOCK_TYPE_MASK */;
        break;
    }

#if defined(SOCK_CLOEXEC)
    if (host_type & SOCK_CLOEXEC) {
        target_type |= TARGET_SOCK_CLOEXEC;
    }
#endif

#if defined(SOCK_NONBLOCK)
    if (host_type & SOCK_NONBLOCK) {
        target_type |= TARGET_SOCK_NONBLOCK;
    }
#endif

    return target_type;
}

static abi_ulong target_brk;
static abi_ulong target_original_brk;
static abi_ulong brk_page;

void target_set_brk(abi_ulong new_brk)
{
    target_original_brk = target_brk = HOST_PAGE_ALIGN(new_brk);
    brk_page = HOST_PAGE_ALIGN(target_brk);
}

//#define DEBUGF_BRK(message, args...) do { fprintf(stderr, (message), ## args); } while (0)
#define DEBUGF_BRK(message, args...)

/* do_brk() must return target values and target errnos. */
abi_long do_brk(abi_ulong new_brk)
{
    abi_long mapped_addr;
    int new_alloc_size;

    DEBUGF_BRK("do_brk(" TARGET_ABI_FMT_lx ") -> ", new_brk);

    if (!new_brk) {
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (!new_brk)\n", target_brk);
        return target_brk;
    }
    if (new_brk < target_original_brk) {
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (new_brk < target_original_brk)\n",
                   target_brk);
        return target_brk;
    }

    /* If the new brk is less than the highest page reserved to the
     * target heap allocation, set it and we're almost done...  */
    if (new_brk <= brk_page) {
        /* Heap contents are initialized to zero, as for anonymous
         * mapped pages.  */
        if (new_brk > target_brk) {
            memset(g2h(target_brk), 0, new_brk - target_brk);
        }
  target_brk = new_brk;
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (new_brk <= brk_page)\n", target_brk);
      return target_brk;
    }

    /* We need to allocate more memory after the brk... Note that
     * we don't use MAP_FIXED because that will map over the top of
     * any existing mapping (like the one with the host libc or qemu
     * itself); instead we treat "mapped but at wrong address" as
     * a failure and unmap again.
     */
    new_alloc_size = HOST_PAGE_ALIGN(new_brk - brk_page);
    mapped_addr = get_errno(target_mmap(brk_page, new_alloc_size,
                                        PROT_READ|PROT_WRITE,
                                        MAP_ANON|MAP_PRIVATE, 0, 0));

    if (mapped_addr == brk_page) {
        /* Heap contents are initialized to zero, as for anonymous
         * mapped pages.  Technically the new pages are already
         * initialized to zero since they *are* anonymous mapped
         * pages, however we have to take care with the contents that
         * come from the remaining part of the previous page: it may
         * contains garbage data due to a previous heap usage (grown
         * then shrunken).  */
        memset(g2h(target_brk), 0, brk_page - target_brk);

        target_brk = new_brk;
        brk_page = HOST_PAGE_ALIGN(target_brk);
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (mapped_addr == brk_page)\n",
            target_brk);
        return target_brk;
    } else if (mapped_addr != -1) {
        /* Mapped but at wrong address, meaning there wasn't actually
         * enough space for this brk.
         */
        target_munmap(mapped_addr, new_alloc_size);
        mapped_addr = -1;
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (mapped_addr != -1)\n", target_brk);
    }
    else {
        DEBUGF_BRK(TARGET_ABI_FMT_lx " (otherwise)\n", target_brk);
    }

#if defined(TARGET_ALPHA)
    /* We (partially) emulate OSF/1 on Alpha, which requires we
       return a proper errno, not an unchanged brk value.  */
    return -TARGET_ENOMEM;
#endif
    /* For everything else, return the previous break. */
    return target_brk;
}

static inline abi_long copy_from_user_fdset(fd_set *fds,
                                            abi_ulong target_fds_addr,
                                            int n)
{
    int i, nw, j, k;
    abi_ulong b, *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_READ,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 1)))
        return -TARGET_EFAULT;

    FD_ZERO(fds);
    k = 0;
    for (i = 0; i < nw; i++) {
        /* grab the abi_ulong */
        __get_user(b, &target_fds[i]);
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            /* check the bit inside the abi_ulong */
            if ((b >> j) & 1)
                FD_SET(k, fds);
            k++;
        }
    }

    unlock_user(target_fds, target_fds_addr, 0);

    return 0;
}

static inline abi_ulong copy_from_user_fdset_ptr(fd_set *fds, fd_set **fds_ptr,
                                                 abi_ulong target_fds_addr,
                                                 int n)
{
    if (target_fds_addr) {
        if (copy_from_user_fdset(fds, target_fds_addr, n))
            return -TARGET_EFAULT;
        *fds_ptr = fds;
    } else {
        *fds_ptr = NULL;
    }
    return 0;
}

static inline abi_long copy_to_user_fdset(abi_ulong target_fds_addr,
                                          const fd_set *fds,
                                          int n)
{
    int i, nw, j, k;
    abi_long v;
    abi_ulong *target_fds;

    nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
    if (!(target_fds = lock_user(VERIFY_WRITE,
                                 target_fds_addr,
                                 sizeof(abi_ulong) * nw,
                                 0)))
        return -TARGET_EFAULT;

    k = 0;
    for (i = 0; i < nw; i++) {
        v = 0;
        for (j = 0; j < TARGET_ABI_BITS; j++) {
            v |= ((abi_ulong)(FD_ISSET(k, fds) != 0) << j);
            k++;
        }
        __put_user(v, &target_fds[i]);
    }

    unlock_user(target_fds, target_fds_addr, sizeof(abi_ulong) * nw);

    return 0;
}

#if defined(__alpha__)
#define HOST_HZ 1024
#else
#define HOST_HZ 100
#endif

static inline abi_long host_to_target_clock_t(long ticks)
{
#if HOST_HZ == TARGET_HZ
    return ticks;
#else
    return ((int64_t)ticks * TARGET_HZ) / HOST_HZ;
#endif
}

static inline abi_long host_to_target_rusage(abi_ulong target_addr,
                                             const struct rusage *rusage)
{
    struct target_rusage *target_rusage;

    if (!lock_user_struct(VERIFY_WRITE, target_rusage, target_addr, 0))
        return -TARGET_EFAULT;
    target_rusage->ru_utime.tv_sec = tswapal(rusage->ru_utime.tv_sec);
    target_rusage->ru_utime.tv_usec = tswapal(rusage->ru_utime.tv_usec);
    target_rusage->ru_stime.tv_sec = tswapal(rusage->ru_stime.tv_sec);
    target_rusage->ru_stime.tv_usec = tswapal(rusage->ru_stime.tv_usec);
    target_rusage->ru_maxrss = tswapal(rusage->ru_maxrss);
    target_rusage->ru_ixrss = tswapal(rusage->ru_ixrss);
    target_rusage->ru_idrss = tswapal(rusage->ru_idrss);
    target_rusage->ru_isrss = tswapal(rusage->ru_isrss);
    target_rusage->ru_minflt = tswapal(rusage->ru_minflt);
    target_rusage->ru_majflt = tswapal(rusage->ru_majflt);
    target_rusage->ru_nswap = tswapal(rusage->ru_nswap);
    target_rusage->ru_inblock = tswapal(rusage->ru_inblock);
    target_rusage->ru_oublock = tswapal(rusage->ru_oublock);
    target_rusage->ru_msgsnd = tswapal(rusage->ru_msgsnd);
    target_rusage->ru_msgrcv = tswapal(rusage->ru_msgrcv);
    target_rusage->ru_nsignals = tswapal(rusage->ru_nsignals);
    target_rusage->ru_nvcsw = tswapal(rusage->ru_nvcsw);
    target_rusage->ru_nivcsw = tswapal(rusage->ru_nivcsw);
    unlock_user_struct(target_rusage, target_addr, 1);

    return 0;
}

static inline rlim_t target_to_host_rlim(abi_ulong target_rlim)
{
    abi_ulong target_rlim_swap;
    rlim_t result;
    
    target_rlim_swap = tswapal(target_rlim);
    if (target_rlim_swap == TARGET_RLIM_INFINITY)
        return RLIM_INFINITY;

    result = target_rlim_swap;
    if (target_rlim_swap != (rlim_t)result)
        return RLIM_INFINITY;
    
    return result;
}

static inline abi_ulong host_to_target_rlim(rlim_t rlim)
{
    abi_ulong target_rlim_swap;
    abi_ulong result;
    
    if (rlim == RLIM_INFINITY || rlim != (abi_long)rlim)
        target_rlim_swap = TARGET_RLIM_INFINITY;
    else
        target_rlim_swap = rlim;
    result = tswapal(target_rlim_swap);
    
    return result;
}

static inline int target_to_host_resource(int code)
{
    switch (code) {
    case TARGET_RLIMIT_AS:
        return RLIMIT_AS;
    case TARGET_RLIMIT_CORE:
        return RLIMIT_CORE;
    case TARGET_RLIMIT_CPU:
        return RLIMIT_CPU;
    case TARGET_RLIMIT_DATA:
        return RLIMIT_DATA;
    case TARGET_RLIMIT_FSIZE:
        return RLIMIT_FSIZE;
    case TARGET_RLIMIT_LOCKS:
        return RLIMIT_LOCKS;
    case TARGET_RLIMIT_MEMLOCK:
        return RLIMIT_MEMLOCK;
    case TARGET_RLIMIT_MSGQUEUE:
        return RLIMIT_MSGQUEUE;
    case TARGET_RLIMIT_NICE:
        return RLIMIT_NICE;
    case TARGET_RLIMIT_NOFILE:
        return RLIMIT_NOFILE;
    case TARGET_RLIMIT_NPROC:
        return RLIMIT_NPROC;
    case TARGET_RLIMIT_RSS:
        return RLIMIT_RSS;
    case TARGET_RLIMIT_RTPRIO:
        return RLIMIT_RTPRIO;
    case TARGET_RLIMIT_SIGPENDING:
        return RLIMIT_SIGPENDING;
    case TARGET_RLIMIT_STACK:
        return RLIMIT_STACK;
    default:
        return code;
    }
}

static inline abi_long copy_from_user_timeval(struct timeval *tv,
                                              abi_ulong target_tv_addr)
{
    struct target_timeval *target_tv;

    if (!lock_user_struct(VERIFY_READ, target_tv, target_tv_addr, 1))
        return -TARGET_EFAULT;

    __get_user(tv->tv_sec, &target_tv->tv_sec);
    __get_user(tv->tv_usec, &target_tv->tv_usec);

    unlock_user_struct(target_tv, target_tv_addr, 0);

    return 0;
}

static inline abi_long copy_to_user_timeval(abi_ulong target_tv_addr,
                                            const struct timeval *tv)
{
    struct target_timeval *target_tv;

    if (!lock_user_struct(VERIFY_WRITE, target_tv, target_tv_addr, 0))
        return -TARGET_EFAULT;

    __put_user(tv->tv_sec, &target_tv->tv_sec);
    __put_user(tv->tv_usec, &target_tv->tv_usec);

    unlock_user_struct(target_tv, target_tv_addr, 1);

    return 0;
}

static inline abi_long copy_from_user_timezone(struct timezone *tz,
                                               abi_ulong target_tz_addr)
{
    struct target_timezone *target_tz;

    if (!lock_user_struct(VERIFY_READ, target_tz, target_tz_addr, 1)) {
        return -TARGET_EFAULT;
    }

    __get_user(tz->tz_minuteswest, &target_tz->tz_minuteswest);
    __get_user(tz->tz_dsttime, &target_tz->tz_dsttime);

    unlock_user_struct(target_tz, target_tz_addr, 0);

    return 0;
}

#define CGC_FD_ISSET(b, set) \
  ((set)->_fd_bits[b / _NFDBITS] & (1 << (b & (_NFDBITS - 1))))

// #if defined(TARGET_NR_select) || defined(TARGET_NR__newselect)
/* do_select() must return target values and target errnos. */
static abi_long do_select(int n,
                          abi_ulong rfd_addr, abi_ulong wfd_addr,
                          abi_ulong efd_addr, abi_ulong target_tv_addr)
{
    fd_set rfds, wfds, efds;
    fd_set *rfds_ptr, *wfds_ptr, *efds_ptr;
    struct timeval tv, *tv_ptr;
    abi_long ret;

    ret = copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n);
    if (ret) {
        return ret;
    }
    ret = copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n);
    if (ret) {
        return ret;
    }
    ret = copy_from_user_fdset_ptr(&efds, &efds_ptr, efd_addr, n);
    if (ret) {
        return ret;
    }

    if (target_tv_addr) {
        if (copy_from_user_timeval(&tv, target_tv_addr))
            return -TARGET_EFAULT;
        tv_ptr = &tv;
    } else {
        tv_ptr = NULL;
    }
      
    ret = get_errno(select(n, rfds_ptr, wfds_ptr, efds_ptr, tv_ptr));

    if (!is_error(ret)) {
        if (rfd_addr && copy_to_user_fdset(rfd_addr, &rfds, n))
            return -TARGET_EFAULT;
        if (wfd_addr && copy_to_user_fdset(wfd_addr, &wfds, n))
            return -TARGET_EFAULT;
        if (efd_addr && copy_to_user_fdset(efd_addr, &efds, n))
            return -TARGET_EFAULT;

        if (target_tv_addr && copy_to_user_timeval(target_tv_addr, &tv))
            return -TARGET_EFAULT;
    }

    return ret;
}
// #endif


#define STRUCT(name, ...) STRUCT_ ## name,
#define STRUCT_SPECIAL(name) STRUCT_ ## name,
enum {
#include "syscall_types.h"
};
#undef STRUCT
#undef STRUCT_SPECIAL

#define STRUCT(name, ...) static const argtype struct_ ## name ## _def[] = {  __VA_ARGS__, TYPE_NULL };
#define STRUCT_SPECIAL(name)
#include "syscall_types.h"
#undef STRUCT
#undef STRUCT_SPECIAL

typedef struct IOCTLEntry IOCTLEntry;

typedef abi_long do_ioctl_fn(const IOCTLEntry *ie, uint8_t *buf_temp,
                             int fd, abi_long cmd, abi_long arg);

struct IOCTLEntry {
    unsigned int target_cmd;
    unsigned int host_cmd;
    const char *name;
    int access;
    do_ioctl_fn *do_ioctl;
    const argtype arg_type[5];
};

#define IOC_R 0x0001
#define IOC_W 0x0002
#define IOC_RW (IOC_R | IOC_W)

#define MAX_STRUCT_SIZE 4096

#ifdef CONFIG_FIEMAP
/* So fiemap access checks don't overflow on 32 bit systems.
 * This is very slightly smaller than the limit imposed by
 * the underlying kernel.
 */
#define FIEMAP_MAX_EXTENTS ((UINT_MAX - sizeof(struct fiemap))  \
                            / sizeof(struct fiemap_extent))

static abi_long do_ioctl_fs_ioc_fiemap(const IOCTLEntry *ie, uint8_t *buf_temp,
                                       int fd, abi_long cmd, abi_long arg)
{
    /* The parameter for this ioctl is a struct fiemap followed
     * by an array of struct fiemap_extent whose size is set
     * in fiemap->fm_extent_count. The array is filled in by the
     * ioctl.
     */
    int target_size_in, target_size_out;
    struct fiemap *fm;
    const argtype *arg_type = ie->arg_type;
    const argtype extent_arg_type[] = { MK_STRUCT(STRUCT_fiemap_extent) };
    void *argptr, *p;
    abi_long ret;
    int i, extent_size = thunk_type_size(extent_arg_type, 0);
    uint32_t outbufsz;
    int free_fm = 0;

    assert(arg_type[0] == TYPE_PTR);
    assert(ie->access == IOC_RW);
    arg_type++;
    target_size_in = thunk_type_size(arg_type, 0);
    argptr = lock_user(VERIFY_READ, arg, target_size_in, 1);
    if (!argptr) {
        return -TARGET_EFAULT;
    }
    thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
    unlock_user(argptr, arg, 0);
    fm = (struct fiemap *)buf_temp;
    if (fm->fm_extent_count > FIEMAP_MAX_EXTENTS) {
        return -TARGET_EINVAL;
    }

    outbufsz = sizeof (*fm) +
        (sizeof(struct fiemap_extent) * fm->fm_extent_count);

    if (outbufsz > MAX_STRUCT_SIZE) {
        /* We can't fit all the extents into the fixed size buffer.
         * Allocate one that is large enough and use it instead.
         */
        fm = malloc(outbufsz);
        if (!fm) {
            return -TARGET_ENOMEM;
        }
        memcpy(fm, buf_temp, sizeof(struct fiemap));
        free_fm = 1;
    }
    ret = get_errno(ioctl(fd, ie->host_cmd, fm));
    if (!is_error(ret)) {
        target_size_out = target_size_in;
        /* An extent_count of 0 means we were only counting the extents
         * so there are no structs to copy
         */
        if (fm->fm_extent_count != 0) {
            target_size_out += fm->fm_mapped_extents * extent_size;
        }
        argptr = lock_user(VERIFY_WRITE, arg, target_size_out, 0);
        if (!argptr) {
            ret = -TARGET_EFAULT;
        } else {
            /* Convert the struct fiemap */
            thunk_convert(argptr, fm, arg_type, THUNK_TARGET);
            if (fm->fm_extent_count != 0) {
                p = argptr + target_size_in;
                /* ...and then all the struct fiemap_extents */
                for (i = 0; i < fm->fm_mapped_extents; i++) {
                    thunk_convert(p, &fm->fm_extents[i], extent_arg_type,
                                  THUNK_TARGET);
                    p += extent_size;
                }
            }
            unlock_user(argptr, arg, target_size_out);
        }
    }
    if (free_fm) {
        free(fm);
    }
    return ret;
}
#endif

static abi_long do_ioctl_ifconf(const IOCTLEntry *ie, uint8_t *buf_temp,
                                int fd, abi_long cmd, abi_long arg)
{
    const argtype *arg_type = ie->arg_type;
    int target_size;
    void *argptr;
    int ret;
    struct ifconf *host_ifconf;
    uint32_t outbufsz;
    const argtype ifreq_arg_type[] = { MK_STRUCT(STRUCT_sockaddr_ifreq) };
    int target_ifreq_size;
    int nb_ifreq;
    int free_buf = 0;
    int i;
    int target_ifc_len;
    abi_long target_ifc_buf;
    int host_ifc_len;
    char *host_ifc_buf;

    assert(arg_type[0] == TYPE_PTR);
    assert(ie->access == IOC_RW);

    arg_type++;
    target_size = thunk_type_size(arg_type, 0);

    argptr = lock_user(VERIFY_READ, arg, target_size, 1);
    if (!argptr)
        return -TARGET_EFAULT;
    thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
    unlock_user(argptr, arg, 0);

    host_ifconf = (struct ifconf *)(unsigned long)buf_temp;
    target_ifc_len = host_ifconf->ifc_len;
    target_ifc_buf = (abi_long)(unsigned long)host_ifconf->ifc_buf;

    target_ifreq_size = thunk_type_size(ifreq_arg_type, 0);
    nb_ifreq = target_ifc_len / target_ifreq_size;
    host_ifc_len = nb_ifreq * sizeof(struct ifreq);

    outbufsz = sizeof(*host_ifconf) + host_ifc_len;
    if (outbufsz > MAX_STRUCT_SIZE) {
        /* We can't fit all the extents into the fixed size buffer.
         * Allocate one that is large enough and use it instead.
         */
        host_ifconf = malloc(outbufsz);
        if (!host_ifconf) {
            return -TARGET_ENOMEM;
        }
        memcpy(host_ifconf, buf_temp, sizeof(*host_ifconf));
        free_buf = 1;
    }
    host_ifc_buf = (char*)host_ifconf + sizeof(*host_ifconf);

    host_ifconf->ifc_len = host_ifc_len;
    host_ifconf->ifc_buf = host_ifc_buf;

    ret = get_errno(ioctl(fd, ie->host_cmd, host_ifconf));
    if (!is_error(ret)) {
  /* convert host ifc_len to target ifc_len */

        nb_ifreq = host_ifconf->ifc_len / sizeof(struct ifreq);
        target_ifc_len = nb_ifreq * target_ifreq_size;
        host_ifconf->ifc_len = target_ifc_len;

  /* restore target ifc_buf */

        host_ifconf->ifc_buf = (char *)(unsigned long)target_ifc_buf;

  /* copy struct ifconf to target user */

        argptr = lock_user(VERIFY_WRITE, arg, target_size, 0);
        if (!argptr)
            return -TARGET_EFAULT;
        thunk_convert(argptr, host_ifconf, arg_type, THUNK_TARGET);
        unlock_user(argptr, arg, target_size);

  /* copy ifreq[] to target user */

        argptr = lock_user(VERIFY_WRITE, target_ifc_buf, target_ifc_len, 0);
        for (i = 0; i < nb_ifreq ; i++) {
            thunk_convert(argptr + i * target_ifreq_size,
                          host_ifc_buf + i * sizeof(struct ifreq),
                          ifreq_arg_type, THUNK_TARGET);
        }
        unlock_user(argptr, target_ifc_buf, target_ifc_len);
    }

    if (free_buf) {
        free(host_ifconf);
    }

    return ret;
}

static abi_long do_ioctl_dm(const IOCTLEntry *ie, uint8_t *buf_temp, int fd,
                            abi_long cmd, abi_long arg)
{
    void *argptr;
    struct dm_ioctl *host_dm;
    abi_long guest_data;
    uint32_t guest_data_size;
    int target_size;
    const argtype *arg_type = ie->arg_type;
    abi_long ret;
    void *big_buf = NULL;
    char *host_data;

    arg_type++;
    target_size = thunk_type_size(arg_type, 0);
    argptr = lock_user(VERIFY_READ, arg, target_size, 1);
    if (!argptr) {
        ret = -TARGET_EFAULT;
        goto out;
    }
    thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
    unlock_user(argptr, arg, 0);

    /* buf_temp is too small, so fetch things into a bigger buffer */
    big_buf = g_malloc0(((struct dm_ioctl*)buf_temp)->data_size * 2);
    memcpy(big_buf, buf_temp, target_size);
    buf_temp = big_buf;
    host_dm = big_buf;

    guest_data = arg + host_dm->data_start;
    if ((guest_data - arg) < 0) {
        ret = -EINVAL;
        goto out;
    }
    guest_data_size = host_dm->data_size - host_dm->data_start;
    host_data = (char*)host_dm + host_dm->data_start;

    argptr = lock_user(VERIFY_READ, guest_data, guest_data_size, 1);
    switch (ie->host_cmd) {
    case DM_REMOVE_ALL:
    case DM_LIST_DEVICES:
    case DM_DEV_CREATE:
    case DM_DEV_REMOVE:
    case DM_DEV_SUSPEND:
    case DM_DEV_STATUS:
    case DM_DEV_WAIT:
    case DM_TABLE_STATUS:
    case DM_TABLE_CLEAR:
    case DM_TABLE_DEPS:
    case DM_LIST_VERSIONS:
        /* no input data */
        break;
    case DM_DEV_RENAME:
    case DM_DEV_SET_GEOMETRY:
        /* data contains only strings */
        memcpy(host_data, argptr, guest_data_size);
        break;
    case DM_TARGET_MSG:
        memcpy(host_data, argptr, guest_data_size);
        *(uint64_t*)host_data = tswap64(*(uint64_t*)argptr);
        break;
    case DM_TABLE_LOAD:
    {
        void *gspec = argptr;
        void *cur_data = host_data;
        const argtype arg_type[] = { MK_STRUCT(STRUCT_dm_target_spec) };
        int spec_size = thunk_type_size(arg_type, 0);
        int i;

        for (i = 0; i < host_dm->target_count; i++) {
            struct dm_target_spec *spec = cur_data;
            uint32_t next;
            int slen;

            thunk_convert(spec, gspec, arg_type, THUNK_HOST);
            slen = strlen((char*)gspec + spec_size) + 1;
            next = spec->next;
            spec->next = sizeof(*spec) + slen;
            strcpy((char*)&spec[1], gspec + spec_size);
            gspec += next;
            cur_data += spec->next;
        }
        break;
    }
    default:
        ret = -TARGET_EINVAL;
        goto out;
    }
    unlock_user(argptr, guest_data, 0);

    ret = get_errno(ioctl(fd, ie->host_cmd, buf_temp));
    if (!is_error(ret)) {
        guest_data = arg + host_dm->data_start;
        guest_data_size = host_dm->data_size - host_dm->data_start;
        argptr = lock_user(VERIFY_WRITE, guest_data, guest_data_size, 0);
        switch (ie->host_cmd) {
        case DM_REMOVE_ALL:
        case DM_DEV_CREATE:
        case DM_DEV_REMOVE:
        case DM_DEV_RENAME:
        case DM_DEV_SUSPEND:
        case DM_DEV_STATUS:
        case DM_TABLE_LOAD:
        case DM_TABLE_CLEAR:
        case DM_TARGET_MSG:
        case DM_DEV_SET_GEOMETRY:
            /* no return data */
            break;
        case DM_LIST_DEVICES:
        {
            struct dm_name_list *nl = (void*)host_dm + host_dm->data_start;
            uint32_t remaining_data = guest_data_size;
            void *cur_data = argptr;
            const argtype arg_type[] = { MK_STRUCT(STRUCT_dm_name_list) };
            int nl_size = 12; /* can't use thunk_size due to alignment */

            while (1) {
                uint32_t next = nl->next;
                if (next) {
                    nl->next = nl_size + (strlen(nl->name) + 1);
                }
                if (remaining_data < nl->next) {
                    host_dm->flags |= DM_BUFFER_FULL_FLAG;
                    break;
                }
                thunk_convert(cur_data, nl, arg_type, THUNK_TARGET);
                strcpy(cur_data + nl_size, nl->name);
                cur_data += nl->next;
                remaining_data -= nl->next;
                if (!next) {
                    break;
                }
                nl = (void*)nl + next;
            }
            break;
        }
        case DM_DEV_WAIT:
        case DM_TABLE_STATUS:
        {
            struct dm_target_spec *spec = (void*)host_dm + host_dm->data_start;
            void *cur_data = argptr;
            const argtype arg_type[] = { MK_STRUCT(STRUCT_dm_target_spec) };
            int spec_size = thunk_type_size(arg_type, 0);
            int i;

            for (i = 0; i < host_dm->target_count; i++) {
                uint32_t next = spec->next;
                int slen = strlen((char*)&spec[1]) + 1;
                spec->next = (cur_data - argptr) + spec_size + slen;
                if (guest_data_size < spec->next) {
                    host_dm->flags |= DM_BUFFER_FULL_FLAG;
                    break;
                }
                thunk_convert(cur_data, spec, arg_type, THUNK_TARGET);
                strcpy(cur_data + spec_size, (char*)&spec[1]);
                cur_data = argptr + spec->next;
                spec = (void*)host_dm + host_dm->data_start + next;
            }
            break;
        }
        case DM_TABLE_DEPS:
        {
            void *hdata = (void*)host_dm + host_dm->data_start;
            int count = *(uint32_t*)hdata;
            uint64_t *hdev = hdata + 8;
            uint64_t *gdev = argptr + 8;
            int i;

            *(uint32_t*)argptr = tswap32(count);
            for (i = 0; i < count; i++) {
                *gdev = tswap64(*hdev);
                gdev++;
                hdev++;
            }
            break;
        }
        case DM_LIST_VERSIONS:
        {
            struct dm_target_versions *vers = (void*)host_dm + host_dm->data_start;
            uint32_t remaining_data = guest_data_size;
            void *cur_data = argptr;
            const argtype arg_type[] = { MK_STRUCT(STRUCT_dm_target_versions) };
            int vers_size = thunk_type_size(arg_type, 0);

            while (1) {
                uint32_t next = vers->next;
                if (next) {
                    vers->next = vers_size + (strlen(vers->name) + 1);
                }
                if (remaining_data < vers->next) {
                    host_dm->flags |= DM_BUFFER_FULL_FLAG;
                    break;
                }
                thunk_convert(cur_data, vers, arg_type, THUNK_TARGET);
                strcpy(cur_data + vers_size, vers->name);
                cur_data += vers->next;
                remaining_data -= vers->next;
                if (!next) {
                    break;
                }
                vers = (void*)vers + next;
            }
            break;
        }
        default:
            ret = -TARGET_EINVAL;
            goto out;
        }
        unlock_user(argptr, guest_data, guest_data_size);

        argptr = lock_user(VERIFY_WRITE, arg, target_size, 0);
        if (!argptr) {
            ret = -TARGET_EFAULT;
            goto out;
        }
        thunk_convert(argptr, buf_temp, arg_type, THUNK_TARGET);
        unlock_user(argptr, arg, target_size);
    }
out:
    g_free(big_buf);
    return ret;
}

static abi_long do_ioctl_blkpg(const IOCTLEntry *ie, uint8_t *buf_temp, int fd,
                               abi_long cmd, abi_long arg)
{
    void *argptr;
    int target_size;
    const argtype *arg_type = ie->arg_type;
    const argtype part_arg_type[] = { MK_STRUCT(STRUCT_blkpg_partition) };
    abi_long ret;

    struct blkpg_ioctl_arg *host_blkpg = (void*)buf_temp;
    struct blkpg_partition host_part;

    /* Read and convert blkpg */
    arg_type++;
    target_size = thunk_type_size(arg_type, 0);
    argptr = lock_user(VERIFY_READ, arg, target_size, 1);
    if (!argptr) {
        ret = -TARGET_EFAULT;
        goto out;
    }
    thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
    unlock_user(argptr, arg, 0);

    switch (host_blkpg->op) {
    case BLKPG_ADD_PARTITION:
    case BLKPG_DEL_PARTITION:
        /* payload is struct blkpg_partition */
        break;
    default:
        /* Unknown opcode */
        ret = -TARGET_EINVAL;
        goto out;
    }

    /* Read and convert blkpg->data */
    arg = (abi_long)(uintptr_t)host_blkpg->data;
    target_size = thunk_type_size(part_arg_type, 0);
    argptr = lock_user(VERIFY_READ, arg, target_size, 1);
    if (!argptr) {
        ret = -TARGET_EFAULT;
        goto out;
    }
    thunk_convert(&host_part, argptr, part_arg_type, THUNK_HOST);
    unlock_user(argptr, arg, 0);

    /* Swizzle the data pointer to our local copy and call! */
    host_blkpg->data = &host_part;
    ret = get_errno(ioctl(fd, ie->host_cmd, host_blkpg));

out:
    return ret;
}

static abi_long do_ioctl_rt(const IOCTLEntry *ie, uint8_t *buf_temp,
                                int fd, abi_long cmd, abi_long arg)
{
    const argtype *arg_type = ie->arg_type;
    const StructEntry *se;
    const argtype *field_types;
    const int *dst_offsets, *src_offsets;
    int target_size;
    void *argptr;
    abi_ulong *target_rt_dev_ptr;
    unsigned long *host_rt_dev_ptr;
    abi_long ret;
    int i;

    assert(ie->access == IOC_W);
    assert(*arg_type == TYPE_PTR);
    arg_type++;
    assert(*arg_type == TYPE_STRUCT);
    target_size = thunk_type_size(arg_type, 0);
    argptr = lock_user(VERIFY_READ, arg, target_size, 1);
    if (!argptr) {
        return -TARGET_EFAULT;
    }
    arg_type++;
    assert(*arg_type == (int)STRUCT_rtentry);
    se = struct_entries + *arg_type++;
    assert(se->convert[0] == NULL);
    /* convert struct here to be able to catch rt_dev string */
    field_types = se->field_types;
    dst_offsets = se->field_offsets[THUNK_HOST];
    src_offsets = se->field_offsets[THUNK_TARGET];
    for (i = 0; i < se->nb_fields; i++) {
        if (dst_offsets[i] == offsetof(struct rtentry, rt_dev)) {
            assert(*field_types == TYPE_PTRVOID);
            target_rt_dev_ptr = (abi_ulong *)(argptr + src_offsets[i]);
            host_rt_dev_ptr = (unsigned long *)(buf_temp + dst_offsets[i]);
            if (*target_rt_dev_ptr != 0) {
                *host_rt_dev_ptr = (unsigned long)lock_user_string(
                                                  tswapal(*target_rt_dev_ptr));
                if (!*host_rt_dev_ptr) {
                    unlock_user(argptr, arg, 0);
                    return -TARGET_EFAULT;
                }
            } else {
                *host_rt_dev_ptr = 0;
            }
            field_types++;
            continue;
        }
        field_types = thunk_convert(buf_temp + dst_offsets[i],
                                    argptr + src_offsets[i],
                                    field_types, THUNK_HOST);
    }
    unlock_user(argptr, arg, 0);

    ret = get_errno(ioctl(fd, ie->host_cmd, buf_temp));
    if (*host_rt_dev_ptr != 0) {
        unlock_user((void *)*host_rt_dev_ptr,
                    *target_rt_dev_ptr, 0);
    }
    return ret;
}

static abi_long do_ioctl_kdsigaccept(const IOCTLEntry *ie, uint8_t *buf_temp,
                                     int fd, abi_long cmd, abi_long arg)
{
    int sig = target_to_host_signal(arg);
    return get_errno(ioctl(fd, ie->host_cmd, sig));
}

static IOCTLEntry ioctl_entries[] = {
#define IOCTL(cmd, access, ...) \
    { TARGET_ ## cmd, cmd, #cmd, access, 0, {  __VA_ARGS__ } },
#define IOCTL_SPECIAL(cmd, access, dofn, ...)                      \
    { TARGET_ ## cmd, cmd, #cmd, access, dofn, {  __VA_ARGS__ } },
#include "ioctls.h"
    { 0, 0, },
};


static const bitmask_transtbl iflag_tbl[] = {
        { TARGET_IGNBRK, TARGET_IGNBRK, IGNBRK, IGNBRK },
        { TARGET_BRKINT, TARGET_BRKINT, BRKINT, BRKINT },
        { TARGET_IGNPAR, TARGET_IGNPAR, IGNPAR, IGNPAR },
        { TARGET_PARMRK, TARGET_PARMRK, PARMRK, PARMRK },
        { TARGET_INPCK, TARGET_INPCK, INPCK, INPCK },
        { TARGET_ISTRIP, TARGET_ISTRIP, ISTRIP, ISTRIP },
        { TARGET_INLCR, TARGET_INLCR, INLCR, INLCR },
        { TARGET_IGNCR, TARGET_IGNCR, IGNCR, IGNCR },
        { TARGET_ICRNL, TARGET_ICRNL, ICRNL, ICRNL },
        { TARGET_IUCLC, TARGET_IUCLC, IUCLC, IUCLC },
        { TARGET_IXON, TARGET_IXON, IXON, IXON },
        { TARGET_IXANY, TARGET_IXANY, IXANY, IXANY },
        { TARGET_IXOFF, TARGET_IXOFF, IXOFF, IXOFF },
        { TARGET_IMAXBEL, TARGET_IMAXBEL, IMAXBEL, IMAXBEL },
        { 0, 0, 0, 0 }
};

static const bitmask_transtbl oflag_tbl[] = {
  { TARGET_OPOST, TARGET_OPOST, OPOST, OPOST },
  { TARGET_OLCUC, TARGET_OLCUC, OLCUC, OLCUC },
  { TARGET_ONLCR, TARGET_ONLCR, ONLCR, ONLCR },
  { TARGET_OCRNL, TARGET_OCRNL, OCRNL, OCRNL },
  { TARGET_ONOCR, TARGET_ONOCR, ONOCR, ONOCR },
  { TARGET_ONLRET, TARGET_ONLRET, ONLRET, ONLRET },
  { TARGET_OFILL, TARGET_OFILL, OFILL, OFILL },
  { TARGET_OFDEL, TARGET_OFDEL, OFDEL, OFDEL },
  { TARGET_NLDLY, TARGET_NL0, NLDLY, NL0 },
  { TARGET_NLDLY, TARGET_NL1, NLDLY, NL1 },
  { TARGET_CRDLY, TARGET_CR0, CRDLY, CR0 },
  { TARGET_CRDLY, TARGET_CR1, CRDLY, CR1 },
  { TARGET_CRDLY, TARGET_CR2, CRDLY, CR2 },
  { TARGET_CRDLY, TARGET_CR3, CRDLY, CR3 },
  { TARGET_TABDLY, TARGET_TAB0, TABDLY, TAB0 },
  { TARGET_TABDLY, TARGET_TAB1, TABDLY, TAB1 },
  { TARGET_TABDLY, TARGET_TAB2, TABDLY, TAB2 },
  { TARGET_TABDLY, TARGET_TAB3, TABDLY, TAB3 },
  { TARGET_BSDLY, TARGET_BS0, BSDLY, BS0 },
  { TARGET_BSDLY, TARGET_BS1, BSDLY, BS1 },
  { TARGET_VTDLY, TARGET_VT0, VTDLY, VT0 },
  { TARGET_VTDLY, TARGET_VT1, VTDLY, VT1 },
  { TARGET_FFDLY, TARGET_FF0, FFDLY, FF0 },
  { TARGET_FFDLY, TARGET_FF1, FFDLY, FF1 },
  { 0, 0, 0, 0 }
};

static const bitmask_transtbl cflag_tbl[] = {
  { TARGET_CBAUD, TARGET_B0, CBAUD, B0 },
  { TARGET_CBAUD, TARGET_B50, CBAUD, B50 },
  { TARGET_CBAUD, TARGET_B75, CBAUD, B75 },
  { TARGET_CBAUD, TARGET_B110, CBAUD, B110 },
  { TARGET_CBAUD, TARGET_B134, CBAUD, B134 },
  { TARGET_CBAUD, TARGET_B150, CBAUD, B150 },
  { TARGET_CBAUD, TARGET_B200, CBAUD, B200 },
  { TARGET_CBAUD, TARGET_B300, CBAUD, B300 },
  { TARGET_CBAUD, TARGET_B600, CBAUD, B600 },
  { TARGET_CBAUD, TARGET_B1200, CBAUD, B1200 },
  { TARGET_CBAUD, TARGET_B1800, CBAUD, B1800 },
  { TARGET_CBAUD, TARGET_B2400, CBAUD, B2400 },
  { TARGET_CBAUD, TARGET_B4800, CBAUD, B4800 },
  { TARGET_CBAUD, TARGET_B9600, CBAUD, B9600 },
  { TARGET_CBAUD, TARGET_B19200, CBAUD, B19200 },
  { TARGET_CBAUD, TARGET_B38400, CBAUD, B38400 },
  { TARGET_CBAUD, TARGET_B57600, CBAUD, B57600 },
  { TARGET_CBAUD, TARGET_B115200, CBAUD, B115200 },
  { TARGET_CBAUD, TARGET_B230400, CBAUD, B230400 },
  { TARGET_CBAUD, TARGET_B460800, CBAUD, B460800 },
  { TARGET_CSIZE, TARGET_CS5, CSIZE, CS5 },
  { TARGET_CSIZE, TARGET_CS6, CSIZE, CS6 },
  { TARGET_CSIZE, TARGET_CS7, CSIZE, CS7 },
  { TARGET_CSIZE, TARGET_CS8, CSIZE, CS8 },
  { TARGET_CSTOPB, TARGET_CSTOPB, CSTOPB, CSTOPB },
  { TARGET_CREAD, TARGET_CREAD, CREAD, CREAD },
  { TARGET_PARENB, TARGET_PARENB, PARENB, PARENB },
  { TARGET_PARODD, TARGET_PARODD, PARODD, PARODD },
  { TARGET_HUPCL, TARGET_HUPCL, HUPCL, HUPCL },
  { TARGET_CLOCAL, TARGET_CLOCAL, CLOCAL, CLOCAL },
  { TARGET_CRTSCTS, TARGET_CRTSCTS, CRTSCTS, CRTSCTS },
  { 0, 0, 0, 0 }
};

static const bitmask_transtbl lflag_tbl[] = {
  { TARGET_ISIG, TARGET_ISIG, ISIG, ISIG },
  { TARGET_ICANON, TARGET_ICANON, ICANON, ICANON },
  { TARGET_XCASE, TARGET_XCASE, XCASE, XCASE },
  { TARGET_ECHO, TARGET_ECHO, ECHO, ECHO },
  { TARGET_ECHOE, TARGET_ECHOE, ECHOE, ECHOE },
  { TARGET_ECHOK, TARGET_ECHOK, ECHOK, ECHOK },
  { TARGET_ECHONL, TARGET_ECHONL, ECHONL, ECHONL },
  { TARGET_NOFLSH, TARGET_NOFLSH, NOFLSH, NOFLSH },
  { TARGET_TOSTOP, TARGET_TOSTOP, TOSTOP, TOSTOP },
  { TARGET_ECHOCTL, TARGET_ECHOCTL, ECHOCTL, ECHOCTL },
  { TARGET_ECHOPRT, TARGET_ECHOPRT, ECHOPRT, ECHOPRT },
  { TARGET_ECHOKE, TARGET_ECHOKE, ECHOKE, ECHOKE },
  { TARGET_FLUSHO, TARGET_FLUSHO, FLUSHO, FLUSHO },
  { TARGET_PENDIN, TARGET_PENDIN, PENDIN, PENDIN },
  { TARGET_IEXTEN, TARGET_IEXTEN, IEXTEN, IEXTEN },
  { 0, 0, 0, 0 }
};

static void target_to_host_termios (void *dst, const void *src)
{
    struct host_termios *host = dst;
    const struct target_termios *target = src;

    host->c_iflag =
        target_to_host_bitmask(tswap32(target->c_iflag), iflag_tbl);
    host->c_oflag =
        target_to_host_bitmask(tswap32(target->c_oflag), oflag_tbl);
    host->c_cflag =
        target_to_host_bitmask(tswap32(target->c_cflag), cflag_tbl);
    host->c_lflag =
        target_to_host_bitmask(tswap32(target->c_lflag), lflag_tbl);
    host->c_line = target->c_line;

    memset(host->c_cc, 0, sizeof(host->c_cc));
    host->c_cc[VINTR] = target->c_cc[TARGET_VINTR];
    host->c_cc[VQUIT] = target->c_cc[TARGET_VQUIT];
    host->c_cc[VERASE] = target->c_cc[TARGET_VERASE];
    host->c_cc[VKILL] = target->c_cc[TARGET_VKILL];
    host->c_cc[VEOF] = target->c_cc[TARGET_VEOF];
    host->c_cc[VTIME] = target->c_cc[TARGET_VTIME];
    host->c_cc[VMIN] = target->c_cc[TARGET_VMIN];
    host->c_cc[VSWTC] = target->c_cc[TARGET_VSWTC];
    host->c_cc[VSTART] = target->c_cc[TARGET_VSTART];
    host->c_cc[VSTOP] = target->c_cc[TARGET_VSTOP];
    host->c_cc[VSUSP] = target->c_cc[TARGET_VSUSP];
    host->c_cc[VEOL] = target->c_cc[TARGET_VEOL];
    host->c_cc[VREPRINT] = target->c_cc[TARGET_VREPRINT];
    host->c_cc[VDISCARD] = target->c_cc[TARGET_VDISCARD];
    host->c_cc[VWERASE] = target->c_cc[TARGET_VWERASE];
    host->c_cc[VLNEXT] = target->c_cc[TARGET_VLNEXT];
    host->c_cc[VEOL2] = target->c_cc[TARGET_VEOL2];
}

static void host_to_target_termios (void *dst, const void *src)
{
    struct target_termios *target = dst;
    const struct host_termios *host = src;

    target->c_iflag =
        tswap32(host_to_target_bitmask(host->c_iflag, iflag_tbl));
    target->c_oflag =
        tswap32(host_to_target_bitmask(host->c_oflag, oflag_tbl));
    target->c_cflag =
        tswap32(host_to_target_bitmask(host->c_cflag, cflag_tbl));
    target->c_lflag =
        tswap32(host_to_target_bitmask(host->c_lflag, lflag_tbl));
    target->c_line = host->c_line;

    memset(target->c_cc, 0, sizeof(target->c_cc));
    target->c_cc[TARGET_VINTR] = host->c_cc[VINTR];
    target->c_cc[TARGET_VQUIT] = host->c_cc[VQUIT];
    target->c_cc[TARGET_VERASE] = host->c_cc[VERASE];
    target->c_cc[TARGET_VKILL] = host->c_cc[VKILL];
    target->c_cc[TARGET_VEOF] = host->c_cc[VEOF];
    target->c_cc[TARGET_VTIME] = host->c_cc[VTIME];
    target->c_cc[TARGET_VMIN] = host->c_cc[VMIN];
    target->c_cc[TARGET_VSWTC] = host->c_cc[VSWTC];
    target->c_cc[TARGET_VSTART] = host->c_cc[VSTART];
    target->c_cc[TARGET_VSTOP] = host->c_cc[VSTOP];
    target->c_cc[TARGET_VSUSP] = host->c_cc[VSUSP];
    target->c_cc[TARGET_VEOL] = host->c_cc[VEOL];
    target->c_cc[TARGET_VREPRINT] = host->c_cc[VREPRINT];
    target->c_cc[TARGET_VDISCARD] = host->c_cc[VDISCARD];
    target->c_cc[TARGET_VWERASE] = host->c_cc[VWERASE];
    target->c_cc[TARGET_VLNEXT] = host->c_cc[VLNEXT];
    target->c_cc[TARGET_VEOL2] = host->c_cc[VEOL2];
}

static const StructEntry struct_termios_def = {
    .convert = { host_to_target_termios, target_to_host_termios },
    .size = { sizeof(struct target_termios), sizeof(struct host_termios) },
    .align = { __alignof__(struct target_termios), __alignof__(struct host_termios) },
};



#if defined(TARGET_I386)

/* NOTE: there is really one LDT for all the threads */


#if defined(TARGET_I386) && defined(TARGET_ABI32)
abi_long do_set_thread_area(CPUX86State *env, abi_ulong ptr)
{
    uint64_t *gdt_table = g2h(env->gdt.base);
    struct target_modify_ldt_ldt_s ldt_info;
    struct target_modify_ldt_ldt_s *target_ldt_info;
    int seg_32bit, contents, read_exec_only, limit_in_pages;
    int seg_not_present, useable, lm;
    uint32_t *lp, entry_1, entry_2;
    int i;

    lock_user_struct(VERIFY_WRITE, target_ldt_info, ptr, 1);
    if (!target_ldt_info)
        return -TARGET_EFAULT;
    ldt_info.entry_number = tswap32(target_ldt_info->entry_number);
    ldt_info.base_addr = tswapal(target_ldt_info->base_addr);
    ldt_info.limit = tswap32(target_ldt_info->limit);
    ldt_info.flags = tswap32(target_ldt_info->flags);
    if (ldt_info.entry_number == -1) {
        for (i=TARGET_GDT_ENTRY_TLS_MIN; i<=TARGET_GDT_ENTRY_TLS_MAX; i++) {
            if (gdt_table[i] == 0) {
                ldt_info.entry_number = i;
                target_ldt_info->entry_number = tswap32(i);
                break;
            }
        }
    }
    unlock_user_struct(target_ldt_info, ptr, 1);

    if (ldt_info.entry_number < TARGET_GDT_ENTRY_TLS_MIN || 
        ldt_info.entry_number > TARGET_GDT_ENTRY_TLS_MAX)
           return -TARGET_EINVAL;
    seg_32bit = ldt_info.flags & 1;
    contents = (ldt_info.flags >> 1) & 3;
    read_exec_only = (ldt_info.flags >> 3) & 1;
    limit_in_pages = (ldt_info.flags >> 4) & 1;
    seg_not_present = (ldt_info.flags >> 5) & 1;
    useable = (ldt_info.flags >> 6) & 1;
#ifdef TARGET_ABI32
    lm = 0;
#else
    lm = (ldt_info.flags >> 7) & 1;
#endif

    if (contents == 3) {
        if (seg_not_present == 0)
            return -TARGET_EINVAL;
    }

    /* NOTE: same code as Linux kernel */
    /* Allow LDTs to be cleared by the user. */
    if (ldt_info.base_addr == 0 && ldt_info.limit == 0) {
        if ((contents == 0             &&
             read_exec_only == 1       &&
             seg_32bit == 0            &&
             limit_in_pages == 0       &&
             seg_not_present == 1      &&
             useable == 0 )) {
            entry_1 = 0;
            entry_2 = 0;
            goto install;
        }
    }

    entry_1 = ((ldt_info.base_addr & 0x0000ffff) << 16) |
        (ldt_info.limit & 0x0ffff);
    entry_2 = (ldt_info.base_addr & 0xff000000) |
        ((ldt_info.base_addr & 0x00ff0000) >> 16) |
        (ldt_info.limit & 0xf0000) |
        ((read_exec_only ^ 1) << 9) |
        (contents << 10) |
        ((seg_not_present ^ 1) << 15) |
        (seg_32bit << 22) |
        (limit_in_pages << 23) |
        (useable << 20) |
        (lm << 21) |
        0x7000;

    /* Install the new entry ...  */
install:
    lp = (uint32_t *)(gdt_table + ldt_info.entry_number);
    lp[0] = tswap32(entry_1);
    lp[1] = tswap32(entry_2);
    return 0;
}


#endif /* TARGET_I386 && TARGET_ABI32 */

#ifndef TARGET_ABI32
abi_long do_arch_prctl(CPUX86State *env, int code, abi_ulong addr)
{
    abi_long ret = 0;
    abi_ulong val;
    int idx;

    switch(code) {
    case TARGET_ARCH_SET_GS:
    case TARGET_ARCH_SET_FS:
        if (code == TARGET_ARCH_SET_GS)
            idx = R_GS;
        else
            idx = R_FS;
        cpu_x86_load_seg(env, idx, 0);
        env->segs[idx].base = addr;
        break;
    case TARGET_ARCH_GET_GS:
    case TARGET_ARCH_GET_FS:
        if (code == TARGET_ARCH_GET_GS)
            idx = R_GS;
        else
            idx = R_FS;
        val = env->segs[idx].base;
        if (put_user(val, addr, abi_ulong))
            ret = -TARGET_EFAULT;
        break;
    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}
#endif

#endif /* defined(TARGET_I386) */

#define NEW_STACK_SIZE 0x40000







#define TRANSTBL_CONVERT(a) { -1, TARGET_##a, -1, a }
static const bitmask_transtbl flock_tbl[] = {
    TRANSTBL_CONVERT(F_RDLCK),
    TRANSTBL_CONVERT(F_WRLCK),
    TRANSTBL_CONVERT(F_UNLCK),
    TRANSTBL_CONVERT(F_EXLCK),
    TRANSTBL_CONVERT(F_SHLCK),
    { 0, 0, 0, 0 }
};



#ifdef USE_UID16

static inline int high2lowuid(int uid)
{
    if (uid > 65535)
        return 65534;
    else
        return uid;
}

static inline int high2lowgid(int gid)
{
    if (gid > 65535)
        return 65534;
    else
        return gid;
}

static inline int low2highuid(int uid)
{
    if ((int16_t)uid == -1)
        return -1;
    else
        return uid;
}

static inline int low2highgid(int gid)
{
    if ((int16_t)gid == -1)
        return -1;
    else
        return gid;
}
static inline int tswapid(int id)
{
    return tswap16(id);
}

#define put_user_id(x, gaddr) put_user_u16(x, gaddr)

#else /* !USE_UID16 */
static inline int high2lowuid(int uid)
{
    return uid;
}
static inline int high2lowgid(int gid)
{
    return gid;F
}
static inline int low2highuid(int uid)
{
    return uid;
}
static inline int low2highgid(int gid)
{
    return gid;
}
static inline int tswapid(int id)
{
    return tswap32(id);
}

#define put_user_id(x, gaddr) put_user_u32(x, gaddr)

#endif /* USE_UID16 */

void syscall_init(void)
{
    IOCTLEntry *ie;
    const argtype *arg_type;
    int size;
    int i;

#define STRUCT(name, ...) thunk_register_struct(STRUCT_ ## name, #name, struct_ ## name ## _def);
#define STRUCT_SPECIAL(name) thunk_register_struct_direct(STRUCT_ ## name, #name, &struct_ ## name ## _def);
#include "syscall_types.h"
#undef STRUCT
#undef STRUCT_SPECIAL

    /* Build target_to_host_errno_table[] table from
     * host_to_target_errno_table[]. */
    for (i = 0; i < ERRNO_TABLE_SIZE; i++) {
        target_to_host_errno_table[host_to_target_errno_table[i]] = i;
    }

    /* we patch the ioctl size if necessary. We rely on the fact that
       no ioctl has all the bits at '1' in the size field */
    ie = ioctl_entries;
    while (ie->target_cmd != 0) {
        if (((ie->target_cmd >> TARGET_IOC_SIZESHIFT) & TARGET_IOC_SIZEMASK) ==
            TARGET_IOC_SIZEMASK) {
            arg_type = ie->arg_type;
            if (arg_type[0] != TYPE_PTR) {
                fprintf(stderr, "cannot patch size for ioctl 0x%x\n",
                        ie->target_cmd);
                exit(1);
            }
            arg_type++;
            size = thunk_type_size(arg_type, 0);
            ie->target_cmd = (ie->target_cmd &
                              ~(TARGET_IOC_SIZEMASK << TARGET_IOC_SIZESHIFT)) |
                (size << TARGET_IOC_SIZESHIFT);
        }

        /* automatic consistency check if same arch */
#if (defined(__i386__) && defined(TARGET_I386) && defined(TARGET_ABI32)) || \
    (defined(__x86_64__) && defined(TARGET_X86_64))
        if (unlikely(ie->target_cmd != ie->host_cmd)) {
            fprintf(stderr, "ERROR: ioctl(%s): target=0x%x host=0x%x\n",
                    ie->name, ie->target_cmd, ie->host_cmd);
        }
#endif
        ie++;
    }
}

// /* ??? Using host futex calls even when target atomic operations
//    are not really atomic probably breaks things.  However implementing
//    futexes locally would make futexes shared between multiple processes
//    tricky.  However they're probably useless because guest atomic
//    operations won't work either.  */


/* Map host to target signal numbers for the wait family of syscalls.
   Assume all other status bits are the same.  */
int host_to_target_waitstatus(int status)
{
    if (WIFSIGNALED(status)) {
        return host_to_target_signal(WTERMSIG(status)) | (status & ~0x7f);
    }
    if (WIFSTOPPED(status)) {
        return (host_to_target_signal(WSTOPSIG(status)) << 8)
               | (status & 0xff);
    }
    return status;
}


#define TIMER_MAGIC 0x0caf0000
#define TIMER_MAGIC_MASK 0xffff0000

#define IMSGS_LENGTH 1024 * 1024



int empty_rec_cnt = 0;

typedef struct 
{
  size_t size;
  int ptr;
  char buf[IMSGS_LENGTH];
} InputMsgs;

InputMsgs input_msgs = {-1,0};



static void display_hex(char* buf, int len)
{
  int i;
  for(i=0;i<len;i++)
  {
    gemu_log("0x%x|", buf[i] & 0xff);
  }
  gemu_log("\n");
}

static abi_long read_from_imsgs_buf(abi_long gaddr, abi_long cnt)
{
  abi_long ret;
  int i, len;
  if(input_msgs.size == -1)
  {
    abi_long fd = 0;
    ret = get_errno(read(fd, input_msgs.buf, IMSGS_LENGTH));
    if(ret <= 0)
      return ret;
    input_msgs.size = ret;
  }
  // gemu_log("\nbuf: ");
  // display_hex(input_msgs.buf, input_msgs.size);
  len = 0;
  for(i=input_msgs.ptr;i<input_msgs.size;i++)
  {
    len++;
    if((input_msgs.buf[i] == '\n')||(len >= cnt))
      break;
  }
  
  if(len==0)
    ret = 0;
  else
  {
    ret = len;
    if(copy_to_user(gaddr, input_msgs.buf + input_msgs.ptr, len))
      ret = -TARGET_EFAULT;
    else
    {
      void* p = lock_user(VERIFY_READ, gaddr, len, 1);
      // gemu_log("\nread: ");
      // display_hex((char*)p, len);
      unlock_user(p, gaddr, 0);
      // for(;i<input_msgs.size;i++)
      // {
      //   if(input_msgs.buf[i] != '\n')
      //     break;
      // }
      input_msgs.ptr += len;
    }

  }
  return ret;
}

static abi_long read_byte_by_byte(abi_long gaddr, abi_long cnt)
{
    // gemu_log("this is read_bbb\n");
    // gemu_log("rbb(gaddr=0x%x, cnt=%i)\n", gaddr, cnt);
    abi_long ret;
    abi_long fd = 0;
    char* buf = malloc(sizeof(char) * cnt);
    int i;
    int len = 0;
    for(i=0; i<cnt; i++)
    {
        ret = get_errno(read(fd, buf + i, 1));
        if(ret < 0)
            return ret;
        if(ret == 0)
            break;
        len++;
        if(buf[i] == '\n')
            break;
    }
    ret = len;
    // gemu_log("  --> read:  ");
    // display_hex(buf, len);
    if((ret > 0) && (copy_to_user(gaddr, buf, len)))
        ret = -TARGET_EFAULT;
    return ret;
}





/* Convert QEMU provided timer ID back to internal 16bit index format */

/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7,
                    abi_long arg8)
{
    CPUState *cpu = ENV_GET_CPU(cpu_env);
    abi_long ret;
    // struct stat st;
    // struct statfs stfs;
    void *p;

#ifdef DEBUG
    gemu_log("syscall %d", num);
#endif
    if(do_strace)
        print_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

#define TARGET_NR_terminate 1
#define TARGET_NR_transmit 2
#define TARGET_NR_receive 3
#define TARGET_NR_fdwait 4
#define TARGET_NR_allocate 5
#define TARGET_NR_deallocate 6
#define TARGET_NR_random 7

    switch(num) {
      case TARGET_NR_terminate:
        /* In old applications this may be used to implement _exit(2).
           However in threaded applictions it is used for thread termination,
           and _exit_group is used for application termination.
           Do thread termination if we have more then one thread.  */
        /* FIXME: This probably breaks if a signal arrives.  We should probably
           be disabling signals.  */
      _terminate:
        if (CPU_NEXT(first_cpu)) {
            TaskState *ts;

            cpu_list_lock();
            /* Remove the CPU from the list.  */
            QTAILQ_REMOVE(&cpus, cpu, node);
            cpu_list_unlock();
            ts = cpu->opaque;
            if (ts->child_tidptr) {
                put_user_u32(0, ts->child_tidptr);
                sys_futex(g2h(ts->child_tidptr), FUTEX_WAKE, INT_MAX,
                          NULL, NULL, 0);
            }
            thread_cpu = NULL;
            object_unref(OBJECT(cpu));
            g_free(ts);
            pthread_exit(NULL);
        }
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;

      case TARGET_NR_receive: 
      {
        if (arg3 == 0)
            ret = 0;
        else 
        {
          if(arg1 == 0)
          {
            // ret = read_from_imsgs_buf(arg2, arg3);
            ret = read_byte_by_byte(arg2, arg3);
            // gemu_log("rec(arg2=0x%x, arg3=%i, arg4=0x%x)\n", arg2, arg3,arg4);
          }
          else
          {
            // gemu_log("arg3: %i\n", arg3);
            if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
                 goto efault;
            ret = get_errno(read(arg1, p, arg3));
            // gemu_log("  -->p read: ");
            // display_hex((char*)p, ret);
            unlock_user(p, arg2, ret);
          }
          
        }
        if(ret >= 0)
        {
          // gemu_log("p: %s\n", (char*)p);
          // gemu_log("rec ret: %i\n", ret);
          if(arg4 && copy_to_user(arg4, &ret, 4))
            goto efault;        

          if (ret == 0)
          {
            // gemu_log("ptr vs size: %i vs %i\n", input_msgs.ptr, input_msgs.size);
            empty_rec_cnt++;
            // gemu_log("empty_rec_cnt: %i\n-----", empty_rec_cnt);
            if(empty_rec_cnt >= 4)
              goto _terminate;
            if(empty_rec_cnt >= 3)
              goto efault;
          }
          else
          {
            empty_rec_cnt = 0;
            ret = 0;
          }
        }
        break;
      }

      case TARGET_NR_fdwait://cgcos_fdwait(int nfds, fd_set __user *readfds, fd_set __user *writefds, struct timeval __user *timeout, int __user *readyfds)
      {

        //assume that fdwait(0, NULL, NULL, ..., NULL) is used to emulate sleep()
        if(arg1 == 0)
        {
            ret = 0;
            if(arg5 && copy_to_user(arg5, &ret, 4))
                goto efault;
        }
        else
        {
            ret = do_select(arg1, arg2, arg3, (abi_long)NULL, arg4);
            // gemu_log("\nfw ret: %i\n", ret);

            if(ret > 0)
            {
              if(arg5 && copy_to_user(arg5, &ret, 4))
                goto efault;
              ret = 0;
            }
        }
        break;
      }

      case TARGET_NR_transmit://cgcos_transmit(int fd, char __user * buf, size_t count, size_t __user *tx_bytes)
      {
      // gemu_log("this is syscall transmit()\n");
        // gemu_log("\ntrans arg1: %i\n", arg1);
        if (arg3 == 0)
          ret = 0;
        else {
          abi_long fd = arg1;
          if(arg1 == 0)
            fd = 1;
          if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
          ret = get_errno(write(fd, p, arg3));  
          // gemu_log("  <--p write: ");
          // display_hex((char*)p, ret);
          unlock_user(p, arg2, 0);
        }
        if(ret >= 0) 
        {
          if(arg4 && copy_to_user(arg4, &ret, 4))
            goto efault;
          ret = 0;
        }
        break;
      }

      case TARGET_NR_allocate://cgcos_allocate(unsigned long len, unsigned long exec, void __user **addr)
      {
        if(arg1 == 0)
        {
            ret = -TARGET_EINVAL;
        }
        else
        {
            int prot = PROT_READ | PROT_WRITE;
            if(arg2)
              prot |= PROT_EXEC;
            // ret = get_errno(target_mmap(0, arg1, prot, 
              // MAP_ANON | MAP_PRIVATE, -1, 0));
            ret = target_mmap(0, arg1, prot, 
              MAP_ANON | MAP_PRIVATE, -1, 0);
            // gemu_log("ret0: 0x%x\n", ret);
            // ret = get_errno(ret);
            // if(ret < 0)
            if(ret == -1)
            {   
                ret = get_errno(ret);
                goto efault;
            }
            if(arg3 && copy_to_user(arg3, &ret, 4))
            {
              // gemu_log("**\n");
              target_munmap(ret, arg1);
              goto efault;
            }

            ret = 0;

        }

        break;
      }

      case TARGET_NR_deallocate: {
        ret = get_errno(target_munmap(arg1, arg2));
        // uint32_t addr = (uint32_t)arg1;
        // heap_obj_free(&heap_object_tree, addr);
        // fprintf(stderr, "\ndeallocate()\n");
        break;
      }

      case TARGET_NR_random: //cgcos_random(char __user * buf, size_t count, size_t __user *rnd_out) 
      {
        if(arg2 < 0)
          goto efault;
        size_t i, size = 1;
        size_t cnt = arg2;
        /*
        uint32_t randval;
        for(i=0; i<cnt; i+=4)
        {
          randval = 0x12345678;
          size = cnt - i;
          if(size > 4)
            size = 4;
          if(copy_to_user(arg1 + i, &randval, size))
            goto efault;
        }*/

        // static uint8_t randval = 0x30;
        // for(i=0; i<cnt; i++)
        // {
        //   if(copy_to_user(arg1 + i, &randval, size))
        //     goto efault;
        //   randval++;
        // }
        for(i=0; i<cnt; i++)
        {
            if(copy_to_user(arg1 + i, g_randvals + g_next_randval_index, size))
                goto efault;
            g_next_randval_index++;
            if(g_next_randval_index > g_max_randval_index)
            {
                g_next_randval_index = 0;
            }
        }

        // void* p = lock_user(VERIFY_READ, arg1, cnt, 1);
        // gemu_log("\nrandom buf: ");
        // display_hex((char*)p, cnt);
        // unlock_user(p, arg1, 0);

        if(arg3 && copy_to_user(arg3, &cnt, 4))
          goto efault;
        ret = 0;     

        break;             
      }

      default:
      // unimplemented:
        gemu_log("qemu: Unsupported syscall: %d\n", num);
        ret = -TARGET_ENOSYS;
        break;
    }


fail:
#ifdef DEBUG
    gemu_log(" = " TARGET_ABI_FMT_ld "\n", ret);
#endif
      if(do_strace)
        print_syscall_ret(num, ret);


      // ret = cgc_map_err(ret); 

      return ret;
  efault:
    ret = -TARGET_EFAULT;
    goto fail;
}
