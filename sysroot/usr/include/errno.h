#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#define	EPERM   1
#define	ENOENT  2
#define	ESRCH   3
#define	EINTR   4
#define	EIO     5
#define	ENXIO   6
#define	E2BIG   7
#define	ENOEXEC 8
#define	EBADF   9
#define	ECHILD  10
#define	EAGAIN  11
#define	ENOMEM  12
#define	EACCES  13
#define	EFAULT  14
#define	EBUSY   16
#define	EEXIST  17
#define	EXDEV   18
#define	ENODEV  19
#define	ENOTDIR 20
#define	EISDIR  21
#define	EINVAL  22

extern int errno;

#ifdef __cplusplus
}
#endif

