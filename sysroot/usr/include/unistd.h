#pragma once

#include <stddef.h>
#include "sys/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef int ssize_t;

pid_t getpid(void);
pid_t getppid(void);

ssize_t read(int fildes, void *buf, size_t nbyte);
ssize_t write(int fildes, void *buf, size_t nbyte);

off_t lseek(int fd, off_t offset, int whence);

int close(int fildes);

#ifdef __cplusplus
}
#endif
