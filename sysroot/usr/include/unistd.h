#pragma once

#include "sys/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef int ssize_t;

pid_t getpid(void);
pid_t getppid(void);

#ifdef __cplusplus
}
#endif
