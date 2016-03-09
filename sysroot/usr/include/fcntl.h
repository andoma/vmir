#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#define O_ACCMODE       00000003
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

#define O_CREAT         00000100
#define O_EXCL          00000200


int open(const char *pathname, int flags, ...);

#ifdef __cplusplus
}
#endif


