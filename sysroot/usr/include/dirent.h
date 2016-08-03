#pragma once

#include "sys/types.h"

#ifdef __cplusplus
extern "C"
{
#endif
#if 0
}
#endif


struct dirent {
  ino_t          d_ino;
  off_t          d_off;
  unsigned short d_reclen;
  unsigned char  d_type;
  char           d_name[256];
};

DIR *opendir(const char *name);
DIR *fdopendir(int fd);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);


#ifdef __cplusplus
}
#endif
