#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif
#if 0
}
#endif

struct tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
};


typedef int time_t;
typedef long long clock_t;

#define CLOCKS_PER_SEC 1000000LL

time_t time(time_t *t);

clock_t clock(void);

double difftime(time_t time1, time_t time0);

time_t mktime(struct tm *tm);

size_t strftime(char *s, size_t max, const char *format,
                const struct tm *tm);


#ifdef __cplusplus
}
#endif
