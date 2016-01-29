#include "stddef.h"

#ifdef __cplusplus
extern "C"
{
#endif

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

int atoi(const char *nptr);

int abs(int j);

char *getenv(const char *name);

void __attribute__((noreturn)) exit(int status);
void __attribute__((noreturn)) abort(void);

#ifdef __cplusplus
}
#endif
