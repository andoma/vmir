#include "stddef.h"

#ifdef __cplusplus
extern "C"
{
#endif

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *b, int c, size_t len);
int   memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dst, const void *src, size_t len);

char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);

int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);

char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);

char *strdup(const char *s);
size_t strlen(const char *s);

char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);


#ifdef __cplusplus
}
#endif
