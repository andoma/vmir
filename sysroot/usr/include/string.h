#include "stddef.h"

#ifdef __cplusplus
extern "C"
{
#endif
#if 0
}
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

int strcoll(const char *s1, const char *s2);

size_t strxfrm(char *s1, const char *s2, size_t n);

char *strstr(const char *big, const char *little);

size_t strcspn(const char *s1, const char *s2);

size_t strspn(const char *s1, const char *s2);

char *strtok(char *str, const char *sep);

char *strpbrk(const char *s, const char *accept);

void *memchr(const void *s, int c, size_t n);

void *memrchr(const void *s, int c, size_t n);

void *rawmemchr(const void *s, int c);

char *strerror(int errnum);

#ifdef __cplusplus
}
#endif
