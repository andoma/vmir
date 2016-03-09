#pragma once
#pragma clang system_header

#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif
#if 0
}
#endif

typedef void FILE;
typedef long long fpos_t;

#define EOF (-1)

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);

int vprintf(const char *format, va_list ap);
int vfprintf(FILE *stream, const char *format, va_list ap);
int vsprintf(char *str, const char *format, va_list ap);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

FILE *fopen(const char *path, const char *mode);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fseek(FILE *stream, long offset, int whence);
int fgetpos(FILE *stream, fpos_t *pos);
int fsetpos(FILE *stream, fpos_t *pos);
long ftell(FILE *stream);
int feof(FILE *stream);
int fclose(FILE *fp);
int fseeko(FILE *stream, off_t offset, int whence);
off_t ftello(FILE *stream);


int fflush(FILE *stream);
void setbuf(FILE *stream, char *buf);
int setvbuf(FILE *stream, char *buf, int type, size_t size);

int scanf(const char *format, ...);
int fscanf(FILE *stream, const char *format, ...);
int sscanf(const char *s, const char *format, ...);
int vfscanf(FILE *stream, const char *format, va_list arg);

int vsscanf(const char *s, const char *format, va_list arg);
int vscanf(const char *format, va_list arg);

int fgetc(FILE *stream);
int fputc(const char *s, FILE *stream);

char *fgets(char * str, int size, FILE * stream);

int puts(const char *s);
int fputs(const char *s, FILE *stream);

int getc(FILE *stream);
int putc(int c, FILE *stream);
int getchar(void);
char *gets(char *str);

int ungetc(int c, FILE *stream);
void rewind(FILE *stream);
void clearerr(FILE *stream);
int ferror(FILE *stream);

void perror(const char *s);

FILE *freopen(const char *filename, const char *mode, FILE *stream);

int remove(const char *path);

int rename(const char *old, const char *newfile);

FILE *tmpfile(void);
char *tmpnam(char *s);

int putchar(int c);


#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2


#ifdef __cplusplus
}
#endif
