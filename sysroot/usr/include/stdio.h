#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef void FILE;

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
long ftell(FILE *stream);
int feof(FILE *stream);
int fclose(FILE *fp);

int fseeko(FILE *stream, off_t offset, int whence);
off_t ftello(FILE *stream);

int fgetc(FILE *stream);
int fputc(const char *s, FILE *stream);

int puts(const char *s);

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2


#ifdef __cplusplus
}
#endif
