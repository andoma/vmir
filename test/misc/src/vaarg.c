#include <stdlib.h>
#include <stdarg.h>

int __attribute__((noinline)) test(int a, ...)
{
  va_list ap;
  va_start(ap, a);
  int b = va_arg(ap, int);
  int c = va_arg(ap, int);
  va_end(ap);
  return a+b+c;
}


int main(void)
{
  if(test(0x10,0x20,0x30) != 0x60)
    abort();
  exit(0);
}
