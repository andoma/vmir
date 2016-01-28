#include <stdlib.h>

int  __attribute__((noinline)) sub(int a, int b)
{
  return a - b;
}

int  __attribute__((noinline))  foo(int a, int b)
{
  if(a > b)
    return sub(a, b);
  else
    return sub(b, a);
}



int main(void)
{
  if(sub(8,5) != 3)
    abort();
  exit(0);
}
