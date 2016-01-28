#include <stdlib.h>

int a = 1;
int b = 2;
int c = 3;
int d = 4;

int
main(void)
{
  int i;
  for(i = 0; i < d; i++) {
    int t = a;
    a = b;
    b = c;
    c = t;
  }

  if(a != 2)
    abort();
  if(b != 3)
    abort();
  if(c != 1)
    abort();

  exit(0);
}
