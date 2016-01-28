#include <stdio.h>


int
main(void)
{
  char tmp[320];
  int x = snprintf(tmp, sizeof(tmp), "output is %*.*f\n", 2,3,20.3);

  puts(tmp);
  printf("snprintf returned %d\n", x);
  return 0;
}
