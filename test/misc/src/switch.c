#include <stdlib.h>

int x = 3213;

int test(int x)
{
  switch(x) {
  case 5:
    return 100;
  case 102:
    return 105;
  case 321:
    return 10044;
  case 121:
    return 100223;
  case 3:
    return 89127883;
  case -3:
    return 12398;
  default:
    return -1;
  }
}


int main(void)
{
  if(test(5) != 100)
    abort();
  if(test(102) != 105)
    abort();
  if(test(321) != 10044)
    abort();
  if(test(121) != 100223)
    abort();
  if(test(-3) != 12398)
    abort();
  if(test(3) != 89127883)
    abort();
  if(test(-2) != -1)
    abort();
  exit(0);
}
