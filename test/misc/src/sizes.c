#include <stdlib.h>
#include <stdbool.h>

volatile bool x = true;

int main(void)
{
  x = 3; // sizeof(x);
  return x;
}
