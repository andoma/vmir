#include <stdio.h>


extern void world(void);

int main(int argc, char **argv)
{
  printf("hello ");
  world();
  printf(": ");
  for(int i = 1 ; i < argc; i++) {
    printf("%s ", argv[i]);
  }
  printf("\n");
}
