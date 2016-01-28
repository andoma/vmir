#include <stdlib.h>
#include <stdio.h>


int
main(void)
{
  FILE *fp = fopen("/tmp/vmirtest", "rb");
  if(fp == NULL)
    abort();

  char buf[10];
  int r = fread(buf, 1, 10, fp);
  buf[r] = 0;
  puts(buf);

  fclose(fp);

}
