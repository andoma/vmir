#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int a = 0x00;
int b = 0x10;
int c = 0x20;
int d = 0x30;
int e = 0x40;
int f = 0x50;
int g = 0x70;
int h = 0x80;

__attribute__((noinline))
int sw(int x)
{
  switch(x & 7) {
  case 0: return a;
  case 1: return b;
  case 2: abort();
  case 3: return d;
  case 4: return e;
  case 5: return f;
  case 6: return g;
  case 7: return h;
  }
  return a;
}


int main(int argc, char **argv)
{
  return sw(argc);
}
