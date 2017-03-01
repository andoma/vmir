#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include "sha1.h"

static uint8_t buf[65536];

static void sumfile(int fd, const char *name)
{
  SHA1Context ctx;
  uint8_t digest[20];
  char digeststr[41] = {};
  int len;

  SHA1Reset(&ctx);

  while((len = read(fd, buf, sizeof(buf))) > 0) {
    SHA1Input(&ctx, buf, len);
  }

  SHA1Finish(&ctx, digest);

  for(int j = 0; j < 20; j++) {
    digeststr[j * 2 + 0] = "0123456789abcdef"[digest[j] >> 4];
    digeststr[j * 2 + 1] = "0123456789abcdef"[digest[j] & 15];
  }

  printf("%s  %s\n", digeststr, name);
}



int main(int argc, char **argv)
{
  if(argc < 2) {
    sumfile(0, "-");
    return 0;
  }
  for(int i = 1; i < argc; i++) {
    int fd = open(argv[1], O_RDONLY);
    if(fd == -1) {
      printf("Unable to open %s\n", argv[i]);
      exit(1);
    }
    sumfile(fd, argv[i]);
    close(fd);
  }
  return 0;
}

