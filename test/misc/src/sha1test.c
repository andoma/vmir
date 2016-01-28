#include <stdio.h>
#include <stdint.h>

#include "sha1_c.h"


static uint8_t buf[65536];

int main(int argc, char **argv)
{
  SHA1Context ctx;
  uint8_t digest[20];
  char digeststr[41];

  digeststr[40] = 0;
  for(int i = 1; i < argc; i++) {
    FILE *fp = fopen(argv[i], "rb");
    if(fp == NULL) {
      printf("Unable to open %s\n", argv[i]);
      exit(1);
    }

    SHA1Reset(&ctx);
    while(!feof(fp)) {
      size_t s = fread(buf, 1, sizeof(buf), fp);

      if(s > 0) {
        SHA1Input(&ctx, buf, s);
      }
    }
    fclose(fp);

    SHA1Finish(&ctx, digest);

    for(int j = 0; j < 20; j++) {
      digeststr[j * 2 + 0] = "0123456789abcdef"[digest[j] >> 4];
      digeststr[j * 2 + 1] = "0123456789abcdef"[digest[j] & 15];
    }

    printf("%s  %s\n", digeststr, argv[i]);
  }
  return 0;
}

