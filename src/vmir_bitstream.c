/*
 * Copyright (c) 2016 Lonelycoder AB
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

typedef struct bcbitstream {
  const uint8_t *rdata;

  int bytes_length;
  int bytes_offset;
  int remain;
  uint8_t tmp;
} bcbitstream_t;



static uint32_t
read_bits(bcbitstream_t *bs, int num)
{
  int r = 0;
  int off = 0;

  while(num > 0) {
    if(bs->bytes_offset >= bs->bytes_length)
      return 0;

    if(bs->remain == 0) {
      bs->tmp = bs->rdata[bs->bytes_offset];
      bs->bytes_offset++;
      bs->remain = 8;
    }

    int pick = VMIR_MIN(num, bs->remain);
    r |= (bs->tmp & ((1 << pick) - 1)) << off;
    bs->tmp = bs->tmp >> pick;
    off += pick;
    num -= pick;
    bs->remain -= pick;
  }
  return r;
}


/**
 *
 */
static void
align_bits32(bcbitstream_t *bs)
{
  bs->bytes_offset = (bs->bytes_offset + 3) & ~3;
  bs->remain = 0;
}

/**
 *
 */
static uint32_t
read_vbr(bcbitstream_t *bs, int width)
{
  assert(width > 0);

  uint32_t ret = 0;
  const uint32_t cont = (1 << (width - 1));
  const uint32_t mask = cont - 1;
  int stride = 0;

  while(1) {
    uint32_t x = read_bits(bs, width);
    ret |= (x & mask) << stride;
    if(cont & x) {
      stride += width - 1;
      assert(stride < 32);
    } else {
      break;
    }
  }
  return ret;
}


/**
 *
 */
static uint64_t
read_vbr64(bcbitstream_t *bs, int width)
{
  assert(width > 0);

  uint64_t ret = 0;
  const uint32_t cont = (1 << (width - 1));
  const uint32_t mask = cont - 1;
  int stride = 0;

  while(1) {
    uint32_t x = read_bits(bs, width);
    ret |= (uint64_t)(x & mask) << stride;
    if(cont & x) {
      stride += width - 1;
      assert(stride < 64);
    } else {
      break;
    }
  }
  return ret;
}


/**
 *
 */
static char *
read_zstr_from_argv(unsigned int *argcp, const int64_t **argvp)
{
  int len = 0;
  const int64_t *argv = *argvp;
  int argc = *argcp;
  for(len = 0; len < argc; len++) {
    if(argv[len] == 0)
      break;
  }
  if(len == argc)
    return NULL;
  len++;
  char *s = malloc(len);

  *argvp = argv + len;
  *argcp = argc - len;


  for(len = 0; len < argc; len++) {
    s[len] = argv[len];
    if(argv[len] == 0)
      break;
  }
  return s;
}


/**
 *
 */
static char *
read_str_from_argv(unsigned int argc, const int64_t *argv)
{
  char *r = malloc(argc + 1);
  r[argc] = 0;
  for(int i = 0; i < argc; i++)
    r[i] = argv[i];
  return r;
}


/**
 *
 */
static int64_t
read_sign_rotated(const int64_t *argv)
{
  uint64_t u64 = *argv;
  if((u64 & 1) == 0)
    return u64 >> 1;
  if(u64 != 1)
    return -(u64 >> 1);
  return 1ULL << 63;
}

/**
 *
 */
static void
printargs(const int64_t *argv, unsigned int argc)
{
  int i, x;
  int64_t v;
  for(x = 0; x < 2; x++) {
    for(i = 0; i < argc; i++) {
      v = argv[i];
      if(x == 0) {
        printf("%c", (v >= ' ' && v <= 0x7f) ? (char)v : '.');
      } else {
        printf("<0x%" PRIx64 ">", v);
      }
    }
    printf("\n");
  }
}
