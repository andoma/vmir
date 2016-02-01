
/**
 *
 */
static int64_t __attribute__((unused))
get_ts(void)
{
#if _POSIX_TIMERS > 0 && defined(_POSIX_MONOTONIC_CLOCK)
  struct timespec tv;
  clock_gettime(CLOCK_MONOTONIC, &tv);
  return (int64_t)tv.tv_sec * 1000000LL + (tv.tv_nsec / 1000);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
#endif
}


#define COMBINE2(a,b) (((a) << 8) | (b))
#define COMBINE3(a,b,c) (((a) << 16) | ((b) << 8) | (c))
#define COMBINE4(a,b,c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))


#define VMIR_ALIGN(a, b) (((a) + (b) - 1) & ~((b) - 1))

#define VECTOR_HEAD(name, type) struct name { \
  type *vh_p; \
  size_t vh_length; \
  size_t vh_capacity; \
  }

#define VECTOR_ITEM(head, n) (head)->vh_p[n]

#define VECTOR_LEN(head) ((head)->vh_length)

#define VECTOR_RESIZE(head, n) do {                             \
    if(n > (head)->vh_capacity) {                               \
      (head)->vh_capacity = (n) * 2;                            \
      size_t memsiz = (head)->vh_capacity *                     \
        sizeof(typeof((head)->vh_p[0]));                        \
      (head)->vh_p = realloc((head)->vh_p, memsiz);             \
    }                                                           \
    (head)->vh_length = n;                                      \
  } while(0)

#define VECTOR_SET_CAPACITY(head, n) do {                       \
    if(n > (head)->vh_capacity) {                               \
      (head)->vh_capacity = (n);                                \
      size_t memsiz = (head)->vh_capacity *                     \
        sizeof(typeof((head)->vh_p[0]));                        \
      (head)->vh_p = realloc((head)->vh_p, memsiz);             \
    }                                                           \
  } while(0)

#define VECTOR_PUSH_BACK(head, item) do {          \
  size_t cursize = VECTOR_LEN(head);               \
  VECTOR_RESIZE(head, cursize + 1);                \
  VECTOR_ITEM(head, cursize) = (item);             \
  } while(0)

#define VECTOR_CLEAR(head) do {                 \
  (head)->vh_capacity = 0;                      \
  (head)->vh_length = 0;                        \
  free((head)->vh_p);                           \
  } while(0)


#define VECTOR_SORT(head, cmpfun) \
  qsort((head)->vh_p, (head)->vh_length,                                \
        sizeof((head)->vh_p[0]), (void *)cmpfun)


static void __attribute__((unused))
vmir_hexdump(const char *pfx, const void *data_, int len)
{
  int i, j, k;
  const uint8_t *data = data_;
  char buf[100];

  for(i = 0; i < len; i+= 16) {
    int p = snprintf(buf, sizeof(buf), "0x%06x: ", i);

    for(j = 0; j + i < len && j < 16; j++) {
      p += snprintf(buf + p, sizeof(buf) - p, "%s%02x ",
                    j==8 ? " " : "", data[i+j]);
    }
    const int cnt = (17 - j) * 3 + (j < 8);
    for(k = 0; k < cnt; k++)
      buf[p + k] = ' ';
    p += cnt;

    for(j = 0; j + i < len && j < 16; j++)
      buf[p++] = data[i+j] < 32 || data[i+j] > 126 ? '.' : data[i+j];
    buf[p] = 0;
    printf("%s: %s\n", pfx, buf);
  }
}


static int
vmir_llvm_alignment(int align)
{
  if(align == 0)
    return 1;
  if(align > 9)
    return 256;
  return (1 << align) >> 1;
}


/**
 *
 */
static void
bitset(uint32_t *bs, int v)
{
  bs[v >> 5] |= 1 << (v & 31);
}

/**
 *
 */
static void
bitclr(uint32_t *bs, int v)
{
  bs[v >> 5] &= ~(1 << (v & 31));
}


/**
 *
 */
static int __attribute__((unused))
bitchk(const uint32_t *bs, int v)
{
  if(bs[v >> 5] & (1 << (v & 31)))
    return 1;
  return 0;
}


/**
 *
 */
static void
bitset_or(uint32_t *bs, const uint32_t *src, int words)
{
  for(int i = 0; i < words; i++)
    bs[i] |= src[i];
}
