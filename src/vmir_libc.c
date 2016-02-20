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

#ifdef VMIR_USE_TLSF

#include "tlsf.h"

static void
vmir_heap_init(ir_unit_t *iu)
{
  iu->iu_heap = tlsf_create(iu->iu_mem + iu->iu_heap_start,
                            iu->iu_memsize - iu->iu_heap_start);
}


#define vmir_heap_malloc(heap, size) tlsf_malloc(heap, size)
#define vmir_heap_free(heap, ptr) tlsf_free(heap, ptr)
#define vmir_heap_realloc(heap, ptr, size) tlsf_realloc(heap, ptr, size)



static void
walker(void* ptr, size_t size, int used, void* user)
{
  printf("%p +%zd %s\n", ptr, size, used ? "Used" : "Free");
}

static void
vmir_heap_print0(void *pool)
{
  printf(" --- Heap allocation dump (TLSF) ---\n");
  tlsf_walk_heap(pool, walker, NULL);
}



#else

typedef struct heap_block {
  int hb_magic;
#define HEAP_MAGIC_FREE   0xf4eef4ee
#define HEAP_MAGIC_ALLOC   0xa110ced

  int hb_size;  // Size of block including this header struct
  TAILQ_ENTRY(heap_block) hb_link;
} heap_block_t;

TAILQ_HEAD(heap_block_queue, heap_block);

typedef struct heap {
  struct heap_block_queue h_blocks;
} heap_t;



static void
vmir_heap_init(ir_unit_t *iu)
{
  int size = iu->iu_memsize - iu->iu_heap_start;
  heap_t *h = iu->iu_mem + iu->iu_heap_start;
  iu->iu_heap = h;
  TAILQ_INIT(&h->h_blocks);

  heap_block_t *hb = (void *)(h + 1);

  hb->hb_size = size - sizeof(heap_t);
  hb->hb_magic = HEAP_MAGIC_FREE;
  TAILQ_INSERT_TAIL(&h->h_blocks, hb, hb_link);
}


static void *
vmir_heap_malloc(heap_t *h, int size)
{
  heap_block_t *hb;
  size += sizeof(heap_block_t);
  size = VMIR_ALIGN(size, 16);

  TAILQ_FOREACH(hb, &h->h_blocks, hb_link) {
    if(hb->hb_magic != HEAP_MAGIC_FREE)
      continue;

    if(size <= hb->hb_size) {
      int remain = hb->hb_size - size;
      if(remain < sizeof(heap_block_t) * 2) {
        size = hb->hb_size;
      } else {
        heap_block_t *split = (void *)hb + size;
        split->hb_magic = HEAP_MAGIC_FREE;
        split->hb_size = remain;
        TAILQ_INSERT_AFTER(&h->h_blocks, hb, split, hb_link);
      }

      hb->hb_magic = HEAP_MAGIC_ALLOC;
      hb->hb_size = size;
      return (void *)(hb + 1);
    }
  }
  return NULL;
}


static void
vmir_heap_merge_next(heap_t *h, heap_block_t *hb)
{
  heap_block_t *next = TAILQ_NEXT(hb, hb_link);
  if(next == NULL || next->hb_magic != HEAP_MAGIC_FREE)
    return;
  assert(next > hb);
  TAILQ_REMOVE(&h->h_blocks, next, hb_link);
  hb->hb_size += next->hb_size;
}

static void
vmir_heap_free(heap_t *h, void *ptr)
{
  if(ptr == NULL)
    return;
  heap_block_t *hb = ptr;
  hb--;
  assert(hb->hb_magic == HEAP_MAGIC_ALLOC);
  hb->hb_magic = HEAP_MAGIC_FREE;

  vmir_heap_merge_next(h, hb);
  heap_block_t *prev = TAILQ_PREV(hb, heap_block_queue, hb_link);
  if(prev != NULL) {
    assert(prev < hb);
    vmir_heap_merge_next(h, prev);
  }
}

static int
vmir_heap_usable_size(heap_t *h, void *ptr)
{
  heap_block_t *hb = ptr;
  hb--;
  assert(hb->hb_magic == HEAP_MAGIC_ALLOC);
  return hb->hb_size - sizeof(heap_block_t);
}

static void *
vmir_heap_realloc(heap_t *h, void *ptr, int size)
{
  void *n = NULL;
  if(size) {
    int cursize = vmir_heap_usable_size(h, ptr);
    if(size < cursize)
      return ptr;

    n = vmir_heap_malloc(h, size);
    if(n == NULL)
      return NULL;

    if(ptr != NULL)
      memcpy(n, ptr, cursize);
  }
  vmir_heap_free(h, ptr);
  return n;
}

static void
vmir_heap_print0(heap_t *h)
{
  heap_block_t *hb;
  printf(" --- Heap allocation dump ---\n");
  TAILQ_FOREACH(hb, &h->h_blocks, hb_link) {
    printf("%s 0x%x bytes\n",
           hb->hb_magic == HEAP_MAGIC_ALLOC ? "use " :
           hb->hb_magic == HEAP_MAGIC_FREE  ? "free" :
           "????",
           hb->hb_size);
  }
}


#endif


#define MEMTRACE(fmt...) printf(fmt)

static void
vmir_malloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t size = vm_arg32(&rf);
  MEMTRACE("malloc(%d) = ...\n", size);
  void *p = vmir_heap_malloc(iu->iu_heap, size);
  vm_retptr(ret, p, iu);
  MEMTRACE("malloc(%d) = 0x%x\n", size, *(uint32_t *)ret);
}

static void
vmir_calloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t nmemb = vm_arg32(&rf);
  uint32_t size = vm_arg32(&rf);
  MEMTRACE("calloc(%d, %d) = ...\n", nmemb, size);
  void *p = vmir_heap_malloc(iu->iu_heap, size * nmemb);
  memset(p, 0, size * nmemb);
  vm_retptr(ret, p, iu);
  MEMTRACE("calloc(%d, %d) = 0x%x\n", nmemb, size, *(uint32_t *)ret);
}

static void
vmir_free(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vm_arg32(&rf);
  if(ptr == 0)
    return;
  MEMTRACE("free(0x%x)\n", ptr);
  vmir_heap_free(iu->iu_heap, iu->iu_mem + ptr);
}

static void
vmir_realloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vm_arg32(&rf);
  uint32_t size = vm_arg32(&rf);

  MEMTRACE("realloc(0x%x, %d) = ...\n", ptr, size);
  void *p = vmir_heap_realloc(iu->iu_heap, ptr ? iu->iu_mem + ptr : NULL, size);
  vm_retptr(ret, p, iu);
  MEMTRACE("realloc(0x%x, %d) = 0x%x\n", ptr, size, *(uint32_t *)ret);
}

static void
vmir_heap_print(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_heap_print0(iu->iu_heap);
}


/*--------------------------------------------------------------------
 * Misc
 */


static void
vmir_toupper(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vm_arg32(&rf);
  if(c >= 'a' && c <= 'z')
    c -= 32;
  vm_ret32(ret, c);
}

static void
vmir_tolower(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vm_arg32(&rf);
  if(c >= 'A' && c <= 'Z')
    c += 32;
  vm_ret32(ret, c);
}

static void
vmir_isprint(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vm_arg32(&rf);
  c &= 0x7f;
  c = (c >= ' ' && c < 127);
  vm_ret32(ret, c);
}


static void
vmir_atoi(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vm_ptr(&rf, iu);
  int r = atoi(str);
  vm_ret32(ret, r);
}


/*--------------------------------------------------------------------
 * File IO
 */

typedef struct vFILE {
  FILE *fp;
} vFILE_t;

static void
vmir_fopen(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *path = vm_ptr(&rf, iu);
  const char *mode = vm_ptr(&rf, iu);
  FILE *fp = fopen(path, mode);
  printf("fopen(\"%s\",\"%s\") == %p\n", path, mode, fp);
  if(fp == NULL) {
    vm_retNULL(ret);
    return;
  }

  vFILE_t *vfile = vmir_heap_malloc(iu->iu_heap, sizeof(vFILE_t));
  vfile->fp = fp;
  vm_retptr(ret, vfile, iu);
}

static void
vmir_fseek(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  uint32_t offset = vm_arg32(&rf);
  uint32_t whence = vm_arg32(&rf);
  int r = fseek(vfile->fp, offset, whence);
  vm_ret32(ret, r);
}

static void
vmir_fread(void *ret, const void *rf, ir_unit_t *iu)
{
  void *buf = vm_ptr(&rf, iu);
  uint32_t size = vm_arg32(&rf);
  uint32_t nmemb = vm_arg32(&rf);
  vFILE_t *vfile = vm_ptr(&rf, iu);
  int r = fread(buf, size, nmemb, vfile->fp);
  vm_ret32(ret, r);
}

static void
vmir_fwrite(void *ret, const void *rf, ir_unit_t *iu)
{
  void *buf = vm_ptr(&rf, iu);
  uint32_t size = vm_arg32(&rf);
  uint32_t nmemb = vm_arg32(&rf);
  vFILE_t *vfile = vm_ptr(&rf, iu);
  int r = fwrite(buf, size, nmemb, vfile->fp);
  vm_ret32(ret, r);
}

static void
vmir_feof(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  int r = feof(vfile->fp);
  vm_ret32(ret, r);
}

static void
vmir_ftell(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  int r = ftell(vfile->fp);
  vm_ret32(ret, r);
}

static void
vmir_fclose(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  fclose(vfile->fp);
  vmir_heap_free(iu->iu_heap, vfile);
  vm_ret32(ret, 0);
}

/*-----------------------------------------------------------------------
 * Other stdio
 */

static void
vmir_puts(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vm_ptr(&rf, iu);
  puts(str);
  vm_ret32(ret, 0);
}

static void
vmir_fputc(void *ret, const void *rf, ir_unit_t *iu)
{
  char c = vm_arg32(&rf);
  vFILE_t *vfile = vm_ptr(&rf, iu);
  fwrite(&c, 1, 1, vfile->fp);
  vm_ret32(ret, c);
}

static void
vmir_putchar(void *ret, const void *rf, ir_unit_t *iu)
{
  char c = vm_arg32(&rf);
  putchar(c);
  vm_ret32(ret, c);
}


#define FMT_TYPE_INT    1
#define FMT_TYPE_INT64  2
#define FMT_TYPE_PTR    3
#define FMT_TYPE_STR    4
#define FMT_TYPE_DOUBLE 5


static void
dofmt2(void (*output)(void *opaque, const char *str, int len),
       void *opaque,
       const char *start, const char *end, int num_field_args,
       int type, const void **va, ir_unit_t *iu)
{
  const void *vacopy = *va;
  size_t len = end - start;
  char fmt[len + 1];
  char tmpbuf[100];
  void *alloc = NULL;
  char *dst;
  size_t dz = sizeof(tmpbuf);
  memcpy(fmt, start, len);
  fmt[len] = 0;
  dst = tmpbuf;

  while(1) {
    int n = -1;
    int l1, l2;
    *va = vacopy;
    switch(type) {
    case FMT_TYPE_INT:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vm_arg32(va));
        break;
      case 1:
        l1 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vm_arg32(va));
        break;
      case 2:
        l1 = vm_arg32(va);
        l2 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vm_arg32(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_INT64:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vm_arg64(va));
        break;
      case 1:
        l1 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vm_arg64(va));
        break;
      case 2:
        l1 = vm_arg32(va);
        l2 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vm_arg64(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_PTR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, (void *)(intptr_t)vm_arg32(va));
        break;
      case 1:
        l1 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1,
                     (void *)(intptr_t)vm_arg32(va));
        break;
      case 2:
        l1 = vm_arg32(va);
        l2 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2,
                     (void *)(intptr_t)vm_arg32(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_STR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vm_ptr(va, iu));
        break;
      case 1:
        l1 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vm_ptr(va, iu));
        break;
      case 2:
        l1 = vm_arg32(va);
        l2 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vm_ptr(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_DOUBLE:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vm_arg_dbl(va));
        break;
      case 1:
        l1 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, vm_arg32(va), vm_arg_dbl(va));
        break;
      case 2:
        l1 = vm_arg32(va);
        l2 = vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vm_arg_dbl(va));
        break;
      default:
        goto done;
      }
      break;
    }

    if(n < 0)
      break;

    if(n < dz) {
      output(opaque, dst, n);
      break;
    }

    assert(alloc == NULL);
    dz = n + 1;
    alloc = malloc(dz);
    dst = alloc;
  }

 done:
  free(alloc);
}


// Useful tests at
// https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/tests/printf.c

#define FMT_FLAGS_LONG  0x1
#define FMT_FLAGS_INT64 0x2


static void
dofmt(void (*output)(void *opaque, const char *str, int len),
      void *opaque, const char *fmt, const void *valist,
      ir_unit_t *iu)
{
  while(*fmt) {
    char c = *fmt;
    if(c != '%') {
      output(opaque, fmt, 1); // xxx: lame, should do long runs of unfmted str
      fmt++;
      continue;
    }
    int num_field_args = 0;
    const char *start = fmt;
    int flags = 0;
    fmt++;
  again:
    c = *fmt++;
  reswitch:
    switch(c) {
    case ' ':
    case '#':
    case '+':
    case '-':
    case '0':
      goto again;
    case '*':
      num_field_args++;
      goto again;

    case '.':
      if((c = *fmt++) == '*') {
        goto reswitch;
      }

      while(c >= '0' && c <= '9')
        c = *fmt++;
      goto reswitch;

    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      do {
        c = *fmt++;
      } while(c >= '0' && c <= '9');
      goto reswitch;



    case 'l':
      if(flags & FMT_FLAGS_LONG)
        flags |= FMT_FLAGS_INT64;
      else
        flags |= FMT_FLAGS_LONG;
      goto again;

    case 'q':
      flags |= FMT_FLAGS_INT64;
      goto again;

    case 'c':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT,
             &valist, iu);
      break;

    case 'O':
    case 'o':
    case 'D':
    case 'd':
    case 'i':
    case 'U':
    case 'u':
    case 'X':
    case 'x':
      if(flags & FMT_FLAGS_INT64) {
        dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT64,
               &valist, iu);
      } else {
        dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT,
               &valist, iu);
      }
      break;

    case 'e':
    case 'E':
    case 'f':
    case 'g':
    case 'G':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_DOUBLE,
             &valist, iu);
      break;

    case 'p':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_PTR,
             &valist, iu);
      break;

    case 's':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_STR,
             &valist, iu);
      break;

    case 0:
      return;

    default:
      output(opaque, &c, 1);
      break;
    }
  }
}


typedef struct fmt_sn_aux {
  char *dst;
  unsigned int remain;
  unsigned int total;
} fmt_sn_aux_t;



static void
fmt_sn(void *opaque, const char *str, int len)
{
  fmt_sn_aux_t *aux = opaque;
  aux->total += len;
  if(aux->remain == 0)
    return;

  // Figure out how much to copy, we always reserve one byte for trailing 0
  int to_copy = MIN(aux->remain - 1, len);

  memcpy(aux->dst, str, to_copy);
  aux->dst += to_copy;
  aux->remain -= to_copy;
}


static void
vmir_vsnprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vm_ptr(&rf, iu);
  int dstlen = vm_arg32(&rf);
  const char *fmt = vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);
  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vm_ret32(ret, aux.total);
}

static void
vmir_snprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vm_ptr(&rf, iu);
  int dstlen = vm_arg32(&rf);
  const char *fmt = vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;

  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vm_ret32(ret, aux.total);
}



static void
vmir_vsprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vm_ptr(&rf, iu);
  const char *fmt = vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vm_ret32(ret, aux.total);
}

static void
vmir_sprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vm_ptr(&rf, iu);
  const char *fmt = vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vm_ret32(ret, aux.total);
}




typedef struct fmt_file_aux {
  FILE *output;
  unsigned int total;
} fmt_file_aux_t;


static void
fmt_file(void *opaque, const char *str, int len)
{
  fmt_file_aux_t *aux = opaque;
  aux->total += len;

  fwrite(str, len, 1, aux->output);
}

static void
vmir_vprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.output = stdout;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, va_rf, iu);

  vm_ret32(ret, aux.total);
}


static void
vmir_printf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.output = stdout;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, rf, iu);

  vm_ret32(ret, aux.total);
}


static void
vmir_vfprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  const char *fmt = vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.output = vfile->fp;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, va_rf, iu);

  vm_ret32(ret, aux.total);
}


static void
vmir_fprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vm_ptr(&rf, iu);
  const char *fmt = vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.output = vfile->fp;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, rf, iu);

  vm_ret32(ret, aux.total);
}


/*-----------------------------------------------------------------------
 * c++
 */

static void
vmir_cxa_guard_acquire(void *ret, const void *rf, ir_unit_t *iu)
{
  uint8_t *p = vm_ptr(&rf, iu);
  if(*p == 0) {
    *p = 1;
    vm_ret32(ret, 1);
  } else {
    vm_ret32(ret, 0);
  }
}

static void
vmir_cxa_guard_release(void *ret, const void *rf, ir_unit_t *iu)
{
}


typedef struct function_tab {
  const char *name;
  vm_op_t vmop;
  int vmop_args;
  vm_ext_function_t *extfunc;
} function_tab_t;

#define FN_VMOP(a,b,c) { .name = a, .vmop = b, .vmop_args = c}
#define FN_EXT(a, b)   { .name = a, .extfunc = b }

static const function_tab_t function_routes[] = {
  FN_VMOP("llvm.memcpy.p0i8.p0i8.i32", VM_LLVM_MEMCPY, 3),
  FN_VMOP("llvm.memset.p0i8.i32", VM_LLVM_MEMSET, 3),
  FN_VMOP("llvm.memset.p0i8.i64", VM_LLVM_MEMSET64, 3),
  FN_VMOP("llvm.va_copy", VM_VACOPY, 2),
  FN_VMOP("llvm.invariant.start", VM_NOP, 2),
  FN_VMOP("llvm.stacksave", VM_STACKSAVE, 0),
  FN_VMOP("llvm.stackrestore", VM_STACKRESTORE, 1),
  FN_VMOP("llvm.cttz.i32", VM_CTZ32, 1),
  FN_VMOP("llvm.ctlz.i32", VM_CLZ32, 1),
  FN_VMOP("llvm.ctpop.i32", VM_POP32, 1),

  FN_VMOP("llvm.cttz.i64", VM_CTZ64, 1),
  FN_VMOP("llvm.ctlz.i64", VM_CLZ64, 1),
  FN_VMOP("llvm.ctpop.i64", VM_POP64, 1),
  FN_VMOP("llvm.uadd.with.overflow.i32", VM_UADDO32, 2),

  FN_VMOP("memcpy",  VM_MEMCPY, 3),
  FN_VMOP("memmove", VM_MEMMOVE, 3),
  FN_VMOP("memset",  VM_MEMSET, 3),
  FN_VMOP("memcmp",  VM_MEMCMP, 3),

  FN_VMOP("strcmp",  VM_STRCMP, 2),
  FN_VMOP("strchr",  VM_STRCHR, 2),
  FN_VMOP("strrchr", VM_STRRCHR, 2),
  FN_VMOP("strlen",  VM_STRLEN, 1),
  FN_VMOP("strcpy",  VM_STRCPY, 2),
  FN_VMOP("strncmp", VM_STRNCMP, 3),
  FN_VMOP("strncpy", VM_STRNCPY, 3),

  FN_VMOP("llvm.va_start", VM_VASTART, 2),

  FN_VMOP("abs",   VM_ABS, 1),

  FN_VMOP("floor", VM_FLOOR, 1),
  FN_VMOP("sin",   VM_SIN,   1),
  FN_VMOP("cos",   VM_COS,   1),
  FN_VMOP("pow",   VM_POW,   2),
  FN_VMOP("fabs",  VM_FABS,  1),
  FN_VMOP("fmod",  VM_FMOD,  2),
  FN_VMOP("log10", VM_LOG10, 1),

  FN_VMOP("floorf", VM_FLOORF, 1),
  FN_VMOP("sinf",   VM_SINF,   1),
  FN_VMOP("cosf",   VM_COSF,   1),
  FN_VMOP("powf",   VM_POWF,   2),
  FN_VMOP("fabsf",  VM_FABSF,  1),
  FN_VMOP("fmodf",  VM_FMODF,  2),
  FN_VMOP("log10f", VM_LOG10F, 1),



  FN_EXT("exit", vm_exit),
  FN_EXT("abort", vm_abort),
  FN_EXT("llvm.trap", vm_abort),

  FN_EXT("atoi", vmir_atoi),
  FN_EXT("toupper", vmir_toupper),
  FN_EXT("tolower", vmir_tolower),
  FN_EXT("isprint", vmir_isprint),

  FN_EXT("malloc",  vmir_malloc),
  FN_EXT("free",    vmir_free),
  FN_EXT("realloc", vmir_realloc),
  FN_EXT("calloc",  vmir_calloc),

  FN_EXT("fopen",   vmir_fopen),
  FN_EXT("fseek",   vmir_fseek),
  FN_EXT("fread",   vmir_fread),
  FN_EXT("fwrite",  vmir_fwrite),
  FN_EXT("feof",    vmir_feof),
  FN_EXT("ftell",   vmir_ftell),
  FN_EXT("fclose",  vmir_fclose),
  FN_EXT("puts",    vmir_puts),
  FN_EXT("fputc",   vmir_fputc),
  FN_EXT("putchar", vmir_putchar),

  FN_EXT("vsnprintf",  vmir_vsnprintf),
  FN_EXT("snprintf",  vmir_snprintf),
  FN_EXT("vsprintf",  vmir_vsprintf),
  FN_EXT("sprintf",  vmir_sprintf),
  FN_EXT("vprintf",  vmir_vprintf),
  FN_EXT("printf",  vmir_printf),
  FN_EXT("vfprintf",  vmir_vfprintf),
  FN_EXT("fprintf",  vmir_fprintf),

  FN_EXT("__vmir_heap_print",  vmir_heap_print),

  // C++ low level stuff

  FN_EXT("__cxa_guard_acquire", vmir_cxa_guard_acquire),
  FN_EXT("__cxa_guard_release", vmir_cxa_guard_release),

  FN_EXT("_ZdlPv",  vmir_free),    // operator delete(void*)
  FN_EXT("_Znwj",   vmir_malloc),  // operator new(unsigned int)


  { NULL },

};


/**
 *
 */
static void
function_route(ir_function_t *f)
{
  f->if_vmop = 0;

  for(int i = 0; function_routes[i].name != NULL; i++) {
    const function_tab_t *ft = &function_routes[i];
    if(strcmp(f->if_name, ft->name))
      continue;

    if(ft->vmop) {
      f->if_vmop = ft->vmop;
      f->if_vmop_args = ft->vmop_args;
      return;
    }

    if(ft->extfunc != NULL) {
      f->if_ext_func = ft->extfunc;
      return;
    }
  }
}



static uint32_t
vfile_alloc(ir_unit_t *iu, FILE *ext)
{
  vFILE_t *vfile = vmir_heap_malloc(iu->iu_heap, sizeof(vFILE_t));
  vfile->fp = ext;
  return (void *)vfile - iu->iu_mem;
}


/**
 *
 */
static void
initialize_libc(ir_unit_t *iu)
{
  for(int i = 0; i < iu->iu_next_value; i++) {
    ir_value_t *iv = value_get(iu, i);
    if(iv->iv_class != IR_VC_GLOBALVAR)
      continue;

    ir_globalvar_t *ig = iv->iv_gvar;
    if(ig->ig_name == NULL)
      continue;

    const char *name = ig->ig_name;
    if(!strcmp(name, "stdin")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vfile_alloc(iu, stdin));
    } else if(!strcmp(name, "stdout")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vfile_alloc(iu, stdout));
    } else if(!strcmp(name, "stderr")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vfile_alloc(iu, stderr));
    }
  }
}
