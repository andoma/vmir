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

static __inline void mem_wrptr(ir_unit_t *iu, uint32_t offset, void *ptr)
{
  mem_wr32(iu->iu_mem + offset, ptr ? ptr - iu->iu_mem : 0, iu);
}

static __inline void *mem_rdptr(ir_unit_t *iu, uint32_t offset)
{
  uint32_t p = mem_rd32(iu->iu_mem + offset, iu);
  if(p)
    return iu->iu_mem + p;
  return NULL;
}




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
walker_print(void* ptr, size_t size, int used, void* user)
{
  printf("%p +%zd %s\n", ptr, size, used ? "Used" : "Free");
}

static void
vmir_heap_print0(void *pool)
{
  printf(" --- Heap allocation dump (TLSF) ---\n");
  tlsf_walk_heap(pool, walker_print, NULL);
}



typedef struct walkeraux {
  void (*fn)(void *opaque, uint32_t addr, uint32_t size,
             int inuse);
  void *opaque;
  ir_unit_t *iu;
} walkeraux_t;


static void
walker_ext(void *ptr, size_t size, int used, void* user)
{
  walkeraux_t *aux = user;
  aux->fn(aux->opaque, (uint32_t)(ptr - aux->iu->iu_mem), size, used);
}


void
vmir_walk_heap(ir_unit_t *iu,
               void (*fn)(void *opaque, uint32_t addr, uint32_t size,
                          int inuse),
               void *opaque)
{
  walkeraux_t aux;
  aux.fn = fn;
  aux.opaque = opaque;
  aux.iu = iu;
  tlsf_walk_heap(iu->iu_heap, walker_ext, &aux);
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


#define MEMTRACE(fmt...) // printf(fmt)

static int
vmir_malloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t size = vmir_vm_arg32(&rf);
  MEMTRACE("malloc(%d) = ...\n", size);
  void *p = vmir_heap_malloc(iu->iu_heap, size);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("malloc(%d) = 0x%x\n", size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_calloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t nmemb = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);
  MEMTRACE("calloc(%d, %d) = ...\n", nmemb, size);
  void *p = vmir_heap_malloc(iu->iu_heap, size * nmemb);
  if(p != NULL)
    memset(p, 0, size * nmemb);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("calloc(%d, %d) = 0x%x\n", nmemb, size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_free(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vmir_vm_arg32(&rf);
  if(ptr == 0)
    return 0;
  MEMTRACE("free(0x%x)\n", ptr);
  vmir_heap_free(iu->iu_heap, iu->iu_mem + ptr);
  return 0;
}

static int
vmir_realloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);

  MEMTRACE("realloc(0x%x, %d) = ...\n", ptr, size);
  void *p = vmir_heap_realloc(iu->iu_heap, ptr ? iu->iu_mem + ptr : NULL, size);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("realloc(0x%x, %d) = 0x%x\n", ptr, size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_heap_print(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_heap_print0(iu->iu_heap);
  return 0;
}


/*--------------------------------------------------------------------
 * Misc
 */


static int
vmir_toupper(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  if(c >= 'a' && c <= 'z')
    c -= 32;
  vmir_vm_ret32(ret, c);
  return 0;
}

static int
vmir_tolower(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  if(c >= 'A' && c <= 'Z')
    c += 32;
  vmir_vm_ret32(ret, c);
  return 0;
}

static int
vmir_isprint(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  c &= 0x7f;
  c = (c >= ' ' && c < 127);
  vmir_vm_ret32(ret, c);
  return 0;
}


static int
vmir_isdigit(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  vmir_vm_ret32(ret, c >= '0' && c <= '9');
  return 0;
}


static int
vmir_atoi(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vmir_vm_ptr(&rf, iu);
  int r = atoi(str);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_getpid(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, 1);
  return 0;
}


/*--------------------------------------------------------------------
 * File IO
 */

typedef struct vmir_fd {
  union {
    intptr_t fh;
    int freelist;
  };
  vmir_fd_release_t *release;
  uint8_t type;
} vmir_fd_t;


static int
vfd_create(ir_unit_t *iu, int type)
{
  int fd = iu->iu_vfd_free;

  if(fd != -1) {
    iu->iu_vfd_free = VECTOR_ITEM(&iu->iu_vfds, fd).freelist;
  } else {
    fd = VECTOR_LEN(&iu->iu_vfds);
    vmir_fd_t vfd = {};
    VECTOR_PUSH_BACK(&iu->iu_vfds, vfd);
  }
  VECTOR_ITEM(&iu->iu_vfds, fd).type = type;
  return fd;
}


static vmir_fd_t *
vfd_get(ir_unit_t *iu, unsigned int fd, int type)
{
  if(fd >= VECTOR_LEN(&iu->iu_vfds))
    return NULL;
  vmir_fd_t *vfd = &VECTOR_ITEM(&iu->iu_vfds, fd);
  if(vfd->type == 0 || (type != -1 && vfd->type != type))
    return NULL; // Bad/Closed fd
  return vfd;
}

intptr_t
vmir_fd_get(ir_unit_t *iu, int fd, int type)
{
  vmir_fd_t *vfd = vfd_get(iu, fd, type);
  if(vfd == NULL)
    return 0;
  return vfd->fh;
}


int
vmir_fd_create(ir_unit_t *iu, intptr_t handle, int type,
               vmir_fd_release_t *relfunc)
{
  int fd = vfd_create(iu, type);
  vmir_fd_t *vfd = &VECTOR_ITEM(&iu->iu_vfds, fd);
  vfd->fh = handle;
  vfd->release = relfunc;
  return fd;
}


static void
vmir_fd_release_fh(ir_unit_t *iu, intptr_t handle)
{
  iu->iu_fsops->close(iu->iu_opaque, handle);
}


int
vmir_fd_create_fh(ir_unit_t *iu, intptr_t handle, int closable)
{
  return vmir_fd_create(iu, handle, VMIR_FD_TYPE_FILEHANDLE,
                        closable ? vmir_fd_release_fh : NULL);
}


static int
vfd_open(ir_unit_t *iu, const char *path, vmir_openflags_t flags)
{
  intptr_t fh;
  vmir_errcode_t err = iu->iu_fsops->open(iu->iu_opaque, path, flags, &fh);
  if(err)
    return -1;
  return vmir_fd_create_fh(iu, fh, 1);
}

void
vmir_fd_close(ir_unit_t *iu, int fd)
{
  vmir_fd_t *vfd = vfd_get(iu, fd, -1);
  if(vfd == NULL)
    return;
  if(vfd->release)
    vfd->release(iu, vfd->fh);
  vfd->type = 0;
  vfd->freelist = iu->iu_vfd_free;
  iu->iu_vfd_free = fd;
}


static ssize_t
vfd_read(ir_unit_t *iu, int fd, char *buf, size_t size)
{
  vmir_fd_t *vfd = vfd_get(iu, fd, VMIR_FD_TYPE_FILEHANDLE);
  if(vfd == NULL)
    return -1;
  return iu->iu_fsops->read(iu->iu_opaque, vfd->fh, buf, size);
}


static ssize_t
vfd_write(ir_unit_t *iu, int fd, const char *buf, size_t size)
{
  vmir_fd_t *vfd = vfd_get(iu, fd, VMIR_FD_TYPE_FILEHANDLE);
  if(vfd == NULL)
    return -1;
  return iu->iu_fsops->write(iu->iu_opaque, vfd->fh, buf, size);
}


static int64_t
vfd_seek(ir_unit_t *iu, int fd, int64_t offset, int whence)
{
  vmir_fd_t *vfd = vfd_get(iu, fd, VMIR_FD_TYPE_FILEHANDLE);
  if(vfd == NULL)
    return -1;
  return iu->iu_fsops->seek(iu->iu_opaque, vfd->fh, offset, whence);
}

/*--------------------------------------------------------------------
 * posix io
 */

static int
vmir_open(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *path = vmir_vm_ptr(&rf, iu);
  uint32_t flags = vmir_vm_arg32(&rf);

  uint32_t vmir_flags = 0;
  if(flags & 0100) // O_CREAT
    vmir_flags |= VMIR_FS_OPEN_CREATE;

  if(flags & 2)
    vmir_flags |= VMIR_FS_OPEN_RW;
  else if(flags & 1)
    vmir_flags |= VMIR_FS_OPEN_WRITE;
  else
    vmir_flags |= VMIR_FS_OPEN_READ;

  int fd = vfd_open(iu, path, vmir_flags);
  vmir_vm_ret32(ret, fd);
  return 0;
}


static int
vmir_read(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t fd = vmir_vm_arg32(&rf);
  void *buf = vmir_vm_ptr(&rf, iu);
  uint32_t nbyte = vmir_vm_arg32(&rf);
  vmir_vm_ret32(ret, vfd_read(iu, fd, buf, nbyte));
  return 0;
}

static int
vmir_write(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t fd = vmir_vm_arg32(&rf);
  const void *buf = vmir_vm_ptr(&rf, iu);
  uint32_t nbyte = vmir_vm_arg32(&rf);
  vmir_vm_ret32(ret, vfd_write(iu, fd, buf, nbyte));
  return 0;
}

static int
vmir_lseek(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t fd = vmir_vm_arg32(&rf);
  int64_t offset = vmir_vm_arg64(&rf);
  uint32_t whence = vmir_vm_arg32(&rf);
  vmir_vm_ret64(ret, vfd_seek(iu, fd, offset, whence));
  return 0;
}

static int
vmir_close(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t fd = vmir_vm_arg32(&rf);
  vmir_fd_close(iu, fd);
  vmir_vm_ret32(ret, 0);
  return 0;
}

/*--------------------------------------------------------------------
 * stdio
 */

typedef struct vFILE {
  FILE *fp;
  ir_unit_t *iu;
  int fd;
  LIST_ENTRY(vFILE) link;
} vFILE_t;

// http://pubs.opengroup.org/onlinepubs/9699919799/functions/fopen.html
static const struct {
  char mode[4];
  vmir_openflags_t flags;
} modetable[] = {
  { "r",   VMIR_FS_OPEN_READ },
  { "rb",  VMIR_FS_OPEN_READ },
  { "w",   VMIR_FS_OPEN_WRITE | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_TRUNC },
  { "wb",  VMIR_FS_OPEN_WRITE | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_TRUNC },
  { "a",   VMIR_FS_OPEN_WRITE | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_APPEND },
  { "ab",  VMIR_FS_OPEN_WRITE | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_APPEND },
  { "r+",  VMIR_FS_OPEN_RW },
  { "rb+", VMIR_FS_OPEN_RW },
  { "r+b", VMIR_FS_OPEN_RW },
  { "w+",  VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_TRUNC },
  { "wb+", VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_TRUNC },
  { "w+b", VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_TRUNC },
  { "a+",  VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_APPEND },
  { "b+",  VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_APPEND },
  { "a+b", VMIR_FS_OPEN_RW    | VMIR_FS_OPEN_CREATE | VMIR_FS_OPEN_APPEND },
};



#ifdef __APPLE__
#define USE_FUNOPEN 1
#endif

#if USE_FUNOPEN

static int
fun_read(void *fh, char *buf, int size)
{
  vFILE_t *vf = fh;
  return vfd_read(vf->iu, vf->fd, buf, size);
}

static int
fun_write(void *fh, const char *buf, int size)
{
  vFILE_t *vf = fh;
  return vfd_write(vf->iu, vf->fd, buf, size);
}

static fpos_t
fun_seek(void *fh, fpos_t offset, int whence)
{
  vFILE_t *vf = fh;
  return vfd_seek(vf->iu, vf->fd, offset, whence);
}

#else

static ssize_t
cookie_read(void *fh, char *buf, size_t size)
{
  vFILE_t *vf = fh;
  return vfd_read(vf->iu, vf->fd, buf, size);
}

static ssize_t
cookie_write(void *fh, const char *buf, size_t size)
{
  vFILE_t *vf = fh;
  return vfd_write(vf->iu, vf->fd, buf, size);
}

static int
cookie_seek(void *fh, off64_t *offsetp, int whence)
{
  vFILE_t *vf = fh;
  int64_t r = vfd_seek(vf->iu, vf->fd, *offsetp, whence);
  if(r < 0)
    return -1;
  *offsetp = r;
  return 0;
}

#endif

static int
vFILE_close(void *fh)
{
  vFILE_t *vf = fh;
  ir_unit_t *iu = vf->iu;
  vmir_fd_close(vf->iu, vf->fd);
  LIST_REMOVE(vf, link);
  vmir_heap_free(iu->iu_heap, vf);
  return 0;
}


#if !USE_FUNOPEN

static const cookie_io_functions_t cookiefuncs = {
  .read  = cookie_read,
  .write = cookie_write,
  .seek  = cookie_seek,
  .close = vFILE_close,
};

#endif



static void *
vFILE_open_fd(ir_unit_t *iu, int fd, int line_buffered, const char *mode)
{
  vFILE_t *vfile = vmir_heap_malloc(iu->iu_heap, sizeof(vFILE_t));
  if(vfile == NULL) {
    vmir_fd_close(iu, fd);
    return NULL;
  }
  vfile->iu = iu;
  vfile->fd = fd;

#if USE_FUNOPEN
  vfile->fp = funopen(vfile, fun_read, fun_write, fun_seek, vFILE_close);
#else
  vfile->fp = fopencookie(vfile, mode, cookiefuncs);
#endif
  if(vfile->fp == NULL) {
    vmir_fd_close(iu, fd);
    vmir_heap_free(iu->iu_heap, vfile);
    return NULL;
  }
  if(line_buffered)
    setlinebuf(vfile->fp);
  LIST_INSERT_HEAD(&iu->iu_vfiles, vfile, link);
  return vfile;
}


static vFILE_t *
vFILE_open(ir_unit_t *iu, const char *path, const char *mode,
           int line_buffered)
{
  vmir_openflags_t flags = 0;
  for(int i = 0; i < VMIR_ARRAYSIZE(modetable); i++) {
    if(!strcmp(mode, modetable[i].mode)) {
      flags = modetable[i].flags;
      break;
    }
  }
  if(flags == 0)
    return NULL;

  int fd = vfd_open(iu, path, flags);
  if(fd == -1)
    return NULL;
  return vFILE_open_fd(iu, fd, line_buffered, mode);
}


static int
vmir_fopen(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *path = vmir_vm_ptr(&rf, iu);
  const char *mode = vmir_vm_ptr(&rf, iu);
  vFILE_t *vfile = vFILE_open(iu, path, mode, 0);
  vmir_vm_retptr(ret, vfile, iu);
  return 0;
}

static int
vmir_fdopen(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t fd = vmir_vm_arg32(&rf);
  const char *mode = vmir_vm_ptr(&rf, iu);
  vFILE_t *vfile = vFILE_open_fd(iu, fd, 0, mode);
  vmir_vm_retptr(ret, vfile, iu);
  return 0;
}

static int
vmir_fseek(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr_nullchk(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, -1);
    return 0;
  }
  uint32_t offset = vmir_vm_arg32(&rf);
  uint32_t whence = vmir_vm_arg32(&rf);
  int r = fseek(vfile->fp, offset, whence);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_fseeko(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr_nullchk(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret64(ret, -1);
    return 0;
  }
  uint64_t offset = vmir_vm_arg64(&rf);
  uint32_t whence = vmir_vm_arg32(&rf);
  int64_t r = fseeko(vfile->fp, offset, whence);
  vmir_vm_ret64(ret, r);
  return 0;
}

static int
vmir_fread(void *ret, const void *rf, ir_unit_t *iu)
{
  void *buf = vmir_vm_ptr(&rf, iu);
  uint32_t size = vmir_vm_arg32(&rf);
  uint32_t nmemb = vmir_vm_arg32(&rf);
  vFILE_t *vfile = vmir_vm_ptr_nullchk(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, -1);
    return 0;
  }
  int r = fread(buf, size, nmemb, vfile->fp);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_fwrite(void *ret, const void *rf, ir_unit_t *iu)
{
  void *buf = vmir_vm_ptr(&rf, iu);
  uint32_t size = vmir_vm_arg32(&rf);
  uint32_t nmemb = vmir_vm_arg32(&rf);
  vFILE_t *vfile = vmir_vm_ptr_nullchk(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, -1);
    return 0;
  }
  int r = fwrite(buf, size, nmemb, vfile->fp);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_feof(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, 1);
    return 0;
  }
  int r = feof(vfile->fp);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_fflush(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, 1);
    return 0;
  }
  int r = fflush(vfile->fp);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_ftell(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile == NULL) {
    vmir_vm_ret32(ret, -1);
    return 0;
  }
  int r = ftell(vfile->fp);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_ftello(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  uint64_t r = ftello(vfile->fp);
  if(vfile == NULL) {
    vmir_vm_ret64(ret, -1);
    return 0;
  }
  vmir_vm_ret64(ret, r);
  return 0;
}

static int
vmir_fclose(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile != NULL)
    fclose(vfile->fp);
  vmir_vm_ret32(ret, 0);
  return 0;
}

static int
vmir_fileno(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  vmir_vm_ret32(ret, vfile->fd);
  return 0;
}

/*-----------------------------------------------------------------------
 * Other stdio
 */

static int
vmir_puts(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vmir_vm_ptr(&rf, iu);
  if(iu->iu_stdout != NULL)
    fwrite(str, strlen(str), 1, iu->iu_stdout->fp);
  vmir_vm_ret32(ret, 0);
  return 0;
}

static int
vmir_fputc(void *ret, const void *rf, ir_unit_t *iu)
{
  char c = vmir_vm_arg32(&rf);
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile != NULL)
    fwrite(&c, 1, 1, vfile->fp);
  vmir_vm_ret32(ret, c);
  return 0;
}

static int
vmir_fgetc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint8_t c;
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  if(vfile == NULL || fread(&c, 1, 1, vfile->fp) != 1) {
    vmir_vm_ret32(ret, -1);
    return 0;
  }
  vmir_vm_ret32(ret, c);
  return 0;
}


static int
vmir_putchar(void *ret, const void *rf, ir_unit_t *iu)
{
  char c = vmir_vm_arg32(&rf);
  if(iu->iu_stdout != NULL)
    fwrite(&c, 1, 1, iu->iu_stdout->fp);
  vmir_vm_ret32(ret, c);
  return 0;
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
        n = snprintf(dst, dz, fmt, vmir_vm_arg32(va));
        break;
      case 1:
        l1 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_arg32(va));
        break;
      case 2:
        l1 = vmir_vm_arg32(va);
        l2 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_arg32(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_INT64:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_arg64(va));
        break;
      case 1:
        l1 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_arg64(va));
        break;
      case 2:
        l1 = vmir_vm_arg32(va);
        l2 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_arg64(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_PTR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, (void *)(intptr_t)vmir_vm_arg32(va));
        break;
      case 1:
        l1 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1,
                     (void *)(intptr_t)vmir_vm_arg32(va));
        break;
      case 2:
        l1 = vmir_vm_arg32(va);
        l2 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2,
                     (void *)(intptr_t)vmir_vm_arg32(va));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_STR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_ptr(va, iu));
        break;
      case 1:
        l1 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_ptr(va, iu));
        break;
      case 2:
        l1 = vmir_vm_arg32(va);
        l2 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_ptr(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_DOUBLE:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_arg_dbl(va));
        break;
      case 1:
        l1 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, vmir_vm_arg32(va), vmir_vm_arg_dbl(va));
        break;
      case 2:
        l1 = vmir_vm_arg32(va);
        l2 = vmir_vm_arg32(va);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_arg_dbl(va));
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


static int
vmir_vsnprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  int dstlen = vmir_vm_arg32(&rf);
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);
  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;
}

static int
vmir_snprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  int dstlen = vmir_vm_arg32(&rf);
  const char *fmt = vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;

  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;
}



static int
vmir_vsprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;

}

static int
vmir_sprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;

}




typedef struct fmt_vFILE_aux {
  vFILE_t *vfile;
  unsigned int total;
} fmt_file_aux_t;


static void
fmt_file(void *opaque, const char *str, int len)
{
  fmt_file_aux_t *aux = opaque;
  aux->total += len;
  if(aux->vfile != NULL)
    fwrite(str, len, 1, aux->vfile->fp);
}

static int
vmir_vprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vmir_vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.vfile = iu->iu_stdout;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, va_rf, iu);

  vmir_vm_ret32(ret, aux.total);
  return 0;
}


static int
vmir_printf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vmir_vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.vfile = iu->iu_stdout;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, rf, iu);

  vmir_vm_ret32(ret, aux.total);
  return 0;
}


static int
vmir_vfprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = *(void **)vmir_vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.vfile = vfile;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, va_rf, iu);

  vmir_vm_ret32(ret, aux.total);
  return 0;
}


static int
vmir_fprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  vFILE_t *vfile = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);

  fmt_file_aux_t aux;
  aux.vfile = vfile;
  aux.total = 0;
  dofmt(fmt_file, &aux, fmt, rf, iu);

  vmir_vm_ret32(ret, aux.total);
  return 0;
}



static int
vmir_getenv(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, 0);
  return 0;
}


/*-----------------------------------------------------------------------
 * libc string functions
 */
static int
vmir_strtok_r(void *retreg, const void *rf, ir_unit_t *iu)
{
  char *str         = vmir_vm_ptr(&rf, iu);
  const char *delim = vmir_vm_ptr(&rf, iu);
  uint32_t nextp = vmir_vm_arg32(&rf);

  if(str == NULL)
    str = mem_rdptr(iu, nextp);

  str += strspn(str, delim);

  if(*str == '\0') {
    vmir_vm_ret32(retreg, 0);
    return 0;
  }

  char *ret = str;
  str += strcspn(str, delim);
  if(*str)
    *str++ = '\0';

  mem_wrptr(iu, nextp, str);

  vmir_vm_retptr(retreg, ret, iu);
  return 0;
}


static int
vmir_strtok(void *retreg, const void *rf, ir_unit_t *iu)
{
  char *str         = vmir_vm_ptr(&rf, iu);
  const char *delim = vmir_vm_ptr(&rf, iu);

  if(str == NULL)
    str = iu->iu_strtok_tmp;

  str += strspn(str, delim);

  if(*str == '\0') {
    vmir_vm_ret32(retreg, 0);
    return 0;
  }

  char *ret = str;
  str += strcspn(str, delim);
  if(*str)
    *str++ = '\0';

  iu->iu_strtok_tmp = str;

  vmir_vm_retptr(retreg, ret, iu);
  return 0;
}



/*-----------------------------------------------------------------------
 * C++
 */

static int
vmir_cxa_guard_acquire(void *ret, const void *rf, ir_unit_t *iu)
{
  uint8_t *p = vmir_vm_ptr(&rf, iu);
  if(*p == 0) {
    *p = 1;
    vmir_vm_ret32(ret, 1);
  } else {
    vmir_vm_ret32(ret, 0);
  }
  return 0;
}

static int
vmir_cxa_guard_release(void *ret, const void *rf, ir_unit_t *iu)
{
  return 0;
}

static int
vmir__cxa_at_exit(void *ret, const void *rf, ir_unit_t *iu)
{
  return 0;
}


/*-----------------------------------------------------------------------
 * C++ exception handling
 */

typedef struct vmir_cxx_exception {
  uint32_t next;
  int handlers;
  uint32_t destructor;

} vmir_cxx_exception_t;

static int
vmir_llvm_eh_typeid_for(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, vmir_vm_arg32(&rf));
  return 0;
}

static int
vmir___cxa_allocate_exception(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t size = vmir_vm_arg32(&rf);
  void *p = vmir_heap_malloc(iu->iu_heap, size + sizeof(vmir_cxx_exception_t));
  memset(p, 0, sizeof(vmir_cxx_exception_t));
  vmir_vm_retptr(ret, p + sizeof(vmir_cxx_exception_t), iu);
  return 0;
}

static int
vmir___cxa_free_exception(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t x = vmir_vm_arg32(&rf) - sizeof(vmir_cxx_exception_t);
  vmir_heap_free(iu->iu_heap, iu->iu_mem + x);
  return 0;
}

static int
vmir___cxa_begin_catch(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t x = vmir_vm_arg32(&rf);
  uint32_t x2 = x - sizeof(vmir_cxx_exception_t);
  vmir_cxx_exception_t *exc = iu->iu_mem + x2;

  if(exc->handlers < 0) {
    exc->handlers = -exc->handlers + 1;
  } else {
    exc->handlers++;
    iu->iu_exception.uncaught--;
  }

  exc->next = iu->iu_exception.caught;
  iu->iu_exception.caught = x2;
  vmir_vm_ret32(ret, x);
  return 0;
}


static int
vmir___cxa_end_catch(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_cxx_exception_t *exc = iu->iu_mem + iu->iu_exception.caught;

  if(--exc->handlers == 0) {
    iu->iu_exception.caught = exc->next;
    vmir_heap_free(iu->iu_heap, exc);
  }
  return 0;
}

static int
vmir___cxa_throw(void *ret, const void *rf, ir_unit_t *iu)
{
  iu->iu_exception.exception = vmir_vm_arg32(&rf);
  iu->iu_exception.type_info = vmir_vm_arg32(&rf);

  vmir_cxx_exception_t *exc =
    iu->iu_mem + iu->iu_exception.exception  - sizeof(vmir_cxx_exception_t);
  exc->destructor = vmir_vm_arg32(&rf);
  assert(exc->destructor == 0); // Not really supported (yet)
  iu->iu_exception.uncaught++;
  return 1;
}


static int
vmir_std_terminate(void *ret, const void *rf, ir_unit_t *iu)
{
  vm_stop(iu, VM_STOP_UNCAUGHT_EXCEPTION, 0);
  return 0;
}



static int
vmir_set_data_breakpoint(void *ret, const void *rf, ir_unit_t *iu)
{
  iu->iu_data_breakpoint = vmir_vm_ptr_nullchk(&rf, iu);
  printf("Data breakpoint: 0x%zx\n", iu->iu_data_breakpoint - iu->iu_mem);
  return 0;
}



static int
vmir_libc_hexdump(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t addr = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);
  printf("Hexdump of 0x%x\n", addr);
  vmir_hexdump("hexdump", iu->iu_mem + addr, size);
  return 0;
}


static int
vmir_libc_traceback(void *ret, const void *rf, ir_unit_t *iu)
{
#ifndef VM_NO_STACK_FRAME
  vmir_traceback(iu, "__vmir_traceback");
#endif
  return 0;
}


#define FN_EXT(a, b)   { .name = a, .extfunc = b }

static const vmir_function_tab_t libc_funcs[] = {

  FN_EXT("exit", vm_exit),
  FN_EXT("abort", vm_abort),
  FN_EXT("llvm.trap", vm_abort),
  FN_EXT("__cxa_guard_abort", vm_abort),

  FN_EXT("getpid", vmir_getpid),
  FN_EXT("atoi", vmir_atoi),
  FN_EXT("toupper", vmir_toupper),
  FN_EXT("tolower", vmir_tolower),
  FN_EXT("isprint", vmir_isprint),
  FN_EXT("isdigit", vmir_isdigit),

  FN_EXT("malloc",  vmir_malloc),
  FN_EXT("free",    vmir_free),
  FN_EXT("realloc", vmir_realloc),
  FN_EXT("calloc",  vmir_calloc),

  FN_EXT("open",    vmir_open),
  FN_EXT("read",    vmir_read),
  FN_EXT("write",   vmir_write),
  FN_EXT("lseek",   vmir_lseek),
  FN_EXT("close",   vmir_close),

  FN_EXT("fopen",   vmir_fopen),
  FN_EXT("fdopen",  vmir_fdopen),
  FN_EXT("fseek",   vmir_fseek),
  FN_EXT("fseeko",  vmir_fseeko),
  FN_EXT("fread",   vmir_fread),
  FN_EXT("fwrite",  vmir_fwrite),
  FN_EXT("feof",    vmir_feof),
  FN_EXT("fflush",  vmir_fflush),
  FN_EXT("ftell",   vmir_ftell),
  FN_EXT("ftello",  vmir_ftello),
  FN_EXT("fclose",  vmir_fclose),
  FN_EXT("puts",    vmir_puts),
  FN_EXT("fputc",   vmir_fputc),
  FN_EXT("fgetc",   vmir_fgetc),
  FN_EXT("putchar", vmir_putchar),
  FN_EXT("fileno",  vmir_fileno),

  FN_EXT("vsnprintf",  vmir_vsnprintf),
  FN_EXT("snprintf",  vmir_snprintf),
  FN_EXT("vsprintf",  vmir_vsprintf),
  FN_EXT("sprintf",  vmir_sprintf),
  FN_EXT("vprintf",  vmir_vprintf),
  FN_EXT("printf",  vmir_printf),
  FN_EXT("vfprintf",  vmir_vfprintf),
  FN_EXT("fprintf",  vmir_fprintf),

  FN_EXT("strtok_r", vmir_strtok_r),
  FN_EXT("strtok", vmir_strtok),

  FN_EXT("getenv",  vmir_getenv),

  FN_EXT("__vmir_heap_print",  vmir_heap_print),
  FN_EXT("__vmir_set_data_breakpoint",  vmir_set_data_breakpoint),
  FN_EXT("__vmir_hexdump",  vmir_libc_hexdump),
  FN_EXT("__vmir_traceback",  vmir_libc_traceback),

  // C++ low level stuff

  FN_EXT("__cxa_guard_acquire", vmir_cxa_guard_acquire),
  FN_EXT("__cxa_guard_release", vmir_cxa_guard_release),

  FN_EXT("_ZdlPv",  vmir_free),    // operator delete(void*)
  FN_EXT("_Znwj",   vmir_malloc),  // operator new(unsigned int)
  FN_EXT("_ZdaPv",  vmir_free),    // operator delete[](void*)
  FN_EXT("_Znaj",   vmir_malloc),  // operator new[](unsigned int)

  FN_EXT("__cxa_atexit", vmir__cxa_at_exit),

  FN_EXT("__cxa_allocate_exception", vmir___cxa_allocate_exception),
  FN_EXT("__cxa_free_exception", vmir___cxa_free_exception),
  FN_EXT("__cxa_begin_catch", vmir___cxa_begin_catch),
  FN_EXT("__cxa_end_catch", vmir___cxa_end_catch),
  FN_EXT("__cxa_throw", vmir___cxa_throw),
  FN_EXT("llvm.eh.typeid.for", vmir_llvm_eh_typeid_for),
  FN_EXT("_ZSt9terminatev", vmir_std_terminate),
};



/**
 *
 */
vm_ext_function_t *
vmir_function_tab_lookup(const char *function,
                         const vmir_function_tab_t *array, int length)
{
  for(int i = 0; i < length; i++) {
    const vmir_function_tab_t *ft = array + i;
    if(!strcmp(function, ft->name)) {
      return ft->extfunc;
    }
  }
  return NULL;
}

/**
 *
 */
vm_ext_function_t *
vmir_default_external_function_resolver(const char *function, void *opaque)
{
  return vmir_function_tab_lookup(function, libc_funcs,
                                  VMIR_ARRAYSIZE(libc_funcs));
}




#include <fcntl.h>
#include <unistd.h>

static vmir_errcode_t
vmir_sysio_open(void *opaque, const char *path, vmir_openflags_t flags,
                intptr_t *fh)
{
  int fs = O_CLOEXEC;
  fs |= flags & VMIR_FS_OPEN_CREATE ? O_CREAT  : 0;
  fs |= flags & VMIR_FS_OPEN_TRUNC  ? O_TRUNC  : 0;
  fs |= flags & VMIR_FS_OPEN_APPEND ? O_APPEND : 0;

  if((flags & (VMIR_FS_OPEN_READ | VMIR_FS_OPEN_WRITE)) ==
     (VMIR_FS_OPEN_READ | VMIR_FS_OPEN_WRITE))
    fs |= O_RDWR;
  else if(flags & VMIR_FS_OPEN_READ)
    fs |= O_RDONLY;
  else if(flags & VMIR_FS_OPEN_WRITE)
    fs |= O_WRONLY;
  else
    return VMIR_ERR_INVALID_ARGS;

  int fd = open(path, fs, 0644);
  if(fd == -1) {
    return VMIR_ERR_FS_ERROR;
  }
  *fh = fd;
  return 0;
}


static void
vmir_sysio_close(void *opaque, intptr_t fh)
{
  close(fh);
}


static ssize_t
vmir_sysio_read(void *opaque, intptr_t fh, void *buf, size_t count)
{
  return read(fh, buf, count);
}

static ssize_t
vmir_sysio_write(void *opaque, intptr_t fh, const void *buf, size_t count)
{
  return write(fh, buf, count);
}


static int64_t
vmir_sysio_seek(void *opaque, intptr_t fh, int64_t offset, int whence)
{
  return lseek(fh, offset, whence);
}


static const vmir_fsops_t vmir_sysio_fsops = {
  .open  = vmir_sysio_open,
  .close = vmir_sysio_close,
  .read  = vmir_sysio_read,
  .write = vmir_sysio_write,
  .seek  = vmir_sysio_seek,
};


void
vmir_set_fsops(ir_unit_t *iu, const vmir_fsops_t *ops)
{
  iu->iu_fsops = ops;
}

/**
 *
 */
static void
libc_initialize(ir_unit_t *iu)
{
  iu->iu_vfd_free = -1;

  if(iu->iu_fsops == NULL)
    iu->iu_fsops = &vmir_sysio_fsops;

  iu->iu_stdin  = vFILE_open(iu, "/dev/stdin",  "r", 1);
  iu->iu_stdout = vFILE_open(iu, "/dev/stdout", "w", 1);
  iu->iu_stderr = vFILE_open(iu, "/dev/stderr", "w", 1);

  const uint32_t vm_stdin  = vmir_host_to_vmaddr(iu, iu->iu_stdin);
  const uint32_t vm_stdout = vmir_host_to_vmaddr(iu, iu->iu_stdout);
  const uint32_t vm_stderr = vmir_host_to_vmaddr(iu, iu->iu_stderr);

  for(int i = 0; i < iu->iu_next_value; i++) {
    ir_value_t *iv = value_get(iu, i);
    if(iv->iv_class != IR_VC_GLOBALVAR)
      continue;

    ir_globalvar_t *ig = iv->iv_gvar;
    if(ig->ig_name == NULL)
      continue;

    const char *name = ig->ig_name;
    if(!strcmp(name, "stdin")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vm_stdin, iu);
    } else if(!strcmp(name, "stdout")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vm_stdout, iu);
    } else if(!strcmp(name, "stderr")) {
      mem_wr32(iu->iu_mem + ig->ig_addr, vm_stderr, iu);
    }
  }
}

static void __attribute__((unused))
libc_terminate(ir_unit_t *iu)
{
  vFILE_t *vf;

  while((vf = LIST_FIRST(&iu->iu_vfiles)) != NULL)
    fclose(vf->fp);
}


void
vmir_walk_fds(ir_unit_t *iu,
              void (*fn)(void *opaque, int fd, int type),
              void *opaque)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_vfds); i++) {
    vmir_fd_t *vfd = &VECTOR_ITEM(&iu->iu_vfds, i);
    if(vfd->type != 0)
      fn(opaque, i, vfd->type);
  }
}


uint32_t
vmir_mem_alloc(ir_unit_t *iu, uint32_t size, void *hostaddr_)
{
  void **hostaddr = hostaddr_;
  void *p = vmir_heap_malloc(iu->iu_heap, size);
  if(p == NULL) {
    if(hostaddr)
      *hostaddr = NULL;
    return 0;
  }
  if(hostaddr)
    *hostaddr = p;
  return p - iu->iu_mem;
}

void
vmir_mem_free(ir_unit_t *iu, uint32_t addr)
{
  return vmir_heap_free(iu->iu_heap, iu->iu_mem + addr);
}
