
#ifdef VM_TRACE

#define CHECK_MEM_ACCESS() do {                         \
  if(p < iu->iu_mem_low || p >= iu->iu_mem_high)        \
    vmir_access_violation(iu, p, __FUNCTION__);         \
  if(p == iu->iu_data_breakpoint)                       \
    vmir_access_trap(iu, p, __FUNCTION__);              \
  } while(0)

#else
#define CHECK_MEM_ACCESS()
#endif


/*
 * Memory access wrappers (and endian conversion routines)
 *
 * Makes sure we swap endianess when running on a bit endian system
 *
 */
static __inline uint8_t mem_rd8(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return *(uint8_t *)p;
}

static __inline void mem_wr8(void *p, uint8_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint8_t *)p = v;
}

#if defined(__BIG_ENDIAN__)


static __inline uint16_t swap16(uint16_t val)
{
  return ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
}

static __inline uint16_t mem_rd16(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return swap16(*(const uint16_t *)p);
}

static __inline uint32_t mem_rd32(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return __builtin_bswap32(*(const uint32_t *)p);
}

static __inline uint64_t mem_rd64(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return __builtin_bswap64(*(const uint64_t *)p);
}




static __inline void mem_wr16(void *p, uint16_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint16_t *)p = swap16(v);
}

static __inline void mem_wr32(void *p, uint32_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint32_t *)p = __builtin_bswap32(v);
}

static __inline void mem_wr64(void *p, uint64_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint64_t *)p = __builtin_bswap64(v);
}





static __inline void host_wr16(void *p, uint16_t v)
{
  *(uint16_t *)p = swap16(v);
}

static __inline void host_wr32(void *p, uint32_t v)
{
  *(uint32_t *)p = __builtin_bswap32(v);
}

static __inline void host_wr64(void *p, uint64_t v)
{
  *(uint64_t *)p = __builtin_bswap64(v);
}


#else

static __inline uint16_t mem_rd16(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return *(const uint16_t *)p;
}

static __inline uint32_t mem_rd32(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return *(const uint32_t *)p;
}

static __inline uint64_t mem_rd64(const void *p, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  return *(const uint64_t *)p;
}


static __inline void mem_wr16(void *p, uint16_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint16_t *)p = v;
}

static __inline void mem_wr32(void *p, uint32_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint32_t *)p = v;
}

static __inline void mem_wr64(void *p, uint64_t v, ir_unit_t *iu)
{
  CHECK_MEM_ACCESS();
  *(uint64_t *)p = v;
}



static __inline void host_wr16(void *p, uint16_t v)
{
  *(uint16_t *)p = v;
}

static __inline void host_wr32(void *p, uint32_t v)
{
  *(uint32_t *)p = v;
}

static __inline void host_wr64(void *p, uint64_t v)
{
  *(uint64_t *)p = v;
}

#endif
