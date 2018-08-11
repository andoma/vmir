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

#include <math.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>


typedef struct vm_frame {
  ir_unit_t *iu;
  uint32_t allocaptr;

#ifndef VM_NO_STACK_FRAME
  const ir_function_t *func;
  const struct vm_frame *prev;
  uint32_t *allocapeak;

#ifdef VM_TRACE
  int trace;
#endif

#endif
} vm_frame_t;


#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifdef VM_TRACE
#define vm_tracef(f, fmt, ...) do {                           \
    if((f)->trace)                                            \
      vmir_log((f)->iu, VMIR_LOG_DEBUG, fmt, ##__VA_ARGS__);  \
  } while(0)

#else
#define vm_tracef(f, fmt...)
#endif

#ifdef VM_TRACE

typedef struct ir_instr_backref {
  char *str;
  int offset;
  int bb;
} ir_instr_backref_t;

#endif

#ifndef VM_NO_STACK_FRAME


static ir_function_t *
vm_getfunc(int callee, ir_unit_t *iu)
{
  if(callee >= VECTOR_LEN(&iu->iu_functions))
    return NULL;
  return VECTOR_ITEM(&iu->iu_functions, callee);
}


static void
vmir_traceback(struct ir_unit *iu, const char *info)
{
  const vm_frame_t *f;

  vmir_log(iu, VMIR_LOG_INFO, "--- Traceback (%s) ---", info);
  for(f = iu->iu_current_frame; f != NULL; f = f->prev) {
    vmir_log(iu, VMIR_LOG_INFO, "%s()", f->func->if_name);
  }
  vmir_log(iu, VMIR_LOG_INFO, "--- Traceback end ---");
}




#endif

static void __attribute__((noinline)) __attribute__((noreturn))
vm_stop(ir_unit_t *iu, int reason, int code)
{
  iu->iu_exit_code = code;
  longjmp(*iu->iu_err_jmpbuf, reason);
}

static void __attribute__((noinline)) __attribute__((noreturn))
vm_bad_function(ir_unit_t *iu, uint32_t fid)
{
#ifndef VM_NO_STACK_FRAME
  vmir_traceback(iu, "bad function called");
#endif
  vm_stop(iu, VM_STOP_BAD_FUNCTION, fid);
}

uint32_t
vmir_vm_arg32(const void **rfp)
{
  const void *rf = *rfp = *rfp - 4;
  return *(uint32_t *)rf;
}

uint64_t
vmir_vm_arg64(const void **rfp)
{
  const void *rf = *rfp = *rfp - 8;
  return *(uint64_t *)rf;
}

double
vmir_vm_arg_dbl(const void **rfp)
{
  const void *rf = *rfp = *rfp - 8;
  return *(double *)rf;
}

float
vmir_vm_arg_flt(const void **rfp)
{
  const void *rf = *rfp = *rfp - 4;
  return *(float *)rf;
}

void *
vmir_vm_ptr(const void **rfp, ir_unit_t *iu)
{
  return vmir_vm_arg32(rfp) + iu->iu_mem;
}

void *
vmir_vm_ptr_nullchk(const void **rfp, ir_unit_t *iu)
{
  uint32_t vma = vmir_vm_arg32(rfp);
  return vma ? vma + iu->iu_mem : NULL;
}

ir_function_t *
vmir_vm_arg_func(const void **rfp, ir_unit_t *iu)
{
  uint32_t fnid = vmir_vm_arg32(rfp);
  if(fnid >= VECTOR_LEN(&iu->iu_functions))
    return NULL;
  return VECTOR_ITEM(&iu->iu_functions, fnid);
}

void
vmir_vm_retptr(void *ret, void *p, const ir_unit_t *iu)
{
  *(uint32_t *)ret = p ? p - iu->iu_mem : 0;
}

void
vmir_vm_ret32(void *ret, uint32_t v)
{
  *(uint32_t *)ret = v;
}

void
vmir_vm_ret64(void *ret, uint64_t v)
{
  *(uint64_t *)ret = v;
}


static int
vm_exit(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t exit_code = vmir_vm_arg32(&rf);
  vm_stop(iu, VM_STOP_EXIT, exit_code);
  return 0;
}

static int
vm_abort(void *ret, const void *rf, ir_unit_t *iu)
{
#ifndef VM_NO_STACK_FRAME
  vmir_traceback(iu, "abort");
#endif
  vm_stop(iu, VM_STOP_ABORT, 0);
  return 0;
}


static uint32_t
vmir_vm_vaarg32(const void **rfp, ir_unit_t *iu)
{
  const uint32_t *p;
  if(iu->iu_mode == VMIR_WASM) {
    p = *rfp;
    *rfp = *rfp + 4;
  } else {
    p = *rfp = *rfp - 4;
  }
  return *p;
}

static uint64_t
vmir_vm_vaarg64(const void **rfp, ir_unit_t *iu)
{
  const uint64_t *p;
  if(iu->iu_mode == VMIR_WASM) {
    p = *rfp;
    *rfp = *rfp + 8;
  } else {
    p = *rfp = *rfp - 8;
  }
  return *p;
}

static double
vmir_vm_vaarg_dbl(const void **rfp, ir_unit_t *iu)
{
  const double *p;
  if(iu->iu_mode == VMIR_WASM) {
    p = *rfp;
    *rfp = *rfp + 8;
  } else {
    p = *rfp = *rfp - 8;
  }
  return *p;
}

static void *
vmir_vm_vaptr(const void **rfp, ir_unit_t *iu)
{
  return vmir_vm_vaarg32(rfp, iu) + iu->iu_mem;
}







static uint32_t __attribute__((noinline))
vm_strchr(uint32_t a, int b, void *mem)
{
  void *s = mem + a;
  void *r = strchr(s, b);
  int ret = r ? r - mem : 0;
  return ret;
}

static uint32_t __attribute__((noinline))
vm_strdup(uint32_t a, void *mem)
{
  void *r = strdup(mem + a);
  int ret = r ? r - mem : 0;
  return ret;
}

static uint32_t __attribute__((noinline))
vm_strrchr(uint32_t a, int b, void *mem)
{
  void *s = mem + a;
  void *r = strrchr(s, b);
  int ret = r ? r - mem : 0;
  return ret;
}


static uint32_t __attribute__((noinline))
vm_vaarg32(void *rf, void **ptr)
{
  void *p = *ptr;
  p -= sizeof(uint32_t);
  uint32_t r = *(uint32_t *)p;
  *ptr = p;
  return r;
}


static uint64_t __attribute__((noinline))
vm_vaarg64(void *rf, void **ptr)
{
  void *p = *ptr;
  p -= sizeof(uint64_t);
  uint64_t r = *(uint64_t *)p;
  *ptr = p;
  return r;
}

#ifdef VM_TRACE
static void __attribute__((noinline))
vm_wr_u32(const vm_frame_t *f, void *rf, int16_t reg, uint32_t data)
{
  vm_tracef(f, "Reg 0x%x (u32) = 0x%x", reg, data);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_wr_u64(const vm_frame_t *f, void *rf, int16_t reg, uint64_t data)
{
  vm_tracef(f, "Reg 0x%x (u64) = 0x%"PRIx64"", reg, data);
  *(uint64_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_wr_flt(const vm_frame_t *f, void *rf, int16_t reg, float data)
{
  vm_tracef(f, "Reg 0x%x (flt) = %f", reg, data);
  *(float *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_wr_dbl(const vm_frame_t *f, void *rf, int16_t reg, double data)
{
  vm_tracef(f, "Reg 0x%x (dbl) = %f", reg, data);
  *(double *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_8(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint8_t data = mem_rd8(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u8) = Loaded 0x%x from 0x%08x",
         reg, data, ea);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_8_zext_32(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint8_t data = mem_rd8(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u32) = Loaded.u8 0x%x from 0x%08x",
         reg, data, ea);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_8_sext_32(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  int8_t data = mem_rd8(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u32) = Loaded.s8 0x%x from 0x%08x",
         reg, data, ea);
  *(int32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_16(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint16_t data = mem_rd16(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u16) = Loaded 0x%x from 0x%08x",
         reg, data, ea);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_16_zext_32(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint16_t data = mem_rd16(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u32) = Loaded.u16 0x%x from 0x%08x",
         reg, data, ea);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_16_sext_32(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  int16_t data = mem_rd16(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u32) = Loaded.s16 0x%x from 0x%08x",
         reg, data, ea);
  *(int32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_32(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint32_t data = mem_rd32(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u32) = Loaded 0x%x from 0x%08x",
         reg, data, ea);
  *(uint32_t *)(rf + reg) = data;
}

static void __attribute__((noinline))
vm_load_64(const vm_frame_t *f, void *rf, int16_t reg, void *mem, uint32_t ea)
{
  uint64_t data = mem_rd64(mem + ea, f->iu);
  vm_tracef(f, "Reg 0x%x (u64) = Loaded 0x%"PRIx64" from 0x%08x",
         reg, data, ea);
  *(uint64_t *)(rf + reg) = data;
}


static void __attribute__((noinline))
vm_store_8(const vm_frame_t *f, void *mem, uint32_t ea, uint8_t v)
{
  vm_tracef(f, "Store (u8) 0x%x to 0x%08x", v, ea);
  mem_wr8(mem + ea, v, f->iu);
}

static void __attribute__((noinline))
vm_store_16(const vm_frame_t *f, void *mem, uint32_t ea, uint16_t v)
{
  vm_tracef(f, "Store (u16) 0x%x to 0x%08x", v, ea);
  mem_wr16(mem + ea, v, f->iu);
}

static void __attribute__((noinline))
vm_store_32(const vm_frame_t *f, void *mem, uint32_t ea, uint32_t v)
{
  vm_tracef(f, "Store (u32) 0x%x to 0x%08x", v, ea);
  mem_wr32(mem + ea, v, f->iu);
}

static void __attribute__((noinline))
vm_store_64(const vm_frame_t *f, void *mem, uint32_t ea, uint64_t v)
{
  vm_tracef(f, "Store (u64) 0x%"PRIx64" to 0x%08x", v, ea);
  mem_wr64(mem + ea, v, f->iu);
}



static const char *
vm_funcname(int callee, ir_unit_t *iu)
{
  if(callee >= VECTOR_LEN(&iu->iu_functions))
    return "Bad-function-global-id";
  ir_function_t *f = VECTOR_ITEM(&iu->iu_functions, callee);
  return f->if_name;
}

#endif

#define R8(r)  (uint8_t)*(uint32_t *)(rf + (int16_t)I[r])
#define S8(r)  (int8_t)*(int32_t  *)(rf + (int16_t)I[r])
#define R16(r) (uint16_t)*(uint32_t *)(rf + (int16_t)I[r])
#define S16(r) (int16_t)*(int32_t  *)(rf + (int16_t)I[r])



#define R32(r) *(uint32_t *)(rf + (int16_t)I[r])
#define S32(r) *(int32_t  *)(rf + (int16_t)I[r])
#define R64(r) *(uint64_t *)(rf + (int16_t)I[r])
#define S64(r) *(int64_t  *)(rf + (int16_t)I[r])
#define RFLT(r)  *(float  *)(rf + (int16_t)I[r])
#define RDBL(r)  *(double *)(rf + (int16_t)I[r])


#ifdef VM_TRACE

#define AR32(reg, src) vm_wr_u32(&F, rf, I[reg], src)
#define AR64(reg, src) vm_wr_u64(&F, rf, I[reg], src)
#define AFLT(reg, src) vm_wr_flt(&F, rf, I[reg], src)
#define ADBL(reg, src) vm_wr_dbl(&F, rf, I[reg], src)



#define LOAD8(reg, ea)       vm_load_8(&F, rf,  I[reg], hostmem, ea)
#define LOAD8_ZEXT_32(r, ea) vm_load_8_zext_32(&F, rf,  I[r], hostmem, ea)
#define LOAD8_SEXT_32(r, ea) vm_load_8_sext_32(&F, rf,  I[r], hostmem, ea)

#define LOAD16(reg, ea)       vm_load_16(&F, rf, I[reg], hostmem, ea)
#define LOAD16_ZEXT_32(r, ea) vm_load_16_zext_32(&F, rf,  I[r], hostmem, ea)
#define LOAD16_SEXT_32(r, ea) vm_load_16_sext_32(&F, rf,  I[r], hostmem, ea)


#define LOAD32(reg, ea)  vm_load_32(&F, rf, I[reg], hostmem, ea)
#define LOAD64(reg, ea)  vm_load_64(&F, rf, I[reg], hostmem, ea)

#define STORE8(ea, v)    vm_store_8(&F, hostmem, ea, v)
#define STORE16(ea, v)   vm_store_16(&F, hostmem, ea, v)
#define STORE32(ea, v)   vm_store_32(&F, hostmem, ea, v)
#define STORE64(ea, v)   vm_store_64(&F, hostmem, ea, v)


#else

#define LOAD8(r, ea)          R32(r) = mem_rd8(HOSTADDR(ea), iu)
#define LOAD8_ZEXT_32(r, ea)  R32(r) = mem_rd8(HOSTADDR(ea), iu)
#define LOAD8_SEXT_32(r, ea)  S32(r) = (int8_t)mem_rd8(HOSTADDR(ea), iu)
#define LOAD16(r, ea)         R32(r) = mem_rd16(HOSTADDR(ea), iu)
#define LOAD16_ZEXT_32(r, ea) R32(r) = mem_rd16(HOSTADDR(ea), iu)
#define LOAD16_SEXT_32(r, ea) S32(r) = (int16_t)mem_rd16(HOSTADDR(ea), iu)
#define LOAD32(r, ea)         R32(r) = mem_rd32(HOSTADDR(ea), iu)
#define LOAD64(r, ea)         R64(r) = mem_rd64(HOSTADDR(ea), iu)
#define STORE8(ea, v)                  mem_wr8(HOSTADDR(ea), v, iu)
#define STORE16(ea, v)                 mem_wr16(HOSTADDR(ea), v, iu)
#define STORE32(ea, v)                 mem_wr32(HOSTADDR(ea), v, iu)
#define STORE64(ea, v)                 mem_wr64(HOSTADDR(ea), v, iu)

#define AR32(r, src) R32(r) = src
#define AR64(r, src) R64(r) = src
#define AFLT(r, src) RFLT(r) = src
#define ADBL(r, src) RDBL(r) = src

#endif




#define UIMM8(r) *(uint8_t *)(I + r)
#define SIMM8(r) *(int8_t *)(I + r)
#define UIMM16(r) *(uint16_t *)(I + r)
#define SIMM16(r) *(int16_t *)(I + r)
#define UIMM32(r) *(uint32_t *)(I + r)
#define SIMM32(r) *(int32_t *)(I + r)
#define UIMM64(r) *(uint64_t *)(I + r)
#define SIMM64(r) *(int64_t *)(I + r)

#define IMMFLT(r) *(float *)(I + r)
#define IMMDBL(r) *(double *)(I + r)

#define HOSTADDR(x) ((hostmem) + (x))


static void *
#ifndef VM_NO_STACK_FRAME
__attribute__((noinline))
#endif
  do_jit_call(void *rf, void *mem, void *(*code)(void *, void *, void *, void *))
{
#if 0
  printf("%p: Pre jit call 8=%x c=%x 10=%x\n", code,
         *(uint32_t *)(rf + 8),
         *(uint32_t *)(rf + 12),
         *(uint32_t *)(rf + 16));
#endif
  void *r = code(NULL, rf, NULL, mem);
#if 0
  printf("%p: Post jit call 8=%x c=%x 10=%x\n", code,
         *(uint32_t *)(rf + 8),
         *(uint32_t *)(rf + 12),
         *(uint32_t *)(rf + 16));
#endif
  return r;
}

#ifdef VM_TRACE

static int vm_find_backref(const void *A, const void *B)
{
  const ir_instr_backref_t *a = (const ir_instr_backref_t *)A;
  const ir_instr_backref_t *b = (const ir_instr_backref_t *)B;
  return a->offset - b->offset;
}


static void
vm_trace_instruction(const vm_frame_t *frame,
                     const ir_function_t *f,
                     const uint16_t *I,
                     const char *opname)
{
  int pc = (int)((void *)I - (void *)f->if_vm_text) - 2;
  ir_instr_backref_t q;
  q.offset = pc;
  ir_instr_backref_t *iib = bsearch(&q, f->if_instr_backrefs,
                                    f->if_instr_backref_size,
                                    sizeof(ir_instr_backref_t),
                                    vm_find_backref);
  if(iib != NULL)
    vm_tracef(frame, "%s().%d: %s [vmop:%s]",
              f->if_name, iib->bb, iib->str, opname);
  else
    vm_tracef(frame, "%s(): %s @ %d", f->if_name, opname, pc);
}
#endif

static inline uint8_t
rol8(uint8_t x, int r)
{
  return (x << r) | (x >> (8 - r));
}

static inline uint16_t
rol16(uint16_t x, int r)
{
  return (x << r) | (x >> (16 - r));
}

static inline uint32_t
rol32(uint32_t x, int r)
{
  return (x << r) | (x >> (32 - r));
}

static inline uint64_t
rol64(uint64_t x, int r)
{
  return (x << r) | (x >> (64 - r));
}


static inline uint8_t
ror8(uint8_t x, int r)
{
  return (x >> r) | (x << (8 - r));
}

static inline uint16_t
ror16(uint16_t x, int r)
{
  return (x >> r) | (x << (16 - r));
}

static inline uint32_t
ror32(uint32_t x, int r)
{
  return (x >> r) | (x << (32 - r));
}

static inline uint64_t
ror64(uint64_t x, int r)
{
  return (x >> r) | (x << (64 - r));
}

static int16_t vm_resolve(uint16_t opcode);

static int __attribute__((noinline))
vm_exec(uint16_t *I, void *rf, void *ret, const vm_frame_t *P)
{
#ifndef VM_DONT_USE_COMPUTED_GOTO
  if(rf == NULL)
    goto resolve;
#endif

  int r;
  int16_t opc;
  vm_frame_t F = *P;
  ir_unit_t *iu = F.iu;
  void *hostmem = iu->iu_mem;

#ifndef VM_NO_STACK_FRAME
  iu->iu_current_frame = &F;
  F.prev = P;
#ifdef VM_TRACE
  F.trace = !iu->iu_traced_function ||
    !strcmp(P->func->if_name, iu->iu_traced_function);
#endif

#define RESTORE_CURRENT_FRAME() iu->iu_current_frame = P
#define SET_CALLEE_FUNC(x) F.func = vm_getfunc(x, iu)
#define ALLOCATRACEPEAK() *F.allocapeak = VMIR_MAX(*F.allocapeak, F.allocaptr)
#else
#define RESTORE_CURRENT_FRAME()
#define SET_CALLEE_FUNC(x)
#define ALLOCATRACEPEAK()
#endif

    RESTORE_CURRENT_FRAME();

#ifndef VM_DONT_USE_COMPUTED_GOTO
#define NEXT(skip) I+=skip; opc = *I++; goto *(&&opz + opc)
#define VMOP(x) x:

  NEXT(0);

  while(1) {

  opz:
    vm_stop(iu, VM_STOP_BAD_INSTRUCTION, 0);
#else

#define NEXT(skip) I+=skip; opc = *I++; goto reswitch

#ifdef VM_TRACE
#define VMOP(x) case VM_ ## x : do { if(F.trace) { vm_trace_instruction(&F, P->func, I, #x);} } while(0);
#else
#define VMOP(x) case VM_ ## x :
#endif

  opc = *I++;
 reswitch:


  switch(opc) {
  default:
    vm_stop(iu, VM_STOP_BAD_INSTRUCTION, 0);
#endif

  VMOP(NOP)
    NEXT(0);

  VMOP(RET_VOID)
    return 0;

  VMOP(JIT_CALL)
  {
    void *(*code)(void *, void *, void *, void*) = iu->iu_jit_mem + UIMM32(0);
    I = do_jit_call(rf, iu->iu_mem, code);
    NEXT(0);
  }

  VMOP(RET_R32)
    *(uint32_t *)ret = R32(0);
    vm_tracef(&F, "Returning 0x%x", *(uint32_t *)ret);
    return 0;
  VMOP(RET_R64)
    *(uint64_t *)ret = R64(0);
    return 0;
  VMOP(RET_R32C)
    *(uint32_t *)ret = UIMM32(0);
    return 0;
  VMOP(RET_R64C)
    *(uint64_t *)ret = UIMM64(0);
    return 0;

  VMOP(B)     I = (void *)I + (int16_t)I[0]; NEXT(0);
  VMOP(BCOND) I = (void *)I + (int16_t)(R32(0) ? I[1] : I[2]); NEXT(0);

  VMOP(JSR)
    vm_tracef(&F, "Calling %s", vm_funcname(I[0], iu));
    SET_CALLEE_FUNC(I[0]);
    if(iu->iu_function_table[I[0]]) {
      I[-1] = vm_resolve(VM_JSR_EXT);
      r = iu->iu_function_table[I[0]](rf + I[2], rf + I[1], iu, hostmem);
    } else {
      I[-1] = vm_resolve(VM_JSR_VM);
      r = vm_exec(iu->iu_vm_funcs[I[0]], rf + I[1], rf + I[2], &F);
    }
    RESTORE_CURRENT_FRAME();
    if(r)
      return r;
    NEXT(3);

  VMOP(JSR_VM)
    vm_tracef(&F, "Calling %s", vm_funcname(I[0], iu));
    SET_CALLEE_FUNC(I[0]);
    r = vm_exec(iu->iu_vm_funcs[I[0]], rf + I[1], rf + I[2], &F);
    RESTORE_CURRENT_FRAME();
    if(r)
      return r;
    NEXT(3);

  VMOP(JSR_EXT)
    vm_tracef(&F, "Calling %s (external)", vm_funcname(I[0], iu));
    r = iu->iu_function_table[I[0]](rf + I[2], rf + I[1], iu, hostmem);
    RESTORE_CURRENT_FRAME();
    if(r)
      return r;
    NEXT(3);

  VMOP(JSR_R)
    vm_tracef(&F, "Calling indirect %s (%d)", vm_funcname(R32(0), iu), R32(0));
    if(R32(0) >= VECTOR_LEN(&iu->iu_functions)) {
      vm_bad_function(iu, R32(0));
    }

    SET_CALLEE_FUNC(R32(0));
    if(iu->iu_vm_funcs[R32(0)]) {
      r = vm_exec(iu->iu_vm_funcs[R32(0)], rf + I[1], rf + I[2], &F);
      RESTORE_CURRENT_FRAME();
      if(r)
        return r;
    } else if(iu->iu_function_table[R32(0)]) {
      iu->iu_function_table[R32(0)](rf + I[2], rf + I[1], iu, hostmem);
      RESTORE_CURRENT_FRAME();
    } else {
      vm_bad_function(iu, R32(0));
    }
    NEXT(3);



  VMOP(INVOKE)
    vm_tracef(&F, "Invoking %s", vm_funcname(I[0], iu));
    SET_CALLEE_FUNC(I[0]);
    if(iu->iu_function_table[I[0]])
      r = iu->iu_function_table[I[0]](rf + I[2], rf + I[1], iu, hostmem);
    else
      r = vm_exec(iu->iu_vm_funcs[I[0]], rf + I[1], rf + I[2], &F);
    RESTORE_CURRENT_FRAME();
    I = (void *)I + (int16_t)I[3 + r]; NEXT(0);

  VMOP(INVOKE_VM)
    vm_tracef(&F, "Invoking %s", vm_funcname(I[0], iu));
    SET_CALLEE_FUNC(I[0]);
    r = vm_exec(iu->iu_vm_funcs[I[0]], rf + I[1], rf + I[2], &F);
    RESTORE_CURRENT_FRAME();
    I = (void *)I + (int16_t)I[3 + r]; NEXT(0);

  VMOP(INVOKE_EXT)
    vm_tracef(&F, "Calling %s (external)", vm_funcname(I[0], iu));
    r = iu->iu_function_table[I[0]](rf + I[2], rf + I[1], iu, hostmem);
    RESTORE_CURRENT_FRAME();
    I = (void *)I + (int16_t)I[3 + r]; NEXT(0);

  VMOP(INVOKE_R)
    vm_tracef(&F, "Calling indirect %s (%d)", vm_funcname(R32(0), iu), R32(0));
    if(R32(0) >= VECTOR_LEN(&iu->iu_functions)) {
      vm_bad_function(iu, R32(0));
    }
    SET_CALLEE_FUNC(R32(0));
    if(iu->iu_vm_funcs[R32(0)]) {
      r = vm_exec(iu->iu_vm_funcs[R32(0)], rf + I[1], rf + I[2], &F);
      RESTORE_CURRENT_FRAME();
    } else if(iu->iu_function_table[R32(0)]) {
      r = iu->iu_function_table[R32(0)](rf + I[2], rf + I[1], iu, hostmem);
      RESTORE_CURRENT_FRAME();
    } else {
      vm_bad_function(iu, R32(0));
    }
    I = (void *)I + (int16_t)I[3 + r]; NEXT(0);

  VMOP(LANDINGPAD)
    AR32(0, iu->iu_exception.exception);
    AR32(1, iu->iu_exception.type_info);
    NEXT(2);

  VMOP(RESUME)
    iu->iu_exception.exception = R32(0);
    iu->iu_exception.type_info = R32(1);
    return 1;

  VMOP(SDIV_R8) AR32(0,  S8(1) /  S8(2)); NEXT(3);
  VMOP(SREM_R8) AR32(0,  S8(1) %  S8(2)); NEXT(3);
  VMOP(ASHR_R8) AR32(0,  S8(1) >> R8(2)); NEXT(3);
  VMOP(ROL_R8)  AR32(0,  rol8(R8(1), R8(2))); NEXT(3);
  VMOP(ROR_R8)  AR32(0,  ror8(R8(1), R8(2))); NEXT(3);

  VMOP(SDIV_R8C) AR32(0, S8(1) /  SIMM8(2)); NEXT(3);
  VMOP(SREM_R8C) AR32(0, S8(1) %  SIMM8(2)); NEXT(3);
  VMOP(ASHR_R8C) AR32(0, S8(1) >> UIMM8(2)); NEXT(3);
  VMOP(ROL_R8C)  AR32(0,  rol8(R8(1), SIMM8(2))); NEXT(3);
  VMOP(ROR_R8C)  AR32(0,  ror8(R8(1), SIMM8(2))); NEXT(3);

  VMOP(SDIV_R16) AR32(0, S16(1) /  S16(2)); NEXT(3);
  VMOP(SREM_R16) AR32(0, S16(1) %  S16(2)); NEXT(3);
  VMOP(ASHR_R16) AR32(0, S16(1) >> R16(2)); NEXT(3);
  VMOP(ROL_R16)  AR32(0,  rol16(R16(1), R16(2))); NEXT(3);
  VMOP(ROR_R16)  AR32(0,  ror16(R16(1), R16(2))); NEXT(3);

  VMOP(ADD_R16C)  AR32(0, R16(1) +  UIMM16(2)); NEXT(3);
  VMOP(SUB_R16C)  AR32(0, R16(1) -  UIMM16(2)); NEXT(3);
  VMOP(MUL_R16C)  AR32(0, R16(1) *  UIMM16(2)); NEXT(3);
  VMOP(UDIV_R16C) AR32(0, R16(1) /  UIMM16(2)); NEXT(3);
  VMOP(SDIV_R16C) AR32(0, S16(1) /  SIMM16(2)); NEXT(3);
  VMOP(UREM_R16C) AR32(0, R16(1) %  UIMM16(2)); NEXT(3);
  VMOP(SREM_R16C) AR32(0, S16(1) %  SIMM16(2)); NEXT(3);
  VMOP(SHL_R16C)  AR32(0, R16(1) << UIMM16(2)); NEXT(3);
  VMOP(LSHR_R16C) AR32(0, R16(1) >> UIMM16(2)); NEXT(3);
  VMOP(ASHR_R16C) AR32(0, S16(1) >> UIMM16(2)); NEXT(3);
  VMOP(AND_R16C)  AR32(0, R16(1) &  UIMM16(2)); NEXT(3);
  VMOP(OR_R16C)   AR32(0, R16(1) |  UIMM16(2)); NEXT(3);
  VMOP(XOR_R16C)  AR32(0, R16(1) ^  UIMM16(2)); NEXT(3);
  VMOP(ROL_R16C)  AR32(0,  rol16(R16(1), SIMM16(2))); NEXT(3);
  VMOP(ROR_R16C)  AR32(0,  ror16(R16(1), SIMM16(2))); NEXT(3);

  VMOP(ADD_R32)  AR32(0, R32(1) +  R32(2)); NEXT(3);
  VMOP(SUB_R32)  AR32(0, R32(1) -  R32(2)); NEXT(3);
  VMOP(MUL_R32)  AR32(0, R32(1) *  R32(2)); NEXT(3);
  VMOP(UDIV_R32) AR32(0, R32(1) /  R32(2)); NEXT(3);
  VMOP(SDIV_R32) AR32(0, S32(1) /  S32(2)); NEXT(3);
  VMOP(UREM_R32) AR32(0, R32(1) %  R32(2)); NEXT(3);
  VMOP(SREM_R32) AR32(0, S32(1) %  S32(2)); NEXT(3);
  VMOP(SHL_R32)  AR32(0, R32(1) << R32(2)); NEXT(3);
  VMOP(LSHR_R32) AR32(0, R32(1) >> R32(2)); NEXT(3);
  VMOP(ASHR_R32) AR32(0, S32(1) >> R32(2)); NEXT(3);
  VMOP(AND_R32)  AR32(0, R32(1) &  R32(2)); NEXT(3);
  VMOP(OR_R32)   AR32(0, R32(1) |  R32(2)); NEXT(3);
  VMOP(XOR_R32)  AR32(0, R32(1) ^  R32(2)); NEXT(3);
  VMOP(ROL_R32)  AR32(0,  rol32(R32(1), R32(2))); NEXT(3);
  VMOP(ROR_R32)  AR32(0,  ror32(R32(1), R32(2))); NEXT(3);

  VMOP(INC_R32)  AR32(0, R32(1) + 1); NEXT(2);
  VMOP(DEC_R32)  AR32(0, R32(1) - 1); NEXT(2);

  VMOP(ADD_R32C)  AR32(0, R32(1) +  UIMM32(2)); NEXT(4);
  VMOP(SUB_R32C)  AR32(0, R32(1) -  UIMM32(2)); NEXT(4);
  VMOP(MUL_R32C)  AR32(0, R32(1) *  UIMM32(2)); NEXT(4);
  VMOP(UDIV_R32C) AR32(0, R32(1) /  UIMM32(2)); NEXT(4);
  VMOP(SDIV_R32C) AR32(0, S32(1) /  SIMM32(2)); NEXT(4);
  VMOP(UREM_R32C) AR32(0, R32(1) %  UIMM32(2)); NEXT(4);
  VMOP(SREM_R32C) AR32(0, S32(1) %  SIMM32(2)); NEXT(4);
  VMOP(SHL_R32C)  AR32(0, R32(1) << UIMM32(2)); NEXT(4);
  VMOP(LSHR_R32C) AR32(0, R32(1) >> UIMM32(2)); NEXT(4);
  VMOP(ASHR_R32C) AR32(0, S32(1) >> UIMM32(2)); NEXT(4);
  VMOP(AND_R32C)  AR32(0, R32(1) &  UIMM32(2)); NEXT(4);
  VMOP(OR_R32C)   AR32(0, R32(1) |  UIMM32(2)); NEXT(4);
  VMOP(XOR_R32C)  AR32(0, R32(1) ^  UIMM32(2)); NEXT(4);
  VMOP(ROL_R32C)  AR32(0,  rol32(R32(1), SIMM32(2))); NEXT(4);
  VMOP(ROR_R32C)  AR32(0,  ror32(R32(1), SIMM32(2))); NEXT(4);


  VMOP(ADD_R64)  AR64(0, R64(1) +  R64(2)); NEXT(3);
  VMOP(SUB_R64)  AR64(0, R64(1) -  R64(2)); NEXT(3);
  VMOP(MUL_R64)  AR64(0, R64(1) *  R64(2)); NEXT(3);
  VMOP(UDIV_R64) AR64(0, R64(1) /  R64(2)); NEXT(3);
  VMOP(SDIV_R64) AR64(0, S64(1) /  S64(2)); NEXT(3);
  VMOP(UREM_R64) AR64(0, R64(1) %  R64(2)); NEXT(3);
  VMOP(SREM_R64) AR64(0, S64(1) %  S64(2)); NEXT(3);
  VMOP(SHL_R64)  AR64(0, R64(1) << R64(2)); NEXT(3);
  VMOP(LSHR_R64) AR64(0, R64(1) >> R64(2)); NEXT(3);
  VMOP(ASHR_R64) AR64(0, S64(1) >> R64(2)); NEXT(3);
  VMOP(AND_R64)  AR64(0, R64(1) &  R64(2)); NEXT(3);
  VMOP(OR_R64)   AR64(0, R64(1) |  R64(2)); NEXT(3);
  VMOP(XOR_R64)  AR64(0, R64(1) ^  R64(2)); NEXT(3);
  VMOP(ROL_R64)  AR64(0,  rol64(R64(1), R64(2))); NEXT(3);
  VMOP(ROR_R64)  AR64(0,  ror64(R64(1), R64(2))); NEXT(3);

  VMOP(ADD_R64C)  AR64(0, R64(1) +  UIMM64(2)); NEXT(6);
  VMOP(SUB_R64C)  AR64(0, R64(1) -  UIMM64(2)); NEXT(6);
  VMOP(MUL_R64C)  AR64(0, R64(1) *  UIMM64(2)); NEXT(6);
  VMOP(UDIV_R64C) AR64(0, R64(1) /  UIMM64(2)); NEXT(6);
  VMOP(SDIV_R64C) AR64(0, S64(1) /  SIMM64(2)); NEXT(6);
  VMOP(UREM_R64C) AR64(0, R64(1) %  UIMM64(2)); NEXT(6);
  VMOP(SREM_R64C) AR64(0, S64(1) %  SIMM64(2)); NEXT(6);
  VMOP(SHL_R64C)  AR64(0, R64(1) << UIMM64(2)); NEXT(6);
  VMOP(LSHR_R64C) AR64(0, R64(1) >> UIMM64(2)); NEXT(6);
  VMOP(ASHR_R64C) AR64(0, S64(1) >> UIMM64(2)); NEXT(6);
  VMOP(AND_R64C)  AR64(0, R64(1) &  UIMM64(2)); NEXT(6);
  VMOP(OR_R64C)   AR64(0, R64(1) |  UIMM64(2)); NEXT(6);
  VMOP(XOR_R64C)  AR64(0, R64(1) ^  UIMM64(2)); NEXT(6);
  VMOP(ROL_R64C)  AR32(0,  rol64(R64(1), SIMM64(2))); NEXT(6);
  VMOP(ROR_R64C)  AR32(0,  ror64(R64(1), SIMM64(2))); NEXT(6);

  VMOP(MLA32)     AR32(0, R32(1) * R32(2) + R32(3)); NEXT(4);

  VMOP(ADD_DBL) ADBL(0, RDBL(1) +  RDBL(2)); NEXT(3);
  VMOP(SUB_DBL) ADBL(0, RDBL(1) -  RDBL(2)); NEXT(3);
  VMOP(MUL_DBL) ADBL(0, RDBL(1) *  RDBL(2)); NEXT(3);
  VMOP(DIV_DBL) ADBL(0, RDBL(1) /  RDBL(2)); NEXT(3);

  VMOP(ADD_DBLC) ADBL(0, RDBL(1) +  IMMDBL(2)); NEXT(6);
  VMOP(SUB_DBLC) ADBL(0, RDBL(1) -  IMMDBL(2)); NEXT(6);
  VMOP(MUL_DBLC) ADBL(0, RDBL(1) *  IMMDBL(2)); NEXT(6);
  VMOP(DIV_DBLC) ADBL(0, RDBL(1) /  IMMDBL(2)); NEXT(6);

  VMOP(ADD_FLT) AFLT(0, RFLT(1) +  RFLT(2)); NEXT(3);
  VMOP(SUB_FLT) AFLT(0, RFLT(1) -  RFLT(2)); NEXT(3);
  VMOP(MUL_FLT) AFLT(0, RFLT(1) *  RFLT(2)); NEXT(3);
  VMOP(DIV_FLT) AFLT(0, RFLT(1) /  RFLT(2)); NEXT(3);

  VMOP(ADD_FLTC) AFLT(0, RFLT(1) +  IMMFLT(2)); NEXT(4);
  VMOP(SUB_FLTC) AFLT(0, RFLT(1) -  IMMFLT(2)); NEXT(4);
  VMOP(MUL_FLTC) AFLT(0, RFLT(1) *  IMMFLT(2)); NEXT(4);
  VMOP(DIV_FLTC) AFLT(0, RFLT(1) /  IMMFLT(2)); NEXT(4);

    // Integer compare

  VMOP(EQ8)    AR32(0, R8(1) == R8(2)); NEXT(3);
  VMOP(NE8)    AR32(0, R8(1) != R8(2)); NEXT(3);
  VMOP(UGT8)   AR32(0, R8(1) >  R8(2)); NEXT(3);
  VMOP(UGE8)   AR32(0, R8(1) >= R8(2)); NEXT(3);
  VMOP(ULT8)   AR32(0, R8(1) <  R8(2)); NEXT(3);
  VMOP(ULE8)   AR32(0, R8(1) <= R8(2)); NEXT(3);
  VMOP(SGT8)   AR32(0, S8(1) >  S8(2)); NEXT(3);
  VMOP(SGE8)   AR32(0, S8(1) >= S8(2)); NEXT(3);
  VMOP(SLT8)   AR32(0, S8(1) <  S8(2)); NEXT(3);
  VMOP(SLE8)   AR32(0, S8(1) <= S8(2)); NEXT(3);

  VMOP(EQ8_C)  AR32(0, R8(1) == UIMM8(2)); NEXT(3);
  VMOP(NE8_C)  AR32(0, R8(1) != UIMM8(2)); NEXT(3);
  VMOP(UGT8_C) AR32(0, R8(1) >  UIMM8(2)); NEXT(3);
  VMOP(UGE8_C) AR32(0, R8(1) >= UIMM8(2)); NEXT(3);
  VMOP(ULT8_C) AR32(0, R8(1) <  UIMM8(2)); NEXT(3);
  VMOP(ULE8_C) AR32(0, R8(1) <= UIMM8(2)); NEXT(3);
  VMOP(SGT8_C) AR32(0, S8(1) >  SIMM8(2)); NEXT(3);
  VMOP(SGE8_C) AR32(0, S8(1) >= SIMM8(2)); NEXT(3);
  VMOP(SLT8_C) AR32(0, S8(1) <  SIMM8(2)); NEXT(3);
  VMOP(SLE8_C) AR32(0, S8(1) <= SIMM8(2)); NEXT(3);

  VMOP(EQ16)    AR32(0, R16(1) == R16(2)); NEXT(3);
  VMOP(NE16)    AR32(0, R16(1) != R16(2)); NEXT(3);
  VMOP(UGT16)   AR32(0, R16(1) >  R16(2)); NEXT(3);
  VMOP(UGE16)   AR32(0, R16(1) >= R16(2)); NEXT(3);
  VMOP(ULT16)   AR32(0, R16(1) <  R16(2)); NEXT(3);
  VMOP(ULE16)   AR32(0, R16(1) <= R16(2)); NEXT(3);
  VMOP(SGT16)   AR32(0, S16(1) >  S16(2)); NEXT(3);
  VMOP(SGE16)   AR32(0, S16(1) >= S16(2)); NEXT(3);
  VMOP(SLT16)   AR32(0, S16(1) <  S16(2)); NEXT(3);
  VMOP(SLE16)   AR32(0, S16(1) <= S16(2)); NEXT(3);

  VMOP(EQ16_C)  AR32(0, R16(1) == UIMM16(2)); NEXT(3);
  VMOP(NE16_C)  AR32(0, R16(1) != UIMM16(2)); NEXT(3);
  VMOP(UGT16_C) AR32(0, R16(1) >  UIMM16(2)); NEXT(3);
  VMOP(UGE16_C) AR32(0, R16(1) >= UIMM16(2)); NEXT(3);
  VMOP(ULT16_C) AR32(0, R16(1) <  UIMM16(2)); NEXT(3);
  VMOP(ULE16_C) AR32(0, R16(1) <= UIMM16(2)); NEXT(3);
  VMOP(SGT16_C) AR32(0, S16(1) >  SIMM16(2)); NEXT(3);
  VMOP(SGE16_C) AR32(0, S16(1) >= SIMM16(2)); NEXT(3);
  VMOP(SLT16_C) AR32(0, S16(1) <  SIMM16(2)); NEXT(3);
  VMOP(SLE16_C) AR32(0, S16(1) <= SIMM16(2)); NEXT(3);

  VMOP(EQ32)    AR32(0, R32(1) == R32(2)); NEXT(3);
  VMOP(NE32)    AR32(0, R32(1) != R32(2)); NEXT(3);
  VMOP(UGT32)   AR32(0, R32(1) >  R32(2)); NEXT(3);
  VMOP(UGE32)   AR32(0, R32(1) >= R32(2)); NEXT(3);
  VMOP(ULT32)   AR32(0, R32(1) <  R32(2)); NEXT(3);
  VMOP(ULE32)   AR32(0, R32(1) <= R32(2)); NEXT(3);
  VMOP(SGT32)   AR32(0, S32(1) >  S32(2)); NEXT(3);
  VMOP(SGE32)   AR32(0, S32(1) >= S32(2)); NEXT(3);
  VMOP(SLT32)   AR32(0, S32(1) <  S32(2)); NEXT(3);
  VMOP(SLE32)   AR32(0, S32(1) <= S32(2)); NEXT(3);

  VMOP(EQ32_C)  AR32(0, R32(1) == UIMM32(2)); NEXT(4);
  VMOP(NE32_C)  AR32(0, R32(1) != UIMM32(2)); NEXT(4);
  VMOP(UGT32_C) AR32(0, R32(1) >  UIMM32(2)); NEXT(4);
  VMOP(UGE32_C) AR32(0, R32(1) >= UIMM32(2)); NEXT(4);
  VMOP(ULT32_C) AR32(0, R32(1) <  UIMM32(2)); NEXT(4);
  VMOP(ULE32_C) AR32(0, R32(1) <= UIMM32(2)); NEXT(4);
  VMOP(SGT32_C) AR32(0, S32(1) >  SIMM32(2)); NEXT(4);
  VMOP(SGE32_C) AR32(0, S32(1) >= SIMM32(2)); NEXT(4);
  VMOP(SLT32_C) AR32(0, S32(1) <  SIMM32(2)); NEXT(4);
  VMOP(SLE32_C) AR32(0, S32(1) <= SIMM32(2)); NEXT(4);

  VMOP(EQ64)    AR32(0, R64(1) == R64(2)); NEXT(3);
  VMOP(NE64)    AR32(0, R64(1) != R64(2)); NEXT(3);
  VMOP(UGT64)   AR32(0, R64(1) >  R64(2)); NEXT(3);
  VMOP(UGE64)   AR32(0, R64(1) >= R64(2)); NEXT(3);
  VMOP(ULT64)   AR32(0, R64(1) <  R64(2)); NEXT(3);
  VMOP(ULE64)   AR32(0, R64(1) <= R64(2)); NEXT(3);
  VMOP(SGT64)   AR32(0, S64(1) >  S64(2)); NEXT(3);
  VMOP(SGE64)   AR32(0, S64(1) >= S64(2)); NEXT(3);
  VMOP(SLT64)   AR32(0, S64(1) <  S64(2)); NEXT(3);
  VMOP(SLE64)   AR32(0, S64(1) <= S64(2)); NEXT(3);

  VMOP(EQ64_C)  AR32(0, R64(1) == UIMM64(2)); NEXT(6);
  VMOP(NE64_C)  AR32(0, R64(1) != UIMM64(2)); NEXT(6);
  VMOP(UGT64_C) AR32(0, R64(1) >  UIMM64(2)); NEXT(6);
  VMOP(UGE64_C) AR32(0, R64(1) >= UIMM64(2)); NEXT(6);
  VMOP(ULT64_C) AR32(0, R64(1) <  UIMM64(2)); NEXT(6);
  VMOP(ULE64_C) AR32(0, R64(1) <= UIMM64(2)); NEXT(6);
  VMOP(SGT64_C) AR32(0, S64(1) >  SIMM64(2)); NEXT(6);
  VMOP(SGE64_C) AR32(0, S64(1) >= SIMM64(2)); NEXT(6);
  VMOP(SLT64_C) AR32(0, S64(1) <  SIMM64(2)); NEXT(6);
  VMOP(SLE64_C) AR32(0, S64(1) <= SIMM64(2)); NEXT(6);


  VMOP(OEQ_DBL) AR32(0, RDBL(1) == RDBL(2)); NEXT(3);
  VMOP(OGT_DBL) AR32(0, RDBL(1) >  RDBL(2)); NEXT(3);
  VMOP(OGE_DBL) AR32(0, RDBL(1) >= RDBL(2)); NEXT(3);
  VMOP(OLT_DBL) AR32(0, RDBL(1) <  RDBL(2)); NEXT(3);
  VMOP(OLE_DBL) AR32(0, RDBL(1) <= RDBL(2)); NEXT(3);

  VMOP(ONE_DBL) AR32(0, !__builtin_isnan(RDBL(1))
                      && !__builtin_isnan(RDBL(2))
                      && RDBL(1) != RDBL(2)); NEXT(3);

  VMOP(ORD_DBL) AR32(0, !__builtin_isnan(RDBL(1))
                      && !__builtin_isnan(RDBL(2))); NEXT(3);

  VMOP(UNO_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(1))); NEXT(3);

  VMOP(UEQ_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(2))
                      || RDBL(1) == RDBL(2)); NEXT(3);

  VMOP(UGT_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(2))
                      || RDBL(1) >  RDBL(2)); NEXT(3);

  VMOP(UGE_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(2))
                      || RDBL(1) <= RDBL(2)); NEXT(3);

  VMOP(ULT_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(2))
                      || RDBL(1) <  RDBL(2)); NEXT(3);

  VMOP(ULE_DBL) AR32(0, __builtin_isnan(RDBL(1))
                      || __builtin_isnan(RDBL(2))
                      || RDBL(1) <= RDBL(2)); NEXT(3);

  VMOP(UNE_DBL) AR32(0, RDBL(1) != RDBL(2)); NEXT(3);



  VMOP(OEQ_DBL_C) AR32(0, RDBL(1) == IMMDBL(2)); NEXT(6);
  VMOP(OGT_DBL_C) AR32(0, RDBL(1) >  IMMDBL(2)); NEXT(6);
  VMOP(OGE_DBL_C) AR32(0, RDBL(1) >= IMMDBL(2)); NEXT(6);
  VMOP(OLT_DBL_C) AR32(0, RDBL(1) <  IMMDBL(2)); NEXT(6);
  VMOP(OLE_DBL_C) AR32(0, RDBL(1) <= IMMDBL(2)); NEXT(6);

  VMOP(ONE_DBL_C) AR32(0, !__builtin_isnan(RDBL(1)) &&
                        RDBL(1) != IMMDBL(2)); NEXT(6);
  VMOP(ORD_DBL_C) AR32(0, !__builtin_isnan(RDBL(1))); NEXT(6);
  VMOP(UNO_DBL_C) AR32(0,  __builtin_isnan(RDBL(1))); NEXT(6);
  VMOP(UEQ_DBL_C) AR32(0, __builtin_isnan(RDBL(1)) ||
                        RDBL(1) == IMMDBL(2)); NEXT(6);
  VMOP(UGT_DBL_C) AR32(0, __builtin_isnan(RDBL(1)) ||
                        RDBL(1) >  IMMDBL(2)); NEXT(6);
  VMOP(UGE_DBL_C) AR32(0, __builtin_isnan(RDBL(1)) ||
                        RDBL(1) <= IMMDBL(2)); NEXT(6);
  VMOP(ULT_DBL_C) AR32(0, __builtin_isnan(RDBL(1)) ||
                        RDBL(1) <  IMMDBL(2)); NEXT(6);
  VMOP(ULE_DBL_C) AR32(0, __builtin_isnan(RDBL(1)) ||
                        RDBL(1) <= IMMDBL(2)); NEXT(6);
  VMOP(UNE_DBL_C) AR32(0, RDBL(1) != IMMDBL(2)); NEXT(6);



  VMOP(OEQ_FLT) AR32(0, RFLT(1) == RFLT(2)); NEXT(3);
  VMOP(OGT_FLT) AR32(0, RFLT(1) >  RFLT(2)); NEXT(3);
  VMOP(OGE_FLT) AR32(0, RFLT(1) >= RFLT(2)); NEXT(3);
  VMOP(OLT_FLT) AR32(0, RFLT(1) <  RFLT(2)); NEXT(3);
  VMOP(OLE_FLT) AR32(0, RFLT(1) <= RFLT(2)); NEXT(3);

  VMOP(ONE_FLT) AR32(0, !__builtin_isnan(RFLT(1))
                      && !__builtin_isnan(RFLT(2))
                      && RFLT(1) != RFLT(2)); NEXT(3);

  VMOP(ORD_FLT) AR32(0, !__builtin_isnan(RFLT(1))
                      && !__builtin_isnan(RFLT(2))); NEXT(3);

  VMOP(UNO_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(1))); NEXT(3);

  VMOP(UEQ_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(2))
                      || RFLT(1) == RFLT(2)); NEXT(3);

  VMOP(UGT_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(2))
                      || RFLT(1) >  RFLT(2)); NEXT(3);

  VMOP(UGE_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(2))
                      || RFLT(1) <= RFLT(2)); NEXT(3);

  VMOP(ULT_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(2))
                      || RFLT(1) <  RFLT(2)); NEXT(3);

  VMOP(ULE_FLT) AR32(0, __builtin_isnan(RFLT(1))
                      || __builtin_isnan(RFLT(2))
                      || RFLT(1) <= RFLT(2)); NEXT(3);

  VMOP(UNE_FLT) AR32(0, RFLT(1) != RFLT(2)); NEXT(3);



  VMOP(OEQ_FLT_C) AR32(0, RFLT(1) == IMMFLT(2)); NEXT(4);
  VMOP(OGT_FLT_C) AR32(0, RFLT(1) >  IMMFLT(2)); NEXT(4);
  VMOP(OGE_FLT_C) AR32(0, RFLT(1) >= IMMFLT(2)); NEXT(4);
  VMOP(OLT_FLT_C) AR32(0, RFLT(1) <  IMMFLT(2)); NEXT(4);
  VMOP(OLE_FLT_C) AR32(0, RFLT(1) <= IMMFLT(2)); NEXT(4);

  VMOP(ONE_FLT_C) AR32(0, !__builtin_isnan(RFLT(1)) &&
                        RFLT(1) != IMMFLT(2)); NEXT(4);
  VMOP(ORD_FLT_C) AR32(0, !__builtin_isnan(RFLT(1))); NEXT(4);
  VMOP(UNO_FLT_C) AR32(0,  __builtin_isnan(RFLT(1))); NEXT(4);
  VMOP(UEQ_FLT_C) AR32(0, __builtin_isnan(RFLT(1)) ||
                        RFLT(1) == IMMFLT(2)); NEXT(4);
  VMOP(UGT_FLT_C) AR32(0, __builtin_isnan(RFLT(1)) ||
                        RFLT(1) >  IMMFLT(2)); NEXT(4);
  VMOP(UGE_FLT_C) AR32(0, __builtin_isnan(RFLT(1)) ||
                        RFLT(1) <= IMMFLT(2)); NEXT(4);
  VMOP(ULT_FLT_C) AR32(0, __builtin_isnan(RFLT(1)) ||
                        RFLT(1) <  IMMFLT(2)); NEXT(4);
  VMOP(ULE_FLT_C) AR32(0, __builtin_isnan(RFLT(1)) ||
                        RFLT(1) <= IMMFLT(2)); NEXT(4);
  VMOP(UNE_FLT_C) AR32(0, RFLT(1) != IMMFLT(2)); NEXT(4);


  VMOP(EQ8_BR)    I = (void *)I + (int16_t)(R8(2) == R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(NE8_BR)    I = (void *)I + (int16_t)(R8(2) != R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGT8_BR)   I = (void *)I + (int16_t)(R8(2) >  R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGE8_BR)   I = (void *)I + (int16_t)(R8(2) >= R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULT8_BR)   I = (void *)I + (int16_t)(R8(2) <  R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULE8_BR)   I = (void *)I + (int16_t)(R8(2) <= R8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGT8_BR)   I = (void *)I + (int16_t)(S8(2) >  S8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGE8_BR)   I = (void *)I + (int16_t)(S8(2) >= S8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLT8_BR)   I = (void *)I + (int16_t)(S8(2) <  S8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLE8_BR)   I = (void *)I + (int16_t)(S8(2) <= S8(3) ? I[0] : I[1]); NEXT(0);

  VMOP(EQ8_C_BR)  I = (void *)I + (int16_t)(R8(2) == UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(NE8_C_BR)  I = (void *)I + (int16_t)(R8(2) != UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGT8_C_BR) I = (void *)I + (int16_t)(R8(2) >  UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGE8_C_BR) I = (void *)I + (int16_t)(R8(2) >= UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULT8_C_BR) I = (void *)I + (int16_t)(R8(2) <  UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULE8_C_BR) I = (void *)I + (int16_t)(R8(2) <= UIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGT8_C_BR) I = (void *)I + (int16_t)(S8(2) >  SIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGE8_C_BR) I = (void *)I + (int16_t)(S8(2) >= SIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLT8_C_BR) I = (void *)I + (int16_t)(S8(2) <  SIMM8(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLE8_C_BR) I = (void *)I + (int16_t)(S8(2) <= SIMM8(3) ? I[0] : I[1]); NEXT(0);

  VMOP(EQ32_BR)    I = (void *)I + (int16_t)(R32(2) == R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(NE32_BR)    I = (void *)I + (int16_t)(R32(2) != R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGT32_BR)   I = (void *)I + (int16_t)(R32(2) >  R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGE32_BR)   I = (void *)I + (int16_t)(R32(2) >= R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULT32_BR)   I = (void *)I + (int16_t)(R32(2) <  R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULE32_BR)   I = (void *)I + (int16_t)(R32(2) <= R32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGT32_BR)   I = (void *)I + (int16_t)(S32(2) >  S32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGE32_BR)   I = (void *)I + (int16_t)(S32(2) >= S32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLT32_BR)   I = (void *)I + (int16_t)(S32(2) <  S32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLE32_BR)   I = (void *)I + (int16_t)(S32(2) <= S32(3) ? I[0] : I[1]); NEXT(0);

  VMOP(EQ32_C_BR)  I = (void *)I + (int16_t)(R32(2) == UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(NE32_C_BR)  I = (void *)I + (int16_t)(R32(2) != UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGT32_C_BR) I = (void *)I + (int16_t)(R32(2) >  UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(UGE32_C_BR) I = (void *)I + (int16_t)(R32(2) >= UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULT32_C_BR) I = (void *)I + (int16_t)(R32(2) <  UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(ULE32_C_BR) I = (void *)I + (int16_t)(R32(2) <= UIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGT32_C_BR) I = (void *)I + (int16_t)(S32(2) >  SIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SGE32_C_BR) I = (void *)I + (int16_t)(S32(2) >= SIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLT32_C_BR) I = (void *)I + (int16_t)(S32(2) <  SIMM32(3) ? I[0] : I[1]); NEXT(0);
  VMOP(SLE32_C_BR) I = (void *)I + (int16_t)(S32(2) <= SIMM32(3) ? I[0] : I[1]); NEXT(0);

  VMOP(EQ32_SEL)    AR32(0, R32(3) == R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(NE32_SEL)    AR32(0, R32(3) != R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(UGT32_SEL)   AR32(0, R32(3) >  R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(UGE32_SEL)   AR32(0, R32(3) >= R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(ULT32_SEL)   AR32(0, R32(3) <  R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(ULE32_SEL)   AR32(0, R32(3) <= R32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(SGT32_SEL)   AR32(0, S32(3) >  S32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(SGE32_SEL)   AR32(0, S32(3) >= S32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(SLT32_SEL)   AR32(0, S32(3) <  S32(4) ? R32(1) : R32(2)); NEXT(5);
  VMOP(SLE32_SEL)   AR32(0, S32(3) <= S32(4) ? R32(1) : R32(2)); NEXT(5);

  VMOP(EQ32_C_SEL)  AR32(0, R32(3) == UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(NE32_C_SEL)  AR32(0, R32(3) != UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(UGT32_C_SEL) AR32(0, R32(3) >  UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(UGE32_C_SEL) AR32(0, R32(3) >= UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(ULT32_C_SEL) AR32(0, R32(3) <  UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(ULE32_C_SEL) AR32(0, R32(3) <= UIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(SGT32_C_SEL) AR32(0, S32(3) >  SIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(SGE32_C_SEL) AR32(0, S32(3) >= SIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(SLT32_C_SEL) AR32(0, S32(3) <  SIMM32(4) ? R32(1) : R32(2)); NEXT(6);
  VMOP(SLE32_C_SEL) AR32(0, S32(3) <= SIMM32(4) ? R32(1) : R32(2)); NEXT(6);


  VMOP(ABS)       AR32(0, abs(S32(1)));  NEXT(2);

  VMOP(FLOOR)     ADBL(0, floor(RDBL(1)));          NEXT(2);
  VMOP(SIN)       ADBL(0,   sin(RDBL(1)));          NEXT(2);
  VMOP(COS)       ADBL(0,   cos(RDBL(1)));          NEXT(2);
  VMOP(POW)       ADBL(0,   pow(RDBL(1), RDBL(2))); NEXT(3);
  VMOP(FABS)      ADBL(0,  fabs(RDBL(1)));          NEXT(2);
  VMOP(FMOD)      ADBL(0,  fmod(RDBL(1), RDBL(2))); NEXT(3);
  VMOP(LOG)       ADBL(0, log(RDBL(1)));            NEXT(2);
  VMOP(LOG10)     ADBL(0, log10(RDBL(1)));          NEXT(2);
  VMOP(ROUND)     ADBL(0, round(RDBL(1)));          NEXT(2);
  VMOP(SQRT)      ADBL(0, sqrt(RDBL(1)));           NEXT(2);
  VMOP(EXP)       ADBL(0, exp(RDBL(1)));            NEXT(2);
  VMOP(CEIL)      ADBL(0, ceil(RDBL(1)));           NEXT(2);

  VMOP(FLOORF)    AFLT(0, floorf(RFLT(1)));          NEXT(2);
  VMOP(SINF)      AFLT(0,   sinf(RFLT(1)));          NEXT(2);
  VMOP(COSF)      AFLT(0,   cosf(RFLT(1)));          NEXT(2);
  VMOP(POWF)      AFLT(0,   powf(RFLT(1), RFLT(2))); NEXT(3);
  VMOP(FABSF)     AFLT(0,  fabsf(RFLT(1)));          NEXT(2);
  VMOP(FMODF)     AFLT(0,  fmodf(RFLT(1), RFLT(2))); NEXT(3);
  VMOP(LOGF)      AFLT(0,   logf(RFLT(1)));          NEXT(2);
  VMOP(LOG10F)    AFLT(0, log10f(RFLT(1)));          NEXT(2);
  VMOP(ROUNDF)    AFLT(0, roundf(RFLT(1)));          NEXT(2);
  VMOP(SQRTF)     AFLT(0, sqrtf(RFLT(1)));           NEXT(2);
  VMOP(EXPF)      AFLT(0, expf(RFLT(1)));            NEXT(2);
  VMOP(CEILF)     AFLT(0, ceilf(RFLT(1)));           NEXT(2);

    // ---

  VMOP(LOAD8)        LOAD8(0, R32(1));             NEXT(2);
  VMOP(LOAD8_G)      LOAD8(0, SIMM32(1));          NEXT(3);

  VMOP(LOAD8_OFF)
    LOAD8(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD8_ZEXT_32_OFF)
    LOAD8_ZEXT_32(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD8_SEXT_32_OFF)
    LOAD8_SEXT_32(0, R32(1) + SIMM16(2));
    NEXT(3);

  VMOP(LOAD8_ROFF)
    LOAD8(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD8_ZEXT_32_ROFF)
    LOAD8_ZEXT_32(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD8_SEXT_32_ROFF)
    LOAD8_SEXT_32(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD8_G_ZEXT_32)
    LOAD8_ZEXT_32(0, SIMM32(1));
    NEXT(3);
  VMOP(LOAD8_G_SEXT_32)
    LOAD8_SEXT_32(0, SIMM32(1));
    NEXT(3);



  VMOP(STORE8_G)     STORE8(SIMM32(1), R8(0));              NEXT(3);
  VMOP(STORE8C_OFF)  STORE8(R32(0) + SIMM16(1), SIMM8(2));  NEXT(3);
  VMOP(STORE8_OFF)   STORE8(R32(0) + SIMM16(2), R8(1));     NEXT(3);
  VMOP(STORE8)       STORE8(R32(0),             R8(1));     NEXT(2);

    // ---

  VMOP(LOAD16)       LOAD16(0, R32(1));             NEXT(2);
  VMOP(LOAD16_OFF)
    LOAD16(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD16_ZEXT_32_OFF)
    LOAD16_ZEXT_32(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD16_SEXT_32_OFF)
    LOAD16_SEXT_32(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD16_ROFF)
    LOAD16(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD16_ZEXT_32_ROFF)
    LOAD16_ZEXT_32(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD16_SEXT_32_ROFF)
    LOAD16_SEXT_32(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD16_G_ZEXT_32)
    LOAD16_ZEXT_32(0, SIMM32(1));
    NEXT(3);
  VMOP(LOAD16_G_SEXT_32)
    LOAD16_SEXT_32(0, SIMM32(1));
    NEXT(3);
  VMOP(LOAD16_G)     LOAD16(0, SIMM32(1));          NEXT(3);

  VMOP(STORE16_G)    STORE16(SIMM32(1), R16(0));             NEXT(3);
  VMOP(STORE16C_OFF) STORE16(R32(0) + SIMM16(1), SIMM16(2)); NEXT(3);
  VMOP(STORE16_OFF)  STORE16(R32(0) + SIMM16(2), R16(1));    NEXT(3);
  VMOP(STORE16)      STORE16(R32(0),             R16(1));    NEXT(2);

    // ---

  VMOP(LOAD32)     LOAD32(0, R32(1));                NEXT(2);
  VMOP(LOAD32_OFF)
    LOAD32(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD32_ROFF)
    LOAD32(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD32_G)   LOAD32(0, SIMM32(1));             NEXT(3);

  VMOP(STORE32_G)    STORE32(SIMM32(1), R32(0));             NEXT(3);
  VMOP(STORE32C_OFF) STORE32(R32(0) + SIMM16(1), UIMM32(2)); NEXT(4);
  VMOP(STORE32_OFF)  STORE32(R32(0) + SIMM16(2), R32(1));    NEXT(3);
  VMOP(STORE32)      STORE32(R32(0),             R32(1));    NEXT(2);

    // ---

  VMOP(LOAD64)     LOAD64(0, R32(1)            ); NEXT(2);
  VMOP(LOAD64_OFF)
    LOAD64(0, R32(1) + SIMM16(2));
    NEXT(3);
  VMOP(LOAD64_ROFF)
    LOAD64(0, R32(1) + SIMM16(2) + R32(3) * SIMM16(4));
    NEXT(5);
  VMOP(LOAD64_G)   LOAD64(0, SIMM32(1)         ); NEXT(3);

  VMOP(STORE64_G)    STORE64(SIMM32(1),          R64(0));    NEXT(3);
  VMOP(STORE64C_OFF) STORE64(R32(0) + SIMM16(1), UIMM64(2)); NEXT(6);
  VMOP(STORE64_OFF)  STORE64(R32(0) + SIMM16(2), R64(1));    NEXT(3);
  VMOP(STORE64)      STORE64(R32(0),             R64(1));    NEXT(2);


  VMOP(MOV32)   AR32(0, R32(1));   NEXT(2);
  VMOP(MOV64)   AR64(0, R64(1));   NEXT(2);

  VMOP(MOV8_C)  AR32(0,  UIMM8(1)); NEXT(2);
  VMOP(MOV16_C) AR32(0, UIMM16(1)); NEXT(2);
  VMOP(MOV32_C) AR32(0, UIMM32(1)); NEXT(3);
  VMOP(MOV64_C) AR64(0, UIMM64(1)); NEXT(5);

  VMOP(LEA_R32_SHL)     AR32(0, R32(1) + (R32(2) << I[3])); NEXT(4);
  VMOP(LEA_R32_SHL2)    AR32(0, R32(1) + (R32(2) << 2)); NEXT(3);
  VMOP(LEA_R32_SHL_OFF) AR32(0, R32(1) + (R32(2) << I[3]) + SIMM32(4)); NEXT(6);
  VMOP(LEA_R32_MUL_OFF) AR32(0, R32(1) + R32(2) * UIMM32(3) + SIMM32(5)); NEXT(7);

  VMOP(CAST_1_TRUNC_8)   AR32(0, !!R8(1)); NEXT(2);
  VMOP(CAST_1_TRUNC_16)   AR32(0, !!R16(1)); NEXT(2);

  VMOP(CAST_8_ZEXT_1)    AR32(0, R32(1)); NEXT(2);
  VMOP(CAST_8_SEXT_1)    AR32(0, R32(1) ? -1 : 0); NEXT(2);
  VMOP(CAST_8_TRUNC_16)  AR32(0, R16(1)); NEXT(2);
  VMOP(CAST_8_TRUNC_32)  AR32(0, R32(1)); NEXT(2);
  VMOP(CAST_8_TRUNC_64)  AR32(0, R64(1)); NEXT(2);

  VMOP(CAST_16_ZEXT_1)   AR32(0, R32(1)); NEXT(2);
  VMOP(CAST_16_ZEXT_8)   AR32(0, R8(1)); NEXT(2);
  VMOP(CAST_16_SEXT_8)   AR32(0, S8(1)); NEXT(2);
  VMOP(CAST_16_TRUNC_32) AR32(0, R16(1)); NEXT(2);
  VMOP(CAST_16_TRUNC_64) AR32(0, R64(1)); NEXT(2);
  VMOP(CAST_16_FPTOSI_FLT) AR32(0, (int32_t)RFLT(1)); NEXT(2);
  VMOP(CAST_16_FPTOUI_FLT) AR32(0, (uint32_t)RFLT(1)); NEXT(2);
  VMOP(CAST_16_FPTOSI_DBL) AR32(0, (int32_t)RDBL(1)); NEXT(2);
  VMOP(CAST_16_FPTOUI_DBL) AR32(0, (uint32_t)RDBL(1)); NEXT(2);

  VMOP(CAST_32_SEXT_1)   AR32(0, R32(1) ? -1 : 0); NEXT(2);
  VMOP(CAST_32_ZEXT_8)   AR32(0, R8(1)); NEXT(2);
  VMOP(CAST_32_SEXT_8)   AR32(0, S8(1)); NEXT(2);
  VMOP(CAST_32_ZEXT_16)  AR32(0, R16(1)); NEXT(2);
  VMOP(CAST_32_SEXT_16)  AR32(0, S16(1)); NEXT(2);
  VMOP(CAST_32_TRUNC_64) AR32(0, R64(1)); NEXT(2);

  VMOP(CAST_32_FPTOSI_FLT) AR32(0, (int32_t)RFLT(1)); NEXT(2);
  VMOP(CAST_32_FPTOUI_FLT) AR32(0, (uint32_t)RFLT(1)); NEXT(2);
  VMOP(CAST_32_FPTOSI_DBL) AR32(0, (int32_t)RDBL(1)); NEXT(2);
  VMOP(CAST_32_FPTOUI_DBL) AR32(0, (uint32_t)RDBL(1)); NEXT(2);


  VMOP(CAST_64_ZEXT_1) AR64(0, R32(1)); NEXT(2);
  VMOP(CAST_64_SEXT_1) AR64(0, R32(1) ? (int64_t)-1LL : 0); NEXT(2);
  VMOP(CAST_64_ZEXT_8) AR64(0, R8(1)); NEXT(2);
  VMOP(CAST_64_SEXT_8) AR64(0, S8(1)); NEXT(2);
  VMOP(CAST_64_ZEXT_16) AR64(0, R16(1)); NEXT(2);
  VMOP(CAST_64_SEXT_16) AR64(0, S16(1)); NEXT(2);
  VMOP(CAST_64_ZEXT_32) AR64(0, R32(1)); NEXT(2);
  VMOP(CAST_64_SEXT_32) AR64(0, S32(1)); NEXT(2);
  VMOP(CAST_64_FPTOSI_FLT) AR64(0, (int64_t)RFLT(1)); NEXT(2);
  VMOP(CAST_64_FPTOUI_FLT) AR64(0, (uint64_t)RFLT(1)); NEXT(2);
  VMOP(CAST_64_FPTOSI_DBL) AR64(0, (int64_t)RDBL(1)); NEXT(2);
  VMOP(CAST_64_FPTOUI_DBL) AR64(0, (uint64_t)RDBL(1)); NEXT(2);

  VMOP(CAST_DBL_FPEXT_FLT)   ADBL(0, RFLT(1)); NEXT(2);

  VMOP(CAST_FLT_FPTRUNC_DBL) AFLT(0, RDBL(1)); NEXT(2);
  VMOP(CAST_FLT_SITOFP_8)    AFLT(0, S8(1)); NEXT(2);
  VMOP(CAST_FLT_UITOFP_8)    AFLT(0, R8(1)); NEXT(2);
  VMOP(CAST_FLT_SITOFP_16)   AFLT(0, S16(1)); NEXT(2);
  VMOP(CAST_FLT_UITOFP_16)   AFLT(0, R16(1)); NEXT(2);
  VMOP(CAST_FLT_SITOFP_32)   AFLT(0, S32(1)); NEXT(2);
  VMOP(CAST_FLT_UITOFP_32)   AFLT(0, R32(1)); NEXT(2);
  VMOP(CAST_FLT_SITOFP_64)   AFLT(0, S64(1)); NEXT(2);
  VMOP(CAST_FLT_UITOFP_64)   AFLT(0, R64(1)); NEXT(2);

  VMOP(CAST_DBL_SITOFP_8)    ADBL(0, S8(1)); NEXT(2);
  VMOP(CAST_DBL_UITOFP_8)    ADBL(0, R8(1)); NEXT(2);
  VMOP(CAST_DBL_SITOFP_16)   ADBL(0, S16(1)); NEXT(2);
  VMOP(CAST_DBL_UITOFP_16)   ADBL(0, R16(1)); NEXT(2);
  VMOP(CAST_DBL_SITOFP_32)   ADBL(0, S32(1)); NEXT(2);
  VMOP(CAST_DBL_UITOFP_32)   ADBL(0, R32(1)); NEXT(2);
  VMOP(CAST_DBL_SITOFP_64)   ADBL(0, S64(1)); NEXT(2);
  VMOP(CAST_DBL_UITOFP_64)   ADBL(0, R64(1)); NEXT(2);

  VMOP(JUMPTABLE)
    I = (void *)I + (int16_t)I[2 + (R8(0) & (I[1] - 1))];
    NEXT(0);

  VMOP(SWITCH8_BS) {
      const uint8_t u8 = R8(0);
      const uint32_t p = I[1];
      int imin = 0;
      int imax = p - 1;
      const uint16_t *Iorg = I;
      I += 2;
      while(imin < imax) {
        int imid = (imin + imax) >> 1;

        if(UIMM8(imid) < u8)
          imin = imid + 1;
        else
          imax = imid;
      }
      if(!((imax == imin) && (UIMM8(imin) == u8)))
        imin = p;

      I = (void *)Iorg + (int16_t)I[p + imin];
      NEXT(0);
    }

  VMOP(SWITCH32_BS) {
      const uint32_t u32 = R32(0);
      const uint32_t p = I[1];
      int imin = 0;
      int imax = p - 1;
      const uint16_t *Iorg = I;
      I += 2;
      while(imin < imax) {
        int imid = (imin + imax) >> 1;

        if(UIMM32(imid * 2) < u32)
          imin = imid + 1;
        else
          imax = imid;
      }
      if(!((imax == imin) && (UIMM32(imin * 2) == u32)))
        imin = p;
      I = (void *)Iorg + (int16_t)I[p * 2 + imin];
      NEXT(0);
    }


  VMOP(SWITCH64_BS) {
      const uint64_t u64 = R64(0);
      const uint32_t p = I[1];
      int imin = 0;
      int imax = p - 1;
      const uint16_t *Iorg = I;
      I += 2;
      while(imin < imax) {
        int imid = (imin + imax) >> 1;

        if(UIMM64(imid * 4) < u64)
          imin = imid + 1;
        else
          imax = imid;
      }
      if(!((imax == imin) && (UIMM64(imin * 4) == u64)))
        imin = p;
      I = (void *)Iorg + (int16_t)I[p * 4 + imin];
      NEXT(0);
    }


  VMOP(SELECT32RR) AR32(0, R32(1) ? R32(2)    : R32(3));    NEXT(4);
  VMOP(SELECT32RC) AR32(0, R32(1) ? R32(2)    : UIMM32(3)); NEXT(5);
  VMOP(SELECT32CR) AR32(0, R32(1) ? UIMM32(3) : R32(2));    NEXT(5);
  VMOP(SELECT32CC) AR32(0, R32(1) ? UIMM32(2) : UIMM32(4)); NEXT(6);

  VMOP(SELECT64RR) AR64(0, R32(1) ? R64(2)    : R64(3));    NEXT(4);
  VMOP(SELECT64RC) AR64(0, R32(1) ? R64(2)    : UIMM64(3)); NEXT(7);
  VMOP(SELECT64CR) AR64(0, R32(1) ? UIMM64(3) : R64(2));    NEXT(7);
  VMOP(SELECT64CC) AR64(0, R32(1) ? UIMM64(2) : UIMM64(6)); NEXT(10);


  VMOP(ALLOCA) {
      F.allocaptr = VMIR_ALIGN(F.allocaptr, I[1]);
      AR32(0, F.allocaptr);
      F.allocaptr += UIMM32(2);
      ALLOCATRACEPEAK();
      NEXT(4);
    }

  VMOP(ALLOCAD) {
      F.allocaptr = VMIR_ALIGN(F.allocaptr, I[1]);
      uint32_t r = F.allocaptr;
      F.allocaptr += UIMM32(3) * R32(2);
      ALLOCATRACEPEAK();
      AR32(0, r);
      NEXT(5);
    }

  VMOP(STACKSHRINK)
    F.allocaptr -= UIMM32(0);
    NEXT(2);

  VMOP(STACKSAVE)
    AR32(0, F.allocaptr);
    NEXT(1);

  VMOP(STACKRESTORE)
    F.allocaptr = R32(0);
    NEXT(1);

  VMOP(STACKCOPYR)
    F.allocaptr = VMIR_ALIGN(F.allocaptr, 4);
    AR32(0, F.allocaptr);
    memcpy(HOSTADDR(F.allocaptr), HOSTADDR(R32(1)), UIMM32(2));
    F.allocaptr += UIMM32(2);
    ALLOCATRACEPEAK();
    NEXT(4);

  VMOP(STACKCOPYC)
    F.allocaptr = VMIR_ALIGN(F.allocaptr, 4);
    AR32(0, F.allocaptr);
    memcpy(HOSTADDR(F.allocaptr), HOSTADDR(UIMM32(1)), UIMM32(3));
    F.allocaptr += UIMM32(3);
    ALLOCATRACEPEAK();
    NEXT(5);

  VMOP(UNREACHABLE) vm_stop(iu, VM_STOP_UNREACHABLE, 0);


  VMOP(MEMCPY) {
      uint32_t r = R32(1);
      memcpy(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3));
      AR32(0, r);
      NEXT(4);
    }

  VMOP(MEMSET) {
      uint32_t r = R32(1);
      memset(HOSTADDR(R32(1)), R32(2), R32(3));
      AR32(0, r);
      NEXT(4);
    }

  VMOP(MEMMOVE) {
      uint32_t r = R32(1);
      memmove(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3));
      AR32(0, r);
      NEXT(4);
    }

  VMOP(LLVM_MEMCPY)
    memcpy(HOSTADDR(R32(0)), HOSTADDR(R32(1)), R32(2)); NEXT(3);
  VMOP(LLVM_MEMSET)
    memset(HOSTADDR(R32(0)), R8(1), R32(2)); NEXT(3);
  VMOP(LLVM_MEMSET64)
    memset(HOSTADDR(R32(0)), R8(1), R64(2)); NEXT(3);

  VMOP(MEMCMP)
    AR32(0, memcmp(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3))); NEXT(4);

  VMOP(STRCPY) {
      uint32_t r = R32(1);
      strcpy(HOSTADDR(R32(1)), HOSTADDR(R32(2)));
      AR32(0, r);
      NEXT(3);
    }

  VMOP(STRCAT) {
      uint32_t r = R32(1);
      strcat(HOSTADDR(R32(1)), HOSTADDR(R32(2)));
      AR32(0, r);
      NEXT(3);
    }

  VMOP(STRNCPY) {
      uint32_t r = R32(1);
      strncpy(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3));
      AR32(0, r);
      NEXT(4);
    }

  VMOP(STRNCAT) {
      uint32_t r = R32(1);
      strncat(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3));
      AR32(0, r);
      NEXT(4);
    }

  VMOP(STRCMP)
    AR32(0, strcmp(HOSTADDR(R32(1)), HOSTADDR(R32(2)))); NEXT(3);
  VMOP(STRCASECMP)
    AR32(0, strcasecmp(HOSTADDR(R32(1)), HOSTADDR(R32(2)))); NEXT(3);
  VMOP(STRNCMP)
    AR32(0, strncmp(HOSTADDR(R32(1)), HOSTADDR(R32(2)), R32(3))); NEXT(4);
  VMOP(STRCHR)
    AR32(0, vm_strchr(R32(1), R32(2), hostmem)); NEXT(3);
  VMOP(STRRCHR)
    AR32(0, vm_strrchr(R32(1), R32(2), hostmem)); NEXT(3);
  VMOP(STRLEN)
    AR32(0, strlen(HOSTADDR(R32(1)))); NEXT(2);
  VMOP(STRDUP)
    AR32(0, vm_strdup(R32(1), hostmem)); NEXT(2);

  VMOP(VAARG32)
    AR32(0, vm_vaarg32(rf, HOSTADDR(R32(1)))); NEXT(2);

  VMOP(VAARG64)
    AR64(0, vm_vaarg64(rf, HOSTADDR(R32(1)))); NEXT(2);

  VMOP(VASTART)
    *(void **)HOSTADDR(R32(0)) = rf + S32(1);
    NEXT(2);

  VMOP(VACOPY)
    *(void **)HOSTADDR(R32(0)) = *(void **)HOSTADDR(R32(1));
    NEXT(2);

  VMOP(CTZ32) AR32(0, __builtin_ctz(R32(1))); NEXT(2);
  VMOP(CLZ32) AR32(0, __builtin_clz(R32(1))); NEXT(2);
  VMOP(POP32) AR32(0, __builtin_popcount(R32(1))); NEXT(2);

  VMOP(CTZ64) AR64(0, __builtin_ctzll(R64(1))); NEXT(2);
  VMOP(CLZ64) AR64(0, __builtin_clzll(R64(1))); NEXT(2);
  VMOP(POP64) AR64(0, __builtin_popcountll(R64(1))); NEXT(2);

  VMOP(UADDO32)
  {
    uint32_t r;
#if __has_builtin(__builtin_uadd_overflow)
    AR32(1, __builtin_uadd_overflow(R32(2), R32(3), &r));
#else
    uint32_t a = R32(2);
    uint32_t b = R32(3);
    AR32(1, UINT32_MAX - a < b);
    r = a + b;
#endif
    AR32(0, r);
    NEXT(4);
  }

  VMOP(UMULO32)
  {
    uint32_t r;
#if __has_builtin(__builtin_umul_overflow)
    AR32(1, __builtin_umul_overflow(R32(2), R32(3), &r));
#else
    uint32_t a = R32(2);
    uint32_t b = R32(3);
    uint64_t p = a * b;
    r = p;
    AR32(1, (p >> 32) != 0);
#endif
    AR32(0, r);
    NEXT(4);
  }

  VMOP(INSTRUMENT_COUNT)
#ifdef VM_TRACE
  {
    ir_instrumentation_t *ii = &VECTOR_ITEM(&iu->iu_instrumentation, UIMM32(0));
    vm_tracef(&F, "Entering basic block %s().%d",
              ii->ii_func->if_name, ii->ii_bb);
  }
#endif
    VECTOR_ITEM(&iu->iu_instrumentation, UIMM32(0)).ii_count++;
    NEXT(2);
  }

#ifndef VM_DONT_USE_COMPUTED_GOTO

 resolve:
  switch(I[0]) {
  case VM_NOP:       return &&NOP      - &&opz;     break;

  case VM_JIT_CALL:  return &&JIT_CALL - &&opz;     break;
  case VM_RET_VOID:  return &&RET_VOID - &&opz;     break;
  case VM_RET_R32:   return &&RET_R32  - &&opz;     break;
  case VM_RET_R64:   return &&RET_R64  - &&opz;     break;
  case VM_RET_R32C:  return &&RET_R32C - &&opz;     break;
  case VM_RET_R64C:  return &&RET_R64C - &&opz;     break;

  case VM_SDIV_R8:  return &&SDIV_R8 - &&opz;     break;
  case VM_SREM_R8:  return &&SREM_R8 - &&opz;     break;
  case VM_ASHR_R8:  return &&ASHR_R8 - &&opz;     break;
  case VM_ROL_R8:   return &&ROL_R8  - &&opz;     break;
  case VM_ROR_R8:   return &&ROR_R8  - &&opz;     break;

  case VM_SDIV_R8C:  return &&SDIV_R8C - &&opz;     break;
  case VM_SREM_R8C:  return &&SREM_R8C - &&opz;     break;
  case VM_ASHR_R8C:  return &&ASHR_R8C - &&opz;     break;
  case VM_ROL_R8C:   return &&ROL_R8C  - &&opz;     break;
  case VM_ROR_R8C:   return &&ROR_R8C  - &&opz;     break;

  case VM_SDIV_R16:  return &&SDIV_R16 - &&opz;     break;
  case VM_SREM_R16:  return &&SREM_R16 - &&opz;     break;
  case VM_ASHR_R16:  return &&ASHR_R16 - &&opz;     break;
  case VM_ROL_R16:   return &&ROL_R16  - &&opz;     break;
  case VM_ROR_R16:   return &&ROR_R16  - &&opz;     break;

  case VM_ADD_R16C:   return &&ADD_R16C  - &&opz;     break;
  case VM_SUB_R16C:   return &&SUB_R16C  - &&opz;     break;
  case VM_MUL_R16C:   return &&MUL_R16C  - &&opz;     break;
  case VM_UDIV_R16C:  return &&UDIV_R16C - &&opz;     break;
  case VM_SDIV_R16C:  return &&SDIV_R16C - &&opz;     break;
  case VM_UREM_R16C:  return &&UREM_R16C - &&opz;     break;
  case VM_SREM_R16C:  return &&SREM_R16C - &&opz;     break;
  case VM_SHL_R16C:   return &&SHL_R16C  - &&opz;     break;
  case VM_LSHR_R16C:  return &&LSHR_R16C - &&opz;     break;
  case VM_ASHR_R16C:  return &&ASHR_R16C - &&opz;     break;
  case VM_AND_R16C:   return &&AND_R16C  - &&opz;     break;
  case VM_OR_R16C:    return &&OR_R16C   - &&opz;     break;
  case VM_XOR_R16C:   return &&XOR_R16C  - &&opz;     break;
  case VM_ROL_R16C:   return &&ROL_R16C  - &&opz;     break;
  case VM_ROR_R16C:   return &&ROR_R16C  - &&opz;     break;

  case VM_ADD_R32:   return &&ADD_R32  - &&opz;     break;
  case VM_SUB_R32:   return &&SUB_R32  - &&opz;     break;
  case VM_MUL_R32:   return &&MUL_R32  - &&opz;     break;
  case VM_UDIV_R32:  return &&UDIV_R32 - &&opz;     break;
  case VM_SDIV_R32:  return &&SDIV_R32 - &&opz;     break;
  case VM_UREM_R32:  return &&UREM_R32 - &&opz;     break;
  case VM_SREM_R32:  return &&SREM_R32 - &&opz;     break;
  case VM_SHL_R32:   return &&SHL_R32  - &&opz;     break;
  case VM_LSHR_R32:  return &&LSHR_R32 - &&opz;     break;
  case VM_ASHR_R32:  return &&ASHR_R32 - &&opz;     break;
  case VM_AND_R32:   return &&AND_R32  - &&opz;     break;
  case VM_OR_R32:    return &&OR_R32   - &&opz;     break;
  case VM_XOR_R32:   return &&XOR_R32  - &&opz;     break;
  case VM_ROL_R32:   return &&ROL_R32  - &&opz;     break;
  case VM_ROR_R32:   return &&ROR_R32  - &&opz;     break;

  case VM_INC_R32:   return &&INC_R32  - &&opz;     break;
  case VM_DEC_R32:   return &&DEC_R32  - &&opz;     break;

  case VM_ADD_R32C:   return &&ADD_R32C  - &&opz;     break;
  case VM_SUB_R32C:   return &&SUB_R32C  - &&opz;     break;
  case VM_MUL_R32C:   return &&MUL_R32C  - &&opz;     break;
  case VM_UDIV_R32C:  return &&UDIV_R32C - &&opz;     break;
  case VM_SDIV_R32C:  return &&SDIV_R32C - &&opz;     break;
  case VM_UREM_R32C:  return &&UREM_R32C - &&opz;     break;
  case VM_SREM_R32C:  return &&SREM_R32C - &&opz;     break;
  case VM_SHL_R32C:   return &&SHL_R32C  - &&opz;     break;
  case VM_LSHR_R32C:  return &&LSHR_R32C - &&opz;     break;
  case VM_ASHR_R32C:  return &&ASHR_R32C - &&opz;     break;
  case VM_AND_R32C:   return &&AND_R32C  - &&opz;     break;
  case VM_OR_R32C:    return &&OR_R32C   - &&opz;     break;
  case VM_XOR_R32C:   return &&XOR_R32C  - &&opz;     break;
  case VM_ROL_R32C:   return &&ROL_R32C  - &&opz;     break;
  case VM_ROR_R32C:   return &&ROR_R32C  - &&opz;     break;



  case VM_ADD_R64:   return &&ADD_R64  - &&opz;     break;
  case VM_SUB_R64:   return &&SUB_R64  - &&opz;     break;
  case VM_MUL_R64:   return &&MUL_R64  - &&opz;     break;
  case VM_UDIV_R64:  return &&UDIV_R64 - &&opz;     break;
  case VM_SDIV_R64:  return &&SDIV_R64 - &&opz;     break;
  case VM_UREM_R64:  return &&UREM_R64 - &&opz;     break;
  case VM_SREM_R64:  return &&SREM_R64 - &&opz;     break;
  case VM_SHL_R64:   return &&SHL_R64  - &&opz;     break;
  case VM_LSHR_R64:  return &&LSHR_R64 - &&opz;     break;
  case VM_ASHR_R64:  return &&ASHR_R64 - &&opz;     break;
  case VM_AND_R64:   return &&AND_R64  - &&opz;     break;
  case VM_OR_R64:    return &&OR_R64   - &&opz;     break;
  case VM_XOR_R64:   return &&XOR_R64  - &&opz;     break;
  case VM_ROL_R64:   return &&ROL_R64  - &&opz;     break;
  case VM_ROR_R64:   return &&ROR_R64  - &&opz;     break;

  case VM_ADD_R64C:  return &&ADD_R64C  - &&opz;     break;
  case VM_SUB_R64C:  return &&SUB_R64C  - &&opz;     break;
  case VM_MUL_R64C:  return &&MUL_R64C  - &&opz;     break;
  case VM_UDIV_R64C: return &&UDIV_R64C - &&opz;     break;
  case VM_SDIV_R64C: return &&SDIV_R64C - &&opz;     break;
  case VM_UREM_R64C: return &&UREM_R64C - &&opz;     break;
  case VM_SREM_R64C: return &&SREM_R64C - &&opz;     break;
  case VM_SHL_R64C:  return &&SHL_R64C  - &&opz;     break;
  case VM_LSHR_R64C: return &&LSHR_R64C - &&opz;     break;
  case VM_ASHR_R64C: return &&ASHR_R64C - &&opz;     break;
  case VM_AND_R64C:  return &&AND_R64C  - &&opz;     break;
  case VM_OR_R64C:   return &&OR_R64C   - &&opz;     break;
  case VM_XOR_R64C:  return &&XOR_R64C  - &&opz;     break;
  case VM_ROL_R64C:  return &&ROL_R64C  - &&opz;     break;
  case VM_ROR_R64C:  return &&ROR_R64C  - &&opz;     break;

  case VM_MLA32:     return &&MLA32     - &&opz;     break;

  case VM_ADD_DBL:   return &&ADD_DBL  - &&opz;     break;
  case VM_SUB_DBL:   return &&SUB_DBL  - &&opz;     break;
  case VM_MUL_DBL:   return &&MUL_DBL  - &&opz;     break;
  case VM_DIV_DBL:   return &&DIV_DBL  - &&opz;     break;

  case VM_ADD_DBLC:   return &&ADD_DBLC  - &&opz;     break;
  case VM_SUB_DBLC:   return &&SUB_DBLC  - &&opz;     break;
  case VM_MUL_DBLC:   return &&MUL_DBLC  - &&opz;     break;
  case VM_DIV_DBLC:   return &&DIV_DBLC  - &&opz;     break;

  case VM_ADD_FLT:   return &&ADD_FLT  - &&opz;     break;
  case VM_SUB_FLT:   return &&SUB_FLT  - &&opz;     break;
  case VM_MUL_FLT:   return &&MUL_FLT  - &&opz;     break;
  case VM_DIV_FLT:   return &&DIV_FLT  - &&opz;     break;

  case VM_ADD_FLTC:   return &&ADD_FLTC  - &&opz;     break;
  case VM_SUB_FLTC:   return &&SUB_FLTC  - &&opz;     break;
  case VM_MUL_FLTC:   return &&MUL_FLTC  - &&opz;     break;
  case VM_DIV_FLTC:   return &&DIV_FLTC  - &&opz;     break;

  case VM_ABS: return &&ABS - &&opz; break;

  case VM_FLOOR: return &&FLOOR - &&opz; break;
  case VM_SIN: return &&SIN - &&opz; break;
  case VM_COS: return &&COS - &&opz; break;
  case VM_POW: return &&POW - &&opz; break;
  case VM_FABS: return &&FABS - &&opz; break;
  case VM_FMOD: return &&FMOD - &&opz; break;
  case VM_LOG: return &&LOG - &&opz; break;
  case VM_LOG10: return &&LOG10 - &&opz; break;
  case VM_ROUND: return &&ROUND - &&opz; break;
  case VM_SQRT: return &&SQRT - &&opz; break;
  case VM_CEIL: return &&CEIL - &&opz; break;
  case VM_EXP:  return &&EXP - &&opz; break;

  case VM_FLOORF: return &&FLOORF - &&opz; break;
  case VM_SINF: return &&SINF - &&opz; break;
  case VM_COSF: return &&COSF - &&opz; break;
  case VM_POWF: return &&POWF - &&opz; break;
  case VM_FABSF: return &&FABSF - &&opz; break;
  case VM_FMODF: return &&FMODF - &&opz; break;
  case VM_LOGF: return &&LOGF - &&opz; break;
  case VM_LOG10F: return &&LOG10F - &&opz; break;
  case VM_ROUNDF: return &&ROUNDF - &&opz; break;
  case VM_SQRTF: return &&SQRTF - &&opz; break;
  case VM_CEILF: return &&CEILF - &&opz; break;
  case VM_EXPF:  return &&EXPF - &&opz; break;

  case VM_LOAD8:     return &&LOAD8      - &&opz;     break;
  case VM_LOAD8_G:   return &&LOAD8_G    - &&opz;     break;
  case VM_LOAD8_OFF: return &&LOAD8_OFF  - &&opz;     break;
  case VM_LOAD8_ZEXT_32_OFF: return &&LOAD8_ZEXT_32_OFF  - &&opz;     break;
  case VM_LOAD8_SEXT_32_OFF: return &&LOAD8_SEXT_32_OFF  - &&opz;     break;
  case VM_LOAD8_ROFF: return &&LOAD8_ROFF  - &&opz;     break;
  case VM_LOAD8_ZEXT_32_ROFF: return &&LOAD8_ZEXT_32_ROFF  - &&opz;     break;
  case VM_LOAD8_SEXT_32_ROFF: return &&LOAD8_SEXT_32_ROFF  - &&opz;     break;

  case VM_LOAD8_G_ZEXT_32: return &&LOAD8_G_ZEXT_32  - &&opz;     break;
  case VM_LOAD8_G_SEXT_32: return &&LOAD8_G_SEXT_32  - &&opz;     break;

  case VM_STORE8_G:    return &&STORE8_G    - &&opz;     break;
  case VM_STORE8C_OFF: return &&STORE8C_OFF - &&opz;     break;
  case VM_STORE8_OFF:  return &&STORE8_OFF  - &&opz;     break;
  case VM_STORE8:      return &&STORE8      - &&opz;     break;


  case VM_LOAD16:     return &&LOAD16      - &&opz;     break;
  case VM_LOAD16_G:   return &&LOAD16_G    - &&opz;     break;
  case VM_LOAD16_OFF: return &&LOAD16_OFF  - &&opz;     break;
  case VM_LOAD16_ZEXT_32_OFF: return &&LOAD16_ZEXT_32_OFF  - &&opz;     break;
  case VM_LOAD16_SEXT_32_OFF: return &&LOAD16_SEXT_32_OFF  - &&opz;     break;
  case VM_LOAD16_ROFF: return &&LOAD16_ROFF  - &&opz;     break;
  case VM_LOAD16_ZEXT_32_ROFF: return &&LOAD16_ZEXT_32_ROFF  - &&opz;     break;
  case VM_LOAD16_SEXT_32_ROFF: return &&LOAD16_SEXT_32_ROFF  - &&opz;     break;

  case VM_LOAD16_G_ZEXT_32: return &&LOAD16_G_ZEXT_32  - &&opz;     break;
  case VM_LOAD16_G_SEXT_32: return &&LOAD16_G_SEXT_32  - &&opz;     break;

  case VM_STORE16_G:    return &&STORE16_G    - &&opz;     break;
  case VM_STORE16C_OFF: return &&STORE16C_OFF - &&opz;     break;
  case VM_STORE16_OFF:  return &&STORE16_OFF  - &&opz;     break;
  case VM_STORE16:      return &&STORE16      - &&opz;     break;


  case VM_LOAD32:    return &&LOAD32     - &&opz;     break;
  case VM_LOAD32_OFF:return &&LOAD32_OFF - &&opz;     break;
  case VM_LOAD32_ROFF:return &&LOAD32_ROFF - &&opz;     break;
  case VM_LOAD32_G:  return &&LOAD32_G   - &&opz;     break;

  case VM_STORE32_G: return &&STORE32_G - &&opz;     break;
  case VM_STORE32C_OFF: return &&STORE32C_OFF - &&opz;     break;
  case VM_STORE32_OFF: return &&STORE32_OFF - &&opz;     break;
  case VM_STORE32: return &&STORE32 - &&opz;     break;

  case VM_LOAD64:    return &&LOAD64     - &&opz;     break;
  case VM_LOAD64_OFF:return &&LOAD64_OFF - &&opz;     break;
  case VM_LOAD64_ROFF:return &&LOAD64_ROFF - &&opz;     break;
  case VM_LOAD64_G:  return &&LOAD64_G   - &&opz;     break;

  case VM_STORE64_G: return &&STORE64_G - &&opz;     break;
  case VM_STORE64C_OFF: return &&STORE64C_OFF - &&opz;     break;
  case VM_STORE64_OFF: return &&STORE64_OFF - &&opz;     break;
  case VM_STORE64: return &&STORE64 - &&opz;     break;

  case VM_EQ8:      return &&EQ8     - &&opz;     break;
  case VM_NE8:      return &&NE8     - &&opz;     break;
  case VM_SGT8:     return &&SGT8    - &&opz;     break;
  case VM_SGE8:     return &&SGE8    - &&opz;     break;
  case VM_SLT8:     return &&SLT8    - &&opz;     break;
  case VM_SLE8:     return &&SLE8    - &&opz;     break;
  case VM_UGT8:     return &&UGT8    - &&opz;     break;
  case VM_UGE8:     return &&UGE8    - &&opz;     break;
  case VM_ULT8:     return &&ULT8    - &&opz;     break;
  case VM_ULE8:     return &&ULE8    - &&opz;     break;

  case VM_EQ8_C:      return &&EQ8_C     - &&opz;     break;
  case VM_NE8_C:      return &&NE8_C     - &&opz;     break;
  case VM_SGT8_C:     return &&SGT8_C    - &&opz;     break;
  case VM_SGE8_C:     return &&SGE8_C    - &&opz;     break;
  case VM_SLT8_C:     return &&SLT8_C    - &&opz;     break;
  case VM_SLE8_C:     return &&SLE8_C    - &&opz;     break;
  case VM_UGT8_C:     return &&UGT8_C    - &&opz;     break;
  case VM_UGE8_C:     return &&UGE8_C    - &&opz;     break;
  case VM_ULT8_C:     return &&ULT8_C    - &&opz;     break;
  case VM_ULE8_C:     return &&ULE8_C    - &&opz;     break;


  case VM_EQ16:      return &&EQ16     - &&opz;     break;
  case VM_NE16:      return &&NE16     - &&opz;     break;
  case VM_SGT16:     return &&SGT16    - &&opz;     break;
  case VM_SGE16:     return &&SGE16    - &&opz;     break;
  case VM_SLT16:     return &&SLT16    - &&opz;     break;
  case VM_SLE16:     return &&SLE16    - &&opz;     break;
  case VM_UGT16:     return &&UGT16    - &&opz;     break;
  case VM_UGE16:     return &&UGE16    - &&opz;     break;
  case VM_ULT16:     return &&ULT16    - &&opz;     break;
  case VM_ULE16:     return &&ULE16    - &&opz;     break;

  case VM_EQ16_C:      return &&EQ16_C     - &&opz;     break;
  case VM_NE16_C:      return &&NE16_C     - &&opz;     break;
  case VM_SGT16_C:     return &&SGT16_C    - &&opz;     break;
  case VM_SGE16_C:     return &&SGE16_C    - &&opz;     break;
  case VM_SLT16_C:     return &&SLT16_C    - &&opz;     break;
  case VM_SLE16_C:     return &&SLE16_C    - &&opz;     break;
  case VM_UGT16_C:     return &&UGT16_C    - &&opz;     break;
  case VM_UGE16_C:     return &&UGE16_C    - &&opz;     break;
  case VM_ULT16_C:     return &&ULT16_C    - &&opz;     break;
  case VM_ULE16_C:     return &&ULE16_C    - &&opz;     break;


  case VM_EQ32:      return &&EQ32     - &&opz;     break;
  case VM_NE32:      return &&NE32     - &&opz;     break;
  case VM_SGT32:     return &&SGT32    - &&opz;     break;
  case VM_SGE32:     return &&SGE32    - &&opz;     break;
  case VM_SLT32:     return &&SLT32    - &&opz;     break;
  case VM_SLE32:     return &&SLE32    - &&opz;     break;
  case VM_UGT32:     return &&UGT32    - &&opz;     break;
  case VM_UGE32:     return &&UGE32    - &&opz;     break;
  case VM_ULT32:     return &&ULT32    - &&opz;     break;
  case VM_ULE32:     return &&ULE32    - &&opz;     break;

  case VM_EQ32_C:      return &&EQ32_C     - &&opz;     break;
  case VM_NE32_C:      return &&NE32_C     - &&opz;     break;
  case VM_SGT32_C:     return &&SGT32_C    - &&opz;     break;
  case VM_SGE32_C:     return &&SGE32_C    - &&opz;     break;
  case VM_SLT32_C:     return &&SLT32_C    - &&opz;     break;
  case VM_SLE32_C:     return &&SLE32_C    - &&opz;     break;
  case VM_UGT32_C:     return &&UGT32_C    - &&opz;     break;
  case VM_UGE32_C:     return &&UGE32_C    - &&opz;     break;
  case VM_ULT32_C:     return &&ULT32_C    - &&opz;     break;
  case VM_ULE32_C:     return &&ULE32_C    - &&opz;     break;

  case VM_EQ64:      return &&EQ64     - &&opz;     break;
  case VM_NE64:      return &&NE64     - &&opz;     break;
  case VM_SGT64:     return &&SGT64    - &&opz;     break;
  case VM_SGE64:     return &&SGE64    - &&opz;     break;
  case VM_SLT64:     return &&SLT64    - &&opz;     break;
  case VM_SLE64:     return &&SLE64    - &&opz;     break;
  case VM_UGT64:     return &&UGT64    - &&opz;     break;
  case VM_UGE64:     return &&UGE64    - &&opz;     break;
  case VM_ULT64:     return &&ULT64    - &&opz;     break;
  case VM_ULE64:     return &&ULE64    - &&opz;     break;

  case VM_EQ64_C:      return &&EQ64_C     - &&opz;     break;
  case VM_NE64_C:      return &&NE64_C     - &&opz;     break;
  case VM_SGT64_C:     return &&SGT64_C    - &&opz;     break;
  case VM_SGE64_C:     return &&SGE64_C    - &&opz;     break;
  case VM_SLT64_C:     return &&SLT64_C    - &&opz;     break;
  case VM_SLE64_C:     return &&SLE64_C    - &&opz;     break;
  case VM_UGT64_C:     return &&UGT64_C    - &&opz;     break;
  case VM_UGE64_C:     return &&UGE64_C    - &&opz;     break;
  case VM_ULT64_C:     return &&ULT64_C    - &&opz;     break;
  case VM_ULE64_C:     return &&ULE64_C    - &&opz;     break;

  case VM_OEQ_DBL:   return &&OEQ_DBL - &&opz;   break;
  case VM_OGT_DBL:   return &&OGT_DBL - &&opz;   break;
  case VM_OGE_DBL:   return &&OGE_DBL - &&opz;   break;
  case VM_OLT_DBL:   return &&OLT_DBL - &&opz;   break;
  case VM_OLE_DBL:   return &&OLE_DBL - &&opz;   break;
  case VM_ONE_DBL:   return &&ONE_DBL - &&opz;   break;
  case VM_ORD_DBL:   return &&ORD_DBL - &&opz;   break;
  case VM_UNO_DBL:   return &&UNO_DBL - &&opz;   break;
  case VM_UEQ_DBL:   return &&UEQ_DBL - &&opz;   break;
  case VM_UGT_DBL:   return &&UGT_DBL - &&opz;   break;
  case VM_UGE_DBL:   return &&UGE_DBL - &&opz;   break;
  case VM_ULT_DBL:   return &&ULT_DBL - &&opz;   break;
  case VM_ULE_DBL:   return &&ULE_DBL - &&opz;   break;
  case VM_UNE_DBL:   return &&UNE_DBL - &&opz;   break;

  case VM_OEQ_DBL_C:   return &&OEQ_DBL_C - &&opz;   break;
  case VM_OGT_DBL_C:   return &&OGT_DBL_C - &&opz;   break;
  case VM_OGE_DBL_C:   return &&OGE_DBL_C - &&opz;   break;
  case VM_OLT_DBL_C:   return &&OLT_DBL_C - &&opz;   break;
  case VM_OLE_DBL_C:   return &&OLE_DBL_C - &&opz;   break;
  case VM_ONE_DBL_C:   return &&ONE_DBL_C - &&opz;   break;
  case VM_ORD_DBL_C:   return &&ORD_DBL_C - &&opz;   break;
  case VM_UNO_DBL_C:   return &&UNO_DBL_C - &&opz;   break;
  case VM_UEQ_DBL_C:   return &&UEQ_DBL_C - &&opz;   break;
  case VM_UGT_DBL_C:   return &&UGT_DBL_C - &&opz;   break;
  case VM_UGE_DBL_C:   return &&UGE_DBL_C - &&opz;   break;
  case VM_ULT_DBL_C:   return &&ULT_DBL_C - &&opz;   break;
  case VM_ULE_DBL_C:   return &&ULE_DBL_C - &&opz;   break;
  case VM_UNE_DBL_C:   return &&UNE_DBL_C - &&opz;   break;

  case VM_OEQ_FLT:   return &&OEQ_FLT - &&opz;   break;
  case VM_OGT_FLT:   return &&OGT_FLT - &&opz;   break;
  case VM_OGE_FLT:   return &&OGE_FLT - &&opz;   break;
  case VM_OLT_FLT:   return &&OLT_FLT - &&opz;   break;
  case VM_OLE_FLT:   return &&OLE_FLT - &&opz;   break;
  case VM_ONE_FLT:   return &&ONE_FLT - &&opz;   break;
  case VM_ORD_FLT:   return &&ORD_FLT - &&opz;   break;
  case VM_UNO_FLT:   return &&UNO_FLT - &&opz;   break;
  case VM_UEQ_FLT:   return &&UEQ_FLT - &&opz;   break;
  case VM_UGT_FLT:   return &&UGT_FLT - &&opz;   break;
  case VM_UGE_FLT:   return &&UGE_FLT - &&opz;   break;
  case VM_ULT_FLT:   return &&ULT_FLT - &&opz;   break;
  case VM_ULE_FLT:   return &&ULE_FLT - &&opz;   break;
  case VM_UNE_FLT:   return &&UNE_FLT - &&opz;   break;

  case VM_OEQ_FLT_C:   return &&OEQ_FLT_C - &&opz;   break;
  case VM_OGT_FLT_C:   return &&OGT_FLT_C - &&opz;   break;
  case VM_OGE_FLT_C:   return &&OGE_FLT_C - &&opz;   break;
  case VM_OLT_FLT_C:   return &&OLT_FLT_C - &&opz;   break;
  case VM_OLE_FLT_C:   return &&OLE_FLT_C - &&opz;   break;
  case VM_ONE_FLT_C:   return &&ONE_FLT_C - &&opz;   break;
  case VM_ORD_FLT_C:   return &&ORD_FLT_C - &&opz;   break;
  case VM_UNO_FLT_C:   return &&UNO_FLT_C - &&opz;   break;
  case VM_UEQ_FLT_C:   return &&UEQ_FLT_C - &&opz;   break;
  case VM_UGT_FLT_C:   return &&UGT_FLT_C - &&opz;   break;
  case VM_UGE_FLT_C:   return &&UGE_FLT_C - &&opz;   break;
  case VM_ULT_FLT_C:   return &&ULT_FLT_C - &&opz;   break;
  case VM_ULE_FLT_C:   return &&ULE_FLT_C - &&opz;   break;
  case VM_UNE_FLT_C:   return &&UNE_FLT_C - &&opz;   break;

  case VM_EQ8_BR:      return &&EQ8_BR     - &&opz;     break;
  case VM_NE8_BR:      return &&NE8_BR     - &&opz;     break;
  case VM_SGT8_BR:     return &&SGT8_BR    - &&opz;     break;
  case VM_SGE8_BR:     return &&SGE8_BR    - &&opz;     break;
  case VM_SLT8_BR:     return &&SLT8_BR    - &&opz;     break;
  case VM_SLE8_BR:     return &&SLE8_BR    - &&opz;     break;
  case VM_UGT8_BR:     return &&UGT8_BR    - &&opz;     break;
  case VM_UGE8_BR:     return &&UGE8_BR    - &&opz;     break;
  case VM_ULT8_BR:     return &&ULT8_BR    - &&opz;     break;
  case VM_ULE8_BR:     return &&ULE8_BR    - &&opz;     break;

  case VM_EQ8_C_BR:      return &&EQ8_C_BR     - &&opz;     break;
  case VM_NE8_C_BR:      return &&NE8_C_BR     - &&opz;     break;
  case VM_SGT8_C_BR:     return &&SGT8_C_BR    - &&opz;     break;
  case VM_SGE8_C_BR:     return &&SGE8_C_BR    - &&opz;     break;
  case VM_SLT8_C_BR:     return &&SLT8_C_BR    - &&opz;     break;
  case VM_SLE8_C_BR:     return &&SLE8_C_BR    - &&opz;     break;
  case VM_UGT8_C_BR:     return &&UGT8_C_BR    - &&opz;     break;
  case VM_UGE8_C_BR:     return &&UGE8_C_BR    - &&opz;     break;
  case VM_ULT8_C_BR:     return &&ULT8_C_BR    - &&opz;     break;
  case VM_ULE8_C_BR:     return &&ULE8_C_BR    - &&opz;     break;

  case VM_EQ32_BR:      return &&EQ32_BR     - &&opz;     break;
  case VM_NE32_BR:      return &&NE32_BR     - &&opz;     break;
  case VM_SGT32_BR:     return &&SGT32_BR    - &&opz;     break;
  case VM_SGE32_BR:     return &&SGE32_BR    - &&opz;     break;
  case VM_SLT32_BR:     return &&SLT32_BR    - &&opz;     break;
  case VM_SLE32_BR:     return &&SLE32_BR    - &&opz;     break;
  case VM_UGT32_BR:     return &&UGT32_BR    - &&opz;     break;
  case VM_UGE32_BR:     return &&UGE32_BR    - &&opz;     break;
  case VM_ULT32_BR:     return &&ULT32_BR    - &&opz;     break;
  case VM_ULE32_BR:     return &&ULE32_BR    - &&opz;     break;

  case VM_EQ32_C_BR:      return &&EQ32_C_BR     - &&opz;     break;
  case VM_NE32_C_BR:      return &&NE32_C_BR     - &&opz;     break;
  case VM_SGT32_C_BR:     return &&SGT32_C_BR    - &&opz;     break;
  case VM_SGE32_C_BR:     return &&SGE32_C_BR    - &&opz;     break;
  case VM_SLT32_C_BR:     return &&SLT32_C_BR    - &&opz;     break;
  case VM_SLE32_C_BR:     return &&SLE32_C_BR    - &&opz;     break;
  case VM_UGT32_C_BR:     return &&UGT32_C_BR    - &&opz;     break;
  case VM_UGE32_C_BR:     return &&UGE32_C_BR    - &&opz;     break;
  case VM_ULT32_C_BR:     return &&ULT32_C_BR    - &&opz;     break;
  case VM_ULE32_C_BR:     return &&ULE32_C_BR    - &&opz;     break;

  case VM_EQ32_SEL:          return &&EQ32_SEL - &&opz; break;
  case VM_NE32_SEL:          return &&NE32_SEL - &&opz; break;
  case VM_UGT32_SEL:          return &&UGT32_SEL - &&opz; break;
  case VM_UGE32_SEL:          return &&UGE32_SEL - &&opz; break;
  case VM_ULT32_SEL:          return &&ULT32_SEL - &&opz; break;
  case VM_ULE32_SEL:          return &&ULE32_SEL - &&opz; break;
  case VM_SGT32_SEL:          return &&SGT32_SEL - &&opz; break;
  case VM_SGE32_SEL:          return &&SGE32_SEL - &&opz; break;
  case VM_SLT32_SEL:          return &&SLT32_SEL - &&opz; break;
  case VM_SLE32_SEL:          return &&SLE32_SEL - &&opz; break;
  case VM_EQ32_C_SEL:          return &&EQ32_C_SEL - &&opz; break;
  case VM_NE32_C_SEL:          return &&NE32_C_SEL - &&opz; break;
  case VM_UGT32_C_SEL:          return &&UGT32_C_SEL - &&opz; break;
  case VM_UGE32_C_SEL:          return &&UGE32_C_SEL - &&opz; break;
  case VM_ULT32_C_SEL:          return &&ULT32_C_SEL - &&opz; break;
  case VM_ULE32_C_SEL:          return &&ULE32_C_SEL - &&opz; break;
  case VM_SGT32_C_SEL:          return &&SGT32_C_SEL - &&opz; break;
  case VM_SGE32_C_SEL:          return &&SGE32_C_SEL - &&opz; break;
  case VM_SLT32_C_SEL:          return &&SLT32_C_SEL - &&opz; break;
  case VM_SLE32_C_SEL:          return &&SLE32_C_SEL - &&opz; break;


  case VM_SELECT32RR: return &&SELECT32RR - &&opz;     break;
  case VM_SELECT32RC: return &&SELECT32RC - &&opz;     break;
  case VM_SELECT32CR: return &&SELECT32CR - &&opz;     break;
  case VM_SELECT32CC: return &&SELECT32CC - &&opz;     break;

  case VM_SELECT64RR: return &&SELECT64RR - &&opz;     break;
  case VM_SELECT64RC: return &&SELECT64RC - &&opz;     break;
  case VM_SELECT64CR: return &&SELECT64CR - &&opz;     break;
  case VM_SELECT64CC: return &&SELECT64CC - &&opz;     break;

  case VM_B:         return &&B        - &&opz;     break;
  case VM_BCOND:     return &&BCOND    - &&opz;     break;
  case VM_JSR:       return &&JSR      - &&opz;     break;
  case VM_JSR_VM:    return &&JSR_VM   - &&opz;     break;
  case VM_JSR_EXT:   return &&JSR_EXT  - &&opz;     break;
  case VM_JSR_R:     return &&JSR_R    - &&opz;     break;

  case VM_INVOKE:    return &&INVOKE   - &&opz;    break;
  case VM_INVOKE_VM: return &&INVOKE_VM - &&opz;    break;
  case VM_INVOKE_EXT: return &&INVOKE_EXT - &&opz;    break;
  case VM_INVOKE_R:  return &&INVOKE_R  - &&opz;    break;

  case VM_LANDINGPAD:return &&LANDINGPAD - &&opz;        break;
  case VM_RESUME:    return &&RESUME - &&opz;       break;

  case VM_MOV32:     return &&MOV32    - &&opz;     break;
  case VM_MOV64:     return &&MOV64    - &&opz;     break;
  case VM_MOV8_C:    return &&MOV8_C   - &&opz;     break;
  case VM_MOV16_C:   return &&MOV16_C  - &&opz;     break;
  case VM_MOV32_C:   return &&MOV32_C  - &&opz;     break;
  case VM_MOV64_C:   return &&MOV64_C  - &&opz;     break;

  case VM_LEA_R32_SHL:     return &&LEA_R32_SHL - &&opz;break;
  case VM_LEA_R32_SHL2:    return &&LEA_R32_SHL2 - &&opz;break;
  case VM_LEA_R32_SHL_OFF: return &&LEA_R32_SHL_OFF - &&opz;break;
  case VM_LEA_R32_MUL_OFF: return &&LEA_R32_MUL_OFF - &&opz;break;

  case VM_CAST_1_TRUNC_8:  return &&CAST_1_TRUNC_8 - &&opz;  break;
  case VM_CAST_1_TRUNC_16: return &&CAST_1_TRUNC_16 - &&opz;  break;

  case VM_CAST_8_ZEXT_1:   return &&CAST_8_ZEXT_1 - &&opz; break;
  case VM_CAST_8_SEXT_1:   return &&CAST_8_SEXT_1 - &&opz; break;
  case VM_CAST_8_TRUNC_16: return &&CAST_8_TRUNC_16 - &&opz;  break;
  case VM_CAST_8_TRUNC_32: return &&CAST_8_TRUNC_32 - &&opz;  break;
  case VM_CAST_8_TRUNC_64: return &&CAST_8_TRUNC_64 - &&opz;  break;

  case VM_CAST_16_ZEXT_1:   return &&CAST_16_ZEXT_1 - &&opz; break;
  case VM_CAST_16_ZEXT_8:   return &&CAST_16_ZEXT_8 - &&opz; break;
  case VM_CAST_16_SEXT_8:   return &&CAST_16_SEXT_8 - &&opz; break;
  case VM_CAST_16_FPTOSI_FLT: return &&CAST_16_FPTOSI_FLT - &&opz; break;
  case VM_CAST_16_FPTOUI_FLT: return &&CAST_16_FPTOUI_FLT - &&opz; break;
  case VM_CAST_16_FPTOSI_DBL: return &&CAST_16_FPTOSI_DBL - &&opz; break;
  case VM_CAST_16_FPTOUI_DBL: return &&CAST_16_FPTOUI_DBL - &&opz; break;
  case VM_CAST_16_TRUNC_32: return &&CAST_16_TRUNC_32 - &&opz; break;
  case VM_CAST_16_TRUNC_64: return &&CAST_16_TRUNC_64 - &&opz; break;

  case VM_CAST_32_SEXT_1: return &&CAST_32_SEXT_1 - &&opz;  break;
  case VM_CAST_32_ZEXT_8: return &&CAST_32_ZEXT_8 - &&opz;  break;
  case VM_CAST_32_SEXT_8: return &&CAST_32_SEXT_8 - &&opz;  break;
  case VM_CAST_32_ZEXT_16: return &&CAST_32_ZEXT_16 - &&opz;  break;
  case VM_CAST_32_SEXT_16: return &&CAST_32_SEXT_16 - &&opz;  break;
  case VM_CAST_32_TRUNC_64: return &&CAST_32_TRUNC_64 - &&opz;  break;
  case VM_CAST_32_FPTOSI_FLT: return &&CAST_32_FPTOSI_FLT - &&opz; break;
  case VM_CAST_32_FPTOUI_FLT: return &&CAST_32_FPTOUI_FLT - &&opz; break;
  case VM_CAST_32_FPTOSI_DBL: return &&CAST_32_FPTOSI_DBL - &&opz; break;
  case VM_CAST_32_FPTOUI_DBL: return &&CAST_32_FPTOUI_DBL - &&opz; break;

  case VM_CAST_64_ZEXT_1: return &&CAST_64_ZEXT_1 - &&opz;  break;
  case VM_CAST_64_SEXT_1: return &&CAST_64_SEXT_1 - &&opz;  break;
  case VM_CAST_64_ZEXT_8: return &&CAST_64_ZEXT_8 - &&opz;  break;
  case VM_CAST_64_SEXT_8: return &&CAST_64_SEXT_8 - &&opz;  break;
  case VM_CAST_64_ZEXT_16: return &&CAST_64_ZEXT_16 - &&opz;  break;
  case VM_CAST_64_SEXT_16: return &&CAST_64_SEXT_16 - &&opz;  break;
  case VM_CAST_64_ZEXT_32: return &&CAST_64_ZEXT_32 - &&opz;  break;
  case VM_CAST_64_SEXT_32: return &&CAST_64_SEXT_32 - &&opz;  break;
  case VM_CAST_64_FPTOSI_FLT: return &&CAST_64_FPTOSI_FLT - &&opz; break;
  case VM_CAST_64_FPTOUI_FLT: return &&CAST_64_FPTOUI_FLT - &&opz; break;
  case VM_CAST_64_FPTOSI_DBL: return &&CAST_64_FPTOSI_DBL - &&opz; break;
  case VM_CAST_64_FPTOUI_DBL: return &&CAST_64_FPTOUI_DBL - &&opz; break;


  case VM_CAST_FLT_FPTRUNC_DBL: return &&CAST_FLT_FPTRUNC_DBL - &&opz; break;
  case VM_CAST_FLT_SITOFP_8:    return &&CAST_FLT_SITOFP_8  - &&opz; break;
  case VM_CAST_FLT_UITOFP_8:    return &&CAST_FLT_UITOFP_8  - &&opz; break;
  case VM_CAST_FLT_SITOFP_16:   return &&CAST_FLT_SITOFP_16 - &&opz; break;
  case VM_CAST_FLT_UITOFP_16:   return &&CAST_FLT_UITOFP_16 - &&opz; break;
  case VM_CAST_FLT_SITOFP_32:   return &&CAST_FLT_SITOFP_32 - &&opz; break;
  case VM_CAST_FLT_UITOFP_32:   return &&CAST_FLT_UITOFP_32 - &&opz; break;
  case VM_CAST_FLT_SITOFP_64:   return &&CAST_FLT_SITOFP_64 - &&opz; break;
  case VM_CAST_FLT_UITOFP_64:   return &&CAST_FLT_UITOFP_64 - &&opz; break;

  case VM_CAST_DBL_SITOFP_8:    return &&CAST_DBL_SITOFP_8  - &&opz; break;
  case VM_CAST_DBL_UITOFP_8:    return &&CAST_DBL_UITOFP_8  - &&opz; break;
  case VM_CAST_DBL_SITOFP_16:   return &&CAST_DBL_SITOFP_16 - &&opz; break;
  case VM_CAST_DBL_UITOFP_16:   return &&CAST_DBL_UITOFP_16 - &&opz; break;
  case VM_CAST_DBL_SITOFP_32:   return &&CAST_DBL_SITOFP_32 - &&opz; break;
  case VM_CAST_DBL_UITOFP_32:   return &&CAST_DBL_UITOFP_32 - &&opz; break;
  case VM_CAST_DBL_SITOFP_64:   return &&CAST_DBL_SITOFP_64 - &&opz; break;
  case VM_CAST_DBL_UITOFP_64:   return &&CAST_DBL_UITOFP_64 - &&opz; break;

  case VM_CAST_DBL_FPEXT_FLT:   return &&CAST_DBL_FPEXT_FLT   - &&opz; break;


  case VM_JUMPTABLE:   return &&JUMPTABLE   - &&opz; break;
  case VM_SWITCH8_BS:  return &&SWITCH8_BS  - &&opz; break;
  case VM_SWITCH32_BS: return &&SWITCH32_BS - &&opz; break;
  case VM_SWITCH64_BS: return &&SWITCH64_BS - &&opz; break;
  case VM_ALLOCA:   return &&ALLOCA - &&opz; break;
  case VM_ALLOCAD:  return &&ALLOCAD - &&opz; break;
  case VM_VASTART:  return &&VASTART - &&opz; break;
  case VM_VAARG32:  return &&VAARG32 - &&opz; break;
  case VM_VAARG64:  return &&VAARG64 - &&opz; break;
  case VM_VACOPY:   return &&VACOPY  - &&opz; break;

  case VM_STACKSHRINK: return &&STACKSHRINK - &&opz; break;
  case VM_STACKSAVE:  return &&STACKSAVE - &&opz; break;
  case VM_STACKRESTORE:  return &&STACKRESTORE - &&opz; break;
  case VM_STACKCOPYR: return &&STACKCOPYR - &&opz; break;
  case VM_STACKCOPYC: return &&STACKCOPYC - &&opz; break;

  case VM_MEMCPY:   return &&MEMCPY  - &&opz; break;
  case VM_MEMSET:   return &&MEMSET  - &&opz; break;

  case VM_LLVM_MEMCPY:   return &&LLVM_MEMCPY  - &&opz; break;
  case VM_LLVM_MEMSET:   return &&LLVM_MEMSET  - &&opz; break;
  case VM_LLVM_MEMSET64: return &&LLVM_MEMSET64 - &&opz; break;

  case VM_CTZ32: return &&CTZ32 - &&opz; break;
  case VM_CLZ32: return &&CLZ32 - &&opz; break;
  case VM_POP32: return &&POP32 - &&opz; break;

  case VM_CTZ64: return &&CTZ64 - &&opz; break;
  case VM_CLZ64: return &&CLZ64 - &&opz; break;
  case VM_POP64: return &&POP64 - &&opz; break;

  case VM_UADDO32: return &&UADDO32 - &&opz; break;
  case VM_UMULO32: return &&UMULO32 - &&opz; break;

  case VM_MEMMOVE:  return &&MEMMOVE - &&opz; break;
  case VM_MEMCMP:   return &&MEMCMP  - &&opz; break;

  case VM_STRCMP:   return &&STRCMP  - &&opz; break;
  case VM_STRCASECMP:   return &&STRCASECMP  - &&opz; break;
  case VM_STRNCMP:  return &&STRNCMP - &&opz; break;
  case VM_STRCPY:   return &&STRCPY  - &&opz; break;
  case VM_STRNCPY:  return &&STRNCPY - &&opz; break;
  case VM_STRCAT:   return &&STRCAT  - &&opz; break;
  case VM_STRNCAT:  return &&STRNCAT - &&opz; break;
  case VM_STRCHR:   return &&STRCHR  - &&opz; break;
  case VM_STRRCHR:  return &&STRRCHR - &&opz; break;
  case VM_STRLEN:   return &&STRLEN  - &&opz; break;
  case VM_STRDUP:   return &&STRDUP  - &&opz; break;

  case VM_UNREACHABLE: return &&UNREACHABLE - &&opz; break;

  case VM_INSTRUMENT_COUNT: return &&INSTRUMENT_COUNT - &&opz; break;

  default:
    printf("Can't emit op %d\n", I[0]);
    abort();
  }
#endif
}


static int16_t
vm_resolve(uint16_t opcode)
{
#ifdef VM_DONT_USE_COMPUTED_GOTO
  return opcode;
#else
  int o = vm_exec(&opcode, NULL, NULL, NULL);
  assert(o <= INT16_MAX);
  assert(o >= INT16_MIN);
  return o;
#endif
}

/**
 *
 */
static void
emit_i16(ir_unit_t *iu, uint16_t i16)
{
  if(iu->iu_text_ptr + 2 >= iu->iu_text_alloc + iu->iu_text_alloc_memsize)
    parser_error(iu, "Function too big");
  *(uint16_t *)iu->iu_text_ptr = i16;
  iu->iu_text_ptr += 2;
}


/**
 *
 */
static void
emit_imm16(ir_unit_t *iu, int immediate)
{
  if(immediate < INT16_MIN || immediate > INT16_MAX)
    parser_error(iu, "Immediate offset too big");
  emit_i16(iu, immediate);
}


/**
 *
 */
static void
emit_i8(ir_unit_t *iu, uint8_t i8)
{
  if(iu->iu_text_ptr + 2 >= iu->iu_text_alloc + iu->iu_text_alloc_memsize)
    parser_error(iu, "Function too big");
  *(uint8_t *)iu->iu_text_ptr = i8;
  iu->iu_text_ptr += 2; // We always align to 16 bits
}

/**
 *
 */
static void
emit_i32(ir_unit_t *iu, uint32_t i32)
{
  if(iu->iu_text_ptr + 4 >= iu->iu_text_alloc + iu->iu_text_alloc_memsize)
    parser_error(iu, "Function too big");
  *(uint32_t *)iu->iu_text_ptr = i32;
  iu->iu_text_ptr += 4;
}

/**
 *
 */
static void
emit_i64(ir_unit_t *iu, uint64_t i64)
{
  if(iu->iu_text_ptr + 8 >= iu->iu_text_alloc + iu->iu_text_alloc_memsize)
    parser_error(iu, "Function too big");
  *(uint64_t *)iu->iu_text_ptr = i64;
  iu->iu_text_ptr += 8;
}

/**
 *
 */
static void *
emit_data(ir_unit_t *iu, int size)
{
  if(iu->iu_text_ptr + size >= iu->iu_text_alloc + iu->iu_text_alloc_memsize)
    parser_error(iu, "Function too big");
  void *r = iu->iu_text_ptr;
  iu->iu_text_ptr += size;
  return r;
}


/**
 *
 */
static void
emit_op(ir_unit_t *iu, vm_op_t op)
{
  emit_i16(iu, vm_resolve(op));
}


/**
 *
 */
static void
emit_op1(ir_unit_t *iu, vm_op_t op, uint16_t arg)
{
  emit_i16(iu, vm_resolve(op));
  emit_i16(iu, arg);
}


/**
 *
 */
static void __attribute__((unused))
emit_op2(ir_unit_t *iu, vm_op_t op,
         uint16_t a1, uint16_t a2)
{
  emit_i16(iu, vm_resolve(op));
  emit_i16(iu, a1);
  emit_i16(iu, a2);
}

/**
 *
 */
static void
emit_op3(ir_unit_t *iu, vm_op_t op,
         uint16_t a1, uint16_t a2, uint16_t a3)
{
  emit_i16(iu, vm_resolve(op));
  emit_i16(iu, a1);
  emit_i16(iu, a2);
  emit_i16(iu, a3);
}

/**
 *
 */
static void
emit_op4(ir_unit_t *iu, vm_op_t op,
         uint16_t a1, uint16_t a2, uint16_t a3, uint16_t a4)
{
  emit_i16(iu, vm_resolve(op));
  emit_i16(iu, a1);
  emit_i16(iu, a2);
  emit_i16(iu, a3);
  emit_i16(iu, a4);
}


/**
 *
 */
static void
vm_align32(ir_unit_t *iu, int imm_at_odd)
{
  int text_is_odd = !!((intptr_t)iu->iu_text_ptr & 2);
  if(imm_at_odd != text_is_odd)
    emit_op(iu, VM_NOP);
}


/**
 *
 */
static void
emit_ret(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  if(ii->value.value == -1) {
    emit_op(iu, VM_RET_VOID);
    return;
  }
  ir_value_t *iv = value_get(iu, ii->value.value);
  ir_type_t *it = type_get(iu, ii->value.type);
  int code = legalize_type(it);

  switch(iv->iv_class) {
  case IR_VC_REGFRAME:

    switch(code) {
    case IR_TYPE_INT1:
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_FLOAT:
      emit_op1(iu, VM_RET_R32, value_reg(iv));
      return;

    case IR_TYPE_INT64:
    case IR_TYPE_DOUBLE:
      emit_op1(iu, VM_RET_R64, value_reg(iv));
      return;

    default:
      parser_error(iu, "Can't return type %s", type_str(iu, it));
    }

  case IR_VC_GLOBALVAR:
    switch(code) {
    case IR_TYPE_POINTER:
      emit_op(iu, VM_RET_R32C);
      emit_i32(iu, value_get_const32(iu, iv));
      return;

    default:
      parser_error(iu, "Can't return global type %s", type_str(iu, it));
    }

  case IR_VC_CONSTANT:
    switch(code) {
    case IR_TYPE_INT1:
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_FLOAT:
      emit_op(iu, VM_RET_R32C);
      emit_i32(iu, value_get_const32(iu, iv));
      return;
    case IR_TYPE_INT64:
    case IR_TYPE_DOUBLE:
      vm_align32(iu, 1);
      emit_op(iu, VM_RET_R64C);
      emit_i64(iu, value_get_const64(iu, iv));
      return;

    default:
      parser_error(iu, "Can't return const type %s", type_str(iu, it));
    }

  case IR_VC_FUNCTION:
    emit_op(iu, VM_RET_R32C);
    emit_i32(iu, value_function_addr(iv));
    return;

  default:
    parser_error(iu, "Can't return value class %d", iv->iv_class);
  }
}



/**
 *
 */
static void
emit_binop(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  const int binop = ii->op;
  const ir_value_t *lhs = value_get(iu, ii->lhs_value.value);
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  vm_op_t op;
  const ir_type_t *it = type_get(iu, ii->lhs_value.type);

  if(lhs->iv_class == IR_VC_REGFRAME &&
     rhs->iv_class == IR_VC_REGFRAME) {

    int lhsreg = value_reg(lhs);

    switch(legalize_type(it)) {

    case IR_TYPE_INT1:
    case IR_TYPE_INT32:
      op = VM_ADD_R32 + binop;
      emit_op3(iu, op, value_reg(ret), lhsreg, value_reg(rhs));
      return;

    case IR_TYPE_INT8:
      switch(binop) {
      case BINOP_SDIV: op = VM_SDIV_R8;         break;
      case BINOP_SREM: op = VM_SREM_R8;         break;
      case BINOP_ASHR: op = VM_ASHR_R8;         break;
      case BINOP_ROL:  op = VM_ROL_R8;          break;
      case BINOP_ROR:  op = VM_ROR_R8;          break;
      default:         op = VM_ADD_R32 + binop; break;
        break;
      }
      emit_op3(iu, op, value_reg(ret), value_reg(lhs), value_reg(rhs));
      return;

    case IR_TYPE_INT16:
      switch(binop) {
      case BINOP_SDIV: op = VM_SDIV_R16;        break;
      case BINOP_SREM: op = VM_SREM_R16;        break;
      case BINOP_ASHR: op = VM_ASHR_R16;        break;
      case BINOP_ROL:  op = VM_ROL_R16;         break;
      case BINOP_ROR:  op = VM_ROR_R16;         break;
      default:         op = VM_ADD_R32 + binop; break;
        break;
      }
      emit_op3(iu, op, value_reg(ret), value_reg(lhs), value_reg(rhs));
      return;

    case IR_TYPE_INT64:
      op = VM_ADD_R64 + binop;
      emit_op3(iu, op, value_reg(ret), value_reg(lhs), value_reg(rhs));
      return;

    case IR_TYPE_DOUBLE:

      switch(binop) {
      case BINOP_ADD:  op = VM_ADD_DBL; break;
      case BINOP_SUB:  op = VM_SUB_DBL; break;
      case BINOP_MUL:  op = VM_MUL_DBL; break;
      case BINOP_SDIV:
      case BINOP_UDIV: op = VM_DIV_DBL; break;
      default:
        parser_error(iu, "Can't binop %d for double", binop);
      }
      emit_op3(iu, op, value_reg(ret), value_reg(lhs), value_reg(rhs));
      break;

    case IR_TYPE_FLOAT:

      switch(binop) {
      case BINOP_ADD:  op = VM_ADD_FLT; break;
      case BINOP_SUB:  op = VM_SUB_FLT; break;
      case BINOP_MUL:  op = VM_MUL_FLT; break;
      case BINOP_SDIV:
      case BINOP_UDIV: op = VM_DIV_FLT; break;
      default:
        parser_error(iu, "Can't binop %d for float", binop);
      }
      emit_op3(iu, op, value_reg(ret), value_reg(lhs), value_reg(rhs));
      break;


    default:
      parser_error(iu, "Can't binop types %s", type_str(iu, it));
    }

  } else if(lhs->iv_class == IR_VC_REGFRAME &&
            rhs->iv_class == IR_VC_CONSTANT) {

    int lhsreg = value_reg(lhs);

    switch(legalize_type(it)) {
    case IR_TYPE_INT8:

      switch(binop) {
      case BINOP_SDIV:
        emit_op2(iu, VM_SDIV_R8C, value_reg(ret), value_reg(lhs));
        emit_i8(iu, value_get_const32(iu, rhs));
        return;
      case BINOP_SREM:
        emit_op2(iu, VM_SREM_R8C, value_reg(ret), value_reg(lhs));
        emit_i8(iu, value_get_const32(iu, rhs));
        return;
      case BINOP_ASHR:
        emit_op2(iu, VM_ASHR_R8C, value_reg(ret), value_reg(lhs));
        emit_i8(iu, value_get_const32(iu, rhs));
        return;
      default:
        op = VM_ADD_R16C + binop;
        emit_op2(iu, op, value_reg(ret), value_reg(lhs));
        emit_i16(iu, value_get_const32(iu, rhs) & 0xff);
        return;
      }

    case IR_TYPE_INT16:
      op = VM_ADD_R16C + binop;
      emit_op2(iu, op, value_reg(ret), value_reg(lhs));
      emit_i16(iu, value_get_const32(iu, rhs));
      return;

    case IR_TYPE_INT1:
    case IR_TYPE_INT32:
      {
        const uint32_t u32 = value_get_const32(iu, rhs);
        if((binop == BINOP_ADD && u32 == 1) ||
           (binop == BINOP_SUB && u32 == -1)) {
          emit_op2(iu, VM_INC_R32, value_reg(ret), value_reg(lhs));
          return;
        }
        if((binop == BINOP_ADD && u32 == -1) ||
           (binop == BINOP_SUB && u32 == 1)) {
          emit_op2(iu, VM_DEC_R32, value_reg(ret), value_reg(lhs));
          return;
        }

        op = VM_ADD_R32C + binop;
        emit_op2(iu, op, value_reg(ret), lhsreg);
        emit_i32(iu, value_get_const32(iu, rhs));
      }
      return;

    case IR_TYPE_INT64:
      vm_align32(iu, 1);
      op = VM_ADD_R64C + binop;
      emit_op2(iu, op, value_reg(ret), value_reg(lhs));
      emit_i64(iu, value_get_const64(iu, rhs));
      return;

    case IR_TYPE_DOUBLE:

      switch(binop) {
      case BINOP_ADD:  op = VM_ADD_DBLC; break;
      case BINOP_SUB:  op = VM_SUB_DBLC; break;
      case BINOP_MUL:  op = VM_MUL_DBLC; break;
      case BINOP_SDIV:
      case BINOP_UDIV: op = VM_DIV_DBLC; break;
      default:
        parser_error(iu, "Can't binop %d for double", binop);
      }
      vm_align32(iu, 1);
      emit_op2(iu, op, value_reg(ret), value_reg(lhs));
      emit_i64(iu, value_get_const64(iu, rhs));
      break;

    case IR_TYPE_FLOAT:

      switch(binop) {
      case BINOP_ADD:  op = VM_ADD_FLTC; break;
      case BINOP_SUB:  op = VM_SUB_FLTC; break;
      case BINOP_MUL:  op = VM_MUL_FLTC; break;
      case BINOP_SDIV:
      case BINOP_UDIV: op = VM_DIV_FLTC; break;
      default:
        parser_error(iu, "Can't binop %d for float", binop);
      }
      vm_align32(iu, 1);
      emit_op2(iu, op, value_reg(ret), value_reg(lhs));
      emit_i32(iu, value_get_const32(iu, rhs));
      break;

    default:
      parser_error(iu, "Can't binop types %s", type_str(iu, it));
    }

  } else {
    parser_error(iu, "Can't binop value class %d and %d",
                 lhs->iv_class, rhs->iv_class);
  }
}

/**
 *
 */
static void
emit_load1(ir_unit_t *iu, const ir_value_t *src,
           const ir_value_t *ret, const ir_type_t *retty,
           const ir_value_t *roff,
           int immediate_offset, int value_offset_multiply,
           const ir_instr_load_t *ii)
{
  const int has_offset = immediate_offset != 0 || roff != NULL;

  switch(COMBINE3(src->iv_class, legalize_type(retty), has_offset)) {

  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT1, 0):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT8, 0):
    emit_op2(iu, VM_LOAD8, value_reg(ret), value_reg(src));
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT8, 1):
    emit_op2(iu, roff ? VM_LOAD8_ROFF : VM_LOAD8_OFF,
             value_reg(ret), value_reg(src));
    emit_imm16(iu, immediate_offset);
    break;
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT8, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT8, 0):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT8, 1):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT8, 1):
    emit_op1(iu, VM_LOAD8_G, value_reg(ret));
    emit_i32(iu, value_get_const32(iu, src) + immediate_offset);
    return;

  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_INT1, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT1, 0):
    emit_op1(iu, VM_LOAD8_G, 0);
    emit_i32(iu, value_get_const32(iu, src));
    emit_op2(iu, VM_CAST_1_TRUNC_8, value_reg(ret), 0);
    return;

  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT16, 0):
    emit_op2(iu, VM_LOAD16, value_reg(ret), value_reg(src));
    return;
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT16, 0):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT16, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT16, 1):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT16, 1):
    emit_op1(iu, VM_LOAD16_G, value_reg(ret));
    emit_i32(iu, value_get_const32(iu, src) + immediate_offset);
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT16, 1):
    emit_op2(iu, roff ? VM_LOAD16_ROFF : VM_LOAD16_OFF,
             value_reg(ret), value_reg(src));
    emit_imm16(iu, immediate_offset);
    break;

  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT32, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_POINTER, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_FLOAT, 0):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_INT32, 0):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_POINTER, 0):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_FLOAT, 0):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_INT32, 1):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_POINTER, 1):
  case COMBINE3(IR_VC_CONSTANT, IR_TYPE_FLOAT, 1):
    emit_op1(iu, VM_LOAD32_G, value_reg(ret));
    emit_i32(iu, value_get_const32(iu, src) + immediate_offset);
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT32, 0):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_POINTER, 0):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_FLOAT, 0):
    emit_op2(iu, VM_LOAD32, value_reg(ret), value_reg(src));
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT32, 1):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_POINTER, 1):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_FLOAT, 1):
    emit_op2(iu, roff ? VM_LOAD32_ROFF : VM_LOAD32_OFF,
             value_reg(ret), value_reg(src));
    emit_imm16(iu, immediate_offset);
    break;


  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT64,  0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_DOUBLE, 0):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT64,  0):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_DOUBLE, 0):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_INT64,  1):
  case COMBINE3(IR_VC_GLOBALVAR, IR_TYPE_DOUBLE, 1):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_INT64,  1):
  case COMBINE3(IR_VC_CONSTANT,  IR_TYPE_DOUBLE, 1):
    emit_op1(iu, VM_LOAD64_G, value_reg(ret));
    emit_i32(iu, value_get_const32(iu, src) + immediate_offset);
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT64, 0):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_DOUBLE, 0):
    emit_op2(iu, VM_LOAD64, value_reg(ret), value_reg(src));
    return;
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_INT64, 1):
  case COMBINE3(IR_VC_REGFRAME, IR_TYPE_DOUBLE, 1):
    emit_op2(iu, roff ? VM_LOAD64_ROFF : VM_LOAD64_OFF,
             value_reg(ret), value_reg(src));
    emit_imm16(iu, immediate_offset);
    break;

  default:
    parser_error(iu, "Can't load from class %d %s immediate-offset:%d (%s)",
                 src->iv_class, type_str(iu, retty),
                 has_offset,
                 instr_str(iu, &ii->super, 0));
  }
  if(roff != NULL) {
    emit_i16(iu, value_reg(roff));
    emit_i16(iu, value_offset_multiply);
  }
}


/**
 *
 */
static void
emit_load(ir_unit_t *iu, ir_instr_load_t *ii)
{
  const ir_value_t *src = value_get(iu, ii->ptr.value);
  const ir_value_t *roff =
    ii->value_offset.value >= 0 ? value_get(iu, ii->value_offset.value) : NULL;
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_type_t *retty = type_get(iu, ii->super.ii_ret.type);

  if(ii->cast != -1) {
    // Load + Cast
    ir_type_t *pointee = type_get(iu, ii->load_type);

    switch(COMBINE4(src->iv_class, legalize_type(retty),
                    legalize_type(pointee), ii->cast)) {
    case COMBINE4(IR_VC_REGFRAME, IR_TYPE_INT32, IR_TYPE_INT8, CAST_ZEXT):
      emit_op2(iu, roff ? VM_LOAD8_ZEXT_32_ROFF :
               VM_LOAD8_ZEXT_32_OFF, value_reg(ret), value_reg(src));
      emit_imm16(iu, ii->immediate_offset);
      break;
    case COMBINE4(IR_VC_REGFRAME, IR_TYPE_INT32, IR_TYPE_INT8, CAST_SEXT):
      emit_op2(iu, roff ? VM_LOAD8_SEXT_32_ROFF : VM_LOAD8_SEXT_32_OFF,
               value_reg(ret), value_reg(src));
      emit_imm16(iu, ii->immediate_offset);
      break;
    case COMBINE4(IR_VC_REGFRAME, IR_TYPE_INT32, IR_TYPE_INT16, CAST_ZEXT):
      emit_op2(iu, roff ? VM_LOAD16_ZEXT_32_ROFF: VM_LOAD16_ZEXT_32_OFF,
               value_reg(ret), value_reg(src));
      emit_imm16(iu, ii->immediate_offset);
      break;
    case COMBINE4(IR_VC_REGFRAME, IR_TYPE_INT32, IR_TYPE_INT16, CAST_SEXT):
      emit_op2(iu, roff ? VM_LOAD16_SEXT_32_ROFF : VM_LOAD16_SEXT_32_OFF,
               value_reg(ret), value_reg(src));
      emit_imm16(iu, ii->immediate_offset);
      break;

    case COMBINE4(IR_VC_CONSTANT, IR_TYPE_INT32, IR_TYPE_INT8, CAST_ZEXT):
      emit_op1(iu, VM_LOAD8_G_ZEXT_32, value_reg(ret));
      emit_i32(iu, value_get_const32(iu, src) + ii->immediate_offset);
      break;

    case COMBINE4(IR_VC_CONSTANT, IR_TYPE_INT32, IR_TYPE_INT8, CAST_SEXT):
      emit_op1(iu, VM_LOAD8_G_SEXT_32, value_reg(ret));
      emit_i32(iu, value_get_const32(iu, src) + ii->immediate_offset);
      break;

    case COMBINE4(IR_VC_CONSTANT, IR_TYPE_INT32, IR_TYPE_INT16, CAST_ZEXT):
      emit_op1(iu, VM_LOAD16_G_ZEXT_32, value_reg(ret));
      emit_i32(iu, value_get_const32(iu, src) + ii->immediate_offset);
      break;

    case COMBINE4(IR_VC_CONSTANT, IR_TYPE_INT32, IR_TYPE_INT16, CAST_SEXT):
      emit_op1(iu, VM_LOAD16_G_SEXT_32, value_reg(ret));
      emit_i32(iu, value_get_const32(iu, src) + ii->immediate_offset);
      break;


    default:
      parser_error(iu, "Can't load+cast to %s from %s cast:%d (%s)",
                   type_str(iu, retty),
                   type_str(iu, pointee),
                   ii->cast, instr_str(iu, &ii->super, 0));
    }
    if(roff != NULL) {
      emit_i16(iu, value_reg(roff));
      emit_i16(iu, ii->value_offset_multiply);
    }
    return;
  }

  emit_load1(iu, src, ret, retty, roff, ii->immediate_offset,
             ii->value_offset_multiply, ii);
}


/**
 *
 */
static void
emit_store(ir_unit_t *iu, ir_instr_store_t *ii)
{
  const ir_value_t *ptr = value_get(iu, ii->ptr.value);
  const ir_value_t *val = value_get(iu, ii->value.value);
  const int has_offset = ii->immediate_offset != 0;

  switch(COMBINE4(legalize_type(type_get(iu, ii->value.type)),
                  val->iv_class,
                  ptr->iv_class,
                  has_offset)) {

    // ---

  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
    emit_op2(iu, VM_STORE8, value_reg(ptr), value_reg(val));
    return;

  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
    emit_op2(iu, VM_STORE8_OFF, value_reg(ptr), value_reg(val));
    emit_imm16(iu, ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT1, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT1, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_INT8, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
    emit_op1(iu, VM_STORE8_G, value_reg(val));
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT1, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT1, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 1):
    emit_op1(iu, VM_MOV8_C, 0);
    emit_i8(iu, value_get_const32(iu, val));
    emit_op1(iu, VM_STORE8_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT1, IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT1, IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT8, IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
    emit_op1(iu, VM_STORE8C_OFF, value_reg(ptr));
    emit_imm16(iu, ii->immediate_offset);
    emit_i8(iu, value_get_const32(iu, val));
    return;


    // ---

  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
    emit_op2(iu, VM_STORE16, value_reg(ptr), value_reg(val));
    return;

  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
    emit_op1(iu, VM_STORE16_G, value_reg(val));
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT16, IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
    emit_op2(iu, VM_STORE16_OFF, value_reg(ptr), value_reg(val));
    emit_imm16(iu, ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
    emit_op1(iu, VM_STORE16C_OFF, value_reg(ptr));
    emit_imm16(iu, ii->immediate_offset);
    emit_i16(iu, value_get_const32(iu, val));
    return;

  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_INT16, IR_VC_CONSTANT, IR_VC_CONSTANT,  1):
    emit_op1(iu, VM_MOV16_C, 0);
    emit_i16(iu, value_get_const32(iu, val));
    emit_op1(iu, VM_STORE16_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

    // ---

  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
    emit_op1(iu, VM_STORE32_G, value_reg(val));
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_GLOBALVAR,  0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_GLOBALVAR,  0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_GLOBALVAR,  0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_GLOBALVAR,  1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_GLOBALVAR,  1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_GLOBALVAR,  1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_GLOBALVAR, 1):
    emit_op1(iu, VM_MOV32_C, 0);
    emit_i32(iu, value_get_const32(iu, val));
    emit_op1(iu, VM_STORE32_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_CONSTANT, 0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_CONSTANT, 0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_CONSTANT, 0):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_CONSTANT, 1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_CONSTANT, 1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_CONSTANT, 1):
    emit_op1(iu, VM_MOV32_C, 0);
    emit_i32(iu, value_get_const32(iu, val));
    emit_op1(iu, VM_STORE32_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_GLOBALVAR, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT32,   IR_VC_GLOBALVAR, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_GLOBALVAR, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_GLOBALVAR, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_GLOBALVAR, IR_VC_REGFRAME, 0):
    emit_op1(iu, VM_STORE32C_OFF, value_reg(ptr));
    emit_imm16(iu, ii->immediate_offset);
    emit_i32(iu, value_get_const32(iu, val));
    return;


  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
    emit_op2(iu, VM_STORE32_OFF, value_reg(ptr), value_reg(val));
    emit_imm16(iu, ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT32,   IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_POINTER, IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_FLOAT,   IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
    emit_op2(iu, VM_STORE32, value_reg(ptr), value_reg(val));
    return;

    // ---

  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_CONSTANT,  1):
    emit_op1(iu, VM_STORE64_G, value_reg(val));
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_CONSTANT,  0):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 0):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_CONSTANT,  1):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_GLOBALVAR, 1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_GLOBALVAR, 1):
    vm_align32(iu, 0);
    emit_op1(iu, VM_MOV64_C, 0);
    emit_i64(iu, value_get_const64(iu, val));
    emit_op1(iu, VM_STORE64_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr) + ii->immediate_offset);
    return;


  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_INT64,  IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_CONSTANT, IR_VC_REGFRAME, 0):
    vm_align32(iu, 1);
    emit_op1(iu, VM_STORE64C_OFF, value_reg(ptr));
    emit_imm16(iu, ii->immediate_offset);
    emit_i64(iu, value_get_const64(iu, val));
    return;

  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_REGFRAME, 1):
    emit_op2(iu, VM_STORE64_OFF, value_reg(ptr), value_reg(val));
    emit_imm16(iu, ii->immediate_offset);
    return;

  case COMBINE4(IR_TYPE_INT64,  IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_DOUBLE, IR_VC_REGFRAME, IR_VC_REGFRAME, 0):
    emit_op2(iu, VM_STORE64, value_reg(ptr), value_reg(val));
    return;


    // ----

  case COMBINE4(IR_TYPE_FUNCTION, IR_VC_FUNCTION, IR_VC_REGFRAME, 0):
  case COMBINE4(IR_TYPE_FUNCTION, IR_VC_FUNCTION, IR_VC_REGFRAME, 1):
    emit_op1(iu, VM_STORE32C_OFF, value_reg(ptr));
    emit_imm16(iu, ii->immediate_offset);
    emit_i32(iu, value_function_addr(val));
    return;

  case COMBINE4(IR_TYPE_FUNCTION, IR_VC_FUNCTION, IR_VC_CONSTANT, 0):
  case COMBINE4(IR_TYPE_FUNCTION, IR_VC_FUNCTION, IR_VC_GLOBALVAR, 0):
    emit_op1(iu, VM_MOV32_C, 0);
    emit_i32(iu, value_function_addr(val));
    emit_op1(iu, VM_STORE32_G, 0);
    emit_i32(iu, value_get_const32(iu, ptr));
    return;


  default:
    parser_error(iu, "Can't store (type %s class %d) ptr class %d off:%d (%s)",
                 type_str_index(iu, ii->value.type),
                 val->iv_class,
                 ptr->iv_class, has_offset,
                 instr_str(iu, &ii->super, 0));
  }
}





/**
 *
 */
static void
emit_cmp2(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  int pred = ii->op;
  const ir_value_t *lhs = value_get(iu, ii->lhs_value.value);
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_type_t *it = type_get(iu, ii->lhs_value.type);

  if(lhs->iv_class == IR_VC_REGFRAME &&
     rhs->iv_class == IR_VC_REGFRAME) {

    if(pred >= FCMP_OEQ && pred <= FCMP_UNE) {
      switch(legalize_type(it)) {
      case IR_TYPE_FLOAT:
        emit_op3(iu, pred - FCMP_OEQ + VM_OEQ_FLT,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      case IR_TYPE_DOUBLE:
        emit_op3(iu, pred - FCMP_OEQ + VM_OEQ_DBL,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      default:
        parser_error(iu, "Can't fcmp type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT8:
        emit_op3(iu, pred - ICMP_EQ + VM_EQ8,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      case IR_TYPE_INT16:
        emit_op3(iu, pred - ICMP_EQ + VM_EQ16,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_op3(iu, pred - ICMP_EQ + VM_EQ32,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      case IR_TYPE_INT64:
        emit_op3(iu, pred - ICMP_EQ + VM_EQ64,
                 value_reg(ret), value_reg(lhs), value_reg(rhs));
        return;

      default:
        parser_error(iu, "Can't icmp type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else {
      parser_error(iu, "Can't compare pred %d", pred);
    }

  } else if((lhs->iv_class == IR_VC_REGFRAME &&
             rhs->iv_class == IR_VC_CONSTANT) ||
            (lhs->iv_class == IR_VC_CONSTANT &&
             rhs->iv_class == IR_VC_REGFRAME)) {


    if(rhs->iv_class == IR_VC_REGFRAME) {
      // Swap LHS RHS
      const ir_value_t *tmp = rhs;
      rhs = lhs;
      lhs = tmp;
      pred = swap_pred(pred);
    }

    if(pred >= FCMP_OEQ && pred <= FCMP_UNE) {
      switch(legalize_type(it)) {

      case IR_TYPE_DOUBLE:
        if(__builtin_isnan(rhs->iv_double))
          parser_error(iu, "Ugh, immediate is nan in fcmp");
        vm_align32(iu, 1);
        emit_op2(iu, pred - FCMP_OEQ + VM_OEQ_DBL_C,
                 value_reg(ret), value_reg(lhs));
        emit_i64(iu, value_get_const64(iu, rhs));
        return;

      case IR_TYPE_FLOAT:
        if(__builtin_isnan(rhs->iv_float))
          parser_error(iu, "Ugh, immediate is nan in fcmp");

        vm_align32(iu, 1);
        emit_op2(iu, pred - FCMP_OEQ + VM_OEQ_FLT_C,
                 value_reg(ret), value_reg(lhs));
        emit_i32(iu, value_get_const32(iu, rhs));
        return;

      default:
        parser_error(iu, "Can't fcmp type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }

    } else if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT8:
        emit_op2(iu, pred - ICMP_EQ + VM_EQ8_C,
                 value_reg(ret), value_reg(lhs));
        emit_i8(iu, value_get_const32(iu, rhs));
        return;

      case IR_TYPE_INT16:
        emit_op2(iu, pred - ICMP_EQ + VM_EQ16_C,
                 value_reg(ret), value_reg(lhs));
        emit_i16(iu, value_get_const32(iu, rhs));
        return;

      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_op2(iu, pred - ICMP_EQ + VM_EQ32_C,
                 value_reg(ret), value_reg(lhs));
        emit_i32(iu, value_get_const32(iu, rhs));
        return;

      case IR_TYPE_INT64:
        vm_align32(iu, 1);
        emit_op2(iu, pred - ICMP_EQ + VM_EQ64_C,
                 value_reg(ret), value_reg(lhs));
        emit_i64(iu, value_get_const64(iu, rhs));
        return;

      default:
        parser_error(iu, "Can't icmp type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else {
      parser_error(iu, "Can't compare pred %d (const)", pred);
    }


  } else if((lhs->iv_class == IR_VC_REGFRAME &&
             rhs->iv_class == IR_VC_GLOBALVAR) ||
            (lhs->iv_class == IR_VC_GLOBALVAR &&
             rhs->iv_class == IR_VC_REGFRAME)) {


    if(lhs->iv_class == IR_VC_GLOBALVAR) {
      // Swap LHS RHS
      const ir_value_t *tmp = rhs;
      rhs = lhs;
      lhs = tmp;
      pred = swap_pred(pred);
    }

    if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_POINTER:
        emit_op2(iu, pred - ICMP_EQ + VM_EQ32_C,
                 value_reg(ret), value_reg(lhs));
        emit_i32(iu, value_get_const32(iu, rhs));
        return;

      default:
        parser_error(iu, "Can't icmp type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else {
      parser_error(iu, "Can't compare pred %d (const)", pred);
    }


  } else {
    parser_error(iu, "Can't icmp value class %d and %d",
                 lhs->iv_class, rhs->iv_class);
  }
}



/**
 *
 */
static void
emit_cmp_branch(ir_unit_t *iu, ir_instr_cmp_branch_t *ii)
{
  int pred = ii->op;
  const ir_value_t *lhs = value_get(iu, ii->lhs_value.value);
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);
  const ir_type_t *it = type_get(iu, ii->lhs_value.type);

  int textpos = iu->iu_text_ptr - iu->iu_text_alloc;
  VECTOR_PUSH_BACK(&iu->iu_branch_fixups, textpos);

  if(lhs->iv_class == IR_VC_REGFRAME &&
     rhs->iv_class == IR_VC_REGFRAME) {

    if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT8:
        emit_i16(iu, pred - ICMP_EQ + VM_EQ8_BR);
        break;

      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_i16(iu, pred - ICMP_EQ + VM_EQ32_BR);
        break;

      default:
        parser_error(iu, "Can't cmpbr type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
      emit_i16(iu, ii->true_branch);
      emit_i16(iu, ii->false_branch);
      emit_i16(iu, value_reg(lhs));
      emit_i16(iu, value_reg(rhs));


    } else {
      parser_error(iu, "Can't compare pred %d", pred);
    }
    return;
  }

  if(rhs->iv_class == IR_VC_REGFRAME) {
    // Swap LHS RHS
    const ir_value_t *tmp = rhs;
    rhs = lhs;
    lhs = tmp;
    pred = swap_pred(pred);
  }

  if(lhs->iv_class == IR_VC_REGFRAME &&
     (rhs->iv_class == IR_VC_CONSTANT ||
      rhs->iv_class == IR_VC_GLOBALVAR)) {

    if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT8:
        emit_i16(iu, pred - ICMP_EQ + VM_EQ8_C_BR);
        emit_i16(iu, ii->true_branch);
        emit_i16(iu, ii->false_branch);
        emit_i16(iu, value_reg(lhs));
        emit_i8(iu, value_get_const32(iu, rhs));
        break;

      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_i16(iu, pred - ICMP_EQ + VM_EQ32_C_BR);
        emit_i16(iu, ii->true_branch);
        emit_i16(iu, ii->false_branch);
        emit_i16(iu, value_reg(lhs));
        emit_i32(iu, value_get_const32(iu, rhs));
        break;

      default:
        parser_error(iu, "Can't cmpbr type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else {
      parser_error(iu, "Can't brcmp pred %d (const)", pred);
    }

  } else if(lhs->iv_class == IR_VC_REGFRAME &&
            rhs->iv_class == IR_VC_FUNCTION) {

    emit_i16(iu, pred - ICMP_EQ + VM_EQ32_C_BR);
    emit_i16(iu, ii->true_branch);
    emit_i16(iu, ii->false_branch);
    emit_i16(iu, value_reg(lhs));
    emit_i32(iu, value_function_addr(rhs));

  } else {
    parser_error(iu, "Can't brcmp value class %d and %d",
                 lhs->iv_class, rhs->iv_class);
  }
}


/**
 *
 */
static void
emit_cmp_select(ir_unit_t *iu, ir_instr_cmp_select_t *ii)
{
  int pred = ii->op;
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_value_t *lhs = value_get(iu, ii->lhs_value.value);
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);
  const ir_value_t *trueval = value_get(iu, ii->true_value.value);
  const ir_value_t *falseval = value_get(iu, ii->false_value.value);
  const ir_type_t *it = type_get(iu, ii->lhs_value.type);

  int truereg;
  int falsereg;


  if(rhs->iv_class == IR_VC_REGFRAME && lhs->iv_class != IR_VC_REGFRAME) {
    // Swap LHS RHS
    const ir_value_t *tmp = rhs;
    rhs = lhs;
    lhs = tmp;
    pred = swap_pred(pred);
  }


  switch(trueval->iv_class) {
  case IR_VC_REGFRAME:
    truereg = value_reg(trueval);
    break;
  case IR_VC_CONSTANT:
  case IR_VC_GLOBALVAR:
    emit_op1(iu, VM_MOV32_C, 0);
    emit_i32(iu, value_get_const32(iu, trueval));
    truereg = 0;
    break;
  default:
    parser_error(iu, "Can't cmpselect value %s", value_str(iu, trueval));
  }

  switch(falseval->iv_class) {
  case IR_VC_REGFRAME:
    falsereg = value_reg(falseval);
    break;
  case IR_VC_CONSTANT:
  case IR_VC_GLOBALVAR:
    emit_op1(iu, VM_MOV32_C, 4);
    emit_i32(iu, value_get_const32(iu, falseval));
    falsereg = 4;
    break;
  default:
    parser_error(iu, "Can't cmpselect value %s", value_str(iu, falseval));
  }



  if(lhs->iv_class == IR_VC_REGFRAME &&
     rhs->iv_class == IR_VC_REGFRAME) {

    if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_op(iu, pred - ICMP_EQ + VM_EQ32_SEL);
        break;

      default:
        parser_error(iu, "Can't cmpselect type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
      emit_i16(iu, value_reg(ret));
      emit_i16(iu, truereg);
      emit_i16(iu, falsereg);
      emit_i16(iu, value_reg(lhs));
      emit_i16(iu, value_reg(rhs));


    } else {
      parser_error(iu, "Can't compare pred %d", pred);
    }
    return;
  }

  if(lhs->iv_class == IR_VC_REGFRAME &&
     (rhs->iv_class == IR_VC_CONSTANT ||
      rhs->iv_class == IR_VC_GLOBALVAR)) {

    if(pred >= ICMP_EQ && pred <= ICMP_SLE) {

      switch(legalize_type(it)) {
      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        emit_op(iu, pred - ICMP_EQ + VM_EQ32_C_SEL);
        emit_i16(iu, value_reg(ret));
        emit_i16(iu, truereg);
        emit_i16(iu, falsereg);
        emit_i16(iu, value_reg(lhs));
        emit_i32(iu, value_get_const32(iu, rhs));
        break;

      default:
        parser_error(iu, "Can't cmpsel type %s class %d/%d op %d",
                     type_str(iu, it),
                     lhs->iv_class, rhs->iv_class, pred);
      }
    } else {
      parser_error(iu, "Can't cmpsel pred %d (const)", pred);
    }
  } else {
    parser_error(iu, "Can't cmpsel value class %d and %d",
                 lhs->iv_class, rhs->iv_class);
  }
}


/**
 *
 */
static void
emit_br(ir_unit_t *iu, ir_instr_br_t *ii, ir_bb_t *currentib)
{
  int textpos = iu->iu_text_ptr - iu->iu_text_alloc;
  VECTOR_PUSH_BACK(&iu->iu_branch_fixups, textpos);

  // We can't emit code yet cause we don't know the final destination
  if(ii->condition.value == -1) {
    ir_bb_t *next = TAILQ_NEXT(currentib, ib_link);
    if(next != NULL && next->ib_id == ii->true_branch) {
      // Jump to next bb is NOP as basic-blocks are contiguous in memory
      VECTOR_POP(&iu->iu_branch_fixups);
      return;
    }

    // Unconditional branch
    emit_i16(iu, VM_B);
    emit_i16(iu, ii->true_branch);
  } else {
    // Conditional branch

    ir_value_t *iv = value_get(iu, ii->condition.value);
    switch(iv->iv_class) {
    case IR_VC_REGFRAME:
      emit_i16(iu, VM_BCOND);
      emit_i16(iu, value_reg(iv));
      emit_i16(iu, ii->true_branch);
      emit_i16(iu, ii->false_branch);
      break;

    case IR_VC_CONSTANT:
      emit_i16(iu, VM_B);
      if(value_get_const32(iu, iv))
        emit_i16(iu, ii->true_branch);
      else
        emit_i16(iu, ii->false_branch);
      break;
    default:
      parser_error(iu, "Unable to branch on value class %d", iv->iv_class);
    }
  }
}


/**
 *
 */
static void
emit_switch(ir_unit_t *iu, ir_instr_switch_t *ii)
{
  const ir_value_t *c = value_get(iu, ii->value.value);
  const ir_type_t *cty = type_get(iu, ii->value.type);

  uint32_t mask32 = 0xffffffff;
  int jumptable_size = 0;
  int width;
  assert(c->iv_class == IR_VC_REGFRAME);
  int reg = value_reg(c);

  switch(cty->it_code) {

  case IR_TYPE_INTx:
    width = type_bitwidth(iu, cty);
    assert(width < 32);

    if(width <= 4) {
      jumptable_size = 1 << width;
      goto jumptable;
    }

    mask32 = (1 << width) - 1;

    assert(c->iv_class == IR_VC_REGFRAME);
    emit_op2(iu, VM_AND_R32C, 0, reg);
    emit_i32(iu, mask32);

    reg = 0;

    goto switch32;
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:

    if(ii->num_paths > 64) {
      jumptable_size = 256;
      goto jumptable;
    }

    VECTOR_PUSH_BACK(&iu->iu_branch_fixups,
                     iu->iu_text_ptr - iu->iu_text_alloc);
    emit_i16(iu, VM_SWITCH8_BS);
    emit_i16(iu, reg);
    emit_i16(iu, ii->num_paths);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i8(iu, ii->paths[n].v64);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i16(iu, ii->paths[n].block);

    emit_i16(iu, ii->defblock);
    break;

  case IR_TYPE_INT16:
    assert(c->iv_class == IR_VC_REGFRAME);
    emit_op2(iu, VM_CAST_16_TRUNC_32, 0, reg);
    reg = 0;
    mask32 = 0xffff;
    goto switch32;


  case IR_TYPE_INT32:

  switch32:
    VECTOR_PUSH_BACK(&iu->iu_branch_fixups,
                     iu->iu_text_ptr - iu->iu_text_alloc);

    emit_i16(iu, VM_SWITCH32_BS);

    emit_i16(iu, reg);
    emit_i16(iu, ii->num_paths);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i32(iu, ii->paths[n].v64 & mask32);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i16(iu, ii->paths[n].block);

    emit_i16(iu, ii->defblock);
    break;

  case IR_TYPE_INT64:
    assert(c->iv_class == IR_VC_REGFRAME);

    vm_align32(iu, 1);

    VECTOR_PUSH_BACK(&iu->iu_branch_fixups,
                     iu->iu_text_ptr - iu->iu_text_alloc);
    emit_i16(iu, VM_SWITCH64_BS);
    emit_i16(iu, reg);
    emit_i16(iu, ii->num_paths);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i64(iu, ii->paths[n].v64);

    for(int n = 0; n < ii->num_paths; n++)
      emit_i16(iu, ii->paths[n].block);

    emit_i16(iu, ii->defblock);
    break;


  jumptable:
    VECTOR_PUSH_BACK(&iu->iu_branch_fixups,
                     iu->iu_text_ptr - iu->iu_text_alloc);
    emit_i16(iu, VM_JUMPTABLE);
    emit_i16(iu, reg);
    emit_i16(iu, jumptable_size);
    const int mask = jumptable_size - 1;
    int16_t *table = emit_data(iu, jumptable_size * 2);

    // Fill table with default paths
    for(int i = 0; i < jumptable_size; i++)
      table[i] = ii->defblock;

    for(int n = 0; n < ii->num_paths; n++)
      table[ii->paths[n].v64 & mask] = ii->paths[n].block;

    break;

  default:
    parser_error(iu, "Bad type in switch (%d paths): %s",
                 ii->num_paths, instr_str(iu, &ii->super, 0));
  }
}


/**
 *
 */
static void
emit_move(ir_unit_t *iu, ir_instr_move_t *ii)
{
  const ir_value_t *src = value_get(iu, ii->value.value);

  int retreg, typecode;

  if(ii->super.ii_ret.value == -2) {
    const ir_value_t *v1 = value_get(iu, ii->super.ii_rets[0].value);
    const ir_value_t *v2 = value_get(iu, ii->super.ii_rets[1].value);

    if(v1->iv_reg + 4 != v2->iv_reg ||
       ii->super.ii_rets[0].type != ii->super.ii_rets[1].type)
      parser_error(iu, "Bad aggregate destination for move");

    const ir_type_t *ty = type_get(iu, ii->super.ii_rets[0].type);
    typecode = legalize_type(ty);
    if(typecode != IR_TYPE_INT32)
      parser_error(iu, "Bad aggregate destination type for move");

    // Merge to one 64bit reg
    retreg = value_reg(v1);
    typecode = IR_TYPE_INT64;

  } else {

    const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
    const ir_type_t *ty = type_get(iu, ii->super.ii_ret.type);
    retreg = value_reg(ret);
    typecode = legalize_type(ty);
  }

  switch(COMBINE2(src->iv_class, typecode)) {
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_INT8):
    emit_op1(iu, VM_MOV8_C, retreg);
    emit_i8(iu, value_get_const32(iu, src));
    return;
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_INT16):
    emit_op1(iu, VM_MOV16_C, retreg);
    emit_i16(iu, value_get_const32(iu, src));
    return;

  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_INT1):
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_INT32):
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_POINTER):
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_FLOAT):
    emit_op1(iu, VM_MOV32_C, retreg);
    emit_i32(iu, value_get_const32(iu, src));
    return;

  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_INT64):
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_DOUBLE):
    vm_align32(iu, 0);
    emit_op1(iu, VM_MOV64_C, retreg);
    emit_i64(iu, value_get_const64(iu, src));
    return;

  case COMBINE2(IR_VC_GLOBALVAR, IR_TYPE_POINTER):
    emit_op1(iu, VM_MOV32_C, retreg);
    emit_i32(iu, value_get_const32(iu, src));
    return;

  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_INT1):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_INT8):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_INT16):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_INT32):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_POINTER):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_FLOAT):
    emit_op2(iu, VM_MOV32, retreg, value_reg(src));
    return;
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_INT64):
  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_DOUBLE):
    emit_op2(iu, VM_MOV64, retreg, value_reg(src));
    return;

  case COMBINE2(IR_VC_FUNCTION, IR_TYPE_FUNCTION):
  case COMBINE2(IR_VC_FUNCTION, IR_TYPE_POINTER):
    emit_op1(iu, VM_MOV32_C, retreg);
    emit_i32(iu, value_function_addr(src));
    break;
  default:
    parser_error(iu, "Can't emit %s", instr_str(iu, &ii->super, 0));
  }
}


/**
 *
 */
static void
emit_stackcopy(ir_unit_t *iu, ir_instr_stackcopy_t *ii)
{
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_value_t *src = value_get(iu, ii->value.value);
  const ir_type_t *ty = type_get(iu, ii->value.type);

  switch(COMBINE2(src->iv_class, legalize_type(ty))) {

  case COMBINE2(IR_VC_GLOBALVAR, IR_TYPE_POINTER):
  case COMBINE2(IR_VC_CONSTANT, IR_TYPE_POINTER):
    emit_op1(iu, VM_STACKCOPYC, value_reg(ret));
    emit_i32(iu, value_get_const32(iu, src));
    emit_i32(iu, ii->size);
    return;

  case COMBINE2(IR_VC_REGFRAME, IR_TYPE_POINTER):
    emit_op2(iu, VM_STACKCOPYR, value_reg(ret), value_reg(src));
    emit_i32(iu, ii->size);
    return;
  default:
    parser_error(iu, "Can't stackcopy from %s class %d",
                 type_str(iu, ty), src->iv_class);
  }
}


/**
 *
 */
static void
emit_stackshrink(ir_unit_t *iu, ir_instr_stackshrink_t *ii)
{
  emit_op(iu, VM_STACKSHRINK);
  emit_i32(iu, ii->size);
}


/**
 *
 */
static void
emit_lea(ir_unit_t *iu, ir_instr_lea_t *ii)
{
  const ir_value_t *    ret = value_get(iu, ii->super.ii_ret.value);
  const ir_value_t *baseptr = value_get(iu, ii->baseptr.value);

  if(ii->value_offset.value == -1) {

    // Lea with immediate offset is same as add32 with constant
    emit_op2(iu, VM_ADD_R32C, value_reg(ret), value_reg(baseptr));
    emit_i32(iu, ii->immediate_offset);

  } else {
    const ir_value_t *off = value_get(iu, ii->value_offset.value);

    if(legalize_type(type_get(iu, ii->value_offset.type)) != IR_TYPE_INT32) {
      parser_error(iu, "LEA: Can't handle %s as offset register",
                   type_str_index(iu, ii->value_offset.type));
    }

    assert(ii->value_offset_multiply != 0);

    int fb = ffs(ii->value_offset_multiply) - 1;
    if((1 << fb) == ii->value_offset_multiply) {

      if(ii->immediate_offset) {
        emit_op4(iu, VM_LEA_R32_SHL_OFF,
                 value_reg(ret), value_reg(baseptr), value_reg(off), fb);
        emit_i32(iu, ii->immediate_offset);
        return;
      }

      if(fb == 2) {
        emit_op3(iu, VM_LEA_R32_SHL2,
               value_reg(ret), value_reg(baseptr), value_reg(off));
        return;
      }
      emit_op4(iu, VM_LEA_R32_SHL,
               value_reg(ret), value_reg(baseptr), value_reg(off), fb);
      return;
    }

    emit_op3(iu, VM_LEA_R32_MUL_OFF,
             value_reg(ret), value_reg(baseptr), value_reg(off));
    emit_i32(iu, ii->value_offset_multiply);
    emit_i32(iu, ii->immediate_offset);
  }
}


/**
 *
 */
static void
emit_cast(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  const ir_value_t *src = value_get(iu, ii->value.value);
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);

  const ir_type_t *srcty = type_get(iu, ii->value.type);
  const ir_type_t *dstty = type_get(iu, ii->super.ii_ret.type);
  const int srccode = legalize_type(srcty);
  const int dstcode = legalize_type(dstty);
  const int castop = ii->op;

  vm_op_t op;
  switch(COMBINE3(dstcode, castop, srccode)) {

  case COMBINE3(IR_TYPE_INT1, CAST_TRUNC, IR_TYPE_INT8):
    op = VM_CAST_1_TRUNC_8;
    break;

  case COMBINE3(IR_TYPE_INT1, CAST_TRUNC, IR_TYPE_INT16):
    op = VM_CAST_1_TRUNC_16;
    break;

  case COMBINE3(IR_TYPE_INT8, CAST_SEXT,  IR_TYPE_INT1):
    op = VM_CAST_8_SEXT_1;
    break;

  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT16):
    op = VM_CAST_8_TRUNC_16;
    break;
  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT8, CAST_ZEXT,  IR_TYPE_INT1):
    op = VM_CAST_8_TRUNC_32;
    break;
  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT64):
    op = VM_CAST_8_TRUNC_64;
    break;

  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT1):
    op = VM_CAST_16_ZEXT_1;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT8):
    op = VM_CAST_16_ZEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_SEXT, IR_TYPE_INT8):
    op = VM_CAST_16_SEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_TRUNC, IR_TYPE_INT32):
    op = VM_CAST_16_TRUNC_32;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_TRUNC, IR_TYPE_INT64):
    op = VM_CAST_16_TRUNC_64;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_FPTOSI, IR_TYPE_FLOAT):
    op = VM_CAST_16_FPTOSI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_FPTOUI, IR_TYPE_FLOAT):
    op = VM_CAST_16_FPTOUI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_FPTOSI, IR_TYPE_DOUBLE):
    op = VM_CAST_16_FPTOSI_DBL;
    break;
  case COMBINE3(IR_TYPE_INT16, CAST_FPTOUI, IR_TYPE_DOUBLE):
    op = VM_CAST_16_FPTOUI_DBL;
    break;


  case COMBINE3(IR_TYPE_INT32, CAST_TRUNC, IR_TYPE_INT64):
    op = VM_CAST_32_TRUNC_64;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT1):
    op = VM_CAST_32_SEXT_1;
    break;

  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT8):
    op = VM_CAST_32_ZEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT8):
    op = VM_CAST_32_SEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT16):
    op = VM_CAST_32_ZEXT_16;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT16):
    op = VM_CAST_32_SEXT_16;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_FPTOSI, IR_TYPE_FLOAT):
    op = VM_CAST_32_FPTOSI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_FPTOUI, IR_TYPE_FLOAT):
    op = VM_CAST_32_FPTOUI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_FPTOSI, IR_TYPE_DOUBLE):
    op = VM_CAST_32_FPTOSI_DBL;
    break;
  case COMBINE3(IR_TYPE_INT32, CAST_FPTOUI, IR_TYPE_DOUBLE):
    op = VM_CAST_32_FPTOUI_DBL;
    break;



  case COMBINE3(IR_TYPE_INT64, CAST_ZEXT, IR_TYPE_INT1):
    op = VM_CAST_64_ZEXT_1;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_SEXT, IR_TYPE_INT1):
    op = VM_CAST_64_SEXT_1;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_ZEXT, IR_TYPE_INT8):
    op = VM_CAST_64_ZEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_SEXT, IR_TYPE_INT8):
    op = VM_CAST_64_SEXT_8;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_ZEXT, IR_TYPE_INT16):
    op = VM_CAST_64_ZEXT_16;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_SEXT, IR_TYPE_INT16):
    op = VM_CAST_64_SEXT_16;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_ZEXT, IR_TYPE_INT32):
    op = VM_CAST_64_ZEXT_32;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_SEXT, IR_TYPE_INT32):
    op = VM_CAST_64_SEXT_32;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_FPTOSI, IR_TYPE_FLOAT):
    op = VM_CAST_64_FPTOSI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_FPTOUI, IR_TYPE_FLOAT):
    op = VM_CAST_64_FPTOUI_FLT;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_FPTOSI, IR_TYPE_DOUBLE):
    op = VM_CAST_64_FPTOSI_DBL;
    break;
  case COMBINE3(IR_TYPE_INT64, CAST_FPTOUI, IR_TYPE_DOUBLE):
    op = VM_CAST_64_FPTOUI_DBL;
    break;


  case COMBINE3(IR_TYPE_FLOAT, CAST_FPTRUNC, IR_TYPE_DOUBLE):
    op = VM_CAST_FLT_FPTRUNC_DBL;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_SITOFP, IR_TYPE_INT8):
    op = VM_CAST_FLT_SITOFP_8;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_UITOFP, IR_TYPE_INT8):
    op = VM_CAST_FLT_UITOFP_8;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_SITOFP, IR_TYPE_INT16):
    op = VM_CAST_FLT_SITOFP_16;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_UITOFP, IR_TYPE_INT16):
    op = VM_CAST_FLT_UITOFP_16;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_SITOFP, IR_TYPE_INT32):
    op = VM_CAST_FLT_SITOFP_32;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_UITOFP, IR_TYPE_INT32):
    op = VM_CAST_FLT_UITOFP_32;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_SITOFP, IR_TYPE_INT64):
    op = VM_CAST_FLT_SITOFP_64;
    break;
  case COMBINE3(IR_TYPE_FLOAT, CAST_UITOFP, IR_TYPE_INT64):
    op = VM_CAST_FLT_UITOFP_64;
    break;

  case COMBINE3(IR_TYPE_DOUBLE, CAST_SITOFP, IR_TYPE_INT8):
    op = VM_CAST_DBL_SITOFP_8;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_UITOFP, IR_TYPE_INT8):
    op = VM_CAST_DBL_UITOFP_8;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_SITOFP, IR_TYPE_INT16):
    op = VM_CAST_DBL_SITOFP_16;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_UITOFP, IR_TYPE_INT16):
    op = VM_CAST_DBL_UITOFP_16;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_SITOFP, IR_TYPE_INT32):
    op = VM_CAST_DBL_SITOFP_32;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_UITOFP, IR_TYPE_INT32):
    op = VM_CAST_DBL_UITOFP_32;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_SITOFP, IR_TYPE_INT64):
    op = VM_CAST_DBL_SITOFP_64;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_UITOFP, IR_TYPE_INT64):
    op = VM_CAST_DBL_UITOFP_64;
    break;
  case COMBINE3(IR_TYPE_DOUBLE, CAST_FPEXT, IR_TYPE_FLOAT):
    op = VM_CAST_DBL_FPEXT_FLT;
    break;


  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT1):
  case COMBINE3(IR_TYPE_INT32, CAST_BITCAST, IR_TYPE_FLOAT):
  case COMBINE3(IR_TYPE_FLOAT, CAST_BITCAST, IR_TYPE_INT32):
    emit_op2(iu, VM_MOV32, value_reg(ret), value_reg(src));
    return;

  case COMBINE3(IR_TYPE_DOUBLE, CAST_BITCAST, IR_TYPE_INT64):
  case COMBINE3(IR_TYPE_INT64,  CAST_BITCAST, IR_TYPE_DOUBLE):
    emit_op2(iu, VM_MOV64, value_reg(ret), value_reg(src));
    return;

  case COMBINE3(IR_TYPE_INT64, CAST_PTRTOINT, IR_TYPE_POINTER):
    op = VM_CAST_64_ZEXT_32;
    return;

  default:
    parser_error(iu, "Unable to convert to %s from %s using castop %d",
                 type_str(iu, dstty),
                 type_str(iu, srcty),
                 castop);
  }
  emit_op2(iu, op, value_reg(ret), value_reg(src));
}


/**
 *
 */
static void
emit_call(ir_unit_t *iu, ir_instr_call_t *ii, ir_function_t *f)
{
  int rf_offset = f->if_regframe_size;
  int return_reg;

  if(ii->super.ii_ret.value != -1) {
    const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
    return_reg = value_reg(ret);
  } else {
    return_reg = 0;
  }

  ir_function_t *callee = value_function(iu, ii->callee.value);

  if(callee != NULL) {
    vm_op_t op;

    if(callee->if_ext_func != NULL) {
      op = VM_JSR_EXT;
    } else {
      op = VM_JSR;
    }

    emit_op3(iu, op, callee->if_gfid, rf_offset, return_reg);

  } else {

    const ir_value_t *iv = value_get(iu, ii->callee.value);

    if(iv->iv_class != IR_VC_REGFRAME)
      parser_error(iu, "Call via incompatible value class %d",
                   iv->iv_class);
    emit_op3(iu, VM_JSR_R, value_reg(iv), rf_offset, return_reg);
  }
}


/**
 *
 */
static void
emit_invoke(ir_unit_t *iu, ir_instr_call_t *ii, ir_function_t *f)
{
  const int textpos = iu->iu_text_ptr - iu->iu_text_alloc;
  VECTOR_PUSH_BACK(&iu->iu_branch_fixups, textpos);

  int rf_offset = f->if_regframe_size;
  int return_reg;

  if(ii->super.ii_ret.value != -1) {
    const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
    return_reg = value_reg(ret);
  } else {
    return_reg = 0;
  }
  ir_function_t *callee = value_function(iu, ii->callee.value);
  if(callee != NULL) {
    vm_op_t op;

    if(callee->if_ext_func != NULL) {
      op = VM_INVOKE_EXT;
    } else {
      op = VM_INVOKE;
    }

    emit_i16(iu, op);
    emit_i16(iu, callee->if_gfid);

  } else {

    const ir_value_t *iv = value_get(iu, ii->callee.value);

    if(iv->iv_class != IR_VC_REGFRAME)
      parser_error(iu, "Invoke via incompatible value class %d",
                   iv->iv_class);
    emit_i16(iu, VM_INVOKE_R);
    emit_i16(iu, value_reg(iv));

  }
  emit_i16(iu, rf_offset);
  emit_i16(iu, return_reg);
  emit_i16(iu, ii->normal_dest);
  emit_i16(iu, ii->unwind_dest);
}


/**
 *
 */
static void
emit_alloca(ir_unit_t *iu, ir_instr_alloca_t *ii)
{
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  ir_value_t *iv = value_get(iu, ii->num_items_value.value);

  switch(iv->iv_class) {
  case IR_VC_CONSTANT:
    emit_op2(iu, VM_ALLOCA, value_reg(ret), ii->alignment);
    emit_i32(iu, ii->size * value_get_const32(iu, iv));
    break;

  case IR_VC_REGFRAME:
    switch(legalize_type(type_get(iu, ii->num_items_value.type))) {
    case IR_TYPE_INT32:
      emit_op3(iu, VM_ALLOCAD, value_reg(ret), ii->alignment, value_reg(iv));
      emit_i32(iu, ii->size);
      break;

    default:
      parser_error(iu, "Unable to alloca num_elements as %s",
                   type_str_index(iu, ii->num_items_value.type));
    }
    return;

  default:
    parser_error(iu, "Bad class %d for alloca elements",
                 iv->iv_class);
  }
}


/**
 *
 */
static void
emit_select(ir_unit_t *iu, ir_instr_select_t *ii)
{
  const ir_value_t *p  = value_get(iu, ii->pred.value);
  const ir_value_t *tv = value_get(iu, ii->true_value.value);
  const ir_value_t *fv = value_get(iu, ii->false_value.value);
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_type_t *ty = type_get(iu, ii->super.ii_ret.type);
  //  assert(tv->iv_type == fv->iv_type);
  const int code = legalize_type(ty);
  switch(COMBINE3(tv->iv_class, fv->iv_class, code)) {

  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_INT8):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_INT16):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_INT32):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_FLOAT):
    emit_op4(iu, VM_SELECT32RR, value_reg(ret), value_reg(p),
             value_reg(tv), value_reg(fv));
    break;

  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_INT8):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_INT16):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_INT32):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_FLOAT):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_GLOBALVAR, IR_TYPE_POINTER):
    emit_op3(iu, VM_SELECT32RC, value_reg(ret), value_reg(p),
             value_reg(tv));
    emit_i32(iu, value_get_const32(iu, fv) & type_code_mask(code));
    break;
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_INT8):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_INT16):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_INT32):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_FLOAT):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_GLOBALVAR, IR_VC_REGFRAME, IR_TYPE_POINTER):
    emit_op3(iu, VM_SELECT32CR, value_reg(ret), value_reg(p),
             value_reg(fv));
    emit_i32(iu, value_get_const32(iu, tv) & type_code_mask(code));
    break;
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_INT8):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_INT16):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_INT32):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_FLOAT):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_GLOBALVAR, IR_VC_CONSTANT, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_GLOBALVAR, IR_TYPE_POINTER):
  case COMBINE3(IR_VC_GLOBALVAR, IR_VC_GLOBALVAR, IR_TYPE_POINTER):
    emit_op2(iu, VM_SELECT32CC, value_reg(ret), value_reg(p));
    emit_i32(iu, value_get_const32(iu, tv) & type_code_mask(code));
    emit_i32(iu, value_get_const32(iu, fv) & type_code_mask(code));
    break;


  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_INT64):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_REGFRAME, IR_TYPE_DOUBLE):
    emit_op4(iu, VM_SELECT64RR, value_reg(ret), value_reg(p),
             value_reg(tv), value_reg(fv));
    break;
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_INT64):
  case COMBINE3(IR_VC_REGFRAME, IR_VC_CONSTANT, IR_TYPE_DOUBLE):
    vm_align32(iu, 0);
    emit_op3(iu, VM_SELECT64RC, value_reg(ret), value_reg(p),
             value_reg(tv));
    emit_i64(iu, value_get_const64(iu, fv));
    break;
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_INT64):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_REGFRAME, IR_TYPE_DOUBLE):
    vm_align32(iu, 0);
    emit_op3(iu, VM_SELECT64CR, value_reg(ret), value_reg(p),
             value_reg(fv));
    emit_i64(iu, value_get_const64(iu, tv));
    break;
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_INT64):
  case COMBINE3(IR_VC_CONSTANT, IR_VC_CONSTANT, IR_TYPE_DOUBLE):
    vm_align32(iu, 1);
    emit_op2(iu, VM_SELECT64CC, value_reg(ret), value_reg(p));
    emit_i64(iu, value_get_const64(iu, tv));
    emit_i64(iu, value_get_const64(iu, fv));
    break;


  default:
    parser_error(iu, "Unable to emit select for %s class %d,%d",
                 type_str(iu, ty), tv->iv_class, fv->iv_class);
  }
}


/**
 *
 */
static void
emit_vmop(ir_unit_t *iu, ir_instr_call_t *ii)
{
  int vmop = ii->vmop;
  assert(vmop != 0);
  emit_op(iu, vmop);

  if(ii->super.ii_ret.value < -1) {
    for(int i = 0; i < -ii->super.ii_ret.value; i++) {
      const ir_value_t *ret = value_get(iu, ii->super.ii_rets[i].value);
      emit_i16(iu, value_reg(ret));
    }
  } else if(ii->super.ii_ret.value != -1) {
    const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
    emit_i16(iu, value_reg(ret));
  }

  for(int i = 0 ; i < ii->argc; i++) {
    const ir_value_t *iv = value_get(iu, ii->argv[i].value.value);
    emit_i16(iu, value_reg(iv));
  }
}


/**
 *
 */
static void
emit_vaarg(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  const ir_value_t *val = value_get(iu, ii->value.value);
  int valreg;
  switch(val->iv_class) {
  case IR_VC_REGFRAME:
    valreg = value_reg(val);
    break;

  case IR_VC_CONSTANT:
  case IR_VC_GLOBALVAR:
    emit_op1(iu, VM_MOV32_C, 0);
    emit_i32(iu, value_get_const32(iu, val));
    valreg = 0;
    break;
  default:
    parser_error(iu, "bad vaarg class");
  }

  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_type_t *ty = type_get(iu, ii->super.ii_ret.type);
  switch(legalize_type(ty)) {
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
  case IR_TYPE_INT1:
    emit_op(iu, VM_VAARG32);
    break;
  case IR_TYPE_DOUBLE:
  case IR_TYPE_INT64:
    emit_op(iu, VM_VAARG64);
    break;
  default:
    parser_error(iu, "Unable to emit vaarg() for type %s",
                 type_str(iu, ty));
  }

  emit_i16(iu, value_reg(ret));
  emit_i16(iu, valreg);
}


/**
 *
 */
static void
emit_mla(ir_unit_t *iu, ir_instr_ternary_t *ii)
{
  const ir_value_t *ret = value_get(iu, ii->super.ii_ret.value);
  const ir_type_t *ty = type_get(iu, ii->super.ii_ret.type);
  const ir_value_t *a1 = value_get(iu, ii->arg1.value);
  const ir_value_t *a2 = value_get(iu, ii->arg2.value);
  const ir_value_t *a3 = value_get(iu, ii->arg3.value);
  switch(legalize_type(ty)) {

  case IR_TYPE_INT32:
    emit_op4(iu, VM_MLA32, value_reg(ret),
             value_reg(a1), value_reg(a2), value_reg(a3));
    break;
  default:
    parser_error(iu, "Unable to emit mla() for type %s",
                 type_str(iu, ty));
  }
}


/**
 *
 */
static void
emit_landingpad(ir_unit_t *iu, ir_instr_landingpad_t *ii)
{
  if(ii->super.ii_ret.value == -2) {
    const ir_value_t *ret;
    emit_op(iu, VM_LANDINGPAD);
    ret = value_get(iu, ii->super.ii_rets[0].value);
    emit_i16(iu, value_reg(ret));
    ret = value_get(iu, ii->super.ii_rets[1].value);
    emit_i16(iu, value_reg(ret));
  } else {
    parser_error(iu, "Unable to emit landingpad");
  }
}


/**
 *
 */
static void
emit_resume(ir_unit_t *iu, ir_instr_resume_t *r)
{
  if(r->num_values != 2) {
    parser_error(iu, "Unable to emit resume with %d args", r->num_values);
  }
  emit_op(iu, VM_RESUME);
  emit_i16(iu, value_reg(value_get(iu, r->values[0].value)));
  emit_i16(iu, value_reg(value_get(iu, r->values[1].value)));
}


/**
 *
 */
static void
instr_emit(ir_unit_t *iu, ir_bb_t *bb, ir_function_t *f
#ifdef VMIR_VM_JIT
           , jitctx_t *jc
#endif
           )
{
  ir_instr_t *ii;
  //  printf("=========== BB %s.%d\n", f->if_name, bb->ib_id);


#ifdef VMIR_VM_JIT
  if(bb->ib_jit) {
    int jitoffset = jit_emit(iu, bb, jc);

    if(bb->ib_only_jit_sucessors)
      return;
    assert(jitoffset >= 0);
#ifdef VM_TRACE
    char tmp[128];
    ir_instr_backref_t *iib = f->if_instr_backrefs + f->if_instr_backref_size;
    iib->offset = iu->iu_text_ptr - iu->iu_text_alloc;
    snprintf(tmp, sizeof(tmp), "JIT CALL to 0x%x", jitoffset);
    iib->str = strdup(tmp);
    iib->bb = bb->ib_id;
    f->if_instr_backref_size++;
#endif
    emit_op(iu, VM_JIT_CALL);
    emit_i32(iu, jitoffset);
    return;
  } else if(bb->ib_force_jit_entrypoint) {
    jit_emit_stub(iu, bb, jc);
  }
#endif


  TAILQ_FOREACH(ii, &bb->ib_instrs, ii_link) {
    //    printf("EMIT INSTR: %s\n", instr_str(iu, ii, 1));
    assert(ii->ii_jit == 0);

#ifdef VM_TRACE
    ir_instr_backref_t *iib = f->if_instr_backrefs + f->if_instr_backref_size;
    iib->offset = iu->iu_text_ptr - iu->iu_text_alloc;
    iib->str = instr_stra(iu, ii, 0);
    iib->bb = bb->ib_id;
    f->if_instr_backref_size++;
#endif


    switch(ii->ii_class) {

    case IR_IC_RET:
      emit_ret(iu, (ir_instr_unary_t *)ii);
      break;
    case IR_IC_BINOP:
      emit_binop(iu, (ir_instr_binary_t *)ii);
      break;
    case IR_IC_LOAD:
      emit_load(iu, (ir_instr_load_t *)ii);
      break;
    case IR_IC_CMP2:
      emit_cmp2(iu, (ir_instr_binary_t *)ii);
      break;
    case IR_IC_BR:
      emit_br(iu, (ir_instr_br_t *)ii, bb);
      break;
    case IR_IC_MOVE:
      emit_move(iu, (ir_instr_move_t *)ii);
      break;
    case IR_IC_STORE:
      emit_store(iu, (ir_instr_store_t *)ii);
      break;
    case IR_IC_LEA:
      emit_lea(iu, (ir_instr_lea_t *)ii);
      break;
    case IR_IC_CAST:
      emit_cast(iu, (ir_instr_unary_t *)ii);
      break;
    case IR_IC_CALL:
      emit_call(iu, (ir_instr_call_t *)ii, f);
      break;
    case IR_IC_INVOKE:
      emit_invoke(iu, (ir_instr_call_t *)ii, f);
      break;
    case IR_IC_SWITCH:
      emit_switch(iu, (ir_instr_switch_t *)ii);
      break;
    case IR_IC_ALLOCA:
      emit_alloca(iu, (ir_instr_alloca_t *)ii);
      break;
    case IR_IC_VAARG:
      emit_vaarg(iu, (ir_instr_unary_t *)ii);
      break;
    case IR_IC_SELECT:
      emit_select(iu, (ir_instr_select_t *)ii);
      break;
    case IR_IC_VMOP:
      emit_vmop(iu, (ir_instr_call_t *)ii);
      break;
    case IR_IC_LANDINGPAD:
      emit_landingpad(iu, (ir_instr_landingpad_t *)ii);
      break;
    case IR_IC_RESUME:
      emit_resume(iu, (ir_instr_resume_t *)ii);
      break;
    case IR_IC_STACKCOPY:
      emit_stackcopy(iu, (ir_instr_stackcopy_t *)ii);
      break;
    case IR_IC_STACKSHRINK:
      emit_stackshrink(iu, (ir_instr_stackshrink_t *)ii);
      break;
    case IR_IC_UNREACHABLE:
      emit_op(iu, VM_UNREACHABLE);
      break;
    case IR_IC_CMP_BRANCH:
      emit_cmp_branch(iu, (ir_instr_cmp_branch_t *)ii);
      break;
    case IR_IC_CMP_SELECT:
      emit_cmp_select(iu, (ir_instr_cmp_select_t *)ii);
      break;
    case IR_IC_MLA:
      emit_mla(iu, (ir_instr_ternary_t *)ii);
      break;
    default:
      parser_error(iu, "Unable to emit instruction %d", ii->ii_class);
    }
  }
}


/**
 *
 */
static int16_t
bb_to_offset_delta(ir_unit_t *iu, ir_function_t *f, int bbi, int off)
{
  ir_bb_t *bb = bb_find(f, bbi);
  if(bb == NULL) {
    vmir_log(iu, VMIR_LOG_FAIL, "%s() basic block %d not found during fixup",
             f->if_name, bbi);
    abort();
  }
  // The 2 is here because we need to compensate that the instruction
  // stream is past the opcode when the branch is executed
  int o = bb->ib_text_offset - (off + 2);

  assert(o >= INT16_MIN);
  assert(o <= INT16_MAX);
  return o;
}


/**
 * Finalize branch instructions.
 *
 * At time when we emitted them we didn't know where all basic blocks
 * started and ends, so we fix that now
 */
static void
branch_fixup(ir_unit_t *iu)
{
  ir_function_t *f = iu->iu_current_function;
  int x = VECTOR_LEN(&iu->iu_branch_fixups);
  int p;
  for(int i = 0; i < x; i++) {
    int off = VECTOR_ITEM(&iu->iu_branch_fixups, i);

    uint16_t *I = f->if_vm_text + off;
    switch(I[0]) {
    case VM_B:
      I[1] = bb_to_offset_delta(iu, f, I[1], off);
      break;
    case VM_BCOND:
      I[2] = bb_to_offset_delta(iu, f, I[2], off);
      I[3] = bb_to_offset_delta(iu, f, I[3], off);
      break;
    case VM_INVOKE:
    case VM_INVOKE_VM:
    case VM_INVOKE_EXT:
    case VM_INVOKE_R:
      I[4] = bb_to_offset_delta(iu, f, I[4], off);
      I[5] = bb_to_offset_delta(iu, f, I[5], off);
      break;
    case VM_EQ8_BR ... VM_SLE32_C_BR:
      I[1] = bb_to_offset_delta(iu, f, I[1], off);
      I[2] = bb_to_offset_delta(iu, f, I[2], off);
      break;
    case VM_JUMPTABLE:
      for(int j = 0; j < I[2]; j++) // one extra for default path (first)
        I[3 + j] = bb_to_offset_delta(iu, f, I[3 + j], off);
      break;

    case VM_SWITCH8_BS:
      p = I[2];
      for(int j = 0; j < p + 1; j++)
        I[3 + p + j] = bb_to_offset_delta(iu, f, I[3 + p + j], off);
      break;
    case VM_SWITCH32_BS:
      p = I[2];
      for(int j = 0; j < p + 1; j++)
        I[3 + p * 2 + j] = bb_to_offset_delta(iu, f, I[3 + p * 2 + j], off);
      break;
    case VM_SWITCH64_BS:
      p = I[2];
      for(int j = 0; j < p + 1; j++)
        I[3 + p * 4 + j] = bb_to_offset_delta(iu, f, I[3 + p * 4 + j], off);
      break;
    default:
      parser_error(iu, "Bad branch temporary opcode %d", I[0]);
    }
    I[0] = vm_resolve(I[0]);
  }
}



/**
 *
 */
static void
vm_emit_function(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *ib;
  ir_instr_t *i;

  iu->iu_text_ptr = iu->iu_text_alloc;

  VECTOR_RESIZE(&iu->iu_branch_fixups, 0);
  VECTOR_RESIZE(&iu->iu_jit_vmbb_fixups, 0);
  VECTOR_RESIZE(&iu->iu_jit_branch_fixups, 0);
  VECTOR_RESIZE(&iu->iu_jit_bb_to_addr_fixups, 0);

#ifdef VM_TRACE
  int total_instructions = 0;
  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(i, &ib->ib_instrs, ii_link) {
      total_instructions++;
    }
  }
  f->if_instr_backrefs = calloc(total_instructions, sizeof(ir_instr_backref_t));
  f->if_instr_backref_size = 0;
#endif

#ifdef VMIR_VM_JIT
  jitctx_t jc;
  jitctx_init(iu, f, &jc);
  f->if_jit_offset = iu->iu_jit_ptr;
#endif

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
#ifdef VMIR_VM_JIT
    if(f->if_full_jit) {
      jit_emit(iu, ib, &jc);
      continue;
    }
#endif
    ib->ib_text_offset = iu->iu_text_ptr - iu->iu_text_alloc;
    if(iu->iu_debug_flags_func & VMIR_DBG_BB_INSTRUMENT) {
      emit_op(iu, VM_INSTRUMENT_COUNT);
      emit_i32(iu, VECTOR_LEN(&iu->iu_instrumentation));

      int num_instructions = 0;
      TAILQ_FOREACH(i, &ib->ib_instrs, ii_link)
        num_instructions++;

      ir_instrumentation_t ii = {f, ib->ib_id, num_instructions, 0};
      VECTOR_PUSH_BACK(&iu->iu_instrumentation, ii);
    }
    instr_emit(iu, ib, f
#ifdef VMIR_VM_JIT
               ,&jc
#endif
               );
  }

#ifdef VMIR_VM_JIT
  jitctx_done(iu, f, &jc);
#endif
  f->if_vm_text_size = iu->iu_text_ptr - iu->iu_text_alloc;
  if(f->if_full_jit) {
    assert(f->if_vm_text_size == 0);
    f->if_ext_func = iu->iu_jit_mem + f->if_jit_offset;
  } else {
    f->if_vm_text = malloc(f->if_vm_text_size);
    memcpy(f->if_vm_text, iu->iu_text_alloc, f->if_vm_text_size);

    iu->iu_stats.vm_code_size += f->if_vm_text_size;
    branch_fixup(iu);
  }
#ifdef VMIR_VM_JIT
  jit_branch_fixup(iu, f);
#endif
}



 

/**
 *
 */
static void
function_process(ir_unit_t *iu, ir_function_t *f)
{
  //  assert(iu->iu_next_value == VECTOR_LEN(&iu->iu_values));
  if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_PARSED_FUNCTION)
    function_print(iu, iu->iu_current_function, "parsed");

  transform_function(iu, f);

  if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_LOWERED_FUNCTION)
    function_print(iu, iu->iu_current_function, "lowered");

  vm_emit_function(iu, f);
}





typedef struct {
  const char *name;
  vm_op_t vmop;
  int vmop_args;
} vmop_tab_t;

#define FN_VMOP(a,b,c) { .name = a, .vmop = b, .vmop_args = c}

static const vmop_tab_t vmop_map[] = {
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
  FN_VMOP("llvm.umul.with.overflow.i32", VM_UMULO32, 2),

  FN_VMOP("memcpy",  VM_MEMCPY, 3),
  FN_VMOP("memmove", VM_MEMMOVE, 3),
  FN_VMOP("memset",  VM_MEMSET, 3),
  FN_VMOP("memcmp",  VM_MEMCMP, 3),

  FN_VMOP("strcmp",  VM_STRCMP, 2),
  FN_VMOP("strcasecmp",  VM_STRCASECMP, 2),
  FN_VMOP("strchr",  VM_STRCHR, 2),
  FN_VMOP("strrchr", VM_STRRCHR, 2),
  FN_VMOP("strlen",  VM_STRLEN, 1),
  FN_VMOP("strcpy",  VM_STRCPY, 2),
  FN_VMOP("strncpy", VM_STRNCPY, 3),
  FN_VMOP("strcat",  VM_STRCAT, 2),
  FN_VMOP("strncat",  VM_STRNCAT, 3),
  FN_VMOP("strncmp", VM_STRNCMP, 3),
  FN_VMOP("strdup",  VM_STRDUP, 1),


  FN_VMOP("llvm.va_start", VM_VASTART, 2),

  FN_VMOP("abs",   VM_ABS, 1),

  FN_VMOP("floor", VM_FLOOR, 1),
  FN_VMOP("sin",   VM_SIN,   1),
  FN_VMOP("cos",   VM_COS,   1),
  FN_VMOP("pow",   VM_POW,   2),
  FN_VMOP("fabs",  VM_FABS,  1),
  FN_VMOP("fmod",  VM_FMOD,  2),
  FN_VMOP("log",   VM_LOG,   1),
  FN_VMOP("log10", VM_LOG10, 1),
  FN_VMOP("round", VM_ROUND, 1),
  FN_VMOP("sqrt",  VM_SQRT,  1),
  FN_VMOP("exp",   VM_EXP,   1),
  FN_VMOP("ceil",  VM_CEIL,  1),

  FN_VMOP("floorf", VM_FLOORF, 1),
  FN_VMOP("sinf",   VM_SINF,   1),
  FN_VMOP("cosf",   VM_COSF,   1),
  FN_VMOP("powf",   VM_POWF,   2),
  FN_VMOP("fabsf",  VM_FABSF,  1),
  FN_VMOP("fmodf",  VM_FMODF,  2),
  FN_VMOP("logf",   VM_LOGF,   1),
  FN_VMOP("log10f", VM_LOG10F, 1),
  FN_VMOP("roundf", VM_ROUNDF, 1),
  FN_VMOP("sqrtf",  VM_SQRTF,  1),
  FN_VMOP("expf",   VM_EXPF,   1),
  FN_VMOP("ceilf",  VM_CEILF,  1),

  FN_VMOP("llvm.floor.f64", VM_FLOOR, 1),
  FN_VMOP("llvm.floor.f32", VM_FLOORF, 1),
};



/**
 *
 */
static int
vmop_resolve(ir_function_t *f)
{
  f->if_vmop = 0;

  for(int i = 0; i < VMIR_ARRAYSIZE(vmop_map); i++) {
    const vmop_tab_t *vt = &vmop_map[i];
    if(!strcmp(f->if_name, vt->name)) {
      f->if_vmop = vt->vmop;
      f->if_vmop_args = vt->vmop_args;
      return 1;
    }
  }
  return 0;
}


/**
 *
 */
int
vmir_vm_function_call(ir_unit_t *iu, ir_function_t *f, void *out, ...)
{
  va_list ap;
  const ir_type_t *it = &VECTOR_ITEM(&iu->iu_types, f->if_type);
  uint32_t u32;
  uint64_t u64;
  int argpos = 0;
  jmp_buf jb;
  uint64_t dummy;

  va_start(ap, out);

  argpos += it->it_function.num_parameters * sizeof(uint32_t);

  void *rf = alloca(4096 * sizeof(uint32_t));
  void *rfa = rf + argpos;

  for(int i = 0; i < it->it_function.num_parameters; i++) {
    const ir_type_t *arg = &VECTOR_ITEM(&iu->iu_types,
                                        it->it_function.parameters[i]);
    switch(legalize_type(arg)) {
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
      argpos -= 4;
      u32 = va_arg(ap, int);
      *(uint32_t *)(rf + argpos) = u32;
      break;
    case IR_TYPE_INT64:
      argpos -= 8;
      u64 = va_arg(ap, uint64_t);
      *(uint64_t *)(rf + argpos) = u64;
      break;

    default:
      vmir_log(iu, VMIR_LOG_FAIL,
               "Unable to encode argument %d (%s) in call to %s",
               i, type_str(iu, arg), f->if_name);
      return VM_STOP_BAD_ARGUMENTS;
    }
  }

  uint32_t allocaptr;

  if(iu->iu_stack_stash) {
    allocaptr = iu->iu_stack_stash;
    iu->iu_stack_stash = 0;
  } else {
    allocaptr = vmir_mem_alloc(iu, iu->iu_asize, NULL);
    if(allocaptr == 0) {
      vmir_log(iu, VMIR_LOG_FAIL,
               "Unable allocate memory for stack when calling %s()",
               f->if_name);
      return VM_STOP_OUT_OF_MEMROY;
    }
  }

#ifndef VM_NO_STACK_FRAME
    uint32_t allocapeak = allocaptr;
#endif

  jmp_buf *prevjb = iu->iu_err_jmpbuf;
  iu->iu_err_jmpbuf = &jb;

  int r = setjmp(jb);
  if(!r) {
    if(out == NULL)
      out = &dummy;

    vm_frame_t F = {
      .iu = iu,
      .allocaptr = allocaptr,
#ifndef VM_NO_STACK_FRAME
      .func = f,
      .allocapeak = &allocapeak,
#endif
    };

    if(f->if_ext_func != NULL) {
      r = f->if_ext_func(out, rfa, iu, iu->iu_mem);
    } else {
      r = vm_exec(f->if_vm_text, rfa, out, &F);
    }

    if(r == 1)
      r = VM_STOP_UNCAUGHT_EXCEPTION;
  }
  iu->iu_err_jmpbuf = prevjb;

#ifndef VM_NO_STACK_FRAME
  uint32_t stackuse = allocapeak - allocaptr;

  if(stackuse > f->if_peak_stack_use) {
    f->if_peak_stack_use = stackuse;
    if(allocapeak - allocaptr > iu->iu_asize) {
      vmir_log(iu, VMIR_LOG_ERROR, "%s() peak stack usage: %d > avail: %d",
               f->if_name, allocapeak - allocaptr, iu->iu_asize);
    } else {
      iu->iu_stats.peak_stack_size =
        VMIR_MAX(iu->iu_stats.peak_stack_size, stackuse);
      vmir_log(iu, VMIR_LOG_DEBUG, "%s() peak stack usage: %d",
               f->if_name, allocapeak - allocaptr);
    }
  }
#endif

  if(iu->iu_stack_stash == 0) {
    iu->iu_stack_stash = allocaptr;
  } else {
    vmir_mem_free(iu, allocaptr);
  }

  switch(r) {
  case 0:
    break;
  case VM_STOP_EXIT:
    vmir_log(iu, VMIR_LOG_INFO, "exit(0x%x) called", iu->iu_exit_code);
    break;
  case VM_STOP_ABORT:
    vmir_log(iu, VMIR_LOG_ERROR, "abort() called");
    break;
  case VM_STOP_UNREACHABLE:
    vmir_log(iu, VMIR_LOG_ERROR, "Unreachable instruction");
    break;
  case VM_STOP_BAD_INSTRUCTION:
    vmir_log(iu, VMIR_LOG_FAIL, "Illegal instruction");
    break;
  case VM_STOP_BAD_FUNCTION:
    vmir_log(iu, VMIR_LOG_FAIL, "Bad function %s", iu->iu_exit_code);
    break;
  case VM_STOP_UNCAUGHT_EXCEPTION:
    vmir_log(iu, VMIR_LOG_ERROR, "Uncaught exception");
    break;
  case VM_STOP_ACCESS_VIOLATION:
    vmir_log(iu, VMIR_LOG_ERROR, "Access violation");
    break;
  }
  return r;
}


#ifdef VM_TRACE
static void
vmir_access_violation(struct ir_unit *iu, const void *p, const char *func)
{
  vmir_log(iu, VMIR_LOG_FAIL, "Access violation in %s @ %zx",
           func, p - iu->iu_mem);
  vmir_log(iu, VMIR_LOG_FAIL, "Host mem base @ %p (%p - %p) trap address: %p",
           iu->iu_mem,
           iu->iu_mem_low,
           iu->iu_mem_high,
           p);
  vm_stop(iu, VM_STOP_ACCESS_VIOLATION, 0);
}


static void
vmir_access_trap(struct ir_unit *iu, const void *p, const char *func)
{
  vmir_log(iu, VMIR_LOG_FAIL, "Data breakpoint in %s @ %zx",
           func, p - iu->iu_mem);
  vmir_log(iu, VMIR_LOG_FAIL, "Host mem base @ %p (%p - %p) trap address: %p",
           iu->iu_mem,
           iu->iu_mem_low,
           iu->iu_mem_high,
           p);
  vmir_traceback(iu, "data breakpoint");
}
#endif
