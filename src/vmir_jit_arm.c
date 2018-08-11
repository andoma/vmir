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

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define ARM_COND_EQ  0x00000000
#define ARM_COND_NE  0x10000000
#define ARM_COND_UGT 0x80000000
#define ARM_COND_UGE 0x20000000
#define ARM_COND_ULT 0x30000000
#define ARM_COND_ULE 0x90000000
#define ARM_COND_SGT 0xc0000000
#define ARM_COND_SGE 0xa0000000
#define ARM_COND_SLT 0xb0000000
#define ARM_COND_SLE 0xd0000000
#define ARM_COND_AL  0xe0000000


#define VMIR_VM_JIT


/**
 * Convert LLVM pred to ARM cond
 */
static uint32_t
armcond(int pred)
{
  uint32_t cond;
  switch(pred) {
  case ICMP_EQ:   cond = ARM_COND_EQ;  break;
  case ICMP_NE:   cond = ARM_COND_NE;  break;
  case ICMP_UGT:  cond = ARM_COND_UGT; break;
  case ICMP_UGE:  cond = ARM_COND_UGE; break;
  case ICMP_ULT:  cond = ARM_COND_ULT; break;
  case ICMP_ULE:  cond = ARM_COND_ULE; break;
  case ICMP_SGT:  cond = ARM_COND_SGT; break;
  case ICMP_SGE:  cond = ARM_COND_SGE; break;
  case ICMP_SLT:  cond = ARM_COND_SLT; break;
  case ICMP_SLE:  cond = ARM_COND_SLE; break;
  default:
    abort();
  }
  return cond;
}



static int
arm_machinereg(int reg)
{
  if(reg < 5)
    return reg + 4;  // r4, r5, r6, r7, r8
  return reg + 5;    // r10, r11
}

#define JIT_MACHINE_REGS 7

/**
 * Registers
 *
 *   r0 - return value pointer
 *   r1 - Register frame
 *   r2 - Stack frame, also used as TMP-C
 *   r3 - Memory
 *   r4 - r8 "machine registers"
 *   r9 - TMP-B
 *  r10 - r11 "machine registers"
 *  r14 - Link register, used for TMP-A
 */


#define REG_SAVE_MASK    0x4ff0
#define REG_RESTORE_MASK 0x8ff0

/**
 * Registers
 */
#define R_RET     0
#define R_VMSTACK 1
#define R_TMPC    2
#define R_MEM     3
#define R_TMPB    9
#define R_TMPA    14
#define R_PC      15

#define LITERAL_POOL_MAX_SIZE 256

#define LITERAL_POOL_CONSTANT 0
#define LITERAL_POOL_VMBB 1

typedef struct jitctx {

  int literal_pool_use;
  struct {
    uint32_t value;
    uint32_t instr;
    int type;
  } literal_pool[LITERAL_POOL_MAX_SIZE];
} jitctx_t;


static int rotr32(uint32_t v, uint32_t bits)
{
  return (v >> bits) | (v << (32 - bits));
}

/**
 *
 */
static int
rotl32(uint32_t v, uint32_t bits)
{
  return (v << bits) | (v >> (32 - bits));
}

/**
 *
 */
static int
make_imm12(uint32_t v)
{
  if((v & 0xffffff00) == 0)
    return v;

  int rot = __builtin_ctz(v) & ~1;
  uint32_t v2 = rotr32(v, rot);
  if((v2 & 0xffffff00) == 0) {
    rot = 32 - rot;
    return rotl32(v, rot) | (rot << 7);
  }
  return -1;
}


/**
 *
 */
static void
jit_push(ir_unit_t *iu, uint32_t opcode)
{
  if(iu->iu_jit_ptr + 4 >= iu->iu_jit_mem_alloced) {
    assert(iu->iu_jit_mem == NULL); // TODO, realloc when we run out of space

    iu->iu_jit_mem_alloced = 1024 * 1024 * 16;
    iu->iu_jit_mem = mmap(NULL, iu->iu_jit_mem_alloced,
                          PROT_EXEC | PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  }
  uint32_t *p = iu->iu_jit_mem + iu->iu_jit_ptr;
  *p = opcode;
  iu->iu_jit_ptr += 4;
}


/**
 *
 */
static void
jit_pushal(ir_unit_t *iu, uint32_t opcode)
{
  jit_push(iu, opcode | ARM_COND_AL);
}


/**
 *
 */
static void
jit_push_literal_pool(ir_unit_t *iu, jitctx_t *jc)
{
  for(int i = 0; i < jc->literal_pool_use; i++) {
    int imm12 = iu->iu_jit_ptr - jc->literal_pool[i].instr - 8;
    assert(imm12 < 4096);
    uint32_t *p = iu->iu_jit_mem + jc->literal_pool[i].instr;

    switch(jc->literal_pool[i].type) {
    case LITERAL_POOL_VMBB:
      VECTOR_PUSH_BACK(&iu->iu_jit_vmbb_fixups, iu->iu_jit_ptr);
      break;
    }
    *p |= imm12;
    jit_push(iu, jc->literal_pool[i].value);
  }
  jc->literal_pool_use = 0;
}


/**
 *
 */
static void
jit_loadimm_from_literal_pool_cond(ir_unit_t *iu, uint32_t imm, int Rd,
                                   int type, jitctx_t *jc,
                                   uint32_t cond)
{
  assert(jc->literal_pool_use != LITERAL_POOL_MAX_SIZE);

  jc->literal_pool[jc->literal_pool_use].value = imm;
  jc->literal_pool[jc->literal_pool_use].instr = iu->iu_jit_ptr;
  jc->literal_pool[jc->literal_pool_use].type = type;
  jc->literal_pool_use++;
  jit_push(iu, cond | (1 << 26) | (1 << 24) | (1 << 23) | (0x1f << 16) |
           (Rd << 12));
}

static void
jit_loadimm_from_literal_pool(ir_unit_t *iu, uint32_t imm, int Rd,
                              int type, jitctx_t *jc)
{
  jit_loadimm_from_literal_pool_cond(iu, imm, Rd, type, jc,
                                     ARM_COND_AL);
}


/**
 *
 */
static void
jit_loadimm_cond(ir_unit_t *iu, uint32_t imm, int Rd, jitctx_t *jc, uint32_t cond)
{
  int imm12 = make_imm12(imm);
  if(imm12 != -1) {
    // MOV A1 encoding
    jit_push(iu, cond | (1 << 25) | (1 << 24) | (1 << 23) | (1 << 21) |
             (Rd << 12) | imm12);
    return;
  }
  imm12 = make_imm12(~imm);
  if(imm12 != -1) {
    // MVN A1 encoding
    jit_push(iu, cond |
             (1 << 25) | (1 << 24) | (1 << 23) | (1 << 22) | (1 << 21) |
             (Rd << 12) | imm12);
    return;
  }

  // MOV A2 encoding ...
  // ... is only available on ARMv7 so play it safe and only emit it
  // if IDIV is available. Not sure if there is a better way to detect
  if((uint32_t)imm <= 0xffff && iu->iu_jit_cpuflags & (1 << 17)) {
    jit_push(iu, cond | (1 << 25) | (1 << 24) |
             ((imm & 0xf000) << 4) | (Rd << 12) | (imm & 0xfff));
    return;
  }
  jit_loadimm_from_literal_pool_cond(iu, imm, Rd, 0, jc, cond);
}


/**
 *
 */
static void
jit_loadimm(ir_unit_t *iu, uint32_t imm, int Rd, jitctx_t *jc)
{
  return jit_loadimm_cond(iu, imm, Rd, jc, ARM_COND_AL);
}


/**
 *
 */
static void
jit_push_add_imm(ir_unit_t *iu, int Rd, int Rn, int imm, int tmpreg,
                 jitctx_t *jc)
{
  int imm12 = make_imm12(imm);
  if(imm12 != -1) {
    jit_pushal(iu, (1 << 25) | (1 << 23) | (Rn << 16) | (Rd << 12) | imm12);
  } else {
    jit_loadimm(iu, imm, tmpreg, jc);
    jit_pushal(iu, (1 << 23) | (Rn << 16) | (Rd << 12) | tmpreg);
  }
}


/**
 *
 */
static uint32_t
jit_offset_to_imm12_U(int off)
{
  assert(off < 4096 && off > -4096);
  return off < 0 ? -off : off | (1 << 23);
}


static int
jit_offset_to_imm8_U(int offset)
{
  if(offset < 256 && offset > -256) {
    uint32_t U = 1 << 23;
    if(offset < 0) {
      offset = -offset;
      U = 0;
    }
    return (offset & 0xf) | ((offset & 0xf0) << 4) | U;
  }
  return -1;

}


/**
 * Load a value into a register
 *
 * If the value is a constant or stored on the regframe the register
 * passed in 'reg' is used as a temoprary
 *
 * If the value is stored in a machine register, that register is returned
 */
#define JIT_LOAD_EXT_NONE     0
#define JIT_LOAD_EXT_UNSIGNED 1
#define JIT_LOAD_EXT_SIGNED   2

static int __attribute__((warn_unused_result))
jit_loadvalue_cond(ir_unit_t *iu, ir_valuetype_t vt, int reg, jitctx_t *jc,
                   uint32_t cond, int ext)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  const ir_type_t *it = type_get(iu, vt.type);
  int mr;
  int imm8;
  switch(iv->iv_class) {
  case IR_VC_MACHINEREG:

    mr = arm_machinereg(iv->iv_reg);

    switch(legalize_type(it)) {
    case IR_TYPE_INT8:
      if(ext == JIT_LOAD_EXT_SIGNED) {
        // SXTB
        jit_push(iu, cond | (1 << 26) | (1 << 25) |
                 (1 << 23) | (1 << 21) | 0xf0070 |
                 (reg << 12) | mr);
        return reg;
      }
      if(ext == JIT_LOAD_EXT_UNSIGNED) {
        // UXTB
        jit_push(iu, cond | (1 << 26) | (1 << 25) |
                 (1 << 23) | (1 << 22) | (1 << 21) | 0xf0070 |
                 (reg << 12) | mr);
        return reg;
      }
      break;

    case IR_TYPE_INT16:
      if(ext == JIT_LOAD_EXT_SIGNED) {
        // SXTH
        jit_push(iu, cond | (1 << 26) | (1 << 25) |
                 (1 << 23) | (1 << 21) | (1 << 20) | 0xf0070 |
                 (reg << 12) | mr);
        return reg;
      }
      if(ext == JIT_LOAD_EXT_UNSIGNED) {
        // UXTH
        jit_push(iu, cond | (1 << 26) | (1 << 25) |
                 (1 << 23) | (1 << 22) | (1 << 21) | (1 << 20) | 0xf0070 |
                 (reg << 12) | mr);
        return reg;
      }
      break;

    case IR_TYPE_INT1:
    case IR_TYPE_INT32:
    case IR_TYPE_FLOAT:
    case IR_TYPE_POINTER:
      break;
    }
    return mr;

  case IR_VC_REGFRAME:
    switch(legalize_type(it)) {
    case IR_TYPE_INT8:
      if(ext == JIT_LOAD_EXT_UNSIGNED) {
        // LDRB
        jit_push(iu, cond | (1 << 26) | (1 << 24) | (1 << 22) | (1 << 20) |
                 (R_VMSTACK << 16) | (reg << 12) |
                 jit_offset_to_imm12_U(iv->iv_reg));
        break;
      }
      if(ext == JIT_LOAD_EXT_SIGNED) {
        imm8 = jit_offset_to_imm8_U(iv->iv_reg);
        if(imm8 != -1) {
          // LDRSB
          jit_push(iu, cond | (1 << 24) | (1 << 22) | (1 << 20) |
                   (R_VMSTACK << 16) | (reg << 12) | imm8 | 0xd0);
          break;
        }

        printf("JIT_LOAD_EXT_SIGNED i8 from regframe not supported\n");
        abort();
      }
      goto load32;

    case IR_TYPE_INT16:
      if(ext == JIT_LOAD_EXT_UNSIGNED) {
        imm8 = jit_offset_to_imm8_U(iv->iv_reg);
        if(imm8 != -1) {
          // LDRH
          jit_push(iu, cond | (1 << 24) | (1 << 22) | (1 << 20) |
                   (R_VMSTACK << 16) | (reg << 12) | imm8 | 0xb0);
          break;
        }

        printf("JIT_LOAD_EXT_UNSIGNED i16 from regframe not supported\n");
        abort();
      }
      if(ext == JIT_LOAD_EXT_SIGNED) {
        imm8 = jit_offset_to_imm8_U(iv->iv_reg);
        if(imm8 != -1) {
          // LDRSH
          jit_push(iu, cond | (1 << 24) | (1 << 22) | (1 << 20) |
                   (R_VMSTACK << 16) | (reg << 12) | imm8 | 0xf0);
          break;
        }

        printf("JIT_LOAD_EXT_SIGNED i16 from regframe not supported\n");
        abort();
      }
      goto load32;

    case IR_TYPE_INT1:
    case IR_TYPE_INT32:
    case IR_TYPE_FLOAT:
    case IR_TYPE_POINTER:
    load32:
      jit_push(iu, cond | (1 << 26) | (1 << 24) | (1 << 20) |
               (R_VMSTACK << 16) | (reg << 12) |
               jit_offset_to_imm12_U(iv->iv_reg));
      break;
    default:
      parser_error(iu, "JIT: Can't load value typecode %d", it->it_code);
    }
    break;
  case IR_VC_CONSTANT:
  case IR_VC_GLOBALVAR:
    jit_loadimm_cond(iu, ext == JIT_LOAD_EXT_SIGNED ?
                     value_get_const32(iu, iv) : value_get_const(iu, iv),
                     reg, jc, cond);
    break;
  case IR_VC_FUNCTION:
    jit_loadimm_cond(iu, value_function_addr(iv), reg, jc, cond);
    break;
  default:
    parser_error(iu, "JIT: Can't load value-class %d", iv->iv_class);
  }
  return reg;
}


/**
 *
 */
static int __attribute__((warn_unused_result))
jit_loadvalue(ir_unit_t *iu, ir_valuetype_t vt, int reg, jitctx_t *jc)
{
  return jit_loadvalue_cond(iu, vt, reg, jc, ARM_COND_AL, 0);
}


/**
 *
 */
static int
jit_storevalue_reg(ir_unit_t *iu, ir_valuetype_t vt, int reg)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  if(iv->iv_class == IR_VC_MACHINEREG)
    return arm_machinereg(iv->iv_reg);
  return reg;
}


/**
 *
 */
static void
jit_storevalue_cond(ir_unit_t *iu, ir_valuetype_t vt, int reg, uint32_t cond)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  const ir_type_t *it = type_get(iu, vt.type);

  switch(iv->iv_class) {
  case IR_VC_MACHINEREG:
    if(arm_machinereg(iv->iv_reg) != reg) {
      int Rd = arm_machinereg(iv->iv_reg);
      int Rm = reg;
      // MOV
      jit_push(iu, cond | (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rm);
    }
    return;

  case IR_VC_REGFRAME:
    switch(legalize_type(it)) {
    case IR_TYPE_INT1:
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_FLOAT:
    case IR_TYPE_POINTER:
      jit_push(iu, cond | (1 << 26) | (1 << 24) |
                 (R_VMSTACK << 16) | (reg << 12) |
                 jit_offset_to_imm12_U(iv->iv_reg));
      break;
    default:
      parser_error(iu, "JIT: Can't store value typecode %d", it->it_code);
    }
    break;
  default:
    parser_error(iu, "JIT: Can't store value-class %d", iv->iv_class);
  }
}


static void
jit_storevalue(ir_unit_t *iu, ir_valuetype_t vt, int reg)
{
  return jit_storevalue_cond(iu, vt, reg, ARM_COND_AL);
}


/**
 *
 */
static int
jit_binop_check(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  const int binop = ii->op;
  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));
  const ir_value_t *rhs;

  switch(binop) {
  case BINOP_SDIV:
  case BINOP_UDIV:
    if(!(iu->iu_jit_cpuflags & (1 << 17))) // Integer division
      return 0;
    if(typecode != IR_TYPE_INT32)
      return 0;
    break;

  case BINOP_SREM:
  case BINOP_UREM:
    return 0;

  case BINOP_ROL:
  case BINOP_ROR:
    rhs = value_get(iu, ii->rhs_value.value);
    if(rhs->iv_class != IR_VC_CONSTANT)
      return 0;
    break;

  case BINOP_ASHR:
    if(typecode != IR_TYPE_INT32)
      return 0;
    break;
  }

  switch(typecode) {
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_binop(ir_unit_t *iu, ir_instr_binary_t *ii, jitctx_t *jc)
{
  const int binop = ii->op;
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);

  int Rd = R_TMPA;
  int Rn = R_TMPA;
  int Rm = R_TMPB;

  Rd = jit_storevalue_reg(iu, ii->super.ii_ret, Rd);
  Rn = jit_loadvalue(iu, ii->lhs_value, Rn, jc);

  if(rhs->iv_class == IR_VC_CONSTANT) {
    int32_t rc = value_get_const(iu, rhs);
    int imm12;

    switch(binop) {
    case BINOP_SUB:
      rc = -rc;
    case BINOP_ADD:
      if((imm12 = make_imm12(rc)) != -1) {
        // ADD immediate
        jit_pushal(iu, (1 << 25) | (1 << 23) | (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      if((imm12 = make_imm12(-rc)) != -1) {
        // SUB immediate
        jit_pushal(iu, (1 << 25) | (1 << 22) | (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      break;

    case BINOP_OR:
      if((imm12 = make_imm12(rc)) != -1) {
        jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 23) |
                   (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      break;
    case BINOP_AND:
      if((imm12 = make_imm12(rc)) != -1) {
        jit_pushal(iu, (1 << 25) |
                   (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      if((imm12 = make_imm12(~rc)) != -1) {
        // BIC
        jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 23) | (1 << 22) |
                   (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      break;

    case BINOP_XOR:
      if((imm12 = make_imm12(rc)) != -1) {
        jit_pushal(iu, (1 << 25) | (1 << 21) |
                   (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      break;

    case BINOP_SHL:
      // LSL
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rn |
                 ((rc & 0x1f) << 7));
      goto wb;
    case BINOP_LSHR:
      if(rc != 0) {
        jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rn |
                   ((rc & 0x1f) << 7) | (1 << 5));
        goto wb;
      }
      break;
    case BINOP_ASHR:
      if(rc != 0) {
        jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rn |
                   ((rc & 0x1f) << 7) | (1 << 6));
        goto wb;
      }
      break;
    case BINOP_ROL:
      rc = 32 - rc;
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rn |
                 ((rc & 0x1f) << 7) | (1 << 6) | (1 << 5));
      goto wb;
    case BINOP_ROR:
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rn |
                 ((rc & 0x1f) << 7) | (1 << 6) | (1 << 5));
      goto wb;
    }
  }

  Rm = jit_loadvalue(iu, ii->rhs_value, Rm, jc);

  switch(binop) {
  case BINOP_ADD:
    jit_push(iu, ARM_COND_AL | (1 << 23) |
             (Rn << 16) | (Rd << 12) | Rm);
    break;
  case BINOP_SUB:
    jit_push(iu, ARM_COND_AL | (1 << 22) |
             (Rn << 16) | (Rd << 12) | Rm);
    break;
  case BINOP_MUL:
    jit_push(iu, ARM_COND_AL | 0x90 |
             (Rd << 16) | (Rm << 8) | Rn);
    break;
  case BINOP_OR:
    jit_push(iu, ARM_COND_AL | (1 << 24) | (1 << 23) |
             (Rn << 16) | (Rd << 12) | Rm);
    break;
  case BINOP_XOR:
    jit_push(iu, ARM_COND_AL | (1 << 21) |
             (Rn << 16) | (Rd << 12) | Rm);
    break;
  case BINOP_AND:
    jit_push(iu, ARM_COND_AL |
             (Rn << 16) | (Rd << 12) | Rm);
    break;
  case BINOP_SHL:
    jit_push(iu, ARM_COND_AL | (1 << 24) | (1 << 23) | (1 << 21) |
             (1 << 4) |
             (Rm << 8) | (Rd << 12) | Rn);
    break;
  case BINOP_LSHR:
    jit_push(iu, ARM_COND_AL | (1 << 24) | (1 << 23) | (1 << 21) |
             (1 << 5) | (1 << 4) |
             (Rm << 8) | (Rd << 12) | Rn);
    break;
  case BINOP_ASHR:
    jit_push(iu, ARM_COND_AL | (1 << 24) | (1 << 23) | (1 << 21) |
             (1 << 6) | (1 << 4) |
             (Rm << 8) | (Rd << 12) | Rn);
    break;
  case BINOP_SDIV:
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) | (1 << 20) |
             0xf000 | (1 << 4) |
             (Rm << 8) | (Rd << 16) | Rn);
    break;
  case BINOP_UDIV:
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) | (1 << 20) |
             (1 << 21) | 0xf000 | (1 << 4) |
             (Rm << 8) | (Rd << 16) | Rn);
    break;
  default:
    printf("armjit bad binop %d\n", binop);
    abort();
  }
 wb:
  jit_storevalue(iu, ii->super.ii_ret, Rd);
}


/**
 *
 */
static int
jit_move_check(ir_unit_t *iu, ir_instr_move_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->value.type));
  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
  case IR_TYPE_FLOAT:
    break;
  default:
    return 0;
  }

  return 1;
}


/**
 *
 */
static void
jit_move(ir_unit_t *iu, ir_instr_move_t *ii, jitctx_t *jc)
{
  int Rd = jit_storevalue_reg(iu, ii->super.ii_ret, R_TMPA);
  int Rn = jit_loadvalue(iu, ii->value, Rd, jc);
  jit_storevalue(iu, ii->super.ii_ret, Rn);
}



/**
 *
 */
static int
jit_compute_ea(ir_unit_t *iu, ir_valuetype_t baseptr,
               ir_valuetype_t value_offset,
               int value_offset_multiply, int immediate_offset,
               int preferred_reg,
               jitctx_t *jc)
{
  assert(preferred_reg != R_TMPB);

  int regoff = -1, shift = 0;
  if(value_offset.value >= 0) {
    regoff = jit_loadvalue(iu, value_offset, R_TMPB, jc);
    shift = ffs(value_offset_multiply) - 1;

    if((1 << shift) != value_offset_multiply) {
      jit_loadimm(iu, value_offset_multiply, R_TMPA, jc);
      jit_push(iu, ARM_COND_AL | 0x90 |
               (R_TMPB << 16) | (regoff << 8) | R_TMPA);
      regoff = R_TMPB;
      shift = 0;
    }
  }
  int ea = jit_loadvalue(iu, baseptr, preferred_reg, jc);

  if(regoff != -1) {
    jit_pushal(iu, (1 << 23) | (ea << 16) | (preferred_reg << 12) |
               (shift << 7) | regoff);
    ea = preferred_reg;
  }

  if(immediate_offset) {
    jit_push_add_imm(iu, preferred_reg, ea, immediate_offset, R_TMPB, jc);
    ea = preferred_reg;
  }
  return ea;
}


/**
 *
 */
static void
jit_lea(ir_unit_t *iu, ir_instr_lea_t *ii, jitctx_t *jc)
{
  jit_storevalue(iu, ii->super.ii_ret,
                 jit_compute_ea(iu, ii->baseptr, ii->value_offset,
                                ii->value_offset_multiply, ii->immediate_offset,
                                R_TMPA, jc));
}


/**
 *
 */
static int
jit_load_check(ir_unit_t *iu, ir_instr_load_t *ii)
{
  const ir_type_t *retty = type_get(iu, ii->super.ii_ret.type);

  switch(legalize_type(retty)) {
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
  case IR_TYPE_FLOAT:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_load(ir_unit_t *iu, ir_instr_load_t *ii, jitctx_t *jc)
{
  int ea = jit_compute_ea(iu, ii->ptr, ii->value_offset,
                          ii->value_offset_multiply, ii->immediate_offset,
                          R_TMPA, jc);

  int Rt = jit_storevalue_reg(iu, ii->super.ii_ret, R_TMPA);

  if(ii->cast != -1) {
    // Load + Cast
    ir_type_t *pointee = type_get(iu, ii->load_type);
    ir_type_t *retty = type_get(iu, ii->super.ii_ret.type);

    switch(COMBINE3(legalize_type(retty), legalize_type(pointee), ii->cast)) {
    case COMBINE3(IR_TYPE_INT32, IR_TYPE_INT8, CAST_ZEXT):
      // LDRB
      jit_pushal(iu, (1 << 26) | (1 << 25) | (1 << 24) | (1 << 23) |
                 (1 << 22) | (1 << 20) |
                 (R_MEM << 16) | (Rt << 12) | ea);
      break;
    case COMBINE3(IR_TYPE_INT32, IR_TYPE_INT8, CAST_SEXT):
      // LDRSB
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 20) |
                 (R_MEM << 16) | (Rt << 12) | 0xd0 | ea);
      break;

    case COMBINE3(IR_TYPE_INT32, IR_TYPE_INT16, CAST_ZEXT):
      // LDRH
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 20) |
               (R_MEM << 16) | (Rt << 12) | 0xb0 | ea);
      break;

    case COMBINE3(IR_TYPE_INT32, IR_TYPE_INT16, CAST_SEXT):
      // LDRSH
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 20) |
               (R_MEM << 16) | (Rt << 12) | 0xf0 | ea);
      break;
    }
  } else {

    ir_type_t *pointee = type_get(iu,  ii->super.ii_ret.type);

    switch(legalize_type(pointee)) {
    default:
      fprintf(stderr, "jit: Bad pointer type in load @ %d\n", __LINE__);
      abort();
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_FLOAT:
      // LDR
      jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) |
               (1 << 23) | (1 << 20) | (R_MEM << 16) | (Rt << 12) | ea);
      break;
    case IR_TYPE_INT16:
      // LDRH
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 20) |
               (R_MEM << 16) | (Rt << 12) | 0xb0 | ea);
      break;
    case IR_TYPE_INT8:
    case IR_TYPE_INT1:
      // LDRB
      jit_pushal(iu, (1 << 26) | (1 << 25) | (1 << 24) | (1 << 23) |
                 (1 << 22) | (1 << 20) |
                 (R_MEM << 16) | (Rt << 12) | ea);
      break;
    }
  }
  jit_storevalue(iu, ii->super.ii_ret, Rt);
}


/**
 *
 */
static int
jit_store_check(ir_unit_t *iu, ir_instr_store_t *ii)
{
  const ir_type_t *ty = type_get(iu, ii->value.type);

  switch(legalize_type(ty)) {
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
  case IR_TYPE_FLOAT:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_store(ir_unit_t *iu, ir_instr_store_t *ii, jitctx_t *jc)
{
  int ea = jit_loadvalue(iu, ii->ptr, R_TMPA, jc);

  if(ii->immediate_offset) {
    jit_push_add_imm(iu, R_TMPA, ea, ii->immediate_offset, R_TMPB, jc);
    ea = R_TMPA;
  }

  int Rt = jit_loadvalue(iu, ii->value, R_TMPB, jc);

  switch(legalize_type(type_get(iu, ii->value.type))) {
  default:
    fprintf(stderr, "jit: Bad pointer type in store @ %d\n", __LINE__);
    abort();
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
  case IR_TYPE_FLOAT:
    // STR
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) |
             (1 << 23) | (R_MEM << 16) | (Rt << 12) | ea);
    break;
  case IR_TYPE_INT16:
    // STRH
    jit_pushal(iu, (1 << 24) | (1 << 23) |
               (R_MEM << 16) | (Rt << 12) | 0xb0 | ea);
    break;
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
    // STRB
    jit_pushal(iu, (1 << 26) | (1 << 25) | (1 << 24) | (1 << 23) |
               (1 << 22) |
               (R_MEM << 16) | (Rt << 12) | ea);
    break;
  }
}



/**
 *
 */
static int
jit_mla_check(ir_unit_t *iu, ir_instr_ternary_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->super.ii_ret.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_mla(ir_unit_t *iu, ir_instr_ternary_t *ii, jitctx_t *jc)
{
  int Rd = jit_storevalue_reg(iu, ii->super.ii_ret, R_TMPA);
  int Rn = jit_loadvalue(iu, ii->arg1, R_TMPA, jc);
  int Rm = jit_loadvalue(iu, ii->arg2, R_TMPB, jc);
  int Ra;
  if(Rn != R_TMPA) {
    Ra = jit_loadvalue(iu, ii->arg3, R_TMPA, jc);
  } else if(Rm != R_TMPB) {
    Ra = jit_loadvalue(iu, ii->arg3, R_TMPB, jc);
  } else {
    Ra = jit_loadvalue(iu, ii->arg3, R_TMPC, jc);
  }

  jit_pushal(iu, (1 << 21) | (Rd << 16) | (Ra << 12) | (Rm << 8) | 0x90 | Rn);
  jit_storevalue(iu, ii->super.ii_ret, Rd);
}


/**
 *
 */
static void
jit_emit_conditional_branch(ir_unit_t *iu, int true_bb, int false_bb, int pred,
                            jitctx_t *jc, ir_bb_t *curbb)
{
  ir_bb_t *tib  = bb_find(iu->iu_current_function, true_bb);
  ir_bb_t *fib = bb_find(iu->iu_current_function, false_bb);
  const int true_cond = armcond(pred);
  int false_cond = ARM_COND_AL;
  int may_push_pool = 1;

  if(tib->ib_jit) {
    if(tib->ib_only_jit_sucessors && TAILQ_NEXT(curbb, ib_link) == tib) {
      // Jumping to consecutive BB can be skipped
      false_cond = armcond(invert_pred(pred));
      may_push_pool = 0;
    } else {
      // Jumping to another JITen instruction, emit a branch
      VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
      jit_push(iu, true_cond | (1 << 27) | (1 << 25) | true_bb);
    }
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    jit_loadimm_from_literal_pool_cond(iu, true_bb, 0, LITERAL_POOL_VMBB,
                                       jc, true_cond);
    jit_push(iu, true_cond | (0x8bd << 16) | REG_RESTORE_MASK);
  }

  if(fib->ib_jit) {
    if(fib->ib_only_jit_sucessors && TAILQ_NEXT(curbb, ib_link) == fib) {
      // Jumping to consecutive BB can be skipped
      may_push_pool = 0;
    } else {
      // Jumping to another JITen instruction, emit a branch
      VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
      jit_push(iu, false_cond | (1 << 27) | (1 << 25) | false_bb);
    }
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    jit_loadimm_from_literal_pool_cond(iu, false_bb, 0, LITERAL_POOL_VMBB,
                                       jc, false_cond);
    jit_push(iu, false_cond | (0x8bd << 16) | REG_RESTORE_MASK);
  }

  if(may_push_pool)
    jit_push_literal_pool(iu, jc);
}



/**
 *
 */
static int
jit_br_check(ir_unit_t *iu, ir_instr_br_t *ii)
{
  return 1;
}


/**
 *
 */
static void
jit_br(ir_unit_t *iu, ir_instr_br_t *ii, jitctx_t *jc, ir_bb_t *curbb)
{
  if(ii->condition.value != -1) {
    int Rn = jit_loadvalue(iu, ii->condition, R_TMPA, jc);
    // CMP immediate (check if equal to zero)
    jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 22) | (1 << 20) | (Rn << 16));
    // Jump to true if condition is not true (makes sure 0 == false, all else is true)
    jit_emit_conditional_branch(iu, ii->true_branch,
                                ii->false_branch, ICMP_NE, jc, curbb);
    return;
  }
  // Unconditional branch
  ir_bb_t *ib = bb_find(iu->iu_current_function, ii->true_branch);
  if(ib->ib_jit) {
    if(TAILQ_NEXT(curbb, ib_link) == ib && ib->ib_only_jit_sucessors) {
      // Jumping to consecutive BB can be skipped
      return;
    }
    // Jumping to another JITed BB, emit a branch
    VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
    jit_pushal(iu, (1 << 27) | (1 << 25) | ii->true_branch);
    jit_push_literal_pool(iu, jc);
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    jit_loadimm_from_literal_pool(iu, ii->true_branch, 0, LITERAL_POOL_VMBB,
                                  jc);
    jit_pushal(iu, (0x8bd << 16) | REG_RESTORE_MASK);
    jit_push_literal_pool(iu, jc);
  }
}


/**
 *
 */
static void
jit_emit_cmp(ir_unit_t *iu, ir_valuetype_t lhs, ir_valuetype_t rhs,
             jitctx_t *jc, int pred)
{
  int ext = JIT_LOAD_EXT_UNSIGNED;
  switch(pred) {
  case ICMP_SGT:
  case ICMP_SLT:
  case ICMP_SGE:
  case ICMP_SLE:
    ext = JIT_LOAD_EXT_SIGNED;
    break;
  }

  int Rn = jit_loadvalue_cond(iu, lhs, R_TMPA, jc, ARM_COND_AL, ext);

  const ir_value_t *rhs_value = value_get(iu, rhs.value);
  if(rhs_value->iv_class == IR_VC_CONSTANT) {
    int32_t rc;

    if(ext == JIT_LOAD_EXT_SIGNED)
      rc = value_get_const32(iu, rhs_value);
    else
      rc = value_get_const(iu, rhs_value);

    int imm12 = make_imm12(rc);
    if(imm12 != -1) {
      // CMP immediate
      jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 22) | (1 << 20) | (Rn << 16) | imm12);
      return;
    }
    imm12 = make_imm12(-rc);
    if(imm12 != -1) {
      // CMN immediate
      jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 22) | (1 << 21) | (1 << 20) | (Rn << 16) | imm12);
      return;
    }
  }

  int Rm = jit_loadvalue_cond(iu, rhs, R_TMPB, jc, ARM_COND_AL, ext);
  // CMP register
  jit_pushal(iu, (1 << 24) | (1 << 22) | (1 << 20) | (Rn << 16) | Rm);
}


/**
 *
 */
static int
jit_cmp_br_check(ir_unit_t *iu, ir_instr_cmp_branch_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_cmp_br(ir_unit_t *iu, ir_instr_cmp_branch_t *ii, jitctx_t *jc,
           ir_bb_t *curbb)
{
  jit_emit_cmp(iu, ii->lhs_value, ii->rhs_value, jc, ii->op);

  jit_emit_conditional_branch(iu, ii->true_branch,
                              ii->false_branch, ii->op, jc, curbb);
}


/**
 *
 */
static int
jit_cmp_select_check(ir_unit_t *iu, ir_instr_cmp_select_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_emit_select(ir_unit_t *iu, int pred, ir_valuetype_t ret_value,
                ir_valuetype_t true_value, ir_valuetype_t false_value,
                jitctx_t *jc)
{
  const uint32_t true_cond = armcond(pred);
  const uint32_t false_cond = armcond(invert_pred(pred));

  int Rd = jit_storevalue_reg(iu, ret_value, R_TMPA);

  int Rx;

  Rx = jit_loadvalue_cond(iu, true_value, Rd, jc, true_cond, 0);
  jit_storevalue_cond(iu, ret_value, Rx, true_cond);

  Rx = jit_loadvalue_cond(iu, false_value, Rd, jc, false_cond, 0);
  jit_storevalue_cond(iu, ret_value, Rx, false_cond);
}


/**
 *
 */
static void
jit_cmp_select(ir_unit_t *iu, ir_instr_cmp_select_t *ii, jitctx_t *jc)
{
  jit_emit_cmp(iu, ii->lhs_value, ii->rhs_value, jc, ii->op);
  jit_emit_select(iu, ii->op, ii->super.ii_ret, ii->true_value,
                  ii->false_value, jc);
}


/**
 *
 */
static int
jit_cmp_check(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_cmp(ir_unit_t *iu, ir_instr_binary_t *ii, jitctx_t *jc)
{
  jit_emit_cmp(iu, ii->lhs_value, ii->rhs_value, jc, ii->op);

  const uint32_t true_cond = armcond(ii->op);
  const uint32_t false_cond = armcond(invert_pred(ii->op));

  int Rd = jit_storevalue_reg(iu, ii->super.ii_ret, R_TMPA);

  jit_loadimm_cond(iu, 1, Rd, jc, true_cond);
  jit_storevalue_cond(iu, ii->super.ii_ret, Rd, true_cond);

  jit_loadimm_cond(iu, 0, Rd, jc, false_cond);
  jit_storevalue_cond(iu, ii->super.ii_ret, Rd, false_cond);
}

/**
 *
 */
static int
jit_select_check(ir_unit_t *iu, ir_instr_select_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->true_value.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 *
 */
static void
jit_select(ir_unit_t *iu, ir_instr_select_t *ii, jitctx_t *jc)
{
  int Rn = jit_loadvalue(iu, ii->pred, R_TMPA, jc);
  jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 22) | (1 << 20) | (Rn << 16));
  jit_emit_select(iu, ICMP_NE, ii->super.ii_ret, ii->true_value,
                  ii->false_value, jc);
}


/**
 *
 */
static int
jit_cast_check(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  const int srccode = legalize_type(type_get(iu, ii->value.type));
  const int dstcode = legalize_type(type_get(iu, ii->super.ii_ret.type));
  const int castop = ii->op;

  switch(COMBINE3(dstcode, castop, srccode)) {
  case COMBINE3(IR_TYPE_INT8,  CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT16, CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT8,  CAST_TRUNC, IR_TYPE_INT16):

  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT16):
  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT8):

  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT1):
  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT16):
  case COMBINE3(IR_TYPE_INT16, CAST_SEXT, IR_TYPE_INT1):
  case COMBINE3(IR_TYPE_INT16, CAST_SEXT, IR_TYPE_INT8):
    return 1;

  default:
    return 0;
  }
}

/**
 *
 */
static void
jit_cast(ir_unit_t *iu, ir_instr_unary_t *ii, jitctx_t *jc)
{
  const int srccode = legalize_type(type_get(iu, ii->value.type));
  const int dstcode = legalize_type(type_get(iu, ii->super.ii_ret.type));
  const int castop = ii->op;

  int Rd = jit_storevalue_reg(iu, ii->super.ii_ret, R_TMPA);
  int Rm = jit_loadvalue(iu, ii->value, R_TMPA, jc);

  switch(COMBINE3(dstcode, castop, srccode)) {
  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT16):
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT8):
    // UXTB
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) |
             (1 << 23) | (1 << 22) | (1 << 21) | 0xf0070 |
             (Rd << 12) | Rm);
    break;

  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT16, CAST_SEXT, IR_TYPE_INT8):
    // SXTB
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) |
             (1 << 23) | (1 << 21) | 0xf0070 |
             (Rd << 12) | Rm);
    break;

  case COMBINE3(IR_TYPE_INT16, CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT16):
    // UXTH
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) |
             (1 << 23) | (1 << 22) | (1 << 21) | (1 << 20) | 0xf0070 |
             (Rd << 12) | Rm);
    break;

  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT16):
    // SXTH
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) |
             (1 << 23) | (1 << 21) | (1 << 20) | 0xf0070 |
             (Rd << 12) | Rm);
    break;

  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT1):
  case COMBINE3(IR_TYPE_INT16, CAST_SEXT, IR_TYPE_INT1):
    // SBFX
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) |
             (1 << 23) | (1 << 21) | (1 /* width */ << 16) |
             (Rd << 12) | (1 << 6) | (1 << 4) | Rm);
    break;
  default:
    fprintf(stderr, "jit: Bad cast @ %d\n", __LINE__);
    abort();
  }

  jit_storevalue(iu, ii->super.ii_ret, Rd);
}


/**
 *
 */
static int
jit_switch_check(ir_unit_t *iu, ir_instr_switch_t *ii)
{
  const ir_type_t *cty = type_get(iu, ii->value.type);
  int width;
  switch(cty->it_code) {

  case IR_TYPE_INTx:
    width = type_bitwidth(iu, cty);
    if(width <= 8)
      break;
    return 0;

  case IR_TYPE_INT8:
    break;

  default:
    return 0;
  }

  // All target BBs must have JIT entry points so we set a flag in
  // each involved BB that will force it to emit an entry point
  // from JIT even if it's only a direct return to the C VM

  ir_function_t *f = iu->iu_current_function;
  bb_find(f, ii->defblock)->ib_force_jit_entrypoint = 1;

  for(int i = 0; i < ii->num_paths; i++)
    bb_find(f, ii->paths[i].block)->ib_force_jit_entrypoint = 1;
  return 1;

}


/**
 *
 */
static void
jit_jumptable(ir_unit_t *iu, ir_instr_switch_t *ii, jitctx_t *jc)
{
  const ir_type_t *cty = type_get(iu, ii->value.type);

  int width = type_bitwidth(iu, cty);
  int items = 1 << width;
  int mask = items - 1;

  int Rv = jit_loadvalue(iu, ii->value, R_TMPA, jc);

  // AND
  jit_pushal(iu, (1 << 25) | (Rv << 16) | (R_TMPB << 12) | mask);

  // LDR PC <- [PC + R_TMPB << 2]
  jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) | (1 << 24) | (1 << 23) |
           (1 << 20) | (0xf << 16) | (0xf << 12) | (2 << 7) | R_TMPB);
  iu->iu_jit_ptr += 4;
  uint32_t *table = iu->iu_jit_mem + iu->iu_jit_ptr;
  // Fill table with default paths
  for(int i = 0; i < items; i++) {
    table[i] = ii->defblock;
    VECTOR_PUSH_BACK(&iu->iu_jit_bb_to_addr_fixups, iu->iu_jit_ptr + i * 4);
  }

  // Fill table with actual items
  for(int i = 0; i < ii->num_paths; i++)
    table[ii->paths[i].v64 & mask] = ii->paths[i].block;

  iu->iu_jit_ptr += 4 * items;

  jit_push_literal_pool(iu, jc);
}

/**
 *
 */
static int
jit_ret_check(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  if(ii->value.value == -1)
    return 1;

  int typecode = legalize_type(type_get(iu, ii->value.type));

  switch(typecode) {
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }
  return 1;
}


static void
jit_ret(ir_unit_t *iu, ir_instr_unary_t *ii, jitctx_t *jc)
{
  if(ii->value.value != -1) {
    int r = jit_loadvalue(iu, ii->value, R_TMPA, jc);
    jit_pushal(iu, (1 << 26) | (1 << 24) | (R_RET << 16) | (r << 12));
  }

  jit_pushal(iu, (1 << 25) | (1 << 24) | (1 << 23) | (1 << 21) |
             (0 << 12) | 0);
  jit_pushal(iu, (0x8bd << 16) | REG_RESTORE_MASK);
  jit_push_literal_pool(iu, jc);
}

/**
 *
 */
static int
jit_check(ir_unit_t *iu, ir_instr_t *ii)
{
  switch(ii->ii_class) {
  case IR_IC_BINOP:
    return jit_binop_check(iu, (ir_instr_binary_t *)ii);
  case IR_IC_CAST:
    return jit_cast_check(iu, (ir_instr_unary_t *)ii);
  case IR_IC_MOVE:
    return jit_move_check(iu, (ir_instr_move_t *)ii);
  case IR_IC_LOAD:
    return jit_load_check(iu, (ir_instr_load_t *)ii);
  case IR_IC_STORE:
    return jit_store_check(iu, (ir_instr_store_t *)ii);
  case IR_IC_MLA:
    return jit_mla_check(iu, (ir_instr_ternary_t *)ii);
  case IR_IC_BR:
    return jit_br_check(iu, (ir_instr_br_t *)ii);
  case IR_IC_CMP_BRANCH:
    return jit_cmp_br_check(iu, (ir_instr_cmp_branch_t *)ii);
  case IR_IC_CMP_SELECT:
    return jit_cmp_select_check(iu, (ir_instr_cmp_select_t *)ii);
  case IR_IC_CMP2:
    return jit_cmp_check(iu, (ir_instr_binary_t *)ii);
  case IR_IC_SELECT:
    return jit_select_check(iu, (ir_instr_select_t *)ii);
  case IR_IC_SWITCH:
    return jit_switch_check(iu, (ir_instr_switch_t *)ii);
  case IR_IC_RET:
    return jit_ret_check(iu, (ir_instr_unary_t *)ii);
  case IR_IC_LEA:
    return 1;
  default:
    return 0;
  }
}



/**
 * DFS to find cluster of fully JITed basic blocks
 */
static void
jit_bb_dfs(ir_bb_t *ib, struct ir_bb_list *cluster)
{
  ir_bb_edge_t *ibe;
  ib->ib_mark = 1;

  LIST_REMOVE(ib, ib_traversal_link);
  LIST_INSERT_HEAD(cluster, ib, ib_traversal_link);

  LIST_FOREACH(ibe, &ib->ib_outgoing_edges, ibe_from_link)
    if(ibe->ibe_to->ib_jit && !ibe->ibe_to->ib_mark)
      jit_bb_dfs(ibe->ibe_to, cluster);

  LIST_FOREACH(ibe, &ib->ib_incoming_edges, ibe_to_link)
    if(ibe->ibe_from->ib_jit && !ibe->ibe_from->ib_mark)
      jit_bb_dfs(ibe->ibe_from, cluster);
}


/**
 * Analyze instruction stream for JITable instructions.
 * This happens just before register allocation.
 */
static void
jit_analyze(ir_unit_t *iu, ir_function_t *f, int setwords, int ffv)
{
  ir_bb_t *ib, *ibn, *curbb;
  ir_instr_t *ii, *iin, *prev;

  int fulljit = 1;

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
      ii->ii_jit = jit_check(iu, ii);
      if(!ii->ii_jit) {
        fulljit = 0;
      }
    }
  }

  if(!fulljit) {
    TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
      ir_instr_t *last = TAILQ_LAST(&ib->ib_instrs, ir_instr_queue);
      if(last->ii_class == IR_IC_RET)
        last->ii_jit = 0;
    }
  } else {
    f->if_full_jit = 1;
    TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
      ib->ib_jit = 1;

      TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
        int r = ii->ii_ret.value;
        if(r < 0)
          continue;
        ir_value_t *iv = value_get(iu, ii->ii_ret.value);
        assert(iv->iv_class == IR_VC_TEMPORARY);
        iv->iv_jit = 1;
      }
    }
    return;
  }

  struct ir_bb_list jitbbs;
  LIST_INIT(&jitbbs);

  for(ib = TAILQ_FIRST(&f->if_bbs); ib != NULL; ib = ibn) {
    ibn = TAILQ_NEXT(ib, ib_link);

    prev = ii = TAILQ_FIRST(&ib->ib_instrs);

    ib->ib_jit = ii->ii_jit;
    curbb = ib;

    if(ib->ib_jit)
      LIST_INSERT_HEAD(&jitbbs, ib, ib_traversal_link);

    ib->ib_mark = 0;

    ii = TAILQ_NEXT(ii, ii_link);
    for(; ii != NULL; ii = iin) {
      iin = TAILQ_NEXT(ii, ii_link);
      ii->ii_jit = ii->ii_jit;

      if(ii->ii_jit != curbb->ib_jit) {
        // Enter/Leaved JIT section, split into new bb

        ir_bb_t *newbb = bb_add(f, curbb);
        newbb->ib_jit = ii->ii_jit;
        if(newbb->ib_jit) {
          LIST_INSERT_HEAD(&jitbbs, newbb, ib_traversal_link);
          newbb->ib_mark = 0;
        }
        // Emit an unconditional branch
        ir_instr_br_t *br = instr_create(sizeof(ir_instr_br_t), IR_IC_BR);
        br->super.ii_bb = curbb;
        TAILQ_INSERT_AFTER(&curbb->ib_instrs, prev, &br->super, ii_link);
        br->true_branch = newbb->ib_id;
        br->condition.value = -1;
        br->super.ii_jit = curbb->ib_jit;
        // Set successor on branch instruction for liveness analysis
        br->super.ii_num_succ = 1;
        br->super.ii_succ = malloc(sizeof(ir_bb_t *));
        br->super.ii_succ[0] = newbb;
        br->super.ii_liveness = malloc(sizeof(uint32_t) * setwords * 3);
        memcpy(br->super.ii_liveness, prev->ii_liveness,
               sizeof(uint32_t) * setwords * 3);

        // Move edges from curbb to newbb
        ir_bb_edge_t *ibe;
        while((ibe = LIST_FIRST(&curbb->ib_outgoing_edges)) != NULL) {
          LIST_REMOVE(ibe, ibe_from_link);
          LIST_INSERT_HEAD(&newbb->ib_outgoing_edges, ibe, ibe_from_link);
          ibe->ibe_from = newbb;
        }

        // Create edge in CFG
        cfg_create_edge(f, curbb, newbb);
        curbb = newbb;
      }

      if(curbb != ib) {
        // Move over instruction if current bb is different than original
        TAILQ_REMOVE(&ib->ib_instrs, ii, ii_link);
        TAILQ_INSERT_TAIL(&curbb->ib_instrs, ii, ii_link);
        ii->ii_bb = curbb;
      }
      prev = ii;
    }
  }

  //  function_print(iu, f, "POST JIT ANALYZE");

  // Mask of values we can't put in machine registers
  uint32_t *mask = alloca(setwords * sizeof(uint32_t));

  while(1) {
    ir_bb_t *start = LIST_FIRST(&jitbbs);
    struct ir_bb_list jitcluster;
    if(start == NULL)
      break;
    LIST_INIT(&jitcluster);
    //    printf("--------------------------------------------\n");

    jit_bb_dfs(start, &jitcluster);

    memset(mask, 0, setwords * sizeof(uint32_t));

    LIST_FOREACH(ib, &jitcluster, ib_traversal_link) {
      ir_bb_edge_t *ibe;

      LIST_FOREACH(ibe, &ib->ib_outgoing_edges, ibe_from_link) {
        if(!ibe->ibe_to->ib_jit) {
          ir_bb_t *to = ibe->ibe_to;
          ir_instr_t *ii = TAILQ_FIRST(&to->ib_instrs);
          const uint32_t *in = ii->ii_liveness + setwords * 2;
          bitset_or(mask, in, setwords);
        }
      }

      ib->ib_only_jit_sucessors = TAILQ_FIRST(&f->if_bbs) != ib;
      LIST_FOREACH(ibe, &ib->ib_incoming_edges, ibe_to_link) {
        if(!ibe->ibe_from->ib_jit) {
          ib->ib_only_jit_sucessors = 0;
          ir_bb_t *from = ibe->ibe_from;
          ir_instr_t *ii = TAILQ_LAST(&from->ib_instrs, ir_instr_queue);
          const uint32_t *out = ii->ii_liveness;
          bitset_or(mask, out, setwords);
        }
      }

    }

#if 0
    for(int i = 0; i < setwords * 32; i++)
      if(bitchk(mask, i))
        printf("\tMask: %s\n", value_str_id(iu, i + ffv));
#endif

    LIST_FOREACH(ib, &jitcluster, ib_traversal_link) {
      ir_instr_t *ii;
      TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
        int r = ii->ii_ret.value;
        if(r < 0)
          continue;
        r -= ffv;
        if(bitchk(mask, r))
          continue;

        ir_value_t *iv = value_get(iu, ii->ii_ret.value);
        assert(iv->iv_class == IR_VC_TEMPORARY);
        ir_value_instr_t *ivi;
        LIST_FOREACH(ivi, &iv->iv_instructions, ivi_value_link)
          if(!ivi->ivi_instr->ii_jit)
            break;
        if(ivi == NULL)
          iv->iv_jit = 1;
      }
    }
  }
}



static void
jitctx_init(ir_unit_t *iu, ir_function_t *f, jitctx_t *jc)
{
  jc->literal_pool_use = 0;
}


static void
jitctx_done(ir_unit_t *iu, ir_function_t *f, jitctx_t *jc)
{
  jit_push_literal_pool(iu, jc);
}

/**
 *
 */
static int
jit_emit(ir_unit_t *iu, ir_bb_t *ib, jitctx_t *jc)
{
  int ret;

  if(!ib->ib_only_jit_sucessors) {
    ret = iu->iu_jit_ptr;
    jit_pushal(iu, (0x92d << 16) | REG_SAVE_MASK);
  } else {
    ret = INT32_MIN;
  }
  ib->ib_jit_offset = iu->iu_jit_ptr;

  ir_instr_t *ii;
  TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {

    switch(ii->ii_class) {
    case IR_IC_BINOP:
      jit_binop(iu, (ir_instr_binary_t *)ii, jc);
      break;
    case IR_IC_CAST:
      jit_cast(iu, (ir_instr_unary_t *)ii, jc);
      break;
    case IR_IC_MOVE:
      jit_move(iu, (ir_instr_move_t *)ii, jc);
      break;
    case IR_IC_LOAD:
      jit_load(iu, (ir_instr_load_t *)ii, jc);
      break;
    case IR_IC_STORE:
      jit_store(iu, (ir_instr_store_t *)ii, jc);
      break;
    case IR_IC_LEA:
      jit_lea(iu, (ir_instr_lea_t *)ii, jc);
      break;
    case IR_IC_MLA:
      jit_mla(iu, (ir_instr_ternary_t *)ii, jc);
      break;
    case IR_IC_CMP2:
      jit_cmp(iu, (ir_instr_binary_t *)ii, jc);
      break;
    case IR_IC_CMP_SELECT:
      jit_cmp_select(iu, (ir_instr_cmp_select_t *)ii, jc);
      break;
    case IR_IC_SELECT:
      jit_select(iu, (ir_instr_select_t *)ii, jc);
      break;
    case IR_IC_BR:
      jit_br(iu, (ir_instr_br_t *)ii, jc, ib);
      return ret;
    case IR_IC_CMP_BRANCH:
      jit_cmp_br(iu, (ir_instr_cmp_branch_t *)ii, jc, ib);
      return ret;
    case IR_IC_SWITCH:
      jit_jumptable(iu, (ir_instr_switch_t *)ii, jc);
      return ret;
    case IR_IC_RET:
      jit_ret(iu, (ir_instr_unary_t *)ii, jc);
      return ret;
    default:
      abort();
    }
  }
  abort();
}

/**
 *
 */
static void
jit_emit_stub(ir_unit_t *iu, ir_bb_t *ib, jitctx_t *jc)
{
  ib->ib_jit_offset = iu->iu_jit_ptr;
  jit_loadimm_from_literal_pool(iu, ib->ib_id, 0, LITERAL_POOL_VMBB, jc);
  jit_pushal(iu, (0x8bd << 16) | REG_RESTORE_MASK);
  jit_push_literal_pool(iu, jc);
}


/**
 *
 */
static void
jit_branch_fixup(ir_unit_t *iu, ir_function_t *f)
{
  assert(sizeof(f->if_vm_text) == 4);
  const int vmtext = (intptr_t)f->if_vm_text;
  int x;

  x = VECTOR_LEN(&iu->iu_jit_vmbb_fixups);
  for(int i = 0; i < x; i++) {
    int off = VECTOR_ITEM(&iu->iu_jit_vmbb_fixups, i);
    int32_t *literal = iu->iu_jit_mem + off;
    ir_bb_t *bb = bb_find(f, *literal);
    assert(bb != NULL);
    *literal = vmtext + bb->ib_text_offset;
  }


  x = VECTOR_LEN(&iu->iu_jit_branch_fixups);
  for(int i = 0; i < x; i++) {
    int off = VECTOR_ITEM(&iu->iu_jit_branch_fixups, i);
    int32_t *instrp = iu->iu_jit_mem + off;
    ir_bb_t *bb = bb_find(f, *instrp & 0xffffff);
    assert(bb != NULL);
    int pc = off + 0x8;
    int delta = (bb->ib_jit_offset - pc) >> 2;
    *instrp = (*instrp & 0xff000000) | (delta & 0x00ffffff);
  }

  x = VECTOR_LEN(&iu->iu_jit_bb_to_addr_fixups);
  for(int i = 0; i < x; i++) {
    int off = VECTOR_ITEM(&iu->iu_jit_bb_to_addr_fixups, i);
    int32_t *datap = iu->iu_jit_mem + off;
    ir_bb_t *bb = bb_find(f, *datap);
    assert(bb != NULL);
    *datap = (uint32_t)(bb->ib_jit_offset + iu->iu_jit_mem);
  }
}


/**
 *
 */
static void
jit_seal_code(ir_unit_t *iu)
{
  mprotect(iu->iu_jit_mem, iu->iu_jit_mem_alloced,
           PROT_EXEC | PROT_READ);
  iu->iu_stats.jit_code_size = iu->iu_jit_mem_alloced;
}


/**
 *
 */
static void
jit_init(ir_unit_t *iu)
{
  int fd = open("/proc/self/auxv", O_RDONLY);
  if(fd != -1) {
    struct {
      uint32_t type;
      uint32_t value;
    } auxv;
    while(read(fd, &auxv, sizeof(auxv)) == sizeof(auxv)) {
      if(auxv.type == 16) {
        iu->iu_jit_cpuflags = auxv.value;
      }
    }
    close(fd);
  }
}
