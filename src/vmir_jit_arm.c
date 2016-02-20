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


/**
 * Registers
 */
#define R_VMSTACK 0
#define R_MEM     1
#define R_TMPA    2
#define R_TMPB    3

#define R_TMPC    11

#define LITERAL_POOL_MAX_SIZE 256

typedef struct jitctx {

  int literal_pool_use;
  struct {
    uint32_t value;
    uint32_t instr;
    int *addrp;
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
#if 0
    printf("imm12=%d jitptr:%x instr:%x\n", imm12,
           iu->iu_jit_ptr, jc->literal_pool[i].instr);
#endif
    uint32_t *p = iu->iu_jit_mem + jc->literal_pool[i].instr;
    if(jc->literal_pool[i].addrp != NULL)
      *jc->literal_pool[i].addrp = iu->iu_jit_ptr;
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
                                   int *literaladdr, jitctx_t *jc, int cond)
{
  assert(jc->literal_pool_use != LITERAL_POOL_MAX_SIZE);

  jc->literal_pool[jc->literal_pool_use].value = imm;
  jc->literal_pool[jc->literal_pool_use].instr = iu->iu_jit_ptr;
  jc->literal_pool[jc->literal_pool_use].addrp = literaladdr;
  jc->literal_pool_use++;
  jit_push(iu, cond | (1 << 26) | (1 << 24) | (1 << 23) | (0x1f << 16) |
           (Rd << 12));
}

static void
jit_loadimm_from_literal_pool(ir_unit_t *iu, uint32_t imm, int Rd,
                              int *literaladdr, jitctx_t *jc)
{
  jit_loadimm_from_literal_pool_cond(iu, imm, Rd, literaladdr, jc,
                                     ARM_COND_AL);
}


/**
 *
 */
static void
jit_loadimm(ir_unit_t *iu, uint32_t imm, int Rd, jitctx_t *jc)
{
  int imm12 = make_imm12(imm);
  if(imm12 != -1) {
    // MOV A1 encoding
    jit_push(iu, ARM_COND_AL | (1 << 25) | (1 << 24) | (1 << 23) | (1 << 21) |
             (Rd << 12) | imm12);
    return;
  }
  imm12 = make_imm12(~imm);
  if(imm12 != -1) {
    // MVN A1 encoding
    jit_push(iu, ARM_COND_AL |
             (1 << 25) | (1 << 24) | (1 << 23) | (1 << 22) | (1 << 21) |
             (Rd << 12) | imm12);
    return;
  }
  if((uint32_t)imm <= 0xffff) {
    // MOV A2 encoding
    jit_push(iu, ARM_COND_AL | (1 << 25) | (1 << 24) |
             ((imm & 0xf000) << 4) | (Rd << 12) | (imm & 0xfff));
    return;
  }
  jit_loadimm_from_literal_pool(iu, imm, Rd, NULL, jc);
}


/**
 *
 */
static void
jit_push_epilogue(ir_unit_t *iu, jitctx_t *jc)
{
  jit_pushal(iu, (0x8bd << 16) | (0x8DF0));
  jit_push_literal_pool(iu, jc);
  //  jit_push(iu, 0xe12fff1e); // bx lr
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


/**
 * Load a value into a register
 *
 * If the value is a constant or stored on the regframe the register
 * passed in 'reg' is used as a temoprary
 *
 * If the value is stored in a machine register, that register is returned
 */
static int __attribute__((warn_unused_result))
jit_loadvalue(ir_unit_t *iu, ir_valuetype_t vt, int reg, jitctx_t *jc)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  const ir_type_t *it = type_get(iu, vt.type);

  switch(iv->iv_class) {
  case IR_VC_MACHINEREG:
    return iv->iv_reg + 4;

  case IR_VC_REGFRAME:
    switch(legalize_type(it)) {
#if 0
    case IR_TYPE_INT8:
      jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 24) | (1 << 22) | (1 << 20) |
               (R_VMSTACK << 16) | (reg << 12) |
               jit_offset_to_imm12_U(iv->iv_reg));
      break;
#endif

    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_FLOAT:
    case IR_TYPE_POINTER:
      jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 24) | (1 << 20) |
               (R_VMSTACK << 16) | (reg << 12) |
               jit_offset_to_imm12_U(iv->iv_reg));
      break;
    default:
      parser_error(iu, "JIT: Can't load value typecode %d", it->it_code);
    }
    break;
  case IR_VC_CONSTANT:
  case IR_VC_GLOBALVAR:
    jit_loadimm(iu, value_get_const32(iu, iv), reg, jc);
    break;
  default:
    parser_error(iu, "JIT: Can't load value-class %d", iv->iv_class);
  }
  return reg;
}


/**
 *
 */
static int
jit_storevalue_reg(ir_unit_t *iu, ir_valuetype_t vt, int reg)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  if(iv->iv_class == IR_VC_MACHINEREG)
    return iv->iv_reg + 4;
  return reg;
}


/**
 *
 */
static void
jit_storevalue(ir_unit_t *iu, ir_valuetype_t vt, int reg)
{
  const ir_value_t *iv = value_get(iu, vt.value);
  const ir_type_t *it = type_get(iu, vt.type);

  switch(iv->iv_class) {
  case IR_VC_MACHINEREG:
    if(iv->iv_reg + 4 != reg) {
      int Rd = iv->iv_reg + 4;
      int Rm = reg;
      // MOV
      jit_pushal(iu, (1 << 24) | (1 << 23) | (1 << 21) | (Rd << 12) | Rm);
    }
    return;

  case IR_VC_REGFRAME:
    switch(legalize_type(it)) {

#if 0
    case IR_TYPE_INT8:
      jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 24) | (1 << 22) |
               (R_VMSTACK << 16) | (reg << 12) |
               jit_offset_to_imm12_U(iv->iv_reg));
      break;
#endif

    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_FLOAT:
    case IR_TYPE_POINTER:
      jit_pushal(iu, (1 << 26) | (1 << 24) |
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



/**
 *
 */
static int
is_r(const ir_value_t *iv)
{
  return iv->iv_class == IR_VC_REGFRAME || iv->iv_class == IR_VC_TEMPORARY;
}

/**
 *
 */
static int
is_rc(const ir_value_t *iv)
{
  return iv->iv_class == IR_VC_REGFRAME || iv->iv_class == IR_VC_TEMPORARY ||
    iv->iv_class == IR_VC_CONSTANT || iv->iv_class == IR_VC_GLOBALVAR;
}



/**
 *
 */
static int
jit_binop_check(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  const int binop = ii->op;
  const ir_value_t *lhs = value_get(iu, ii->lhs_value.value);
  const ir_value_t *rhs = value_get(iu, ii->rhs_value.value);

  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));

  switch(binop) {
  case BINOP_SDIV:
  case BINOP_UDIV:
  case BINOP_SREM:
  case BINOP_UREM:
    return 0;

  case BINOP_LSHR:
  case BINOP_ASHR:
    if(typecode != IR_TYPE_INT32)
      return 0;
    break;
  }

  switch(typecode) {
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    break;
  default:
    return 0;
  }

  return is_r(lhs) && is_rc(rhs);
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
    int32_t rc = value_get_const32(iu, rhs);
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
      break;

    case BINOP_XOR:
      if((imm12 = make_imm12(rc)) != -1) {
        jit_pushal(iu, (1 << 25) | (1 << 21) |
                   (Rn << 16) | (Rd << 12) | imm12);
        goto wb;
      }
      break;

    case BINOP_SHL:
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
  default:
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
jit_load_check(ir_unit_t *iu, ir_instr_load_t *ii)
{
  const ir_type_t *retty = type_get(iu, ii->super.ii_ret.type);

  switch(legalize_type(retty)) {
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

  if(ii->offset) {
    jit_push_add_imm(iu, R_TMPA, ea, ii->offset, R_TMPB, jc);
    ea = R_TMPA;
  }

  int Rt = jit_loadvalue(iu, ii->value, R_TMPB, jc);

  switch(legalize_type(type_get(iu, ii->value.type))) {
  default:
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
  }else {
    Ra = jit_loadvalue(iu, ii->arg3, R_TMPC, jc);
  }

  jit_pushal(iu, (1 << 21) | (Rd << 16) | (Ra << 12) | (Rm << 8) | 0x90 | Rn);
  jit_storevalue(iu, ii->super.ii_ret, Rd);
}


/**
 *
 */
static int
jit_br_check(ir_unit_t *iu, ir_instr_br_t *ii)
{
  // We can JIT unconditional branches
  return ii->condition.value == -1;
}


/**
 *
 */
static void
jit_br(ir_unit_t *iu, ir_instr_br_t *ii, jitctx_t *jc)
{
  ir_bb_t *ib = bb_find(iu->iu_current_function, ii->true_branch);
  ir_instr_t *tgt = TAILQ_FIRST(&ib->ib_instrs);
  if(tgt->ii_jit) {
    // Jumping to another JITen instruction, emit a branch
    VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
    jit_pushal(iu, (1 << 27) | (1 << 25) | ii->true_branch);
    jit_push_literal_pool(iu, jc);
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    int ptr;
    jit_loadimm_from_literal_pool(iu, ii->true_branch, 0, &ptr, jc);
    jit_push_epilogue(iu, jc);
    VECTOR_PUSH_BACK(&iu->iu_jit_vmbb_fixups, ptr);
  }
}


/**
 *
 */
static int
jit_cmp_branch_check(ir_unit_t *iu, ir_instr_cmp_branch_t *ii)
{
  int typecode = legalize_type(type_get(iu, ii->lhs_value.type));

  switch(typecode) {
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
jit_cmp_br(ir_unit_t *iu, ir_instr_cmp_branch_t *ii, jitctx_t *jc)
{
  int ptr1 = 0;
  int ptr2 = 0;
  ir_bb_t *ib;
  ir_instr_t *tgt;

  int Rn = jit_loadvalue(iu, ii->lhs_value, R_TMPA, jc);
  int Rm = jit_loadvalue(iu, ii->rhs_value, R_TMPB, jc);
  jit_pushal(iu, (1 << 24) | (1 << 22) | (1 << 20) | (Rn << 16) | Rm);

  int cond;
  switch(ii->op) {
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

  ib = bb_find(iu->iu_current_function, ii->true_branch);
  tgt = TAILQ_FIRST(&ib->ib_instrs);
  if(tgt->ii_jit) {
    // Jumping to another JITen instruction, emit a branch
    VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
    jit_push(iu, cond | (1 << 27) | (1 << 25) | ii->true_branch);
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    jit_loadimm_from_literal_pool_cond(iu, ii->true_branch, 0, &ptr1, jc, cond);
    jit_push(iu, cond | (0x8bd << 16) | (0x8DF0));
  }

  ib = bb_find(iu->iu_current_function, ii->false_branch);
  tgt = TAILQ_FIRST(&ib->ib_instrs);
  if(tgt->ii_jit) {
    // Jumping to another JITen instruction, emit a branch
    VECTOR_PUSH_BACK(&iu->iu_jit_branch_fixups, iu->iu_jit_ptr);
    jit_pushal(iu, (1 << 27) | (1 << 25) | ii->false_branch);
  } else {
    // Jumping to non-JITed instruction, emit return + jump to VM location
    jit_loadimm_from_literal_pool(iu, ii->false_branch, 0, &ptr2, jc);
    jit_pushal(iu, (0x8bd << 16) | (0x8DF0));
  }

  jit_push_literal_pool(iu, jc);
  if(ptr1)
    VECTOR_PUSH_BACK(&iu->iu_jit_vmbb_fixups, ptr1);
  if(ptr2)
    VECTOR_PUSH_BACK(&iu->iu_jit_vmbb_fixups, ptr2);
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
  case COMBINE3(IR_TYPE_INT8, CAST_TRUNC, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT8):

  case COMBINE3(IR_TYPE_POINTER, CAST_INTTOPTR, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT32, CAST_PTRTOINT, IR_TYPE_POINTER):
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
  case COMBINE3(IR_TYPE_INT32, CAST_ZEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_INT16, CAST_ZEXT, IR_TYPE_INT8):
    jit_push(iu, ARM_COND_AL | (1 << 26) | (1 << 25) |
             (1 << 23) | (1 << 22) | (1 << 21) | 0xf0070 |
             (Rd << 12) | Rm);
    break;

  case COMBINE3(IR_TYPE_INT32, CAST_SEXT, IR_TYPE_INT8):
  case COMBINE3(IR_TYPE_POINTER, CAST_INTTOPTR, IR_TYPE_INT32):
  case COMBINE3(IR_TYPE_INT32, CAST_PTRTOINT, IR_TYPE_POINTER):
    jit_storevalue(iu, ii->super.ii_ret, Rm);
    return;

  default:
    abort();
  }

  jit_storevalue(iu, ii->super.ii_ret, Rd);
}


/**
 *
 */
static void
jit_check(ir_unit_t *iu, ir_instr_t *ii)
{
  int r;
  if(ii->ii_jit_checked)
    return;
  ii->ii_jit_checked = 1;

  switch(ii->ii_class) {
  case IR_IC_BINOP:
    r = jit_binop_check(iu, (ir_instr_binary_t *)ii);
    break;
  case IR_IC_CAST:
    r = jit_cast_check(iu, (ir_instr_unary_t *)ii);
    break;
  case IR_IC_MOVE:
    r = jit_move_check(iu, (ir_instr_move_t *)ii);
    break;
  case IR_IC_LOAD:
    r = jit_load_check(iu, (ir_instr_load_t *)ii);
    break;
  case IR_IC_STORE:
    r = jit_store_check(iu, (ir_instr_store_t *)ii);
    break;
  case IR_IC_MLA:
    r = jit_mla_check(iu, (ir_instr_ternary_t *)ii);
    break;
  case IR_IC_BR:
    r = jit_br_check(iu, (ir_instr_br_t *)ii);
    break;
  case IR_IC_CMP_BRANCH:
    r = jit_cmp_branch_check(iu, (ir_instr_cmp_branch_t *)ii);
    break;
  case IR_IC_LEA:
    r = 1;
    break;
  default:
    return;
  }

  ii->ii_jit = r;
}


/**
 * Figure out which values are live only during a specific JIT
 * segment. Such values are allocated to machine registers.
 */
static void
jit_analyze_segment(ir_unit_t *iu, ir_instr_t *first, ir_instr_t *last)
{
  const ir_instr_t *stop = TAILQ_NEXT(last, ii_link);
  ir_instr_t *ii;

  // Live-out values from JITed segment
  const uint32_t *liveout = last->ii_liveness;
  const int ffv = iu->iu_first_func_value;
#if 0
  printf("Analyze segment first: ");
  instr_print(iu, first, 0);
  printf("\n");

  printf("Analyze segment  last: ");
  instr_print(iu, last, 0);
  printf("\n");
  printf("last liveout values\n");
  for(int i = 0; i < 32;i++) {
    if(bitchk(liveout, i))
      printf("%s\n", value_str_id(iu, i + ffv));
  }
#endif
  for(ii = first; ii != stop; ii = TAILQ_NEXT(ii, ii_link)) {
    int r = ii->ii_ret.value;
    if(r == -1)
      continue;
    r -= ffv;
    if(bitchk(liveout, r))
      continue; // Value is liveout

    ir_value_t *iv = value_get(iu, ii->ii_ret.value);
    assert(iv->iv_class == IR_VC_TEMPORARY);
    iv->iv_jit = 1;
#if 0
    printf("Value %s is machineregisterable, emitted by ", value_str(iu, iv));
    instr_print(iu, ii, 0);
    printf("\n");
#endif
  }
}


/**
 * Analyze instruction stream for JITable instructions.
 * This happens just before register allocation.
 */
static void
jit_analyze(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *ib;
  ir_instr_t *ii;

  ir_instr_t *first = NULL;

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {

      jit_check(iu, ii);
      if(ii->ii_jit && first == NULL)
        first = ii;

      if(!ii->ii_jit && first != NULL) {
        jit_analyze_segment(iu, first, TAILQ_PREV(ii, ir_instr_queue, ii_link));
        first = NULL;
      }
    }
    if(first != NULL) {
      jit_analyze_segment(iu, first, TAILQ_LAST(&ib->ib_instrs, ir_instr_queue));
      first = NULL;
    }
  }
}


/**
 *
 */
static ir_instr_t *
jit_emit(ir_unit_t *iu, ir_instr_t *ii, int *codeptr, int retvalue)
{
  jitctx_t jc;
  jc.literal_pool_use = 0;

  *codeptr = iu->iu_jit_ptr;

  jit_pushal(iu, (0x92d << 16) | (0x4DF0));

  if(ii == TAILQ_FIRST(&ii->ii_bb->ib_instrs))
    ii->ii_bb->ib_jit_offset = iu->iu_jit_ptr;

  while(ii != NULL && ii->ii_jit) {
#if 0
    printf("JIT ");
    instr_print(iu, ii, 0);
    printf("\n");
#endif
    switch(ii->ii_class) {
    case IR_IC_BINOP:
      jit_binop(iu, (ir_instr_binary_t *)ii, &jc);
      break;
    case IR_IC_CAST:
      jit_cast(iu, (ir_instr_unary_t *)ii, &jc);
      break;
    case IR_IC_MOVE:
      jit_move(iu, (ir_instr_move_t *)ii, &jc);
      break;
    case IR_IC_LOAD:
      jit_load(iu, (ir_instr_load_t *)ii, &jc);
      break;
    case IR_IC_STORE:
      jit_store(iu, (ir_instr_store_t *)ii, &jc);
      break;
    case IR_IC_LEA:
      jit_lea(iu, (ir_instr_lea_t *)ii, &jc);
      break;
    case IR_IC_MLA:
      jit_mla(iu, (ir_instr_ternary_t *)ii, &jc);
      break;
    case IR_IC_BR:
      jit_br(iu, (ir_instr_br_t *)ii, &jc);
      return NULL;
    case IR_IC_CMP_BRANCH:
      jit_cmp_br(iu, (ir_instr_cmp_branch_t *)ii, &jc);
      return NULL;
    default:
      abort();
    }
    ii = TAILQ_NEXT(ii, ii_link);
  }

  // Offset in code segment where to write the return value from this
  // JITed segment.
  int retvalueptr;

  jit_loadimm_from_literal_pool(iu, retvalue, 0, &retvalueptr, &jc);
  jit_push_epilogue(iu, &jc);
  VECTOR_PUSH_BACK(&iu->iu_jit_vmcode_fixups, retvalueptr);

  return ii;
}


/**
 *
 */
static void
jit_branch_fixup(ir_unit_t *iu, ir_function_t *f)
{
  assert(sizeof(f->if_vm_text) == 4);
  const int vmtext = (intptr_t)f->if_vm_text;

  int x = VECTOR_LEN(&iu->iu_jit_vmcode_fixups);
  for(int i = 0; i < x; i++) {
    int off = VECTOR_ITEM(&iu->iu_jit_vmcode_fixups, i);
    int32_t *literal = iu->iu_jit_mem + off;
    *literal += vmtext;
  }

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
}


/**
 *
 */
static void
jit_seal_code(ir_unit_t *iu)
{
  mprotect(iu->iu_jit_mem, iu->iu_jit_mem_alloced,
           PROT_EXEC | PROT_READ);
}

#define VMIR_VM_JIT
#define JIT_MACHINE_REGS 5

