/*
 * Copyright (c) 2016 - 2017 Lonelycoder AB
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


#define WASM_TYPE_VOID 0
#define WASM_TYPE_I32  1
#define WASM_TYPE_I64  2
#define WASM_TYPE_F32  3
#define WASM_TYPE_F64  4
#define WASM_TYPE_I8   5
#define WASM_TYPE_I16  6


#define WASM_SECTION_TYPE     1
#define WASM_SECTION_IMPORT   2
#define WASM_SECTION_FUNCTION 3
#define WASM_SECTION_TABLE    4
#define WASM_SECTION_MEMORY   5
#define WASM_SECTION_GLOBAL   6
#define WASM_SECTION_EXPORTS  7
#define WASM_SECTION_START    8
#define WASM_SECTION_ELEMENT  9
#define WASM_SECTION_CODE     10
#define WASM_SECTION_DATA     11



typedef struct {
  const uint8_t *ptr;
  const uint8_t *end;
  const uint8_t *start;
} wasm_bytestream_t;



#if defined(__BIG_ENDIAN__)
#error fix bigendian support here
#else

static uint32_t
wbs_get_u32(wasm_bytestream_t *wbs)
{
  if(wbs->ptr + 4 > wbs->end)
    return 0;

  uint32_t r;
  memcpy(&r, wbs->ptr, 4);
  wbs->ptr += 4;
  return r;
}

static uint64_t
wbs_get_u64(wasm_bytestream_t *wbs)
{
  if(wbs->ptr + 8 > wbs->end)
    return 0;

  uint64_t r;
  memcpy(&r, wbs->ptr, 8);
  wbs->ptr += 8;
  return r;
}


#endif


static uint8_t
wbs_get_byte(wasm_bytestream_t *wbs)
{
  if(wbs->ptr >= wbs->end)
    return 0xff;

  uint8_t r = *wbs->ptr;
  wbs->ptr += 1;
  return r;
}

static uint32_t
wbs_get_vu32(wasm_bytestream_t *wbs)
{
  uint32_t v = 0;
  uint8_t b;
  unsigned int shift = 0;
  do {
    b = wbs_get_byte(wbs);
    v |= (0x7f & b) << shift;
    shift += 7;
  } while(b & 0x80);
  return v;
}


/**
 *
 */
static int32_t
wbs_get_v32(wasm_bytestream_t *wbs)
{
  uint32_t v = 0;
  uint8_t b;
  unsigned int shift = 0;
  do {
    b = wbs_get_byte(wbs);
    v |= (0x7f & b) << shift;
    shift += 7;
  } while(b & 0x80);

  if(shift < 32 && (b & 0x40))
    v |= - (1 << shift);

  return v;
}

/**
 *
 */
static int64_t
wbs_get_v64(wasm_bytestream_t *wbs)
{
  uint64_t v = 0;
  uint8_t b;
  unsigned int shift = 0;
  do {
    b = wbs_get_byte(wbs);
    v |= (int64_t)(0x7f & b) << shift;
    shift += 7;
  } while(b & 0x80);

  if(shift < 64 && (b & 0x40)) {
    v |= - (1LL << shift);
  }
  return v;
}


/**
 *
 */
static char *
wbs_get_string(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t len = wbs_get_vu32(wbs);

  if(len > (wbs->end - wbs->ptr))
    parser_error(iu, "String length too long");

  char *mem = malloc(len + 1);
  memcpy(mem, wbs->ptr, len);
  wbs->ptr += len;
  mem[len] = 0;
  return mem;
}

/**
 *
 */
static int
wasm_parse_value_type(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  const uint8_t arg_type = wbs_get_byte(wbs);
  switch(arg_type) {
  case 0x40:
    return 0;
  case 0x7f:
  case 0x7e:
  case 0x7d:
  case 0x7c:
    return 0x7f - arg_type + 1;
  default:
    parser_error(iu, "Bad type code (byte) 0x%x at 0x%zx",
                 arg_type, wbs->ptr - wbs->start - 1);
    break;
  }
}


/**
 *
 */
static void
wasm_parse_section_type(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  ir_type_t it;
  uint32_t count = wbs_get_vu32(wbs);
  for(int i = 0; i < count; i++) {
    uint8_t form = wbs_get_byte(wbs);

    if(form != 0x60) {
      // Function type
      parser_error(iu, "Bad form 0x%x in type section", form);
    }
    const uint32_t param_count = wbs_get_vu32(wbs);
    it.it_code = IR_TYPE_FUNCTION;
    it.it_function.varargs = 0;
    it.it_function.num_parameters = param_count;
    it.it_function.parameters =
      malloc(it.it_function.num_parameters * sizeof(int));

    for(int i = 0; i < it.it_function.num_parameters; i++) {
      it.it_function.parameters[i] = wasm_parse_value_type(iu, wbs);
    }

    const uint32_t return_count = wbs_get_vu32(wbs);
    if(return_count > 1) {
      parser_error(iu, "Multiple return values not supported");
    }
    if(return_count == 0) {
      it.it_function.return_type = 0; // (void) is type #0


    } else {
      it.it_function.return_type = wasm_parse_value_type(iu, wbs);
    }
    VECTOR_PUSH_BACK(&iu->iu_wasm_type_map, iu->iu_types.vh_length);
    VECTOR_PUSH_BACK(&iu->iu_types, it);
  }
}



static void
import_function(ir_unit_t *iu, const char *module, const char *name, int type)
{
  uint32_t vmir_type = VECTOR_ITEM(&iu->iu_wasm_type_map, type);

  ir_function_t *f = calloc(1, sizeof(ir_function_t));

  TAILQ_INIT(&f->if_bbs);
  f->if_type = vmir_type;
  f->if_gfid = VECTOR_LEN(&iu->iu_functions);
  f->if_name = strdup(name);
  VECTOR_PUSH_BACK(&iu->iu_functions, f);

  if(f->if_ext_func == NULL) {
    if(!vmop_resolve(f)) {
      f->if_ext_func =
        (void *)iu->iu_external_function_resolver(f->if_name, iu->iu_opaque);
    }
  }
}


static void
import_table(ir_unit_t *iu, const char *module, const char *name,
              wasm_bytestream_t *wbs)
{
  const uint8_t elem_type = wbs_get_byte(wbs);
  if(elem_type != 0x70)
    parser_error(iu, "Table %s::%s is not of type 'anyfunc'",
                 module, name);

  const uint32_t flags = wbs_get_vu32(wbs);
  if(flags)
    parser_error(iu, "Resizable table %s::%s not supported",
                 module, name);

  const uint32_t initial = wbs_get_vu32(wbs);
  parser_error(iu, "Imported tables not yet supported: %s.%s size:%u",
               module, name, initial);
}


static void
import_memory(ir_unit_t *iu, const char *module, const char *name,
              wasm_bytestream_t *wbs)
{
  const uint32_t flags = wbs_get_vu32(wbs);
  if(flags)
    parser_error(iu, "Resizable memory %s::%s not supported",
                 module, name);

  const uint32_t initial = wbs_get_vu32(wbs);
  parser_error(iu, "Importing memory not yet supported: %s.%s initial_size:%u",
               module, name, initial);
}

static void
import_global(ir_unit_t *iu, const char *module, const char *name,
              wasm_bytestream_t *wbs)
{
  const uint8_t type = wasm_parse_value_type(iu, wbs);
  const uint32_t mutable = wbs_get_vu32(wbs);
  parser_error(iu, "Importing global not yet supported: "
               "%s::%s type:0x%x mutable:%d",
               module, name, type, mutable);
}



/**
 *
 */
static void
wasm_parse_section_import_decl(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    char *module = wbs_get_string(iu, wbs);
    char *field  = wbs_get_string(iu, wbs);
    int kind = wbs_get_byte(wbs);
    switch(kind) {
    case 0:
      import_function(iu, module, field, wbs_get_vu32(wbs));
      break;
    case 1:
      import_table(iu, module, field, wbs);
      break;
    case 2:
      import_memory(iu, module, field, wbs);
      break;
    case 3:
      import_global(iu, module, field, wbs);
      break;
    default:
      parser_error(iu, "Import section can't handle kind %d for %s::%s",
                   kind, module, field);
    }
    free(module);
    free(field);
  }
}


/**
 *
 */
static void
wasm_parse_section_table(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {

    const uint8_t elem_type = wbs_get_byte(wbs);
    if(elem_type != 0x70)
      parser_error(iu, "Declared table is not of type 'anyfunc'");

    const uint32_t flags = wbs_get_vu32(wbs);
    if(flags)
      parser_error(iu, "Resizable table not supported");

    const uint32_t initial = wbs_get_vu32(wbs);
    printf("Declared table size:%u\n", initial);
  }
}


/**
 *
 */
static void
wasm_parse_section_memory(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    const uint32_t flags = wbs_get_vu32(wbs);
    if(flags)
      parser_error(iu, "Resizable memory not supported");

    const uint32_t initial = wbs_get_vu32(wbs);
    printf("Declared memory size:%u\n", initial);
  }
}



/**
 *
 */
static void
export_function(ir_unit_t *iu, const char *field, int func_index)
{
  ir_function_t *f = VECTOR_ITEM(&iu->iu_functions, func_index);
  f->if_name = strdup(field);
}

/**
 *
 */
static void
wasm_parse_section_exports(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    char *field  = wbs_get_string(iu, wbs);
    int kind = wbs_get_byte(wbs);
    unsigned int index = wbs_get_vu32(wbs);
    switch(kind) {
    case 0:
      export_function(iu, field, index);
      break;
    case 2:
      break;
    default:
      parser_error(iu, "Export section can't handle kind %d '%s' index %d",
                   kind, field, index);
    }
    free(field);
  }
}

/**
 *
 */
static void
wasm_parse_section_functions(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    uint32_t type_index = wbs_get_vu32(wbs);
    uint32_t vmir_type = VECTOR_ITEM(&iu->iu_wasm_type_map, type_index);

    ir_function_t *f = calloc(1, sizeof(ir_function_t));

    TAILQ_INIT(&f->if_bbs);
    f->if_type = vmir_type;
    f->if_gfid = VECTOR_LEN(&iu->iu_functions);
    TAILQ_INSERT_TAIL(&iu->iu_functions_with_bodies, f, if_body_link);
    VECTOR_PUSH_BACK(&iu->iu_functions, f);
  }
}



/**
 *
 */
static ir_valuetype_t
vstack_pop(ir_unit_t *iu)
{
  if(iu->iu_wasm_value_stack.vh_length == 0)
    parser_error(iu, "Value stack underflow");
  ir_valuetype_t vt =
    iu->iu_wasm_value_stack.vh_p[--iu->iu_wasm_value_stack.vh_length];
  //  printf("vstack pop %s\n", value_str_vt(iu, vt));
  return vt;
}

static void
vstack_push(ir_unit_t *iu, ir_valuetype_t vt)
{
  //  printf("vstack push %s\n", value_str_vt(iu, vt));
  VECTOR_PUSH_BACK(&iu->iu_wasm_value_stack, vt);
}

static void
vstack_push_value(ir_unit_t *iu, int value)
{
  ir_valuetype_t vt;
  vt.value = value;
  vt.type = value_get(iu, value)->iv_type;
  vstack_push(iu, vt);
}

static void
vstack_clear(ir_unit_t *iu)
{
  iu->iu_wasm_value_stack.vh_length = 0;
}

__attribute__((unused))
static void
vstack_dump(ir_unit_t *iu)
{
  printf("VALUESTACK DUMP\n");
  for(int i = 0; i < VECTOR_LEN(&iu->iu_wasm_value_stack); i++) {
    printf("%3d: %s\n", i,
           value_str_vt(iu, VECTOR_ITEM(&iu->iu_wasm_value_stack, i)));
  }
}



static void
init_local_vars(ir_unit_t *iu, ir_bb_t *ib, wasm_bytestream_t *wbs,
                const int num_locals, ir_function_t *f)
{
  ir_type_t *it = type_get(iu, f->if_type);

  // We need to copy all function arguments to local var area
  // as wasm assume those are writable

  for(int i = 0; i < it->it_function.num_parameters; i++) {
    ir_instr_move_t *move = instr_add(ib, sizeof(ir_instr_move_t), IR_IC_MOVE);
    move->value.value = iu->iu_first_func_value + i;
    move->value.type = it->it_function.parameters[i];
    move->super.ii_ret = value_alloc_temporary(iu, move->value.type);

    value_bind_return_value(iu, &move->super);
  }

  if(num_locals > 4096) {
    abort();
  }

  int *local_types = alloca(sizeof(int) * num_locals);
  int *local_nums  = alloca(sizeof(int) * num_locals);

  int local_init_index = iu->iu_next_value;

  for(int i = 0; i < num_locals; i++) {
    const int num = wbs_get_vu32(wbs);
    const int type = wasm_parse_value_type(iu, wbs);
    local_nums[i]  = num;
    local_types[i] = type;
    for(int j = 0; j < num; j++) {
      value_alloc_temporary(iu, type);
    }
  }

  // Do another pass where we create constant types for initializing

  for(int i = 0; i < num_locals; i++) {
    const int num = local_nums[i];
    const int type = local_types[i];
    for(int j = 0; j < num; j++) {
      ir_instr_move_t *move =
        instr_add(ib, sizeof(ir_instr_move_t), IR_IC_MOVE);
      move->value = value_create_zero(iu, type);
      move->super.ii_ret.value = local_init_index++;
      move->super.ii_ret.type = move->value.type;

      value_bind_return_value(iu, &move->super);
    }
  }
}

/**
 *
 */
static void
wasm_vmop(ir_unit_t *iu, ir_bb_t *ib, int num_args, int vmop, int return_type)
{
  ir_instr_call_t *i =
    instr_add(ib, sizeof(ir_instr_call_t) +
              sizeof(ir_instr_arg_t) * num_args, IR_IC_VMOP);
  i->vmop = vmop;
  i->argc = num_args;
  for(int j = num_args - 1; j >= 0; j--) {
    i->argv[j].value = vstack_pop(iu);
  }

  value_alloc_instr_ret(iu, return_type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}


/**
 *
 */
static void
wasm_numeric(ir_unit_t *iu, ir_bb_t *ib, int code)
{
  int binop = -1;
  switch(code) {
  case 0x67:  return wasm_vmop(iu, ib, 1, VM_CLZ32, WASM_TYPE_I32);
  case 0x68:  return wasm_vmop(iu, ib, 1, VM_CTZ32, WASM_TYPE_I32);
  case 0x69:  return wasm_vmop(iu, ib, 1, VM_POP32, WASM_TYPE_I32);
  case 0x79:  return wasm_vmop(iu, ib, 1, VM_CLZ64, WASM_TYPE_I64);
  case 0x7a:  return wasm_vmop(iu, ib, 1, VM_CTZ64, WASM_TYPE_I64);
  case 0x7b:  return wasm_vmop(iu, ib, 1, VM_POP64, WASM_TYPE_I64);

  case 0x9c:  return wasm_vmop(iu, ib, 1, VM_FLOOR,  WASM_TYPE_F64);
  case 0x8e:  return wasm_vmop(iu, ib, 1, VM_FLOORF, WASM_TYPE_F32);

  case 0x92:
  case 0xa0:
  case 0x7c:
  case 0x6a: binop = BINOP_ADD;  break;
  case 0x93:
  case 0xa1:
  case 0x7d:
  case 0x6b: binop = BINOP_SUB;  break;
  case 0x94:
  case 0xa2:
  case 0x7e:
  case 0x6c: binop = BINOP_MUL;  break;
  case 0x95:
  case 0xa3:
  case 0x7f:
  case 0x6d: binop = BINOP_SDIV; break;
  case 0x80:
  case 0x6e: binop = BINOP_UDIV; break;
  case 0x81:
  case 0x6f: binop = BINOP_SREM; break;
  case 0x82:
  case 0x70: binop = BINOP_UREM; break;
  case 0x83:
  case 0x71: binop = BINOP_AND;  break;
  case 0x84:
  case 0x72: binop = BINOP_OR;   break;
  case 0x85:
  case 0x73: binop = BINOP_XOR;  break;
  case 0x86:
  case 0x74: binop = BINOP_SHL;  break;
  case 0x87:
  case 0x75: binop = BINOP_ASHR; break;
  case 0x88:
  case 0x76: binop = BINOP_LSHR; break;
  case 0x89:
  case 0x77: binop = BINOP_ROL;  break;
  case 0x8a:
  case 0x78: binop = BINOP_ROR;  break;
  default:
    parser_error(iu, "Can't handle binop 0x%x", code);
  }

  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_BINOP);
  i->rhs_value = vstack_pop(iu);
  i->lhs_value = vstack_pop(iu);
  i->op = binop;
  value_alloc_instr_ret(iu, i->lhs_value.type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}


/**
 *
 */
static void
wasm_convert(ir_unit_t *iu, ir_bb_t *ib, int code)
{
  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_CAST);
  int op;
  int type;
  switch(code) {
  case 0xa7:  op = CAST_TRUNC;   type = WASM_TYPE_I32;   break;
  case 0xa8:  op = CAST_FPTOSI;  type = WASM_TYPE_I32;   break;
  case 0xa9:  op = CAST_FPTOUI;  type = WASM_TYPE_I32;   break;
  case 0xaa:  op = CAST_FPTOSI;  type = WASM_TYPE_I32;   break;
  case 0xab:  op = CAST_FPTOUI;  type = WASM_TYPE_I32;   break;

  case 0xac:  op = CAST_SEXT;    type = WASM_TYPE_I64;   break;
  case 0xad:  op = CAST_ZEXT;    type = WASM_TYPE_I64;   break;
  case 0xae:  op = CAST_FPTOSI;  type = WASM_TYPE_I64;   break;
  case 0xaf:  op = CAST_FPTOUI;  type = WASM_TYPE_I64;   break;
  case 0xb0:  op = CAST_FPTOSI;  type = WASM_TYPE_I64;   break;
  case 0xb1:  op = CAST_FPTOUI;  type = WASM_TYPE_I64;   break;

  case 0xb2:  op = CAST_SITOFP;  type = WASM_TYPE_F32;   break;
  case 0xb3:  op = CAST_UITOFP;  type = WASM_TYPE_F32;   break;
  case 0xb4:  op = CAST_SITOFP;  type = WASM_TYPE_F32;   break;
  case 0xb5:  op = CAST_UITOFP;  type = WASM_TYPE_F32;   break;
  case 0xb6:  op = CAST_FPTRUNC; type = WASM_TYPE_F32;   break;

  case 0xb7:  op = CAST_SITOFP;  type = WASM_TYPE_F64;   break;
  case 0xb8:  op = CAST_UITOFP;  type = WASM_TYPE_F64;   break;
  case 0xb9:  op = CAST_SITOFP;  type = WASM_TYPE_F64;   break;
  case 0xba:  op = CAST_UITOFP;  type = WASM_TYPE_F64;   break;
  case 0xbb:  op = CAST_FPEXT;   type = WASM_TYPE_F64;   break;
  case 0xbc:  op = CAST_BITCAST; type = WASM_TYPE_I32;   break;
  case 0xbd:  op = CAST_BITCAST; type = WASM_TYPE_I64;   break;
  case 0xbe:  op = CAST_BITCAST; type = WASM_TYPE_F32;   break;
  case 0xbf:  op = CAST_BITCAST; type = WASM_TYPE_F64;   break;

  default:
    parser_error(iu, "Can't handle convert opcode 0x%x", code);
  }
  i->op = op;
  i->value = vstack_pop(iu);
  value_alloc_instr_ret(iu, type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}

/**
 *
 */
static void
wasm_cmp(ir_unit_t *iu, ir_bb_t *ib, int code)
{
  int cmpop = -1;
  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_CMP2);

  switch(code) {
  case 0x45:
    i->lhs_value = value_create_const32(iu, 0, IR_TYPE_INT32);
    i->rhs_value = vstack_pop(iu);
    i->op = ICMP_EQ;
    value_alloc_instr_ret(iu, WASM_TYPE_I32, &i->super);
    vstack_push(iu, i->super.ii_ret);
    return;

  case 0x50:
    i->lhs_value = value_create_const32(iu, 0, IR_TYPE_INT64);
    i->rhs_value = vstack_pop(iu);
    i->op = ICMP_EQ;
    value_alloc_instr_ret(iu, WASM_TYPE_I32, &i->super);
    vstack_push(iu, i->super.ii_ret);
    return;

  case 0x51:
  case 0x46:  cmpop = ICMP_EQ;   break;
  case 0x52:
  case 0x47:  cmpop = ICMP_NE;   break;
  case 0x53:
  case 0x48:  cmpop = ICMP_SLT;  break;
  case 0x54:
  case 0x49:  cmpop = ICMP_ULT;  break;
  case 0x55:
  case 0x4a:  cmpop = ICMP_SGT;  break;
  case 0x56:
  case 0x4b:  cmpop = ICMP_UGT;  break;
  case 0x57:
  case 0x4c:  cmpop = ICMP_SLE;  break;
  case 0x58:
  case 0x4d:  cmpop = ICMP_ULE;  break;
  case 0x59:
  case 0x4e:  cmpop = ICMP_SGE;  break;
  case 0x5a:
  case 0x4f:  cmpop = ICMP_UGE;  break;

  case 0x61:
  case 0x5b:  cmpop = FCMP_OEQ;   break;
  case 0x62:
  case 0x5c:  cmpop = FCMP_UNE;   break;
  case 0x63:
  case 0x5d:  cmpop = FCMP_OLT;   break;
  case 0x64:
  case 0x5e:  cmpop = FCMP_OGT;   break;
  case 0x65:
  case 0x5f:  cmpop = FCMP_OLE;   break;
  case 0x66:
  case 0x60:  cmpop = FCMP_OGE;   break;
  default:
    parser_error(iu, "Can't handle cmp 0x%x", code);
  }

  i->rhs_value = vstack_pop(iu);
  i->lhs_value = vstack_pop(iu);
  i->op = cmpop;
  value_alloc_instr_ret(iu, WASM_TYPE_I32, &i->super);
  vstack_push(iu, i->super.ii_ret);
}

/**
 *
 */
static void
wasm_load(ir_unit_t *iu, ir_bb_t *ib, int code, wasm_bytestream_t *wbs)
{
  int type;
  int cast = -1;
  int p = 0;
  switch(code) {
  case 0x28: type = WASM_TYPE_I32; break;
  case 0x29: type = WASM_TYPE_I64; break;
  case 0x2a: type = WASM_TYPE_F32; break;
  case 0x2b: type = WASM_TYPE_F64; break;

    // Load from smaller values and extend

  case 0x2c: type = WASM_TYPE_I32; p = WASM_TYPE_I8;  cast = CAST_SEXT; break;
  case 0x2d: type = WASM_TYPE_I32; p = WASM_TYPE_I8;  cast = CAST_ZEXT; break;
  case 0x2e: type = WASM_TYPE_I32; p = WASM_TYPE_I16; cast = CAST_SEXT; break;
  case 0x2f: type = WASM_TYPE_I32; p = WASM_TYPE_I16; cast = CAST_ZEXT; break;

  case 0x30: type = WASM_TYPE_I64; p = WASM_TYPE_I8;  cast = CAST_SEXT; break;
  case 0x31: type = WASM_TYPE_I64; p = WASM_TYPE_I8;  cast = CAST_ZEXT; break;
  case 0x32: type = WASM_TYPE_I64; p = WASM_TYPE_I16; cast = CAST_SEXT; break;
  case 0x33: type = WASM_TYPE_I64; p = WASM_TYPE_I16; cast = CAST_ZEXT; break;
  case 0x34: type = WASM_TYPE_I64; p = WASM_TYPE_I32; cast = CAST_SEXT; break;
  case 0x35: type = WASM_TYPE_I64; p = WASM_TYPE_I32; cast = CAST_ZEXT; break;

  default:
    parser_error(iu, "Can't handle load 0x%x", code);
  }

  /* int flags =*/ wbs_get_vu32(wbs);
  int offset = wbs_get_vu32(wbs);

  ir_instr_load_t *i = instr_add(ib, sizeof(ir_instr_load_t), IR_IC_LOAD);
  i->ptr = vstack_pop(iu);
  i->immediate_offset = offset;
  i->value_offset.value = -1;
  i->cast = cast;
  i->load_type = p;
  value_alloc_instr_ret(iu, type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}


/**
 *
 */
static void
wasm_store(ir_unit_t *iu, ir_bb_t *ib, int code, wasm_bytestream_t *wbs)
{
  int type;
  switch(code) {
  case 0x36: type = WASM_TYPE_I32; break;
  case 0x37: type = WASM_TYPE_I64; break;
  case 0x38: type = WASM_TYPE_F32; break;
  case 0x39: type = WASM_TYPE_F64; break;
  case 0x3a: type = WASM_TYPE_I8;  break;
  case 0x3b: type = WASM_TYPE_I16; break;
  case 0x3c: type = WASM_TYPE_I8;  break;
  case 0x3d: type = WASM_TYPE_I16; break;
  case 0x3e: type = WASM_TYPE_I32; break;
  default:
    parser_error(iu, "Can't handle store 0x%x", code);
  }

  /* int flags =*/ wbs_get_vu32(wbs);
  int offset = wbs_get_vu32(wbs);

  ir_instr_store_t *i = instr_add(ib, sizeof(ir_instr_store_t), IR_IC_STORE);
  i->value = vstack_pop(iu);
  i->ptr = vstack_pop(iu);
  i->value.type = type;
  i->immediate_offset = offset;
}


static void
wasm_const(ir_unit_t *iu, int code, wasm_bytestream_t *wbs)
{
  ir_valuetype_t vt;

  switch(code) {
  case 0x41:
    vt = value_create_const32(iu, wbs_get_v32(wbs), IR_TYPE_INT32);
    break;
  case 0x42:
    vt = value_create_const64(iu, wbs_get_v64(wbs), IR_TYPE_INT64);
    break;
  case 0x43:
    vt = value_create_const32(iu, wbs_get_u32(wbs), IR_TYPE_FLOAT);
    break;
  case 0x44:
    vt = value_create_const64(iu, wbs_get_u64(wbs), IR_TYPE_DOUBLE);
    break;
  default:
    parser_error(iu, "Can't handle const type 0x%x", code);
  }
  vstack_push(iu, vt);
}


static void
wasm_return(ir_unit_t *iu, ir_bb_t *ib)
{
  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_RET);
  const ir_type_t *it = type_get(iu, iu->iu_current_function->if_type);

  if(it->it_function.return_type == 0) {
    i->value.value = -1;
  } else {
    i->value = vstack_pop(iu);
  }
}


static void
wasm_set_local(ir_unit_t *iu, ir_bb_t *ib, const int localvar)
{
  ir_instr_move_t *move = instr_add(ib, sizeof(ir_instr_move_t), IR_IC_MOVE);
  move->value = vstack_pop(iu);

  move->super.ii_ret.value = localvar;
  move->super.ii_ret.type = move->value.type;
  value_bind_return_value(iu, &move->super);
}


static void
wasm_load_global(ir_unit_t *iu, ir_bb_t *ib, const ir_valuetype_t global_var)
{
  const int pointee_type = value_get(iu, global_var.value)->iv_gvar->ig_type;
  ir_instr_load_t *i = instr_add(ib, sizeof(ir_instr_load_t), IR_IC_LOAD);
  i->ptr = global_var;
  i->immediate_offset = 0;
  i->value_offset.value = -1;
  i->cast = -1;
  i->load_type = pointee_type;
  value_alloc_instr_ret(iu, pointee_type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}


static void
wasm_store_global(ir_unit_t *iu, ir_bb_t *ib, const ir_valuetype_t global_var)
{
  ir_instr_store_t *st = instr_add(ib, sizeof(ir_instr_store_t), IR_IC_STORE);
  st->value = vstack_pop(iu);
  st->ptr = global_var;
  st->immediate_offset = 0;
}


static void
wasm_call(ir_unit_t *iu, ir_bb_t *ib, wasm_bytestream_t *wbs,
          int indirect)
{
  int callee_type;

  if(indirect) {
    const int wasm_callee_type = wbs_get_vu32(wbs);
    callee_type = VECTOR_ITEM(&iu->iu_wasm_type_map, wasm_callee_type);

  } else {

    const int callee_index = wbs_get_vu32(wbs);
    ir_function_t *callee = VECTOR_ITEM(&iu->iu_functions, callee_index);
    callee_type = callee->if_type;

    ir_value_t *iv = value_append_and_get(iu);
    iv->iv_class = IR_VC_FUNCTION;
    iv->iv_type = callee_type;
    iv->iv_func = callee;
  }

  const ir_type_t *it = type_get(iu, callee_type);
  const int num_args = it->it_function.num_parameters;

  ir_instr_call_t *i =
    instr_add(ib, sizeof(ir_instr_call_t) +
              sizeof(ir_instr_arg_t) * num_args, IR_IC_CALL);

  if(indirect) {

    i->callee = vstack_pop(iu);
    wbs_get_vu32(wbs); // reserved

  } else {
    i->callee.value = iu->iu_next_value - 1;
  }
  i->argc = num_args;
  for(int j = num_args - 1; j >= 0; j--) {
    i->argv[j].value = vstack_pop(iu);
  }

  const ir_type_t *rety = type_get(iu, it->it_function.return_type);
  if(rety->it_code == IR_TYPE_VOID)
    return;

  value_alloc_instr_ret(iu, it->it_function.return_type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}

/**
 *
 */
static void
wasm_select(ir_unit_t *iu, ir_bb_t *ib)
{
  ir_instr_select_t *i = instr_add(ib, sizeof(ir_instr_select_t), IR_IC_SELECT);

  i->pred        = vstack_pop(iu);
  i->false_value = vstack_pop(iu);
  i->true_value  = vstack_pop(iu);

  value_alloc_instr_ret(iu, i->true_value.type, &i->super);
  vstack_push(iu, i->super.ii_ret);
}


typedef struct label_stack_frame {
  ir_bb_t *label;

  struct label_stack_frame *parent;

} label_stack_frame_t;


static int
bb_from_relative_depth(const label_stack_frame_t *lsf, int relative_depth)
{
  for(int i = 0; i < relative_depth; i++) {
    lsf = lsf->parent;
  }
  return lsf->label->ib_id;
}


static ir_bb_t *
wasm_branch(ir_unit_t *iu, ir_bb_t *ib, int code, int relative_depth,
            const label_stack_frame_t *lsf)
{
  ir_bb_t *next = bb_add_named(iu->iu_current_function, ib, "Branch split");

  ir_instr_br_t *i = instr_add(ib, sizeof(ir_instr_br_t), IR_IC_BR);

  i->true_branch = bb_from_relative_depth(lsf, relative_depth);

  switch(code) {
  case 0xc:
    i->condition.value = -1;
    break;
  case 0xd:
    i->false_branch = next->ib_id;
    i->condition = vstack_pop(iu);
    break;
  }
  return next;
}




static ir_bb_t *
wasm_branch_table(ir_unit_t *iu, ir_bb_t *ib, wasm_bytestream_t *wbs,
                  const label_stack_frame_t *lsf)
{
  ir_bb_t *next = bb_add_named(iu->iu_current_function, ib, "Branch-table split");

  const int paths = wbs_get_vu32(wbs);

  ir_instr_switch_t *i = instr_add(ib, sizeof(ir_instr_switch_t) +
                                   sizeof(ir_instr_path_t) * paths, IR_IC_SWITCH);
  i->value = vstack_pop(iu);
  i->num_paths = paths;

  for(int n = 0; n < paths; n++) {
    i->paths[n].v64 = n;
    i->paths[n].block = bb_from_relative_depth(lsf, wbs_get_vu32(wbs));
  }
  i->defblock = bb_from_relative_depth(lsf, wbs_get_vu32(wbs));
  return next;
}



/**
 *
 */
static void
unconditional_branch(ir_bb_t *ib, ir_bb_t *target)
{
  ir_instr_br_t *i = instr_add(ib, sizeof(ir_instr_br_t), IR_IC_BR);
  i->true_branch = target->ib_id;
  i->condition.value = -1;
}


static void
wasm_unreachable(ir_unit_t *iu, ir_bb_t *ib)
{
  instr_add(ib, sizeof(ir_instr_t), IR_IC_UNREACHABLE);
}




#define WASM_OP_BLOCK 0x2
#define WASM_OP_LOOP  0x3
#define WASM_OP_IF    0x4
#define WASM_OP_ELSE  0x5

static ir_bb_t *
wasm_parse_block(ir_unit_t *iu, ir_bb_t *ib,
                 wasm_bytestream_t *wbs, uint32_t local_var_base,
                 label_stack_frame_t *parent, int type, int depth,
                 int yield_value)
{
  unsigned int local_var;
  uint8_t rettype;
  ir_bb_t *exitblock = NULL;
  label_stack_frame_t lsf;
  lsf.parent = parent;

  switch(type) {
  case WASM_OP_BLOCK:
    lsf.label = bb_add_named(iu->iu_current_function, ib, "Block exit");
    exitblock = lsf.label;
    break;

  case WASM_OP_LOOP:
    lsf.label = bb_add_named(iu->iu_current_function, ib, "Loop start");
    unconditional_branch(ib, lsf.label);
    ib = lsf.label;
    break;

  case WASM_OP_IF:
    lsf.label = bb_add_named(iu->iu_current_function, ib, "False");
    exitblock = lsf.label;
    ir_instr_br_t *i = instr_add(ib, sizeof(ir_instr_br_t), IR_IC_BR);
    ib = bb_add_named(iu->iu_current_function, ib, "True");
    i->true_branch = ib->ib_id;
    i->false_branch = lsf.label->ib_id;
    i->condition =  vstack_pop(iu);
    break;

  default:
    abort();
  }

  while(wbs->ptr < wbs->end) {

    uint8_t code = wbs_get_byte(wbs);
    //    printf("%*.scode=%x @ 0x%zx\n", depth * 2, "", code, wbs->ptr - wbs->start);
    if(code == 0xb)
      break;

    switch(code) {
    case WASM_OP_BLOCK:
    case WASM_OP_LOOP:
    case WASM_OP_IF:
      rettype = wasm_parse_value_type(iu, wbs);
      int yielded = rettype ? value_alloc_temporary(iu, rettype).value : -1;
      ib = wasm_parse_block(iu, ib, wbs, local_var_base, &lsf, code, depth + 1,
                            yielded);
      if(yielded != -1)
        vstack_push_value(iu, yielded);
      break;

    case 0x0:
      wasm_unreachable(iu, ib);
      code = wbs_get_byte(wbs);
      while(code == 0)
        code = wbs_get_byte(wbs);
      if(code == 0xb) {
        if(depth == 0)
          return NULL;
        return exitblock;
      } else if(code != WASM_OP_ELSE) {
        parser_error(iu, "unreachable not followed by block termination");
      }
      // fallthru
    case WASM_OP_ELSE:
      if(yield_value != -1)
        wasm_set_local(iu, ib, yield_value);
      lsf.label = bb_add_named(iu->iu_current_function, ib, "Else exit");
      unconditional_branch(ib, lsf.label);
      ib = exitblock;
      exitblock = lsf.label;
      break;


    case 1:
      break;

    case 0xf:  // Return
      wasm_return(iu, ib);
      ib = bb_add_named(iu->iu_current_function, ib, "Return split");
      break;
    case 0xc:  // branch
    case 0xd:  // br_if
      ib = wasm_branch(iu, ib, code, wbs_get_vu32(wbs), &lsf);
      break;
    case 0xe:  // br_table
      ib = wasm_branch_table(iu, ib, wbs, &lsf);
      break;
    case 0x10:
    case 0x11:
      wasm_call(iu, ib, wbs, code == 0x11);
      break;
    case 0x1a:
      vstack_pop(iu);
      break;
    case 0x1b:
      wasm_select(iu, ib);
      break;
    case 0x20:
      vstack_push_value(iu, wbs_get_vu32(wbs) + local_var_base);
      break;
    case 0x21:
      wasm_set_local(iu, ib, wbs_get_vu32(wbs) + local_var_base);
      break;
    case 0x22:
      local_var = wbs_get_vu32(wbs) + local_var_base;
      wasm_set_local(iu, ib, local_var);
      vstack_push_value(iu, local_var);
      break;
    case 0x23:
      wasm_load_global(iu, ib, VECTOR_ITEM(&iu->iu_wasm_globalvar_map,
                                           wbs_get_vu32(wbs)));
      break;
    case 0x24:
      wasm_store_global(iu, ib, VECTOR_ITEM(&iu->iu_wasm_globalvar_map,
                                            wbs_get_vu32(wbs)));
      break;
    case 0x28 ... 0x35:
      wasm_load(iu, ib, code, wbs);
      break;
    case 0x36 ... 0x3e:
      wasm_store(iu, ib, code, wbs);
      break;
    case 0x41 ... 0x44:
      wasm_const(iu, code, wbs);
      break;
    case 0x45 ... 0x66:
      wasm_cmp(iu, ib, code);
      break;
    case 0x67 ... 0xa6:
      wasm_numeric(iu, ib, code);
      break;
    case 0xa7 ... 0xbf:
      wasm_convert(iu, ib, code);
      break;

    default:
      function_print(iu, iu->iu_current_function, "faildump");
      parser_error(iu, "Can't handle opcode 0x%x", code);
    }
  }

  if(yield_value != -1)
    wasm_set_local(iu, ib, yield_value);

  if(exitblock) {
    unconditional_branch(ib, exitblock);
    return exitblock;
  }
  return ib;
}


/**
 *
 */
static void
wasm_parse_section_code(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  iu->iu_current_function = TAILQ_FIRST(&iu->iu_functions_with_bodies);

  ir_bb_t *ib = NULL;
  for(uint32_t i = 0; i < count; i++) {
    vstack_clear(iu);
    iu->iu_first_func_value = iu->iu_next_value;

    function_prepare_parse(iu, iu->iu_current_function);

    const uint32_t local_var_base = iu->iu_next_value;

    /* const uint32_t body_size =*/ wbs_get_vu32(wbs);
    const uint32_t local_vars = wbs_get_vu32(wbs);

    ir_bb_t *preamble = bb_add_named(iu->iu_current_function, NULL, "Preamble");
    init_local_vars(iu, preamble, wbs, local_vars, iu->iu_current_function);

    ib = bb_add_named(iu->iu_current_function, preamble, "Func block");

    unconditional_branch(preamble, ib);

    ib = wasm_parse_block(iu, ib, wbs, local_var_base, NULL, 0x02, 0, -1);

    if(ib != NULL)
      wasm_return(iu, ib);

    function_process(iu, iu->iu_current_function);
    value_resize(iu, iu->iu_first_func_value);

    iu->iu_current_function = TAILQ_NEXT(iu->iu_current_function, if_body_link);
  }
}

static void
parse_init_expr(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  vstack_clear(iu);
  iu->iu_first_func_value = iu->iu_next_value;

  while(wbs->ptr < wbs->end) {
    const uint8_t code = wbs_get_byte(wbs);
    if(code == 0xb)
      break;

    switch(code) {
    case 0x41 ... 0x44:
      wasm_const(iu, code, wbs);
      break;

    default:
      parser_error(iu, "Init expression: Can't handle opcode 0x%x", code);
    }
  }
}

/**
 *
 */
static void
wasm_parse_section_data(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    const uint32_t index = wbs_get_vu32(wbs);

    parse_init_expr(iu, wbs); // Will leave value on vstack
    const uint32_t offset =
      value_get_const32(iu, value_get(iu, vstack_pop(iu).value));
    value_resize(iu, iu->iu_first_func_value);

    const uint32_t size = wbs_get_vu32(wbs);
    if(index == 0) {
      memcpy(iu->iu_mem + offset, wbs->ptr, size);
      iu->iu_data_ptr = MAX(iu->iu_data_ptr, offset + size);
    }
    wbs->ptr += size;
  }
}



/**
 *
 */
static void
wasm_parse_section_global(ir_unit_t *iu, wasm_bytestream_t *wbs)
{
  uint32_t count = wbs_get_vu32(wbs);
  for(uint32_t i = 0; i < count; i++) {
    const int pointee_type = wasm_parse_value_type(iu, wbs);
    const int pointer_type = type_make_pointer(iu, pointee_type, 1);
    const uint32_t mutable = wbs_get_vu32(wbs);

    const int val_id = value_create_global(iu, pointee_type, pointer_type, 0);
    const ir_valuetype_t vt = { val_id, pointer_type };
    VECTOR_PUSH_BACK(&iu->iu_wasm_globalvar_map, vt);

    parse_init_expr(iu, wbs); // Will leave value on vstack
    const ir_initializer_t ii = {val_id, vstack_pop(iu).value};
    VECTOR_PUSH_BACK(&iu->iu_initializers, ii);
    printf("Global var %s (globaindex: %zd) mutable=%d\n",
           value_str_id(iu, val_id),
           VECTOR_LEN(&iu->iu_wasm_globalvar_map) - 1, mutable);
  }
}


/**
 *
 */
static void
wasm_add_fundamental_types(ir_unit_t *iu)
{
  ir_type_t it = {};

  it.it_code = IR_TYPE_VOID;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_INT32;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_INT64;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_FLOAT;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_DOUBLE;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_INT8;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  it.it_code = IR_TYPE_INT16;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
}



/**
 *
 */
static void
wasm_parse_module(ir_unit_t *iu, const void *start, const void *end)
{
  wasm_bytestream_t bs = {
    .start = start - 4,
    .ptr = start,
    .end = end
  };

  const uint32_t version = wbs_get_u32(&bs);
  vmir_log(iu, VMIR_LOG_DEBUG, "WASM version %d", version);

  wasm_add_fundamental_types(iu);

  while(bs.ptr < bs.end) {
    const uint32_t section_code = wbs_get_vu32(&bs);
    const uint32_t section_len  = wbs_get_vu32(&bs);
    const uint8_t *section_end = bs.ptr + section_len;

    if(section_code == 0) {
      char *section_name = wbs_get_string(iu, &bs);
      vmir_log(iu, VMIR_LOG_DEBUG, "Skipping named section %s", section_name);
      free(section_name);
      bs.ptr = section_end;
      continue;
    }

    switch(section_code) {
    case WASM_SECTION_TYPE:
      wasm_parse_section_type(iu, &bs);
      break;
    case WASM_SECTION_IMPORT:
      wasm_parse_section_import_decl(iu, &bs);
      break;
    case WASM_SECTION_FUNCTION:
      wasm_parse_section_functions(iu, &bs);
      break;
    case WASM_SECTION_TABLE:
      wasm_parse_section_table(iu, &bs);
      break;
    case WASM_SECTION_MEMORY:
      wasm_parse_section_memory(iu, &bs);
      break;
    case WASM_SECTION_GLOBAL:
      wasm_parse_section_global(iu, &bs);
      break;
    case WASM_SECTION_EXPORTS:
      wasm_parse_section_exports(iu, &bs);
      break;
    case WASM_SECTION_CODE:
      wasm_parse_section_code(iu, &bs);
      break;
    case WASM_SECTION_DATA:
      wasm_parse_section_data(iu, &bs);
      break;
    default:
      vmir_log(iu, VMIR_LOG_ERROR, "Skipping section type %d", section_code);
      break;
    }
    bs.ptr = section_end;
  }


  iu->iu_data_ptr = VMIR_ALIGN(iu->iu_data_ptr, 4096);

  iu->iu_data_ptr += 1024 * 1024;

  // WASM stack
  uint32_t *u32p = iu->iu_mem;
  u32p[1] = iu->iu_data_ptr;
}

