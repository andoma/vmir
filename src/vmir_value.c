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

typedef enum {
  IR_VC_UNDEF,
  IR_VC_FUNCTION,
  IR_VC_GLOBALVAR,
  IR_VC_CONSTANT,
  IR_VC_TEMPORARY,
  IR_VC_REGFRAME,
  IR_VC_MACHINEREG,
  IR_VC_DATA,
  IR_VC_CE,   // Const expression
  IR_VC_AGGREGATE,
  IR_VC_ALIAS,
  IR_VC_ZERO_INITIALIZER,
  IR_VC_DEAD, // Value is not used
} ir_value_class_t;


typedef struct ir_constexpr {
  int ic_code;

  union {
    struct {
      int op;
      int src;
    } ic_cast;

    struct {
      int num_values;
      int *values;
    } ic_gep;

    struct {
      int op;
      int lhs;
      int rhs;
    } ic_binop;

    struct {
      int opty;
      int lhs;
      int rhs;
      int pred;
    } ic_cmp;
  };

} ir_constexpr_t;


/**
 * Relation between instruction and temporaries
 */
typedef struct ir_value_instr {
  LIST_ENTRY(ir_value_instr) ivi_value_link;
  LIST_ENTRY(ir_value_instr) ivi_instr_link;
  struct ir_value *ivi_value;
  struct ir_instr *ivi_instr;

  enum {
    IVI_INPUT,
    IVI_OUTPUT,
  } ivi_relation;

} ir_value_instr_t;

/**
 *
 */
typedef struct ir_value {
  ir_value_class_t iv_class;
  struct ir_value_instr_list iv_instructions;
  char *iv_name;
  void *iv_data;

  int iv_id;
  int iv_type;
  int iv_edges;

  union {
    // These guys must be in a union cause how we initialize float/double
    // constants
    uint32_t iv_u32;
    uint64_t iv_u64;
    float iv_float;
    double iv_double;

    ir_function_t *iv_func;
    ir_globalvar_t *iv_gvar;
    ir_constexpr_t *iv_ce;
    int iv_reg;

    int iv_num_values; // For aggregate types
    int iv_jit;        // For IR_VC_TEMPORARY that only exist in JITed code (Machine registers)
  };

  int iv_precolored;
  SLIST_ENTRY(ir_value) iv_tmp_link;

} ir_value_t;

static const char *value_str(ir_unit_t *iu, const ir_value_t *iv);
static const char *value_str_id(ir_unit_t *iu, int id);
static const char *value_str_vt(ir_unit_t *iu, const ir_valuetype_t vt);


/**
 *
 */
static void
value_bind_instr(ir_value_t *iv, ir_instr_t *ii, int relation)
{
  ir_value_instr_t *ivi = malloc(sizeof(ir_value_instr_t));
  ivi->ivi_instr = ii;
  ivi->ivi_value = iv;
  ivi->ivi_relation = relation;
  LIST_INSERT_HEAD(&ii->ii_values,       ivi, ivi_instr_link);
  LIST_INSERT_HEAD(&iv->iv_instructions, ivi, ivi_value_link);
}


/**
 *
 */
static ir_instr_t *
value_get_assigning_instr(ir_unit_t *iu, ir_value_t *iv)
{
  ir_value_instr_t *ivi;
  LIST_FOREACH(ivi, &iv->iv_instructions, ivi_value_link)
    if(ivi->ivi_relation == IVI_OUTPUT)
      return ivi->ivi_instr;
  return NULL;
}


/**
 *
 */
static void
ivi_destroy(ir_value_instr_t *ivi)
{
  LIST_REMOVE(ivi, ivi_instr_link);
  LIST_REMOVE(ivi, ivi_value_link);
  free(ivi);
}

/**
 *
 */
static void
instr_bind_clear(ir_instr_t *ii)
{
  ir_value_instr_t *ivi;
  while((ivi = LIST_FIRST(&ii->ii_values)) != NULL)
    ivi_destroy(ivi);
}


/**
 *
 */
static void
instr_bind_clear_inputs(ir_instr_t *ii)
{
  ir_value_instr_t *ivi, *next;
  for(ivi = LIST_FIRST(&ii->ii_values); ivi != NULL; ivi = next) {
    next = LIST_NEXT(ivi, ivi_instr_link);
    if(ivi->ivi_relation == IVI_INPUT)
      ivi_destroy(ivi);
  }
}


/**
 *
 */
static void
value_clear(ir_value_t *iv)
{
  free(iv->iv_name);
  iv->iv_name = NULL;

  free(iv->iv_data);
  iv->iv_data = NULL;

  ir_value_instr_t *ivi;
  while((ivi = LIST_FIRST(&iv->iv_instructions)) != NULL)
    ivi_destroy(ivi);

  switch(iv->iv_class) {
  case IR_VC_GLOBALVAR:
    free(iv->iv_gvar->ig_name);
    free(iv->iv_gvar);
    break;
  default:
    break;
  }
  iv->iv_class = IR_VC_UNDEF;
}

/**
 *
 */
static void
value_resize(ir_unit_t *iu, int newsize)
{
  assert(newsize <= VECTOR_LEN(&iu->iu_values));
  for(int i = newsize; i < VECTOR_LEN(&iu->iu_values); i++) {
    ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, i);
    if(iv == NULL)
      continue;
    VECTOR_ITEM(&iu->iu_values, i) = NULL;
    value_clear(iv);
    free(iv);
  }
  iu->iu_next_value = newsize;
}


/**
 *
 */
static int
value_append(ir_unit_t *iu)
{
  ir_value_t *iv;

  if(iu->iu_next_value == VECTOR_LEN(&iu->iu_values)) {
    iv = calloc(1, sizeof(ir_value_t));
    VECTOR_PUSH_BACK(&iu->iu_values, iv);
  } else {
    assert(iu->iu_next_value < VECTOR_LEN(&iu->iu_values));

    if(VECTOR_ITEM(&iu->iu_values, iu->iu_next_value) == NULL) {
      iv = calloc(1, sizeof(ir_value_t));
      VECTOR_ITEM(&iu->iu_values, iu->iu_next_value) = iv;
    } else {
      iv = VECTOR_ITEM(&iu->iu_values, iu->iu_next_value);
    }
  }
  iv->iv_id = iu->iu_next_value;
  return iu->iu_next_value++;
}


/**
 *
 */
static unsigned int __attribute__((unused))
value_reg(const ir_value_t *iv)
{
  assert(iv->iv_class == IR_VC_REGFRAME);
  return iv->iv_reg;
}


/**
 *
 */
static ir_function_t *__attribute__((unused))
value_function(ir_unit_t *iu, int id)
{
  if(id >= VECTOR_LEN(&iu->iu_values))
    return NULL;
  const ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, id);
  if(iv->iv_class != IR_VC_FUNCTION)
    return NULL;
  return iv->iv_func;
}

/**
 *
 */
static uint32_t __attribute__((unused))
value_function_addr(const ir_value_t *iv)
{
  assert(iv->iv_class == IR_VC_FUNCTION);
  return iv->iv_func->if_gfid;
}


/**
 *
 */
static ir_value_t *
value_append_and_get(ir_unit_t *iu)
{
  const int val = value_append(iu);
  return VECTOR_ITEM(&iu->iu_values, val);
}



/**
 *
 */
static ir_value_t *
value_get(ir_unit_t *iu, unsigned int index)
{
  if(index >= VECTOR_LEN(&iu->iu_values))
    parser_error(iu, "Bad value index %d", index);
  return VECTOR_ITEM(&iu->iu_values, index);
}



/**
 *
 */
static void
value_bind_return_value(ir_unit_t *iu, ir_instr_t *ii)
{
  value_bind_instr(value_get(iu, ii->ii_ret.value), ii, IVI_OUTPUT);
}


/**
 *
 */
static void
value_alloc_instr_ret(ir_unit_t *iu, int type, struct ir_instr *ii)
{
  int val = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val);
  iv->iv_class = IR_VC_TEMPORARY;
  iv->iv_type = type;
  iv->iv_precolored = -1;
  ii->ii_ret.value = val;
  ii->ii_ret.type = type;

  value_bind_instr(iv, ii, IVI_OUTPUT);
}


/**
 *
 */
static ir_valuetype_t
value_alloc_temporary(ir_unit_t *iu, int type)
{
  int val = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val);
  iv->iv_class = IR_VC_TEMPORARY;
  iv->iv_precolored = -1;
  iv->iv_type = type;
  return (ir_valuetype_t) {.value = val, .type = type};
}


/**
 *
 */
static int
value_regframe_slots(ir_unit_t *iu, int type)
{
  ir_type_t *it = type_get(iu, type);

  switch(it->it_code) {
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_FLOAT:
  case IR_TYPE_POINTER:
  case IR_TYPE_FUNCTION:
    return 1;
  case IR_TYPE_INT64:
  case IR_TYPE_DOUBLE:
    return 2;
  case IR_TYPE_INTx:
    if(it->it_bits <= 32)
      return 1;
    else
      return 2;

  default:
    parser_error(iu, "Can't determine regframe slots for type %s",
                 type_str(iu, it));
  }
}

/**
 *
 */
static int
value_regframe_size(ir_unit_t *iu, int type)
{
  return value_regframe_slots(iu, type) * 4;
}



/**
 *
 */
static void
value_alloc_function_arg(ir_unit_t *iu, int type)
{
  int val = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val);
  iv->iv_class = IR_VC_REGFRAME;
  iv->iv_type = type;

  ir_function_t *f = iu->iu_current_function;
  int size = value_regframe_size(iu, type);
  f->if_callarg_size -= size;
  iv->iv_reg = f->if_callarg_size;
}


/**
 *
 */
static uint32_t __attribute__((unused))
value_get_const32(ir_unit_t *iu, const ir_value_t *iv)
{
  ir_type_t *it = type_get(iu, iv->iv_type);

  switch(iv->iv_class) {

  case IR_VC_GLOBALVAR:
    return iv->iv_gvar->ig_addr;

  case IR_VC_CONSTANT:
    switch(it->it_code) {
    case IR_TYPE_INT1:
      return !!iv->iv_u32;
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_FLOAT:
      return iv->iv_u32;
    case IR_TYPE_INTx:
    case IR_TYPE_INT64:
  case IR_TYPE_DOUBLE:
      return iv->iv_u64;
    default:
      break;
    }
    break;
  default:
    break;
  }

  parser_error(iu, "Unable to value_get_const for value %s",
               value_str(iu, iv));
}


/**
 *
 */
static uint32_t __attribute__((unused))
value_get_const(ir_unit_t *iu, const ir_value_t *iv)
{
  ir_type_t *it = type_get(iu, iv->iv_type);

  switch(iv->iv_class) {

  case IR_VC_GLOBALVAR:
    return iv->iv_gvar->ig_addr;

  case IR_VC_CONSTANT:
    switch(it->it_code) {
    case IR_TYPE_INT1:
      return !!iv->iv_u32;
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_FLOAT:
      return iv->iv_u32 & type_code_mask(it->it_code);
    case IR_TYPE_INTx:
    case IR_TYPE_INT64:
    case IR_TYPE_DOUBLE:
      return iv->iv_u64;
    default:
      break;
    }
    break;
  default:
    break;
  }

  parser_error(iu, "Unable to value_get_const for value %s",
               value_str(iu, iv));
}


/**
 *
 */
static uint64_t __attribute__((unused))
value_get_const64(ir_unit_t *iu, const ir_value_t *iv)
{
  assert(iv->iv_class == IR_VC_CONSTANT);

  ir_type_t *it = type_get(iu, iv->iv_type);
  switch(it->it_code) {
  case IR_TYPE_INT1:
    return !!iv->iv_u32;
  case IR_TYPE_INT8:
  case IR_TYPE_INT16:
  case IR_TYPE_INT32:
  case IR_TYPE_POINTER:
    return iv->iv_u32;
  case IR_TYPE_INTx:
  case IR_TYPE_INT64:
  case IR_TYPE_DOUBLE:
    return iv->iv_u64;
  default:
    parser_error(iu, "Unable to get_constant for type %s",
                 type_str(iu, it));
  }
}


/**
 *
 */
static ir_valuetype_t
value_create_const32(ir_unit_t *iu, int v, ir_type_code_t code)
{
  int type = type_find_by_code(iu, code);
  int ret = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, ret);

  iv->iv_class = IR_VC_CONSTANT;
  iv->iv_type = type;
  iv->iv_u32 = v;
  return (ir_valuetype_t) {.value = ret, .type = type};
}

/**
 *
 */
__attribute__((unused))
static ir_valuetype_t
value_create_const64(ir_unit_t *iu, uint64_t v, ir_type_code_t code)
{
  int type = type_find_by_code(iu, code);
  int ret = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, ret);

  iv->iv_class = IR_VC_CONSTANT;
  iv->iv_type = type;
  iv->iv_u64 = v;
  return (ir_valuetype_t) {.value = ret, .type = type};
}


/**
 *
 */
static ir_valuetype_t
value_create_zero(ir_unit_t *iu, int type)
{
  int ret = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, ret);

  iv->iv_class = IR_VC_CONSTANT;
  iv->iv_type = type;
  iv->iv_u64 = 0;
  return (ir_valuetype_t) {.value = ret, .type = type};
}

static int value_print_id(char **dstp, ir_unit_t *iu, int id);
static int value_print_vt(char **dstp, ir_unit_t *iu, ir_valuetype_t vt);

/**
 *
 */
static int
value_print(char **dstp, ir_unit_t *iu, const ir_value_t *iv,
            const ir_type_t *it)
{
  int value = iv->iv_id;
  int len = 0;
  char tmpbuf[64];

  if(it == NULL) {
    if(iv->iv_type < VECTOR_LEN(&iu->iu_types))
      it = &VECTOR_ITEM(&iu->iu_types, iv->iv_type);
  }

  switch(iv->iv_class) {
  case IR_VC_UNDEF:
    len += addstr(dstp, "<undefined>");
    break;

  case IR_VC_CE:
    len += addstr(dstp, "<constexpr>");
    break;

  case IR_VC_AGGREGATE:
    len += type_print(dstp, iu, it);
    len += addstr(dstp, " = {");
    ir_valuetype_t *values = iv->iv_data;
    for(int i = 0; i < iv->iv_num_values; i++) {
      if(i != 0)
        len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, values[i]);
    }
    len += addstr(dstp, "}");
    break;

  case IR_VC_DEAD:
    snprintf(tmpbuf, sizeof(tmpbuf), "<dead>%%%d", value);
    len += addstr(dstp, tmpbuf);
    break;

  case IR_VC_ALIAS:
    len += addstr(dstp, "alias -> ");
    len += value_print_id(dstp, iu, iv->iv_reg);
    break;

  case IR_VC_FUNCTION:
    len += addstr(dstp, "function ");
    if(iv->iv_func->if_name != NULL) {
      len += addstr(dstp, iv->iv_func->if_name);
      len += addstr(dstp, "() ");
    }
    len += type_print_id(dstp, iu, iv->iv_func->if_type);
    break;

  case IR_VC_GLOBALVAR:
    len += addstr(dstp, "global ");
    if(iv->iv_gvar->ig_name != NULL) {
      len += addstr(dstp, iv->iv_gvar->ig_name);
      len += addstr(dstp, " ");
    }
    len += type_print(dstp, iu, it);
    snprintf(tmpbuf, sizeof(tmpbuf), " @ 0x%x", iv->iv_gvar->ig_addr);
    len += addstr(dstp, tmpbuf);
    break;

  case IR_VC_TEMPORARY:
    len += addstr(dstp, "(");
    len += type_print(dstp, iu, it);
    snprintf(tmpbuf, sizeof(tmpbuf), ")%%%d", value);
    len += addstr(dstp, tmpbuf);
    break;

  case IR_VC_CONSTANT:
    len += addstr(dstp, "(");
    len += type_print(dstp, iu, it);
    snprintf(tmpbuf, sizeof(tmpbuf), ")%%%d", value);
    len += addstr(dstp, tmpbuf);
    if(it == NULL) {
      len += addstr(dstp, "badtype");
      break;
    }

    switch(it->it_code) {
    case IR_TYPE_INT1:
      snprintf(tmpbuf, sizeof(tmpbuf), "#0x%x", !!iv->iv_u32);
      break;
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
      snprintf(tmpbuf, sizeof(tmpbuf), "#0x%x", iv->iv_u32);
      break;
    case IR_TYPE_INT64:
      snprintf(tmpbuf, sizeof(tmpbuf), "#0x%"PRIx64, iv->iv_u64);
      break;
    case IR_TYPE_FLOAT:
      snprintf(tmpbuf, sizeof(tmpbuf), "#%f", iv->iv_float);
      break;
    case IR_TYPE_DOUBLE:
      snprintf(tmpbuf, sizeof(tmpbuf), "#%f", iv->iv_double);
      break;
    default:
      snprintf(tmpbuf, sizeof(tmpbuf), "#?(code-%d)", it->it_code);
      break;
    }
    len += addstr(dstp, tmpbuf);
    break;

  case IR_VC_ZERO_INITIALIZER:
    len += addstr(dstp, "zeroinitializer");
    break;

  case IR_VC_REGFRAME:
    len += addstr(dstp, "(");
    len += type_print(dstp, iu, it);
    snprintf(tmpbuf, sizeof(tmpbuf), ")%%%d{0x%x}", value, iv->iv_reg);
    len += addstr(dstp, tmpbuf);
    break;
  case IR_VC_MACHINEREG:
    len += addstr(dstp, "(");
    len += type_print(dstp, iu, it);
    snprintf(tmpbuf, sizeof(tmpbuf), ")%%%d{r%d}", value, iv->iv_reg);
    len += addstr(dstp, tmpbuf);
    break;
  case IR_VC_DATA:
    {
      len += addstr(dstp, "data [");
      int size = type_sizeof(iu, iv->iv_type);
      for(int i = 0; i < size; i++) {
        if(i)
          len += addstr(dstp, ".");
        snprintf(tmpbuf, sizeof(tmpbuf), "%02x", ((uint8_t *)iv->iv_data)[i]);
        len += addstr(dstp, tmpbuf);
      }
      len += addstr(dstp, "]");
    }
    break;
  }

  if(iv->iv_name != NULL) {
    len += addstr(dstp, "\"");
    len += addstr(dstp, iv->iv_name);
    len += addstr(dstp, "\"");
  }
  return len;
}

/**
 *
 */
static int
value_print_id(char **dstp, ir_unit_t *iu, int value)
{
  if(value >= VECTOR_LEN(&iu->iu_values)) {
    char tmpbuf[64];
    snprintf(tmpbuf, sizeof(tmpbuf), ">>BADVALUE:%d<<", value);
    return addstr(dstp, tmpbuf);
  }
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, value);
  return value_print(dstp, iu, iv, NULL);
}

/**
 *
 */
static int
value_print_vt(char **dstp, ir_unit_t *iu, ir_valuetype_t vt)
{
  if(vt.value >= VECTOR_LEN(&iu->iu_values)) {
    char tmpbuf[64];
    snprintf(tmpbuf, sizeof(tmpbuf), ">>BADVALUE:%d<<", vt.value);
    return addstr(dstp, tmpbuf);
  }

  if(vt.type >= VECTOR_LEN(&iu->iu_types)) {
    char tmpbuf[64];
    snprintf(tmpbuf, sizeof(tmpbuf), ">>BADTYPE:%d<<", vt.type);
    return addstr(dstp, tmpbuf);
  }

  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, vt.value);
  const ir_type_t *it = &VECTOR_ITEM(&iu->iu_types, vt.type);
  return value_print(dstp, iu, iv, it);
}


/**
 *
 */
static const char *
value_str(ir_unit_t *iu, const ir_value_t *iv)
{
  int len = value_print(NULL, iu, iv, NULL);
  char *dst = tmpstr(iu, len);
  const char *ret = dst;
  value_print(&dst, iu, iv, NULL);
  return ret;
}


/**
 *
 */
static const char *
value_str_id(ir_unit_t *iu, int id)
{
  int len = value_print_id(NULL, iu, id);
  char *dst = tmpstr(iu, len);
  const char *ret = dst;
  value_print_id(&dst, iu, id);
  return ret;
}


/**
 *
 */
  __attribute__((unused)) static const char *
value_str_vt(ir_unit_t *iu, ir_valuetype_t vt)
{
  int len = value_print_vt(NULL, iu, vt);
  char *dst = tmpstr(iu, len);
  const char *ret = dst;
  value_print_vt(&dst, iu, vt);
  return ret;
}



/**
 *
 */
static void __attribute__((unused))
value_print_list(ir_unit_t *iu)
{
  for(int i = 0; i < iu->iu_next_value; i++) {
    printf("i=%d %p\n", i, value_get(iu, i));
    printf("[%5d]: %s\n", i, value_str_id(iu, i));
  }
}


/**
 *
 */
static void
eval_constexpr(ir_unit_t *iu, ir_value_t *iv, ir_constexpr_t *ic)
{
  switch(ic->ic_code) {
  case CST_CODE_CE_CAST:
    {
      ir_type_code_t tc = type_get(iu, iv->iv_type)->it_code;
      ir_value_t *src = value_get(iu, ic->ic_cast.src);

      if(src->iv_class == IR_VC_CE)
        eval_constexpr(iu, src, src->iv_ce);

      if(src->iv_class == IR_VC_ALIAS) {
        src = value_get(iu, src->iv_reg);
      }

      iv->iv_class = IR_VC_CONSTANT;

      switch(COMBINE3(tc, ic->ic_cast.op, src->iv_class)) {
      case COMBINE3(IR_TYPE_POINTER, CAST_INTTOPTR, IR_VC_CONSTANT):
        iv->iv_u32 = src->iv_u32;
        break;

      case COMBINE3(IR_TYPE_POINTER, CAST_BITCAST, IR_VC_GLOBALVAR):
        iv->iv_u32 = value_get_const32(iu, src);
        break;

      case COMBINE3(IR_TYPE_POINTER, CAST_BITCAST, IR_VC_CONSTANT):
        iv->iv_u32 = value_get_const32(iu, src);
        break;

      case COMBINE3(IR_TYPE_POINTER, CAST_BITCAST, IR_VC_FUNCTION):
        iv->iv_class = IR_VC_FUNCTION;
        iv->iv_func = src->iv_func;
        iv->iv_type = src->iv_type;
        break;

      case COMBINE3(IR_TYPE_INT32, CAST_PTRTOINT, IR_VC_CONSTANT):
      case COMBINE3(IR_TYPE_INT32, CAST_PTRTOINT, IR_VC_GLOBALVAR):
      case COMBINE3(IR_TYPE_INT8, CAST_PTRTOINT, IR_VC_CONSTANT):
      case COMBINE3(IR_TYPE_INT8, CAST_PTRTOINT, IR_VC_GLOBALVAR):
        iv->iv_u32 = value_get_const32(iu, src);
        break;

      case COMBINE3(IR_TYPE_INT32, CAST_PTRTOINT, IR_VC_FUNCTION):
        iv->iv_u32 = value_function_addr(src);
        break;

      default:
        parser_error(iu,
                     "Unable to constant-cast %s from %s using op %d class=%d",
                     type_str_index(iu, iv->iv_type),
                     type_str_index(iu, src->iv_type),
                     ic->ic_cast.op, src->iv_class);
      }
    }
    break;

  case CST_CODE_CE_BINOP:
    {
      ir_value_t *lhs = value_get(iu, ic->ic_binop.lhs);
      ir_value_t *rhs = value_get(iu, ic->ic_binop.rhs);
      ir_type_code_t tc = type_get(iu, iv->iv_type)->it_code;

      switch(tc) {
      case IR_TYPE_INT8:
      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        {
          const uint32_t l = value_get_const32(iu, lhs);
          const uint32_t r = value_get_const32(iu, rhs);

          switch(ic->ic_binop.op) {
          case BINOP_ADD:  iv->iv_u32 = l + r; break;
          case BINOP_SUB:  iv->iv_u32 = l - r; break;
          case BINOP_MUL:  iv->iv_u32 = l * r; break;

          case BINOP_UDIV: iv->iv_u32 = l / r; break;
          case BINOP_SDIV: iv->iv_u32 = (int32_t)l / (int32_t)r; break;
          case BINOP_UREM: iv->iv_u32 = l % r; break;
          case BINOP_SREM: iv->iv_u32 = (int32_t)l % (int32_t)r; break;

          case BINOP_SHL:  iv->iv_u32 = l << r; break;
          case BINOP_LSHR: iv->iv_u32 = l >> r; break;
          case BINOP_ASHR: iv->iv_u32 = (int32_t)l >> r; break;
          case BINOP_AND:  iv->iv_u32 = l & r; break;
          case BINOP_OR:   iv->iv_u32 = l | r; break;
          case BINOP_XOR:  iv->iv_u32 = l ^ r; break;
          default:
            parser_error(iu, "Unable to handle opcode %d in constant binop",
                         ic->ic_binop.op);
          }
        }
        break;

      default:
        parser_error(iu, "Unable to handle constant binop for typecode %d",
                     tc);
      }
      iv->iv_class = IR_VC_CONSTANT;
    }
    break;

  case CST_CODE_CE_CMP:
    {
      ir_value_t *lhs = value_get(iu, ic->ic_cmp.lhs);
      ir_value_t *rhs = value_get(iu, ic->ic_cmp.rhs);
      ir_type_code_t opty = type_get(iu, ic->ic_cmp.opty)->it_code;

      switch(opty) {
      case IR_TYPE_INT32:
      case IR_TYPE_POINTER:
        {
          const uint32_t l = value_get_const32(iu, lhs);
          const uint32_t r = value_get_const32(iu, rhs);

          switch(ic->ic_cmp.pred) {
          case ICMP_EQ:  iv->iv_u32 = l == r; break;
          case ICMP_NE:  iv->iv_u32 = l != r; break;
          case ICMP_UGT: iv->iv_u32 = l >  r; break;
          case ICMP_UGE: iv->iv_u32 = l >= r; break;
          case ICMP_ULT: iv->iv_u32 = l <  r; break;
          case ICMP_ULE: iv->iv_u32 = l <= r; break;
          case ICMP_SGT: iv->iv_u32 = (int32_t)l >  (int32_t)r; break;
          case ICMP_SGE: iv->iv_u32 = (int32_t)l >= (int32_t)r; break;
          case ICMP_SLT: iv->iv_u32 = (int32_t)l <  (int32_t)r; break;
          case ICMP_SLE: iv->iv_u32 = (int32_t)l <= (int32_t)r; break;

          default:
            parser_error(iu, "Unable to handle opcode %d in constant cmp",
                         ic->ic_binop.op);
          }
        }
        break;

      default:
        parser_error(iu, "Unable to handle constant cmp for type %s",
                     type_str_index(iu, ic->ic_cmp.opty));
      }
      iv->iv_class = IR_VC_CONSTANT;
    }
    break;

  case CST_CODE_CE_GEP:
  case CST_CODE_CE_INBOUNDS_GEP:
    {
      const int *vv = ic->ic_gep.values;
      ir_value_t *curval = value_get(iu, vv[0]);

      if(curval->iv_class == IR_VC_CE)
        eval_constexpr(iu, curval, curval->iv_ce);

      uint32_t addr = value_get_const32(iu, curval);
      int type_index = curval->iv_type;
      for(int i = 1; i < ic->ic_gep.num_values; i++) {
        ir_type_t *curtype = type_get(iu, type_index);
        curval = value_get(iu, vv[i]);

        int x = value_get_const32(iu, curval);

        switch(curtype->it_code) {
        default:
          parser_error(iu, "Unable to handle type %s in constexpr GEP",
                       type_str(iu, curtype));

        case IR_TYPE_POINTER:
          addr += x * type_sizeof(iu, curtype->it_pointer.pointee);
          type_index = curtype->it_pointer.pointee;
          break;

        case IR_TYPE_STRUCT:
          if(x >= curtype->it_struct.num_elements)
            parser_error(iu, "Bad index %d info struct", x);
          type_index = curtype->it_struct.elements[x].type;
          addr += curtype->it_struct.elements[x].offset;
          break;

        case IR_TYPE_ARRAY:
          addr +=  x * type_sizeof(iu, curtype->it_array.element_type);
          type_index = curtype->it_array.element_type;
          break;
        }
      }
      iv->iv_type = type_make_pointer(iu, type_index, 1);
      iv->iv_u32 = addr;
      iv->iv_class = IR_VC_CONSTANT;

      free(ic->ic_gep.values);
    }
    break;

  default:
    parser_error(iu, "Unable to eval constexpr for code %d", ic->ic_code);
  }
  free(ic);
}

/**
 * Evaluate all const expressions and convert to purely constant values
 */
static void
eval_constexprs(ir_unit_t *iu)
{
  for(int i = 0; i < iu->iu_next_value; i++) {
    ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, i);
    if(iv->iv_class == IR_VC_CE)
      eval_constexpr(iu, iv, iv->iv_ce);
  }
}


/**
 * Create a new global variable
 */
static int
value_create_global(ir_unit_t *iu, int pointee_type, int pointer_type,
                    int alignment)
{
  if(alignment == 0)
    alignment = type_alignment(iu, pointee_type);

  ir_globalvar_t *ig = calloc(1, sizeof(ir_globalvar_t));
  ig->ig_type = pointee_type;

  const int val_id = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val_id);
  iv->iv_class = IR_VC_GLOBALVAR;
  iv->iv_type = pointer_type;
  iv->iv_gvar = ig;
  iu->iu_data_ptr = VMIR_ALIGN(iu->iu_data_ptr, alignment);
  ig->ig_addr = iu->iu_data_ptr;
  ig->ig_size = type_sizeof(iu, pointee_type);
  iu->iu_data_ptr += type_sizeof(iu, pointee_type);
  return val_id;
}
