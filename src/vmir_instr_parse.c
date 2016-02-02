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


/**
 *
 */
static ir_bb_t *
bb_add(ir_function_t *f, ir_bb_t *after)
{
  ir_bb_t *ib = calloc(1, sizeof(ir_bb_t));
  TAILQ_INIT(&ib->ib_instrs);
  ib->ib_id = f->if_num_bbs++;
  if(after != NULL)
    TAILQ_INSERT_AFTER(&f->if_bbs, after, ib, ib_link);
  else
    TAILQ_INSERT_TAIL(&f->if_bbs, ib, ib_link);
  return ib;
}



/**
 *
 */
static int
instr_get_vtp(ir_unit_t *iu, unsigned int *argcp, const ir_arg_t **argvp)
{
  const ir_arg_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing value code");

  unsigned int val = iu->iu_next_value - argv[0].i64;

  if(val < iu->iu_next_value) {
    *argvp = argv + 1;
    *argcp = argc - 1;
    return val;
  }

  if(val >= VECTOR_LEN(&iu->iu_values))
    VECTOR_RESIZE(&iu->iu_values, val + 1);

  ir_value_t *iv = calloc(1, sizeof(ir_value_t));
  VECTOR_ITEM(&iu->iu_values, val) = iv;
  iv->iv_class = IR_VC_UNDEF;
  iv->iv_type = argv[1].i64;

  *argvp = argv + 2;
  *argcp = argc - 2;
  return val;
}


/**
 *
 */
static unsigned int
instr_get_value(ir_unit_t *iu, unsigned int *argcp, const ir_arg_t **argvp)
{
  const ir_arg_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing value code");

  *argvp = argv + 1;
  *argcp = argc - 1;

  return iu->iu_next_value - argv[0].i64;
}


/**
 *
 */
static unsigned int
instr_get_value_signed(ir_unit_t *iu,
                       unsigned int *argcp, const ir_arg_t **argvp)
{
  const ir_arg_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing value code");

  *argvp = argv + 1;
  *argcp = argc - 1;

  return iu->iu_next_value - read_sign_rotated(argv);
}


/**
 *
 */
static unsigned int
instr_get_uint(ir_unit_t *iu, unsigned int *argcp, const ir_arg_t **argvp)
{
  const ir_arg_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing argument");

  *argvp = argv + 1;
  *argcp = argc - 1;
  return argv[0].i64;
}

/**
 *
 */
static void *
instr_isa(ir_instr_t *ii, instr_class_t c)
{
  if(ii == NULL || ii->ii_class != c)
    return NULL;
  return ii;
}


/**
 *
 */
typedef struct ir_instr_unary {
  ir_instr_t super;
  int value;  // Value must be first so we can alias on ir_instr_move
  int op;

} ir_instr_unary_t;


/**
 *
 */
typedef struct ir_instr_store {
  ir_instr_t super;
  int ptr;
  int value;
  int offset;
} ir_instr_store_t;


/**
 *
 */
typedef struct ir_instr_load {
  ir_instr_t super;
  int ptr;
  int immediate_offset;
  int value_offset;
  int value_offset_multiply;
  int8_t cast;
  uint8_t load_type; // Only valid when cast != -1
} ir_instr_load_t;


/**
 *
 */
typedef struct ir_instr_binary {
  ir_instr_t super;
  int op;
  int lhs_value;
  int rhs_value;

} ir_instr_binary_t;


/**
 *
 */
typedef struct ir_instr_ternary {
  ir_instr_t super;
  int arg1;
  int arg2;
  int arg3;
} ir_instr_ternary_t;


/**
 *
 */
typedef struct ir_gep_index {
  int value;
  int type;
} ir_gep_index_t;

/**
 *
 */
typedef struct ir_instr_gep {
  ir_instr_t super;
  int num_indicies;
  int baseptr;
  ir_gep_index_t indicies[0];
} ir_instr_gep_t;


/**
 *
 */
typedef struct ir_instr_lea {
  ir_instr_t super;
  int baseptr;
  int immediate_offset;
  int value_offset;
  int value_offset_multiply;
} ir_instr_lea_t;


/**
 *
 */
typedef struct ir_instr_br {
  ir_instr_t super;
  int condition;
  int true_branch;
  int false_branch;
} ir_instr_br_t;


typedef struct ir_phi_node {
  int predecessor;
  int value;
} ir_phi_node_t;

/**
 *
 */
typedef struct ir_instr_phi {
  ir_instr_t super;
  int num_nodes;
  ir_phi_node_t nodes[0];
} ir_instr_phi_t;


typedef struct ir_instr_arg {
  int value;
  int copy_size;
} ir_instr_arg_t;

/**
 * Shared with IR_IC_INTRINSIC
 */
typedef struct ir_instr_call {
  ir_instr_t super;
  int callee;
  int argc;
  ir_instr_arg_t argv[0];
} ir_instr_call_t;


/**
 *
 */
typedef struct ir_instr_jsr {
  ir_instr_t super;
  int callee;
  int registers;
} ir_instr_jsr_t;


/**
 *
 */
typedef struct ir_instr_path {
  int64_t v64;
  int block;
} ir_instr_path_t;

/**
 *
 */
typedef struct ir_instr_switch {
  ir_instr_t super;
  int value;
  int defblock;
  int num_paths;
  int width;  /* Width of 'value' in bits before converting all values
               * to 8,16,32,64 widths.
               */
  ir_type_code_t typecode;
  ir_instr_path_t paths[0];
} ir_instr_switch_t;


/**
 *
 */
typedef struct ir_instr_alloca {
  ir_instr_t super;
  int size;
  int num_items_value;
  int alignment;
} ir_instr_alloca_t;


/**
 *
 */
typedef struct ir_instr_select {
  ir_instr_t super;
  int true_value;
  int false_value;
  int pred;
} ir_instr_select_t;



/**
 *
 */
typedef struct ir_instr_move {
  ir_instr_t super;
  int value;
} ir_instr_move_t;


typedef struct ir_instr_stackcopy {
  ir_instr_t super;
  int value;
  int size;
} ir_instr_stackcopy_t;


typedef struct ir_instr_stackshrink {
  ir_instr_t super;
  int size;
} ir_instr_stackshrink_t;

/**
 *
 */
typedef struct ir_instr_cmp_branch {
  ir_instr_t super;
  int op;
  int lhs_value;
  int rhs_value;
  int true_branch;
  int false_branch;
} ir_instr_cmp_branch_t;


typedef struct ir_instr_extractval {
  ir_instr_t super;
  int value;
  int num_indicies;
  int indicies[0];
} ir_instr_extractval_t;

/**
 *
 */
static ir_instr_t *
instr_create(size_t size, instr_class_t ic)
{
  ir_instr_t *ii = calloc(1, size);
  LIST_INIT(&ii->ii_values);
  ii->ii_class = ic;
  ii->ii_ret_value = -1;
  return ii;
}


/**
 *
 */
static void *
instr_add(ir_bb_t *ib, size_t size, instr_class_t ic)
{
  ir_instr_t *ii = instr_create(size, ic);
  ii->ii_bb = ib;
  TAILQ_INSERT_TAIL(&ib->ib_instrs, ii, ii_link);
  return ii;
}


/**
 *
 */
static void *
instr_add_before(size_t size, instr_class_t ic, ir_instr_t *before)
{
  ir_bb_t *ib = before->ii_bb;
  ir_instr_t *ii = instr_create(size, ic);
  ii->ii_bb = ib;
  TAILQ_INSERT_BEFORE(before, ii, ii_link);
  return ii;
}


/**
 *
 */
static void *
instr_add_after(size_t size, instr_class_t ic, ir_instr_t *after)
{
  ir_bb_t *ib = after->ii_bb;
  ir_instr_t *ii = instr_create(size, ic);
  ii->ii_bb = ib;
  TAILQ_INSERT_AFTER(&ib->ib_instrs,  after, ii, ii_link);
  return ii;
}


/**
 *
 */
static void
instr_destroy(ir_instr_t *ii)
{
  instr_bind_clear(ii);
  free(ii->ii_ret_values);
  free(ii->ii_succ);
  free(ii->ii_liveness);

  TAILQ_REMOVE(&ii->ii_bb->ib_instrs, ii, ii_link);
  free(ii);
}


/**
 *
 */
static void
parse_ret(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_RET);

  if(argc == 0) {
    i->value = -1;
  } else {
    i->value = instr_get_vtp(iu, &argc, &argv);
  }
}


/**
 *
 */
static void
parse_unreachable(ir_unit_t *iu)
{
  ir_bb_t *ib = iu->iu_current_bb;

  instr_add(ib, sizeof(ir_instr_t), IR_IC_UNREACHABLE);
}


/**
 *
 */
static void
parse_binop(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_BINOP);
  i->lhs_value = instr_get_vtp(iu, &argc, &argv);
  i->rhs_value = instr_get_value(iu, &argc, &argv);
  i->op        = instr_get_uint(iu, &argc, &argv);

  value_alloc_instr_ret(iu, value_get_type(iu, i->lhs_value),
                        &i->super);
}


/**
 *
 */
static void
parse_cast(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_CAST);
  i->value = instr_get_vtp(iu, &argc, &argv);
  int type = instr_get_uint(iu, &argc, &argv);
  i->op    = instr_get_uint(iu, &argc, &argv);
  value_alloc_instr_ret(iu, type, &i->super);
}


/**
 *
 */
static void
parse_load(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_load_t *i = instr_add(ib, sizeof(ir_instr_load_t), IR_IC_LOAD);
  i->immediate_offset = 0;
  i->ptr = instr_get_vtp(iu, &argc, &argv);
  i->value_offset = -1;
  i->value_offset_multiply = 0;
  i->cast = -1;
  if(argc == 3) {
    // Explicit type
    value_alloc_instr_ret(iu, argv[0].i64, &i->super);
  } else {
    value_alloc_instr_ret(iu,
                          type_get_pointee(iu,
                                           value_get_type(iu, i->ptr)),
                          &i->super);
  }
}


/**
 *
 */
static void
parse_store(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv,
            int old)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_store_t *i = instr_add(ib, sizeof(ir_instr_store_t), IR_IC_STORE);
  i->offset = 0;
  i->ptr   = instr_get_vtp(iu, &argc, &argv);
  if(old)
    i->value = instr_get_value(iu, &argc, &argv);
  else
    i->value = instr_get_vtp(iu, &argc, &argv);

}


/**
 *
 */
static void
parse_gep(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv, int op)
{
  ir_bb_t *ib = iu->iu_current_bb;

  if(op == FUNC_CODE_INST_GEP) {
    argv+=2;
    argc-=2;
  }

  int baseptr = instr_get_vtp(iu, &argc, &argv);

  int *values = alloca(argc * sizeof(int));

  int num_indicies = 0;
  while(argc > 0)
    values[num_indicies++] = instr_get_vtp(iu, &argc, &argv);

  ir_instr_gep_t *i = instr_add(ib,
                                sizeof(ir_instr_gep_t) +
                                sizeof(ir_gep_index_t) *
                                num_indicies, IR_IC_GEP);

  i->num_indicies = num_indicies;
  i->baseptr = baseptr;
  int current_type_index = value_get_type(iu, baseptr);

  for(int n = 0; n < num_indicies; n++) {
    i->indicies[n].value = values[n];
    i->indicies[n].type = current_type_index;
    ir_value_t *index_value = value_get(iu, values[n]);
    int element;
    int inner_type_index;
    ir_type_t *ct = type_get(iu, current_type_index);

    switch(ct->it_code) {
    case IR_TYPE_POINTER:
      inner_type_index = ct->it_pointer.pointee;
      break;

    case IR_TYPE_STRUCT:
      switch(index_value->iv_class) {
      case IR_VC_CONSTANT:
        element = value_get_const32(iu, index_value);
        if(element >= ct->it_struct.num_elements)
          parser_error(iu, "Bad index %d into struct %s",
                       element, type_str_index(iu, current_type_index));
        inner_type_index = ct->it_struct.elements[element].type;
        break;
      default:
        parser_error(iu, "Bad value class %d for struct index",
                     index_value->iv_class);
      }
      break;

    case IR_TYPE_ARRAY:
      inner_type_index = ct->it_array.element_type;
      break;

    default:
      parser_error(iu, "gep unable to index %s",
                   type_str_index(iu, current_type_index));
    }
    current_type_index = inner_type_index;
  }

  int gep_return_type = type_make_pointer(iu, current_type_index, 1);
  value_alloc_instr_ret(iu, gep_return_type, &i->super);
}


/**
 *
 */
static void
parse_cmp2(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_CMP2);
  i->lhs_value = instr_get_vtp(iu, &argc, &argv);
  i->rhs_value = instr_get_value(iu, &argc, &argv);
  i->op    = instr_get_uint(iu, &argc, &argv);
  value_alloc_instr_ret(iu, type_find_by_code(iu, IR_TYPE_INT1), &i->super);
}


/**
 *
 */
static void
parse_br(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_br_t *i = instr_add(ib, sizeof(ir_instr_br_t), IR_IC_BR);

  i->true_branch = instr_get_uint(iu, &argc, &argv);

  if(argc == 0) {
    i->condition = -1;
  } else {
    i->false_branch = instr_get_uint(iu, &argc, &argv);
    i->condition = instr_get_value(iu, &argc, &argv);
  }
}


/**
 *
 */
static int
phi_sort(const void *A, const void *B)
{
  const ir_phi_node_t *a = (const ir_phi_node_t *)A;
  const ir_phi_node_t *b = (const ir_phi_node_t *)B;
  return a->predecessor - b->predecessor;
}

/**
 *
 */
static void
parse_phi(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  int type = instr_get_uint(iu, &argc, &argv);

  int num_nodes = argc / 2;

  ir_instr_phi_t *i =
    instr_add(ib, sizeof(ir_instr_phi_t) + num_nodes * sizeof(ir_phi_node_t),
              IR_IC_PHI);

  i->num_nodes = num_nodes;

  for(int j = 0; j < num_nodes; j++) {
    i->nodes[j].value       = instr_get_value_signed(iu, &argc, &argv);
    i->nodes[j].predecessor = instr_get_uint(iu, &argc, &argv);
  }
  qsort(i->nodes, num_nodes, sizeof(ir_phi_node_t), phi_sort);

  int w = 1;
  for(int j = 1; j < num_nodes; j++) {
    if(i->nodes[j].predecessor == i->nodes[w - 1].predecessor)
      continue;
    i->nodes[w].predecessor = i->nodes[j].predecessor;
    i->nodes[w].value       = i->nodes[j].value;
    w++;
  }
  i->num_nodes = w;

  value_alloc_instr_ret(iu, type, &i->super);
}


/**
 *
 */
static void
parse_call(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  unsigned int attribute_set = instr_get_uint(iu, &argc, &argv) - 1;
  int cc            = instr_get_uint(iu, &argc, &argv);

  if(cc & 0x8000) {
    argc--;
    argv++;
  }

  int fnidx         = instr_get_vtp(iu, &argc, &argv);

  const ir_value_t *fn;
  const ir_type_t *fnty = NULL;

  while(1) {
    fn = value_get(iu, fnidx);
    if(fn->iv_class == IR_VC_ALIAS) {
      fnidx = fn->iv_reg;
      continue;
    }
    break;
  }


  switch(fn->iv_class) {
  case IR_VC_FUNCTION:
    {
      const ir_function_t *f = fn->iv_func;
      // Some functions that have no effect for us, drop them here
      if(!strcmp(f->if_name, "llvm.lifetime.start") ||
         !strcmp(f->if_name, "llvm.lifetime.end") ||
         !strcmp(f->if_name, "llvm.prefetch") ||
         !strcmp(f->if_name, "llvm.va_end"))
        return;

    }
    fnty = type_get(iu, fn->iv_type);
    break;

  case IR_VC_TEMPORARY:
  case IR_VC_REGFRAME:
    fnty = type_get(iu, type_get_pointee(iu, fn->iv_type));
    break;
  default:
    parser_error(iu, "Funcation call via value '%s' not supported",
                 value_str(iu, fn));
    break;
  }


  if(fnty->it_code != IR_TYPE_FUNCTION)
    parser_error(iu, "Call to non-function type %s",
                 type_str(iu, fnty));

  if(cc & (1 << 14))
    // MustTail
    parser_error(iu, "Can't handle must-tail call to %s",
                 type_str(iu, fnty));

  int function_args = fnty->it_function.num_parameters;

  int *args = alloca(argc * sizeof(int));
  int n = 0;

  while(argc > 0) {

    if(n >= function_args) {
      // Vararg, so type not know, encoded as valuetypepair
      args[n] = instr_get_vtp(iu, &argc, &argv);
    } else {
      // Just the value
      args[n] = instr_get_value(iu, &argc, &argv);
    }
    n++;
  }
  ir_instr_call_t *i =
    instr_add(ib, sizeof(ir_instr_call_t) +
              sizeof(ir_instr_arg_t) * n, IR_IC_CALL);
  i->callee = fnidx;
  i->argc = n;


  for(int j = 0; j < n; j++) {
    i->argv[j].value = args[j];
    i->argv[j].copy_size = 0;
  }

  if(attribute_set < VECTOR_LEN(&iu->iu_attrsets)) {
    const ir_attrset_t *ias = &VECTOR_ITEM(&iu->iu_attrsets, attribute_set);
    for(int k = 0; k < ias->ias_size; k++) {
      const ir_attr_t *ia = ias->ias_list[k];
      if(ia->ia_index == -1) {
        // Function attributes
      } if(ia->ia_index == 0) {
        // Return value attributes
      } else {
        int arg = ia->ia_index - 1;
        if(arg < i->argc) {
          if(ia->ia_flags & (1ULL << ATTR_KIND_BY_VAL)) {
            ir_value_t *val = value_get(iu, i->argv[arg].value);
            ir_type_t *ty = type_get(iu, val->iv_type);
            if(ty->it_code != IR_TYPE_POINTER) {
              parser_error(iu, "Copy-by-value on non-pointer %s",
                           type_str(iu, ty));
            }
            i->argv[arg].copy_size = type_sizeof(iu, ty->it_pointer.pointee);
          }
        }
      }
    }
  }

  const ir_type_t *rety = type_get(iu, fnty->it_function.return_type);

  if(rety->it_code == IR_TYPE_VOID)
    return;

  value_alloc_instr_ret(iu, fnty->it_function.return_type, &i->super);
}


/**
 *
 */
static int
switch_sort64(const void *A, const void *B)
{
  const ir_instr_path_t *a = (const ir_instr_path_t *)A;
  const ir_instr_path_t *b = (const ir_instr_path_t *)B;
  if(a->v64 > b->v64)
    return 1;
  if(a->v64 < b->v64)
    return -1;
  return 0;
}

/**
 *
 */
static void
parse_switch(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  unsigned int typeid = instr_get_uint(iu, &argc, &argv);
  ir_type_t *it = type_get(iu, typeid);

  unsigned int valueid = instr_get_value(iu, &argc, &argv);
  unsigned int defblock = instr_get_uint(iu, &argc, &argv);
  ir_value_t *iv = value_get(iu, valueid);
  int paths = argc / 2;

  ir_instr_switch_t *i =
    instr_add(ib, sizeof(ir_instr_switch_t) +
              sizeof(ir_instr_path_t) * paths, IR_IC_SWITCH);

  i->value = valueid;
  i->defblock = defblock;
  i->num_paths = paths;
  i->typecode = it->it_code;
  i->width = type_bitwidth(iu, iv->iv_type);

  for(int n = 0; n < paths; n++) {
    int val = instr_get_uint(iu, &argc, &argv);
    i->paths[n].block = instr_get_uint(iu, &argc, &argv);
    ir_value_t *iv = value_get(iu, val);

    if(iv->iv_class != IR_VC_CONSTANT)
      parser_error(iu, "Switch on non-constant value");
    if(iv->iv_type != typeid)
      parser_error(iu, "Type mismatch for switch/case values");
    i->paths[n].v64 = value_get_const64(iu, iv);
  }
  qsort(i->paths, paths, sizeof(ir_instr_path_t), switch_sort64);
}


/**
 *
 */
static void
parse_alloca(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  if(argc != 4)
    parser_error(iu, "Invalid number of args to alloca");

  int flags = argv[3].i64;

  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_alloca_t *i =
    instr_add(ib, sizeof(ir_instr_alloca_t), IR_IC_ALLOCA);

  unsigned int rtype  = argv[0].i64;

  if(flags & (1 << 6)) { // ExplicitType
    i->size = type_sizeof(iu, rtype);
    rtype = type_make_pointer(iu, rtype, 1);
  } else {
    unsigned int pointee = type_get_pointee(iu, rtype);
    i->size = type_sizeof(iu, pointee);
  }

  value_alloc_instr_ret(iu, rtype, &i->super);

  i->alignment = vmir_llvm_alignment(flags & 0x1f);
  i->num_items_value = argv[2].i64;

}


/**
 *
 */
static void
parse_vselect(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_select_t *i = instr_add(ib, sizeof(ir_instr_select_t), IR_IC_SELECT);
  i->true_value  = instr_get_vtp(iu, &argc, &argv);
  i->false_value = instr_get_value(iu, &argc, &argv);
  i->pred        = instr_get_vtp(iu, &argc, &argv);

  value_alloc_instr_ret(iu, value_get_type(iu, i->true_value), &i->super);
}


/**
 *
 */
static void
parse_vaarg(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_VAARG);
  argc--;
  argv++;
  i->value = instr_get_value(iu, &argc, &argv);
  int type     = instr_get_uint(iu,  &argc, &argv);
  value_alloc_instr_ret(iu, type, &i->super);
}

/**
 *
 */
static void
parse_extractval(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  int base = instr_get_vtp(iu, &argc, &argv);
  const int num_indicies = argc;
  int current_type_index = value_get_type(iu, base);

  ir_instr_extractval_t *ii = instr_add(ib,
                                        sizeof(ir_instr_extractval_t) +
                                        sizeof(int) * num_indicies,
                                        IR_IC_EXTRACTVAL);
  ii->num_indicies = num_indicies;
  ii->value = base;

  for(int i = 0; i < num_indicies; i++) {
    ir_type_t *ty = type_get(iu, current_type_index);
    int idx = argv[i].i64;
    ii->indicies[i] = idx;
    switch(ty->it_code) {
    default:
      parser_error(iu, "Bad type %s into struct in extractval", type_str(iu, ty));

    case IR_TYPE_STRUCT:
      if(idx >= ty->it_struct.num_elements)
        parser_error(iu, "Bad index %d into struct in extractval", idx);
      current_type_index = ty->it_struct.elements[idx].type;
      break;
    case IR_TYPE_ARRAY:
      current_type_index = ty->it_array.element_type;
      break;
    }
  }

  value_alloc_instr_ret(iu, current_type_index, &ii->super);
}

/**
 *
 */
static void
function_rec_handler(ir_unit_t *iu, int op,
                     unsigned int argc, const ir_arg_t *argv)
{
  ir_function_t *f = iu->iu_current_function;

  switch(op) {
  case FUNC_CODE_DECLAREBLOCKS:

    if(TAILQ_FIRST(&f->if_bbs) != NULL)
      parser_error(iu, "Multiple BB decl in function");

    unsigned int numbbs = argv[0].i64;
    if(numbbs == 0)
      parser_error(iu, "Declareblocks: Zero basic blocks");
    if(numbbs > 65535)
      parser_error(iu, "Declareblocks: Too many basic blocks: %d", numbbs);

    for(int i = 0; i < numbbs; i++)
      bb_add(f, NULL);

    iu->iu_current_bb = TAILQ_FIRST(&f->if_bbs);
    return;

  case FUNC_CODE_INST_RET:
    parse_ret(iu, argc, argv);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    return;

  case FUNC_CODE_INST_BINOP:
    return parse_binop(iu, argc, argv);

  case FUNC_CODE_INST_CAST:
    return parse_cast(iu, argc, argv);

  case FUNC_CODE_INST_LOAD:
  case FUNC_CODE_INST_LOADATOMIC:
    return parse_load(iu, argc, argv);

  case FUNC_CODE_INST_STORE_OLD:
  case FUNC_CODE_INST_STOREATOMIC_OLD:
    return parse_store(iu, argc, argv, 1);

  case FUNC_CODE_INST_STORE:
  case FUNC_CODE_INST_STOREATOMIC:
    return parse_store(iu, argc, argv, 0);

  case FUNC_CODE_INST_INBOUNDS_GEP_OLD:
  case FUNC_CODE_INST_GEP_OLD:
  case FUNC_CODE_INST_GEP:
    return parse_gep(iu, argc, argv, op);

  case FUNC_CODE_INST_CMP2:
    return parse_cmp2(iu, argc, argv);

  case FUNC_CODE_INST_BR:
    parse_br(iu, argc, argv);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    break;

  case FUNC_CODE_INST_PHI:
    return parse_phi(iu, argc, argv);

  case FUNC_CODE_INST_CALL:
    return parse_call(iu, argc, argv);

  case FUNC_CODE_INST_SWITCH:
    parse_switch(iu, argc, argv);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    break;

  case FUNC_CODE_INST_ALLOCA:
    parse_alloca(iu, argc, argv);
    break;

  case FUNC_CODE_INST_UNREACHABLE:
    parse_unreachable(iu);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    break;

  case FUNC_CODE_INST_VSELECT:
    parse_vselect(iu, argc, argv);
    break;

  case FUNC_CODE_INST_VAARG:
    parse_vaarg(iu, argc, argv);
    break;

  case FUNC_CODE_INST_EXTRACTVAL:
    parse_extractval(iu, argc, argv);
    break;

  default:
    printargs(argv, argc);
    parser_error(iu, "Can't handle functioncode %d", op);
  }
}






static void
instr_print(ir_unit_t *iu, ir_instr_t *ii, int flags)
{
  printf("%c %p: ", ii->ii_jit ? 'J' : ' ', ii);
  if(ii->ii_ret_value < - 1) {
    int num_values = -ii->ii_ret_value;
    printf("{ ");
    for(int i = 0; i < num_values; i++) {
      printf("%s%s", i ? ", " : "", value_str_id(iu, ii->ii_ret_values[i]));
    }
    printf(" } = ");
  } else if(ii->ii_ret_value != -1) {
    printf("%s = ", value_str_id(iu, ii->ii_ret_value));
  }

  switch(ii->ii_class) {

  case IR_IC_UNREACHABLE:
    {
      printf("unreachable ");
    }
    break;

  case IR_IC_RET:
    {
      ir_instr_unary_t *u = (ir_instr_unary_t *)ii;
      printf("ret ");
      if(u->value != -1)
        printf("%s", value_str_id(iu, u->value));
    }
    break;

  case IR_IC_BINOP:
    {
      ir_instr_binary_t *b = (ir_instr_binary_t *)ii;
      const char *op = "???";
      switch(b->op) {
      case BINOP_ADD:
        op = "add"; break;
      case BINOP_SUB:
        op = "sub"; break;
      case BINOP_MUL:
        op = "mul"; break;
      case BINOP_UDIV:
        op = "udiv"; break;
      case BINOP_SDIV:
        op = "sdiv"; break;
      case BINOP_UREM:
        op = "urem"; break;
      case BINOP_SREM:
        op = "srem"; break;
      case BINOP_SHL:
        op = "shl"; break;
      case BINOP_LSHR:
        op = "lshr"; break;
      case BINOP_ASHR:
        op = "ashr"; break;
      case BINOP_AND:
        op = "and"; break;
      case BINOP_OR:
        op = "or"; break;
      case BINOP_XOR:
        op = "xor"; break;
      }

      printf("%s %s, %s", op,
             value_str_id(iu, b->lhs_value),
             value_str_id(iu, b->rhs_value));
    }
    break;
  case IR_IC_CAST:
    {
      ir_instr_unary_t *u = (ir_instr_unary_t *)ii;
      const char *op = "???";
      switch(u->op) {
      case CAST_TRUNC: op = "trunc"; break;
      case CAST_ZEXT: op = "zext"; break;
      case CAST_SEXT: op = "sext"; break;
      case CAST_FPTOUI: op = "fptoui"; break;
      case CAST_FPTOSI: op = "fptosi"; break;
      case CAST_UITOFP: op = "uitofp"; break;
      case CAST_SITOFP: op = "sitofp"; break;
      case CAST_FPTRUNC: op = "fptrunc"; break;
      case CAST_FPEXT: op = "fpext"; break;
      case CAST_PTRTOINT: op = "ptrtoint"; break;
      case CAST_INTTOPTR: op = "inttoptr"; break;
      case CAST_BITCAST: op = "bitcast"; break;
      }
      printf("cast.%s %s", op, value_str_id(iu, u->value));
    }
    break;

  case IR_IC_LOAD:
    {
      ir_instr_load_t *u = (ir_instr_load_t *)ii;
      const char *cast = "";
      switch(u->cast) {
      case CAST_ZEXT:
        cast = ".zext";
        break;
      case CAST_SEXT:
        cast = ".sext";
        break;
      }
      printf("load%s %s + #0x%x", cast, value_str_id(iu, u->ptr),
             u->immediate_offset);
      if(u->value_offset >= 0) {
        printf(" + %s * #0x%x",
               value_str_id(iu, u->value_offset),
               u->value_offset_multiply);
      }
    }
    break;

  case IR_IC_STORE:
    {
      ir_instr_store_t *s = (ir_instr_store_t *)ii;
      printf("store %s + #0x%x, %s",
             value_str_id(iu, s->ptr), s->offset, value_str_id(iu, s->value));
    }
    break;

  case IR_IC_GEP:
    {
      ir_instr_gep_t *g = (ir_instr_gep_t *)ii;
      printf("gep ");
      if(g->baseptr != -1)
        printf("%s", value_str_id(iu, g->baseptr));

      for(int i = 0; i < g->num_indicies; i++) {
        printf(" + %s[%s]", type_str_index(iu, g->indicies[i].type),
               value_str_id(iu, g->indicies[i].value));
      }
    }
    break;
  case IR_IC_CMP2:
    {
      ir_instr_binary_t *b = (ir_instr_binary_t *)ii;
      const char *op = "???";
      switch(b->op) {
      case FCMP_FALSE: op = "fcmp_false"; break;
      case FCMP_OEQ: op = "fcmp_oeq"; break;
      case FCMP_OGT: op = "fcmp_ogt"; break;
      case FCMP_OGE: op = "fcmp_oge"; break;
      case FCMP_OLT: op = "fcmp_olt"; break;
      case FCMP_OLE: op = "fcmp_ole"; break;
      case FCMP_ONE: op = "fcmp_one"; break;
      case FCMP_ORD: op = "fcmp_ord"; break;
      case FCMP_UNO: op = "fcmp_uno"; break;
      case FCMP_UEQ: op = "fcmp_ueq"; break;
      case FCMP_UGT: op = "fcmp_ugt"; break;
      case FCMP_UGE: op = "fcmp_uge"; break;
      case FCMP_ULT: op = "fcmp_ult"; break;
      case FCMP_ULE: op = "fcmp_ule"; break;
      case FCMP_UNE: op = "fcmp_une"; break;
      case FCMP_TRUE: op = "fcmp_true"; break;
      case ICMP_EQ: op = "icmp_eq"; break;
      case ICMP_NE: op = "icmp_ne"; break;
      case ICMP_UGT: op = "icmp_ugt"; break;
      case ICMP_UGE: op = "icmp_uge"; break;
      case ICMP_ULT: op = "icmp_ult"; break;
      case ICMP_ULE: op = "icmp_ule"; break;
      case ICMP_SGT: op = "icmp_sgt"; break;
      case ICMP_SGE: op = "icmp_sge"; break;
      case ICMP_SLT: op = "icmp_slt"; break;
      case ICMP_SLE: op = "icmp_sle"; break;
      }
      printf("%s %s, %s", op, value_str_id(iu, b->lhs_value),
             value_str_id(iu, b->rhs_value));
    }
    break;

  case IR_IC_CMP_BRANCH:
    {
      ir_instr_cmp_branch_t *icb = (ir_instr_cmp_branch_t *)ii;
      const char *op = "???";
      switch(icb->op) {
      case ICMP_EQ: op = "eq"; break;
      case ICMP_NE: op = "ne"; break;
      case ICMP_UGT: op = "ugt"; break;
      case ICMP_UGE: op = "uge"; break;
      case ICMP_ULT: op = "ult"; break;
      case ICMP_ULE: op = "ule"; break;
      case ICMP_SGT: op = "sgt"; break;
      case ICMP_SGE: op = "sge"; break;
      case ICMP_SLT: op = "slt"; break;
      case ICMP_SLE: op = "sle"; break;
      }
      printf("cmpbr.%s %s, %s true:.%d false:.%d",
             op,
             value_str_id(iu, icb->lhs_value),
             value_str_id(iu, icb->rhs_value),
             icb->true_branch,
             icb->false_branch);
    }
    break;

  case IR_IC_BR:
    {
      ir_instr_br_t *br = (ir_instr_br_t *)ii;
      if(br->condition == -1) {
        printf("b .%d", br->true_branch);
      } else {
        printf("bcond %s, true:.%d, false:.%d",
               value_str_id(iu, br->condition),
               br->true_branch,
               br->false_branch);
      }
    }
    break;
  case IR_IC_PHI:
    {
      ir_instr_phi_t *p = (ir_instr_phi_t *)ii;
      printf("phi");
      for(int i = 0; i < p->num_nodes; i++) {
        printf(" [.%d %s]", p->nodes[i].predecessor,
               value_str_id(iu, p->nodes[i].value));
      }
    }
    break;
  case IR_IC_CALL:
  case IR_IC_VMOP:
    {
      ir_instr_call_t *p = (ir_instr_call_t *)ii;
      ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, p->callee);
      ir_function_t *f = value_function(iu, p->callee);

      if(f != NULL) {

        printf("%s %s (%s) (",
               f->if_vmop ? "vmop" : "call",
               f->if_name,
               type_str_index(iu, iv->iv_type));
      } else {
        printf("fptr in %s (%s) (", value_str_id(iu, p->callee),
               type_str_index(iu, iv->iv_type));
      }
      for(int i = 0; i < p->argc; i++) {
        if(i)printf(", ");
        printf("%s", value_str_id(iu, p->argv[i].value));
        if(p->argv[i].copy_size) {
          printf(" (byval %d bytes)", p->argv[i].copy_size);
        }
      }
      printf(")");
    }
    break;

  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
      printf("switch on %s ", value_str_id(iu, s->value));
      for(int i = 0; i < s->num_paths; i++) {
        printf(" [#%"PRIx64, s->paths[i].v64);
        printf(" -> .%d]", s->paths[i].block);
      }
      printf(" default: .%d", s->defblock);
    }
    break;
  case IR_IC_ALLOCA:
    {
      ir_instr_alloca_t *a = (ir_instr_alloca_t *)ii;
      printf("alloca [%d * %s], align: %d",
             a->size, value_str_id(iu, a->num_items_value), a->alignment);
    }
    break;
  case IR_IC_SELECT:
    {
      ir_instr_select_t *s = (ir_instr_select_t *)ii;
      printf("select %s, true: %s, false: %s",
             value_str_id(iu, s->pred),
             value_str_id(iu, s->true_value),
             value_str_id(iu, s->false_value));
    }
    break;
  case IR_IC_VAARG:
    {
      ir_instr_unary_t *m = (ir_instr_unary_t *)ii;

      printf("vaarg %s", value_str_id(iu, m->value));
    }
    break;
  case IR_IC_EXTRACTVAL:
    {
      ir_instr_extractval_t *jj = (ir_instr_extractval_t *)ii;

      printf("extractval %s [", value_str_id(iu, jj->value));
      for(int i = 0; i < jj->num_indicies; i++)
        printf("%s%d", i ? ",  " : "", jj->indicies[i]);
      printf("]");
    }
    break;
  case IR_IC_LEA:
    {
      ir_instr_lea_t *l = (ir_instr_lea_t *)ii;

      printf("lea %s + #0x%x",
             value_str_id(iu, l->baseptr),
             l->immediate_offset);

      if(l->value_offset >= 0) {
        printf(" + %s * #0x%x",
               value_str_id(iu, l->value_offset),
               l->value_offset_multiply);
      }
    }
    break;
  case IR_IC_MOVE:
    {
      ir_instr_move_t *m = (ir_instr_move_t *)ii;

      printf("move %s", value_str_id(iu, m->value));
    }
    break;
  case IR_IC_STACKCOPY:
    {
      ir_instr_stackcopy_t *sc = (ir_instr_stackcopy_t *)ii;

      printf("stackcopy %s size:#0x%x",
             value_str_id(iu, sc->value),
             sc->size);
    }
    break;
  case IR_IC_STACKSHRINK:
    {
      ir_instr_stackshrink_t *ss = (ir_instr_stackshrink_t *)ii;
      printf("stackshrink #0x%x", ss->size);
    }
    break;
  case IR_IC_MLA:
    {
      ir_instr_ternary_t *mla = (ir_instr_ternary_t *)ii;

      printf("mla %s, %s, %s",
             value_str_id(iu, mla->arg1),
             value_str_id(iu, mla->arg2),
             value_str_id(iu, mla->arg3));
    }
    break;
  }

  if(flags & 1) {
    const ir_value_instr_t *ivi;
    printf(" <");
    LIST_FOREACH(ivi, &ii->ii_values, ivi_instr_link) {
      printf("%s=%s ",
             ivi->ivi_relation == IVI_INPUT ? "input" :
             ivi->ivi_relation == IVI_OUTPUT ? "output" : "???",
             value_str(iu, ivi->ivi_value));
    }
    printf(">");
  }

}
