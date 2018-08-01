

/**
 *
 */
static ir_valuetype_t
instr_get_vtp(ir_unit_t *iu, unsigned int *argcp, const int64_t **argvp)
{
  const int64_t *argv = *argvp;
  int argc = *argcp;
  if(argc < 1)
    parser_error(iu, "Missing value code");

  unsigned int val = iu->iu_next_value - argv[0];
  int type;

  if(val < iu->iu_next_value) {
    *argvp = argv + 1;
    *argcp = argc - 1;
    type = VECTOR_ITEM(&iu->iu_values, val)->iv_type;
  } else {

    type = argv[1];

    if(val >= VECTOR_LEN(&iu->iu_values)) {
      size_t prevsize = VECTOR_LEN(&iu->iu_values);
      VECTOR_RESIZE(&iu->iu_values, val + 1);
      for(int i = prevsize; i <= val; i++) {
        VECTOR_ITEM(&iu->iu_values, i) = NULL;
      }
    }
    ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val);

    if(iv == NULL) {
      iv = calloc(1, sizeof(ir_value_t));
      VECTOR_ITEM(&iu->iu_values, val) = iv;
      iv->iv_class = IR_VC_UNDEF;
    }
    iv->iv_type = type;

    *argvp = argv + 2;
    *argcp = argc - 2;
  }
  ir_valuetype_t r = {.type = type, .value = val};
  return r;
}


/**
 *
 */
static ir_valuetype_t
instr_get_value(ir_unit_t *iu, unsigned int *argcp, const int64_t **argvp,
                int type)
{
  const int64_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing value code");

  *argvp = argv + 1;
  *argcp = argc - 1;

  int val = iu->iu_next_value - argv[0];
  ir_valuetype_t r = {.type = type, .value = val};
  return r;
}


/**
 *
 */
static ir_valuetype_t
instr_get_value_signed(ir_unit_t *iu,
                       unsigned int *argcp, const int64_t **argvp,
                       int type)
{
  const int64_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing value code");

  *argvp = argv + 1;
  *argcp = argc - 1;

  int val = iu->iu_next_value - read_sign_rotated(argv);

  ir_valuetype_t r = {.type = type, .value = val};
  return r;
}


/**
 *
 */
static unsigned int
instr_get_uint(ir_unit_t *iu, unsigned int *argcp, const int64_t **argvp)
{
  const int64_t *argv = *argvp;
  int argc = *argcp;

  if(argc < 1)
    parser_error(iu, "Missing argument");

  *argvp = argv + 1;
  *argcp = argc - 1;
  return argv[0];
}


/**
 *
 */
static void
parse_ret(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_RET);

  if(argc == 0) {
    i->value.value = -1;
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
parse_binop(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_BINOP);
  i->lhs_value = instr_get_vtp(iu, &argc, &argv);
  i->rhs_value = instr_get_value(iu, &argc, &argv, i->lhs_value.type);
  i->op        = instr_get_uint(iu, &argc, &argv);

  value_alloc_instr_ret(iu, i->lhs_value.type, &i->super);
}


/**
 *
 */
static void
parse_cast(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
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
parse_load(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_load_t *i = instr_add(ib, sizeof(ir_instr_load_t), IR_IC_LOAD);
  i->immediate_offset = 0;
  i->ptr = instr_get_vtp(iu, &argc, &argv);
  i->value_offset.value = -1;
  i->value_offset_multiply = 0;
  i->cast = -1;
  if(argc == 3) {
    // Explicit type
    value_alloc_instr_ret(iu, argv[0], &i->super);
  } else {
    value_alloc_instr_ret(iu, type_get_pointee(iu, i->ptr.type), &i->super);
  }
}


/**
 *
 */
static void
parse_store(ir_unit_t *iu, unsigned int argc, const int64_t *argv,
            int old)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_store_t *i = instr_add(ib, sizeof(ir_instr_store_t), IR_IC_STORE);
  i->immediate_offset = 0;
  i->ptr   = instr_get_vtp(iu, &argc, &argv);
  if(old)
    i->value = instr_get_value(iu, &argc, &argv,
                               type_get_pointee(iu, i->ptr.type));
  else
    i->value = instr_get_vtp(iu, &argc, &argv);

}

static void
parse_insertval(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_valuetype_t src = instr_get_vtp(iu, &argc, &argv);
  ir_valuetype_t replacement = instr_get_vtp(iu, &argc, &argv);

  int num_indices = argc;

  ir_instr_insertval_t *i =
    instr_add(ib, sizeof(ir_instr_insertval_t) +
              sizeof(int) * num_indices, IR_IC_INSERTVAL);

  i->src = src;
  i->replacement = replacement;
  i->num_indicies = num_indices;

  for(int j = 0; j < num_indices; j++) {
    i->indicies[j] = instr_get_uint(iu, &argc, &argv);
  }

  value_alloc_instr_ret(iu, i->src.type, &i->super);
}



/**
 *
 */
static void
parse_gep(ir_unit_t *iu, unsigned int argc, const int64_t *argv, int op)
{
  ir_bb_t *ib = iu->iu_current_bb;

  if(op == FUNC_CODE_INST_GEP) {
    argv+=2;
    argc-=2;
  }

  ir_valuetype_t baseptr = instr_get_vtp(iu, &argc, &argv);

  ir_valuetype_t *values = alloca(argc * sizeof(ir_valuetype_t));

  int num_indicies = 0;
  while(argc > 0)
    values[num_indicies++] = instr_get_vtp(iu, &argc, &argv);

  ir_instr_gep_t *i = instr_add(ib,
                                sizeof(ir_instr_gep_t) +
                                sizeof(ir_gep_index_t) *
                                num_indicies, IR_IC_GEP);

  i->num_indicies = num_indicies;
  i->baseptr = baseptr;
  int current_type_index = baseptr.type;

  for(int n = 0; n < num_indicies; n++) {
    i->indicies[n].value = values[n];
    i->indicies[n].type = current_type_index;
    ir_value_t *index_value = value_get(iu, values[n].value);
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
parse_cmp2(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_binary_t *i = instr_add(ib, sizeof(ir_instr_binary_t), IR_IC_CMP2);
  i->lhs_value = instr_get_vtp(iu, &argc, &argv);
  i->rhs_value = instr_get_value(iu, &argc, &argv, i->lhs_value.type);
  i->op    = instr_get_uint(iu, &argc, &argv);
  value_alloc_instr_ret(iu, type_find_by_code(iu, IR_TYPE_INT1), &i->super);
}


/**
 *
 */
static void
parse_br(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_br_t *i = instr_add(ib, sizeof(ir_instr_br_t), IR_IC_BR);

  i->true_branch = instr_get_uint(iu, &argc, &argv);

  if(argc == 0) {
    i->condition.value = -1;
  } else {
    i->false_branch = instr_get_uint(iu, &argc, &argv);
    i->condition = instr_get_value(iu, &argc, &argv,
                                   type_make(iu, IR_TYPE_INT1));
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
parse_phi(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  int type = instr_get_uint(iu, &argc, &argv);

  int num_nodes = argc / 2;

  ir_instr_phi_t *i =
    instr_add(ib, sizeof(ir_instr_phi_t) + num_nodes * sizeof(ir_phi_node_t),
              IR_IC_PHI);

  i->num_nodes = num_nodes;

  for(int j = 0; j < num_nodes; j++) {
    i->nodes[j].value       = instr_get_value_signed(iu, &argc, &argv, type);
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
parse_call_or_invoke(ir_unit_t *iu, unsigned int argc, const int64_t *argv,
                     int ii_class)
{
  // http://llvm.org/docs/LangRef.html#call-instruction
  // http://llvm.org/docs/LangRef.html#invoke-instruction

  ir_bb_t *ib = iu->iu_current_bb;

  unsigned int attribute_set = instr_get_uint(iu, &argc, &argv) - 1;
  int cc            = instr_get_uint(iu, &argc, &argv);



  int normal_dest            = -1;
  int unwind_dest            = -1;

  if(ii_class == IR_IC_INVOKE) {
    normal_dest = instr_get_uint(iu, &argc, &argv);
    unwind_dest = instr_get_uint(iu, &argc, &argv);

    if(cc & 0x2000) {
      argc--;
      argv++;
    }

  } else {
    if(cc & 0x8000) {
      argc--;
      argv++;
    }

  }

  ir_valuetype_t fnidx = instr_get_vtp(iu, &argc, &argv);

  const ir_value_t *fn;
  const ir_type_t *fnty = NULL;

  while(1) {
    fn = value_get(iu, fnidx.value);
    if(fn->iv_class == IR_VC_ALIAS) {
      fnidx.value = fn->iv_reg;
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
    parser_error(iu, "Function call via value '%s' not supported",
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

  ir_valuetype_t *args = alloca(argc * sizeof(ir_valuetype_t));
  int n = 0;

  while(argc > 0) {

    if(n >= function_args) {
      // Vararg, so type not know, encoded as valuetypepair
      args[n] = instr_get_vtp(iu, &argc, &argv);
    } else {
      // Just the value
      args[n] = instr_get_value(iu, &argc, &argv,
                                fnty->it_function.parameters[n]);
    }
    n++;
  }
  ir_instr_call_t *i =
    instr_add(ib, sizeof(ir_instr_call_t) +
              sizeof(ir_instr_arg_t) * n, ii_class);

  i->callee = fnidx;
  i->normal_dest = normal_dest;
  i->unwind_dest = unwind_dest;
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
            ir_type_t *ty = type_get(iu, i->argv[arg].value.type);
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
static void
parse_landingpad(ir_unit_t *iu, unsigned int argc, const int64_t *argv,
                 int old)
{
  ir_bb_t *ib = iu->iu_current_bb;

  unsigned int type = instr_get_uint(iu, &argc, &argv);

  if(old) {
    instr_get_vtp(iu, &argc, &argv);
  }
  unsigned int is_clean_up = instr_get_uint(iu, &argc, &argv);
  unsigned int num_clauses = instr_get_uint(iu, &argc, &argv);

  ir_instr_landingpad_t *i =
    instr_add(ib, sizeof(ir_instr_landingpad_t) +
              sizeof(ir_instr_landingpad_clause_t) * num_clauses,
              IR_IC_LANDINGPAD);

  i->type = type;
  //  i->personality = personality;
  i->is_clean_up = is_clean_up;
  i->num_clauses = num_clauses;

  for(int j = 0; j < num_clauses; j++) {
    i->clauses[j].clause = instr_get_uint(iu, &argc, &argv);
    i->clauses[j].is_catch = instr_get_uint(iu, &argc, &argv);
  }

  value_alloc_instr_ret(iu, i->type, &i->super);
}

/**
 *
 */

static void
parse_resume(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_resume_t *i =
    instr_add(ib, sizeof(ir_instr_resume_t) + MAX_RESUME_VALUES * sizeof(ir_valuetype_t), IR_IC_RESUME);

  i->values[0] = instr_get_vtp(iu, &argc, &argv);
  i->num_values = 1;
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
parse_switch(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  unsigned int typeid = instr_get_uint(iu, &argc, &argv);
  ir_valuetype_t value = instr_get_value(iu, &argc, &argv, typeid);
  unsigned int defblock = instr_get_uint(iu, &argc, &argv);
  int paths = argc / 2;

  ir_instr_switch_t *i =
    instr_add(ib, sizeof(ir_instr_switch_t) +
              sizeof(ir_instr_path_t) * paths, IR_IC_SWITCH);

  i->value = value;
  i->defblock = defblock;
  i->num_paths = paths;

  const int width = type_bitwidth(iu, type_get(iu, typeid));
  const uint64_t mask = width == 64 ? ~1ULL : (1ULL << width) - 1;
  for(int n = 0; n < paths; n++) {
    int val = instr_get_uint(iu, &argc, &argv);
    i->paths[n].block = instr_get_uint(iu, &argc, &argv);
    ir_value_t *iv = value_get(iu, val);

    if(iv->iv_class != IR_VC_CONSTANT)
      parser_error(iu, "Switch on non-constant value");
    if(iv->iv_type != typeid)
      parser_error(iu, "Type mismatch for switch/case values");
    i->paths[n].v64 = value_get_const64(iu, iv) & mask;
  }
  qsort(i->paths, paths, sizeof(ir_instr_path_t), switch_sort64);
}


/**
 *
 */
static void
parse_alloca(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  if(argc != 4)
    parser_error(iu, "Invalid number of args to alloca");

  int flags = argv[3];

  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_alloca_t *i =
    instr_add(ib, sizeof(ir_instr_alloca_t), IR_IC_ALLOCA);

  unsigned int rtype  = argv[0];

  if(flags & (1 << 6)) { // ExplicitType
    i->size = type_sizeof(iu, rtype);
    rtype = type_make_pointer(iu, rtype, 1);
  } else {
    unsigned int pointee = type_get_pointee(iu, rtype);
    i->size = type_sizeof(iu, pointee);
  }

  value_alloc_instr_ret(iu, rtype, &i->super);

  i->alignment = vmir_llvm_alignment(flags & 0x1f, 4);
  i->num_items_value.value = argv[2];
  i->num_items_value.type = argv[1];
}


/**
 *
 */
static void
parse_vselect(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_select_t *i = instr_add(ib, sizeof(ir_instr_select_t), IR_IC_SELECT);
  i->true_value  = instr_get_vtp(iu, &argc, &argv);
  i->false_value = instr_get_value(iu, &argc, &argv, i->true_value.type);
  i->pred        = instr_get_vtp(iu, &argc, &argv);

  value_alloc_instr_ret(iu, i->true_value.type, &i->super);
}


/**
 *
 */
static void
parse_vaarg(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_instr_unary_t *i = instr_add(ib, sizeof(ir_instr_unary_t), IR_IC_VAARG);
  int type = argv[0];
  argc--;
  argv++;
  i->value = instr_get_value(iu, &argc, &argv, type);
  int rtype = instr_get_uint(iu,  &argc, &argv);
  value_alloc_instr_ret(iu, rtype, &i->super);
}

/**
 *
 */
static void
parse_extractval(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  ir_bb_t *ib = iu->iu_current_bb;

  ir_valuetype_t base = instr_get_vtp(iu, &argc, &argv);
  const int num_indicies = argc;
  int current_type_index = base.type;

  ir_instr_extractval_t *ii = instr_add(ib,
                                        sizeof(ir_instr_extractval_t) +
                                        sizeof(int) * num_indicies,
                                        IR_IC_EXTRACTVAL);
  ii->num_indicies = num_indicies;
  ii->value = base;

  for(int i = 0; i < num_indicies; i++) {
    ir_type_t *ty = type_get(iu, current_type_index);
    int idx = argv[i];
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
                     unsigned int argc, const int64_t *argv)
{
  ir_function_t *f = iu->iu_current_function;

  switch(op) {
  case FUNC_CODE_DECLAREBLOCKS:

    if(TAILQ_FIRST(&f->if_bbs) != NULL)
      parser_error(iu, "Multiple BB decl in function");

    unsigned int numbbs = argv[0];
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

  case FUNC_CODE_INST_INVOKE:
    parse_call_or_invoke(iu, argc, argv, IR_IC_INVOKE);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    break;

  case FUNC_CODE_INST_CALL:
    parse_call_or_invoke(iu, argc, argv, IR_IC_CALL);
    break;

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

  case FUNC_CODE_INST_LANDINGPAD_OLD:
    parse_landingpad(iu, argc, argv, 1);
    break;

  case FUNC_CODE_INST_LANDINGPAD:
    parse_landingpad(iu, argc, argv, 0);
    break;

  case FUNC_CODE_INST_INSERTVAL:
    parse_insertval(iu, argc, argv);
    break;

  case FUNC_CODE_INST_RESUME:
    parse_resume(iu, argc, argv);
    iu->iu_current_bb = TAILQ_NEXT(iu->iu_current_bb, ib_link);
    break;

  default:
    printargs(argv, argc);
    parser_error(iu, "Can't handle functioncode %d", op);
  }
}

