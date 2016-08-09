
static void
abbrev_queue_free(struct ir_abbrev_queue *iaq)
{
  ir_abbrev_t *ia;
  while((ia = TAILQ_FIRST(iaq)) != NULL) {
    TAILQ_REMOVE(iaq, ia, ia_link);
    free(ia);
  }
}

/**
 *
 */
static void
blockinfo_destroy(ir_blockinfo_t *ib)
{
  LIST_REMOVE(ib, ib_link);
  abbrev_queue_free(&ib->ib_abbrevs);
  free(ib);
}

/**
 *
 */
static ir_blockinfo_t *
blockinfo_find(ir_unit_t *iu, int id)
{
  ir_blockinfo_t *ib;
  LIST_FOREACH(ib, &iu->iu_blockinfos, ib_link) {
    if(ib->ib_id == id)
      return ib;
  }
  ib = calloc(1, sizeof(ir_blockinfo_t));
  ib->ib_id = id;
  LIST_INSERT_HEAD(&iu->iu_blockinfos, ib, ib_link);
  TAILQ_INIT(&ib->ib_abbrevs);
  return ib;
}


/**
 *
 */
static void
block_destroy(ir_block_t *ib)
{
  abbrev_queue_free(&ib->ib_scoped_abbrevs);
  LIST_REMOVE(ib, ib_link);
  free(ib);
}


/**
 *
 */
static void
blockinfo_rec_handler(ir_unit_t *iu, int op,
                      unsigned int argc, const ir_arg_t *argv)
{
  ir_block_t *ib = LIST_FIRST(&iu->iu_blocks);
  switch(op) {

  case 1: // SETBID
    if(argc != 1)
      parser_error(iu, "Bad number of args (%d) for SETBID", argc);

    ib->ib_blockinfo = blockinfo_find(iu, argv[0].i64);
    break;
  }
}


/**
 * GLOBALVAR: [pointer type, isconst, initid,
 *             linkage, alignment, section, visibility, threadlocal,
 *             unnamed_addr, dllstorageclass]
 */
static void
module_globalvar(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  if(argc < 6)
    parser_error(iu, "Bad number of args for global var def");

  int explicit_type = argv[1].i64 & 2;
  unsigned int type, pointee;


  if(explicit_type) {
    pointee = argv[0].i64;
    type = type_make_pointer(iu, pointee, 0);
    if(type == -1)
      parser_error(iu, "No pointer type for pointee '%s'",
                   type_str_index(iu, pointee));
  } else {
    type = argv[0].i64;
    pointee = type_get_pointee(iu, type);
  }

  ir_globalvar_t *ig = calloc(1, sizeof(ir_globalvar_t));
  ig->ig_type = pointee;

  unsigned int alignment = vmir_llvm_alignment(argv[4].i64, 4);
  const int val_id = value_append(iu);
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val_id);
  iv->iv_class = IR_VC_GLOBALVAR;
  iv->iv_type = type;
  iv->iv_gvar = ig;
  assert(alignment > 0);
  iu->iu_data_ptr = VMIR_ALIGN(iu->iu_data_ptr, alignment);
  ig->ig_addr = iu->iu_data_ptr;
  iu->iu_data_ptr += type_sizeof(iu, pointee);

  const unsigned int initializer = argv[2].i64;

  if(initializer > 0) {
    ir_initializer_t ii = {val_id, initializer - 1};
    VECTOR_PUSH_BACK(&iu->iu_initializers, ii);
  }
}


/**
 * FUNCTION:  [type, callingconv, isproto, linkage, paramattr,
 *             alignment, section, visibility, gc, unnamed_addr,
 *             dllstorageclass]
 */
static void
module_function(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  if(argc < 8)
    parser_error(iu, "Bad number of args");

  unsigned int type = argv[0].i64;
  ir_type_t *it = type_get(iu, type);
  if(it->it_code == IR_TYPE_POINTER)
    type = it->it_pointer.pointee;

  ir_function_t *f = calloc(1, sizeof(ir_function_t));

  TAILQ_INIT(&f->if_bbs);
  f->if_isproto = !!argv[2].i64;
  f->if_type = type;

  if(!f->if_isproto)
    TAILQ_INSERT_TAIL(&iu->iu_functions_with_bodies, f, if_body_link);

  f->if_gfid = VECTOR_LEN(&iu->iu_functions);
  VECTOR_PUSH_BACK(&iu->iu_functions, f);

  ir_value_t *iv = value_append_and_get(iu);
  iv->iv_class = IR_VC_FUNCTION;
  iv->iv_type = type;
  iv->iv_func = f;
}

/**
 * ALIAS: [alias type, aliasee val#, linkage]
 */
static void
module_alias(ir_unit_t *iu, unsigned int argc, const ir_arg_t *argv)
{
  if(argc < 3)
    parser_error(iu, "Bad number of args");

  ir_value_t *iv = value_append_and_get(iu);
  iv->iv_class = IR_VC_ALIAS;
  iv->iv_type = argv[0].i64;
  iv->iv_reg = argv[1].i64;
}


/**
 *
 */
static void
module_rec_handler(ir_unit_t *iu, int op,
                   unsigned int argc, const ir_arg_t *argv)
{
  switch(op) {
  case MODULE_CODE_VERSION:
    iu->iu_version = argv[0].i64;
    break;

  case MODULE_CODE_TRIPLE:
    free(iu->iu_triple);
    iu->iu_triple = read_str_from_argv(argc, argv);
    break;

  case MODULE_CODE_DATALAYOUT:
    break;

  case MODULE_CODE_GLOBALVAR:
    return module_globalvar(iu, argc, argv);

  case MODULE_CODE_FUNCTION:
    return module_function(iu, argc, argv);

  case MODULE_CODE_ALIAS:
    return module_alias(iu, argc, argv);

  case MODULE_CODE_COMDAT:
    break;

  default:
    printargs(argv, argc);
    parser_error(iu, "Unknown module code %d", op);
  }
}


/**
 *
 */
static void
paramattr_group_rec_handler(ir_unit_t *iu, int op,
                            unsigned int argc, const ir_arg_t *argv)
{
  char *key, *value;
  const char *ctx = "PARAMATTR_GRP_CODE_ENTRY";
  switch(op) {
  case 3: // PARAMATTR_GRP_CODE_ENTRY
    if(argc < 3)
      parser_error(iu, "%s: Short (%d records)", ctx, argc);

    ir_attr_t *ia = calloc(1, sizeof(ir_attr_t));
    LIST_INSERT_HEAD(&iu->iu_attribute_groups, ia, ia_link);

    ia->ia_group_id = argv[0].i64;
    ia->ia_index    = argv[1].i64;
    argv += 2;
    argc -= 2;
    while(argc > 0) {
      int type = argv[0].i64;
      argv++;
      argc--;
      if(argc == 0)
        parser_error(iu, "%s: Short record", ctx);

      switch(type) {
      case 0:
        // ENUM attribute
        ia->ia_flags |= (1ULL << argv[0].i64);
        argv++;
        argc--;
        break;
      case 1:
        if(argc < 1)
          parser_error(iu, "%s: Missing int-arg", ctx);
        // Integer attribute
        argv += 2;
        argc -= 2;
        break;
      case 3:
        key = read_zstr_from_argv(&argc, &argv);
        if(key == NULL)
          parser_error(iu, "%s: short string", ctx);
        free(key);
        break;
      case 4:
        key = read_zstr_from_argv(&argc, &argv);
        if(key == NULL)
          parser_error(iu, "%s: short string", ctx);
        value = read_zstr_from_argv(&argc, &argv);
        if(value == NULL) {
          free(key);
          parser_error(iu, "%s: short string", ctx);
        }
        free(key);
        free(value);
        break;
      default:
        parser_error(iu, "%s: Unknown attr %d", ctx, type);
      }
    }
    break;
  default:
    parser_error(iu, "Unknown op %d in paramattr_group", op);
  }
}




/**
 *
 */
static void
paramattr_rec_handler(ir_unit_t *iu, int op,
                      unsigned int argc, const ir_arg_t *argv)
{
  int off;
  const char *ctx = "paramattr";

  switch(op) {
  case 2:
    off = VECTOR_LEN(&iu->iu_attrsets);
    VECTOR_RESIZE(&iu->iu_attrsets, off + 1);
    ir_attrset_t *ias = &VECTOR_ITEM(&iu->iu_attrsets, off);
    ias->ias_list = malloc(argc * sizeof(const ir_attr_t *));
    ias->ias_size = argc;
    for(int i = 0; i < argc; i++) {
      const ir_attr_t *ia;
      LIST_FOREACH(ia, &iu->iu_attribute_groups, ia_link) {
        if(ia->ia_group_id == argv[i].i64)
          break;
      }

      if(ia == NULL)
        parser_error(iu, "%s: Group %d not found",
                            ctx, (int)argv[i].i64);

      ias->ias_list[i] = ia;
    }
    break;

  default:
    parser_error(iu, "Unknown op %d in paramattr", op);
  }
}


/**
 *
 */
static void
metadata_rec_handler(ir_unit_t *iu, int op,
                     unsigned int argc, const ir_arg_t *argv)
{
  //  printf("metadata: Handling rec %d\n", op);
  //  prinargs(argv, argc);
}




/**
 *
 */
static void
uselist_rec_handler(ir_unit_t *iu, int op,
                    unsigned int argc, const ir_arg_t *argv)
{
}

/**
 *
 */
static void
value_symtab_rec_handler(ir_unit_t *iu, int op,
                         unsigned int argc, const ir_arg_t *argv)
{
  ir_value_t *iv;

  switch(op) {
  case 1: // VST_CODE_ENTRY
    if(argc < 2)
      parser_error(iu, "Bad args to VST_CODE_ENTRY");

    unsigned int vid = argv[0].i64;
    char *str = read_str_from_argv(argc - 1, argv + 1);

    iv = value_get(iu, vid);

    free(iv->iv_name);
    iv->iv_name = strdup(str);

    switch(iv->iv_class) {
    case IR_VC_FUNCTION:
      free(iv->iv_func->if_name);
      iv->iv_func->if_name = str;
      if(!vmop_resolve(iv->iv_func)) {
        iv->iv_func->if_ext_func = iu->iu_external_function_resolver(iv->iv_func->if_name, iu->iu_opaque);
      }

      if(iu->iu_debug_flags & VMIR_DBG_LIST_FUNCTIONS) {
        const ir_function_t *f = iv->iv_func;
        printf("Function %-10s %s\n",
               !f->if_isproto ? "defined" :
               f->if_vmop != 0 ? "vmop" :
               f->if_ext_func != NULL ? "external" :
               "undefined",
               f->if_name);

      }
      break;

    case IR_VC_GLOBALVAR:
      free(iv->iv_gvar->ig_name);
      iv->iv_gvar->ig_name = str;
      break;

    case IR_VC_CONSTANT:
    case IR_VC_ZERO_INITIALIZER:
    case IR_VC_TEMPORARY:
    case IR_VC_REGFRAME:
    case IR_VC_ALIAS:
      free(str);
      break;

    default:
      parser_error(iu, "Can't give name %s to value of class %d\n",
                   str, iv->iv_class);
      break;
    }
    break;

  case 2: // VST_CODE_BBENTRY
    break;

  default:
    parser_error(iu, "Unknown op %d in symtab\n", op);
  }
}


/**
 *
 */
static void
constants_rec_handler(ir_unit_t *iu, int op,
                      unsigned int argc, const ir_arg_t *argv)
{
  ir_value_t *iv;
  ir_constexpr_t *ic;

  if(op == CST_CODE_SETTYPE) {
    if(argc < 1)
      parser_error(iu, "Bad # of args for CST_CODE_SETTYPE");
    assert(argc > 0);
    iu->iu_current_type = argv[0].i64;
    return;
  }

  iv = value_append_and_get(iu);
  iv->iv_type = iu->iu_current_type;

  switch(op) {

  case CST_CODE_UNDEF:
  case CST_CODE_NULL:
    switch(type_get(iu, iv->iv_type)->it_code) {
    case IR_TYPE_INT1:
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
    case IR_TYPE_POINTER:
    case IR_TYPE_DOUBLE:
    case IR_TYPE_INT64:
    case IR_TYPE_FLOAT:
    case IR_TYPE_INTx:
      iv->iv_class = IR_VC_CONSTANT;
      iv->iv_u64 = 0;
      break;
    case IR_TYPE_ARRAY:
    case IR_TYPE_STRUCT:
      iv->iv_class = IR_VC_ZERO_INITIALIZER;
      break;
    default:
      parser_error(iu, "Bad type (%s) for NULL integer constant",
                   type_str_index(iu, iu->iu_current_type));
    }
    break;

  case CST_CODE_INTEGER:
    assert(argc > 0);
    iv->iv_class = IR_VC_CONSTANT;
    switch(type_get(iu, iv->iv_type)->it_code) {
    case IR_TYPE_INT1:
    case IR_TYPE_INT8:
    case IR_TYPE_INT16:
    case IR_TYPE_INT32:
      iv->iv_u32 = read_sign_rotated(argv);
      break;

    case IR_TYPE_INT64:
    case IR_TYPE_INTx:
      iv->iv_u64 = read_sign_rotated(argv);
      break;
    default:
      parser_error(iu, "Bad type (%s) for integer constant",
                          type_str_index(iu, iu->iu_current_type));
    }

    break;


  case CST_CODE_FLOAT:
    assert(argc > 0);
    iv->iv_class = IR_VC_CONSTANT;
    switch(type_get(iu, iv->iv_type)->it_code) {
    case IR_TYPE_FLOAT:
      iv->iv_u32 = argv[0].i64; // iv_u32 is union with iv_float
      break;
    case IR_TYPE_DOUBLE:
      iv->iv_u64 = argv[0].i64; // iv_u64 is union with iv_double
      break;
    default:
      parser_error(iu, "Bad type (%s) for float constant",
                          type_str_index(iu, iu->iu_current_type));
    }

    break;


  case CST_CODE_AGGREGATE:
    iv->iv_class = IR_VC_AGGREGATE;
    iv->iv_num_values = argc;
    ir_valuetype_t *values = malloc(sizeof(ir_valuetype_t) * iv->iv_num_values);
    iv->iv_data = values;
    for(int i = 0; i < iv->iv_num_values; i++) {
      ir_value_t *ivx = value_get(iu, argv[i].i64);
      values[i].value = argv[i].i64;
      values[i].type = ivx->iv_type;
    }
    break;

  case CST_CODE_DATA:
    {
      iv->iv_class = IR_VC_DATA;
      ir_type_t *ty = type_get(iu, iu->iu_current_type);

      switch(ty->it_code) {
      case IR_TYPE_ARRAY:
        switch(type_get(iu, ty->it_array.element_type)->it_code) {

        case IR_TYPE_INT64:
        case IR_TYPE_DOUBLE:
          iv->iv_data = malloc(sizeof(uint64_t) * argc);
          for(int i = 0; i < argc; i++)
            host_wr64(iv->iv_data + i * sizeof(uint64_t), argv[i].i64);
          return;

        case IR_TYPE_INT32:
        case IR_TYPE_FLOAT:
          iv->iv_data = malloc(sizeof(uint32_t) * argc);
          for(int i = 0; i < argc; i++)
            host_wr32(iv->iv_data + i * sizeof(uint32_t), argv[i].i64);
          return;

        case IR_TYPE_INT16:
          iv->iv_data = malloc(sizeof(uint16_t) * argc);
          for(int i = 0; i < argc; i++)
            host_wr16(iv->iv_data + i * sizeof(uint16_t), argv[i].i64);
          return;

        default:
          break;
        }
      default:
        break;
      }
      parser_error(iu, "Can't parse constant data for type %s",
                   type_str_index(iu, iu->iu_current_type));
    }
    break;

  case CST_CODE_CSTRING:
  case CST_CODE_STRING:
    iv->iv_class = IR_VC_DATA;
    iv->iv_data = read_str_from_argv(argc, argv);
    break;

  case CST_CODE_CE_CAST:
    iv->iv_class = IR_VC_CE;
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    ic->ic_cast.op  = argv[0].i64;
    ic->ic_cast.src = argv[2].i64;
    break;

  case CST_CODE_CE_GEP:
  case CST_CODE_CE_INBOUNDS_GEP:
    iv->iv_class = IR_VC_CE;
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    if(argc & 1) {
      // explicit return type
      argc--;
      argv++;
    }
    ic->ic_gep.num_values = argc / 2;
    ic->ic_gep.values = malloc(iv->iv_ce->ic_gep.num_values * sizeof(int));
    for(int i = 0; i < ic->ic_gep.num_values; i++)
      ic->ic_gep.values[i] = argv[1 + i * 2].i64;
    break;

  case CST_CODE_CE_BINOP:
    iv->iv_class = IR_VC_CE;
    if(argc < 3)
      parser_error(iu, "CST_CODE_CE_BINOP with invalid number of args %d", argc);
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    ic->ic_binop.op  = argv[0].i64;
    ic->ic_binop.lhs = argv[1].i64;
    ic->ic_binop.rhs = argv[2].i64;
    break;

  case CST_CODE_CE_CMP:
    iv->iv_class = IR_VC_CE;
    if(argc < 4)
      parser_error(iu, "CST_CODE_CE_CMP with invalid number of args %d", argc);
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    ic->ic_cmp.opty = argv[0].i64;
    ic->ic_cmp.lhs  = argv[1].i64;
    ic->ic_cmp.rhs  = argv[2].i64;
    ic->ic_cmp.pred = argv[3].i64;
    break;

  case CST_CODE_BLOCKADDRESS:
    parser_error(iu, "CST_CODE_BLOCKADDRESS (computed goto) is not supported");

  case CST_CODE_INLINEASM:
  case CST_CODE_INLINEASM_OLD:
    parser_error(iu, "Inline asm not supported");

  default:
    parser_error(iu, "Unknown op %d in constant block curty=%s",
                 op, type_str_index(iu, iu->iu_current_type));
  }
}


/**
 *
 */
static void
metadata_attachment_rec_handler(ir_unit_t *iu, int op,
                                unsigned int argc, const ir_arg_t *argv)
{
  //  printf("metadata_attachment: Handling rec %d\n", op);
  //  prinargs(argv, argc);
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


/**
 *
 */
static void
ir_enter_subblock(ir_unit_t *iu)
{
  bcbitstream_t *bs = iu->iu_bs;
  const uint32_t blockid = read_vbr(bs, 8);
  const uint32_t inner_id_width = read_vbr(bs, 4);
  align_bits32(bs);
  const uint32_t blocklen = read_bits(bs, 32) * 4;

  ir_block_t *ib = calloc(1, sizeof(ir_block_t));

  LIST_INSERT_HEAD(&iu->iu_blocks, ib, ib_link);

  TAILQ_INIT(&ib->ib_scoped_abbrevs);
  ir_blockinfo_t *ibi = blockinfo_find(iu, blockid);

  int valuelistsize = 0;
  rec_handler_t *rh;

  switch(blockid) {
  case 0:  // BLOCKINFO block
    rh = blockinfo_rec_handler;
    break;
  case 8:  // MODULE block
    rh = module_rec_handler;
    break;
  case 9:  // PARAMATTR block
    rh = paramattr_rec_handler;
    break;
  case 10: // PARAMATTR_GROUP
    rh = paramattr_group_rec_handler;
    break;
  case 11: // CONSTANTS block
    rh = constants_rec_handler;
    break;
  case 12:  // FUNCTION block
    valuelistsize = iu->iu_next_value;
    iu->iu_first_func_value = iu->iu_next_value;

    if(iu->iu_current_function == NULL) {
      iu->iu_current_function = TAILQ_FIRST(&iu->iu_functions_with_bodies);
    } else {
      iu->iu_current_function = TAILQ_NEXT(iu->iu_current_function,
                                           if_body_link);
    }

    ir_function_t *f = iu->iu_current_function;

    if(f == NULL)
      parser_error(iu, "Function body without matching function");

    if(iu->iu_debugged_function != NULL &&
       strcmp(iu->iu_debugged_function, f->if_name))
      iu->iu_debug_flags_func = 0;
    else
      iu->iu_debug_flags_func = iu->iu_debug_flags;

    function_prepare_parse(iu, f);
    rh = function_rec_handler;
    break;
  case 14:  // VALUE_SYMTAB block
    rh = value_symtab_rec_handler;
    break;
  case 15:  // METADATA block
    rh = metadata_rec_handler;
    break;
  case 16:  // METADATA_ATTACHMENT block
    rh = metadata_attachment_rec_handler;
    break;
  case 17:  // TYPES_NEW block
    rh = types_new_rec_handler;
    break;
  case 18:  // USELIST block
    rh = uselist_rec_handler;
    break;
  default:
    parser_error(iu, "Invalid block type %d", blockid);
  }

  ir_parse_blocks(iu, inner_id_width, blocklen, rh, ibi);

  switch(blockid) {
  case 12:
    function_process(iu, iu->iu_current_function);

    value_resize(iu, valuelistsize);
    break;

  case 11:
    eval_constexprs(iu);
    break;

  case 17:
    types_finalize(iu);
    break;
  }

  block_destroy(ib);
}

/**
 *
 */
static void
ir_unabbrev_record(ir_unit_t *iu, rec_handler_t *rh)
{
  int i;
  bcbitstream_t *bs = iu->iu_bs;
  const uint32_t code = read_vbr(bs, 6);
  const uint32_t numops = read_vbr(bs, 6);

  ir_arg_t *argv = malloc(numops * sizeof(ir_arg_t));
  for(i = 0; i < numops; i++) {
    argv[i].i64 = read_vbr64(bs, 6);
  }

  rh(iu, code, numops, argv);
  free(argv);
}


/**
 *
 */
static int
ir_define_abbrev(ir_unit_t *iu)
{
  bcbitstream_t *bs = iu->iu_bs;
  const uint32_t numops = read_vbr(bs, 5);
  ir_abbrev_t *ia = calloc(1, sizeof(ir_abbrev_t) +
                           sizeof(ir_abbrev_operand_t) * numops);
  ia->ia_nops = numops;
  int i;
  for(i = 0; i < numops; i++) {
    ir_abbrev_operand_t *iao = &ia->ia_ops[i];
    const int litteral = read_bits(bs, 1);
    if(litteral) {
      iao->iao_type = IAOT_LITTERAL;
      iao->iao_data = read_vbr(bs, 8);
      continue;
    }

    iao->iao_type = read_bits(bs, 3);
    switch(iao->iao_type) {
    case IAOT_FIXED_WIDTH:
    case IAOT_VBR:
      iao->iao_data = read_vbr(bs, 5);
      break;

    case IAOT_CHAR6:
      break;

    case IAOT_BLOB:
      if(i != numops - 1)
        parser_error(iu, "Blob is not last\n");
      break;

    case IAOT_ARRAY:
      if(i != numops - 2)
        parser_error(iu, "Array is not next to last\n");
      break;

    default:
      parser_error(iu, "Bad type %d in abbrev", iao->iao_type);
    }
  }

  ir_block_t *ib = LIST_FIRST(&iu->iu_blocks);

  if(ib->ib_blockinfo != NULL) {
    TAILQ_INSERT_TAIL(&ib->ib_blockinfo->ib_abbrevs, ia, ia_link);
    ib->ib_blockinfo->ib_num_abbrevs++;
  } else {
    TAILQ_INSERT_TAIL(&ib->ib_scoped_abbrevs, ia, ia_link);
  }
  return 0;
}


/**
 *
 */
static int
load_array(bcbitstream_t *bs, ir_unit_t *iu, const ir_abbrev_operand_t *type)
{
  const int arraysize = read_vbr(bs, 6);
  for(int i = 0; i < arraysize; i++) {

    ir_arg_t a;

    switch(type->iao_type) {
    case IAOT_FIXED_WIDTH:
      a.i64 = read_bits(bs, type->iao_data);
      break;
    case IAOT_VBR:
      a.i64 = read_vbr(bs, type->iao_data);
      break;
    case IAOT_CHAR6:
      a.i64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789._"[read_bits(bs, 6)];
      break;
    default:
      parser_error(iu, "Bad array type %d\n", type->iao_type);
    }
    VECTOR_PUSH_BACK(&iu->iu_argv, a);
  }
  return arraysize;
}


/**
 *
 */
static void
ir_dispatch_abbrev(ir_unit_t *iu, unsigned int id, rec_handler_t *rh,
                   const ir_blockinfo_t *ibi)
{
  bcbitstream_t *bs = iu->iu_bs;
  const ir_abbrev_t *ia;
  const struct ir_abbrev_queue *iaq;
  const int orig_id = id;
  id -= 4;
  ir_block_t *b = LIST_FIRST(&iu->iu_blocks);

  if(id >= ibi->ib_num_abbrevs) {
    // Search in local scope
    id -= ibi->ib_num_abbrevs;
    iaq = &b->ib_scoped_abbrevs;
  } else {
    iaq = &ibi->ib_abbrevs;
  }
  TAILQ_FOREACH(ia, iaq, ia_link) {
    if(id == 0)
      break;
    id--;
  }

  if(ia == NULL)
    parser_error(iu, "Abbrev %d not found\n", orig_id);


  VECTOR_RESIZE(&iu->iu_argv, 0);

  int i;
  int nops = ia->ia_nops;

  for(i = 0; i < nops; i++) {
    ir_arg_t a;
    switch(ia->ia_ops[i].iao_type) {
    case IAOT_LITTERAL:
      a.i64 = ia->ia_ops[i].iao_data;
      break;
    case IAOT_FIXED_WIDTH:
      a.i64 = read_bits(bs, ia->ia_ops[i].iao_data);
      break;
    case IAOT_VBR:
      a.i64 = read_vbr64(bs, ia->ia_ops[i].iao_data);
      break;
    case IAOT_ARRAY:
      assert(i == ia->ia_nops - 2);
      load_array(bs, iu, &ia->ia_ops[i + 1]);
      nops--; // Cut off last argument (which was array type)
      continue;

    default:
      parser_error(iu, "Can't handle abbrevs with arg %d yet",
                           ia->ia_ops[i].iao_type);
    }
    VECTOR_PUSH_BACK(&iu->iu_argv, a);
  }

  rh(iu, iu->iu_argv.vh_p[0].i64, iu->iu_argv.vh_length - 1,
     &iu->iu_argv.vh_p[1]);
}


/**
 *
 */
static void
ir_parse_blocks(ir_unit_t *iu, int abbrev_id_width, int bytes,
                rec_handler_t *rh, const ir_blockinfo_t *ibi)
{
  uint32_t id;
  bcbitstream_t *bs = iu->iu_bs;
  assert(bs->remain == 0);
  const int start = bs->bytes_offset;

  while((id = read_bits(bs, abbrev_id_width)) != 0) {
    switch(id) {
    case 1:  ir_enter_subblock(iu);               break;
    case 2:  ir_define_abbrev(iu);                break;
    case 3:  ir_unabbrev_record(iu, rh);          break;
    default: ir_dispatch_abbrev(iu, id, rh, ibi); break;
    }
  }

  align_bits32(bs);

  assert(bs->remain == 0);
  const int stop = bs->bytes_offset;

  assert(bytes == (stop - start));
}
