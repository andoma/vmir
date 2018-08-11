typedef enum {
  IAOT_LITTERAL = 0,
  IAOT_FIXED_WIDTH = 1,
  IAOT_VBR = 2,
  IAOT_ARRAY = 3,
  IAOT_CHAR6 = 4,
  IAOT_BLOB = 5,
} ia_abbrev_operand_type_t;

/**
 *
 */
typedef struct ir_abbrev_operand {
  ia_abbrev_operand_type_t iao_type;
  uint32_t iao_data;
} ir_abbrev_operand_t;


/**
 *
 */
typedef struct ir_abbrev {
  TAILQ_ENTRY(ir_abbrev) ia_link;
  int ia_nops;
  ir_abbrev_operand_t ia_ops[0];
} ir_abbrev_t;

static void ir_parse_blocks(ir_unit_t *iu, int abbrev_id_width,
                            rec_handler_t *rh, const ir_blockinfo_t *ibi,
                            bcbitstream_t *bs);

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
                      unsigned int argc, const int64_t *argv)
{
  ir_block_t *ib = LIST_FIRST(&iu->iu_blocks);
  switch(op) {

  case 1: // SETBID
    if(argc != 1)
      parser_error(iu, "Bad number of args (%d) for SETBID", argc);

    ib->ib_blockinfo = blockinfo_find(iu, argv[0]);
    break;
  }
}


/**
 * GLOBALVAR: [pointer type, isconst, initid,
 *             linkage, alignment, section, visibility, threadlocal,
 *             unnamed_addr, dllstorageclass]
 */
static void
module_globalvar(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  if(argc < 6)
    parser_error(iu, "Bad number of args for global var def");

  int explicit_type = argv[1] & 2;
  unsigned int type, pointee;


  if(explicit_type) {
    pointee = argv[0];
    type = type_make_pointer(iu, pointee, 0);
    if(type == -1)
      parser_error(iu, "No pointer type for pointee '%s'",
                   type_str_index(iu, pointee));
  } else {
    type = argv[0];
    pointee = type_get_pointee(iu, type);
  }

  const int val_id =
    value_create_global(iu, pointee, type, vmir_llvm_alignment(argv[4], 4));

  const unsigned int initializer = argv[2];
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
module_function(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  if(argc < 8)
    parser_error(iu, "Bad number of args");

  unsigned int type = argv[0];
  ir_type_t *it = type_get(iu, type);
  if(it->it_code == IR_TYPE_POINTER)
    type = it->it_pointer.pointee;

  ir_function_t *f = calloc(1, sizeof(ir_function_t));

  TAILQ_INIT(&f->if_bbs);
  f->if_isproto = !!argv[2];
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
module_alias(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  if(argc < 3)
    parser_error(iu, "Bad number of args");

  ir_value_t *iv = value_append_and_get(iu);
  iv->iv_class = IR_VC_ALIAS;
  iv->iv_type = argv[0];
  iv->iv_reg = argv[1];
}


/**
 * Value symtab offset
 */
static void
module_vstoffset(ir_unit_t *iu, unsigned int argc, const int64_t *argv)
{
  if(argc != 1)
    parser_error(iu, "Bad number of args");
  iu->iu_vstoffset = (int)argv[0];
}


/**
 *
 */
static void
module_rec_handler(ir_unit_t *iu, int op,
                   unsigned int argc, const int64_t *argv)
{
  switch(op) {
  case MODULE_CODE_VERSION:
    iu->iu_version = argv[0];
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

  case MODULE_CODE_VSTOFFSET:
    return module_vstoffset(iu, argc, argv);

  case MODULE_CODE_COMDAT:
  case MODULE_CODE_METADATA_VALUES_UNUSED:
  case MODULE_CODE_SOURCE_FILENAME:
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
                            unsigned int argc, const int64_t *argv)
{
  char *key, *value;
  const char *ctx = "PARAMATTR_GRP_CODE_ENTRY";
  switch(op) {
  case 3: // PARAMATTR_GRP_CODE_ENTRY
    if(argc < 3)
      parser_error(iu, "%s: Short (%d records)", ctx, argc);

    ir_attr_t *ia = calloc(1, sizeof(ir_attr_t));
    LIST_INSERT_HEAD(&iu->iu_attribute_groups, ia, ia_link);

    ia->ia_group_id = argv[0];
    ia->ia_index    = argv[1];
    argv += 2;
    argc -= 2;
    while(argc > 0) {
      int type = argv[0];
      argv++;
      argc--;
      if(argc == 0)
        parser_error(iu, "%s: Short record", ctx);

      switch(type) {
      case 0:
        // ENUM attribute
        ia->ia_flags |= (1ULL << argv[0]);
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
                      unsigned int argc, const int64_t *argv)
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
        if(ia->ia_group_id == argv[i])
          break;
      }

      if(ia == NULL)
        parser_error(iu, "%s: Group %d not found",
                            ctx, (int)argv[i]);

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
                     unsigned int argc, const int64_t *argv)
{
  //  printf("metadata: Handling rec %d\n", op);
  //  prinargs(argv, argc);
}




/**
 *
 */
static void
dummy_rec_handler(ir_unit_t *iu, int op,
                  unsigned int argc, const int64_t *argv)
{
}


/**
 *
 */
static void
set_value_name(ir_unit_t *iu, int vid, char *str)
{
  ir_value_t *iv = value_get(iu, vid);
  free(iv->iv_name);
  iv->iv_name = strdup(str);

  switch(iv->iv_class) {
  case IR_VC_FUNCTION:
    free(iv->iv_func->if_name);
    iv->iv_func->if_name = str;
    if(iv->iv_func->if_ext_func == NULL) {
      if(!vmop_resolve(iv->iv_func)) {
        iv->iv_func->if_ext_func =
          (void *)iu->iu_external_function_resolver(iv->iv_func->if_name, iu->iu_opaque);
      }
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
}


/**
 *
 */
static void
value_symtab_rec_handler(ir_unit_t *iu, int op,
                         unsigned int argc, const int64_t *argv)
{
  unsigned int vid;
  char *str;
  switch(op) {
  case 1: // VST_CODE_ENTRY
    if(argc < 2)
      parser_error(iu, "Bad args to VST_CODE_ENTRY");

    vid = argv[0];
    str = read_str_from_argv(argc - 1, argv + 1);
    set_value_name(iu, vid, str);
    break;

  case 2: // VST_CODE_BBENTRY
    break;

  case 3: // VST_CODE_FNENTRY
    if(argc < 3)
      parser_error(iu, "Bad args to VST_CODE_FNENTRY");

    vid = argv[0];
    str = read_str_from_argv(argc - 2, argv + 2);
    set_value_name(iu, vid, str);
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
                      unsigned int argc, const int64_t *argv)
{
  ir_value_t *iv;
  ir_constexpr_t *ic;

  if(op == CST_CODE_SETTYPE) {
    if(argc < 1)
      parser_error(iu, "Bad # of args for CST_CODE_SETTYPE");
    assert(argc > 0);
    iu->iu_current_type = argv[0];
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
      iv->iv_u32 = argv[0]; // iv_u32 is union with iv_float
      break;
    case IR_TYPE_DOUBLE:
      iv->iv_u64 = argv[0]; // iv_u64 is union with iv_double
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
      ir_value_t *ivx = value_get(iu, argv[i]);
      values[i].value = argv[i];
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
            host_wr64(iv->iv_data + i * sizeof(uint64_t), argv[i]);
          return;

        case IR_TYPE_INT32:
        case IR_TYPE_FLOAT:
          iv->iv_data = malloc(sizeof(uint32_t) * argc);
          for(int i = 0; i < argc; i++)
            host_wr32(iv->iv_data + i * sizeof(uint32_t), argv[i]);
          return;

        case IR_TYPE_INT16:
          iv->iv_data = malloc(sizeof(uint16_t) * argc);
          for(int i = 0; i < argc; i++)
            host_wr16(iv->iv_data + i * sizeof(uint16_t), argv[i]);
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
    ic->ic_cast.op  = argv[0];
    ic->ic_cast.src = argv[2];
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
      ic->ic_gep.values[i] = argv[1 + i * 2];
    break;

  case CST_CODE_CE_BINOP:
    iv->iv_class = IR_VC_CE;
    if(argc < 3)
      parser_error(iu, "CST_CODE_CE_BINOP with invalid number of args %d", argc);
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    ic->ic_binop.op  = argv[0];
    ic->ic_binop.lhs = argv[1];
    ic->ic_binop.rhs = argv[2];
    break;

  case CST_CODE_CE_CMP:
    iv->iv_class = IR_VC_CE;
    if(argc < 4)
      parser_error(iu, "CST_CODE_CE_CMP with invalid number of args %d", argc);
    ic = iv->iv_ce = malloc(sizeof(ir_constexpr_t));
    ic->ic_code = op;
    ic->ic_cmp.opty = argv[0];
    ic->ic_cmp.lhs  = argv[1];
    ic->ic_cmp.rhs  = argv[2];
    ic->ic_cmp.pred = argv[3];
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
                                unsigned int argc, const int64_t *argv)
{
  //  printf("metadata_attachment: Handling rec %d\n", op);
  //  prinargs(argv, argc);
}


/**
 *
 */
static void
types_new_rec_handler(struct ir_unit *iu, int op,
                      unsigned int argc, const int64_t *argv)
{
  ir_type_t it;
  const char *ctx = "types";

  assert(iu->iu_types_created == 0);

  switch(op) {
  case TYPE_CODE_NUMENTRY:
    if(argc < 1)
      parser_error(iu, "%s: Short NUMENTRY record", ctx);

    VECTOR_SET_CAPACITY(&iu->iu_types, argv[0]);
    return;

  case TYPE_CODE_VOID:
    it.it_code = IR_TYPE_VOID;
    break;
  case TYPE_CODE_FLOAT:
    it.it_code = IR_TYPE_FLOAT;
    break;
  case TYPE_CODE_DOUBLE:
    it.it_code = IR_TYPE_DOUBLE;
    break;
  case TYPE_CODE_INTEGER:
    if(argv[0] == 1) {
      it.it_code = IR_TYPE_INT1;
    } else if(argv[0] == 8) {
      it.it_code = IR_TYPE_INT8;
    } else if(argv[0] == 16) {
      it.it_code = IR_TYPE_INT16;
    } else if(argv[0] == 32) {
      it.it_code = IR_TYPE_INT32;
    } else if(argv[0] == 64) {
      it.it_code = IR_TYPE_INT64;
    } else if(argv[0] < 64) {
      it.it_code = IR_TYPE_INTx;
      it.it_bits = argv[0];
    } else {
      parser_error(iu, "%s: Integer width %d bit not supported",
                   ctx, (int)argv[0]);
    }
    break;
  case TYPE_CODE_ARRAY:
    it.it_code = IR_TYPE_ARRAY;
    it.it_array.num_elements = argv[0];
    it.it_array.element_type = argv[1];
    break;

  case TYPE_CODE_STRUCT_NAME:
    free(iu->iu_current_struct_name);
    iu->iu_current_struct_name = read_str_from_argv(argc, argv);
    return;

  case TYPE_CODE_STRUCT_NAMED:

    it.it_struct.name = iu->iu_current_struct_name;
    iu->iu_current_struct_name = NULL;

    if(0)
  case TYPE_CODE_STRUCT_ANON:
      it.it_struct.name = NULL;

    it.it_code = IR_TYPE_STRUCT;
    it.it_struct.computed = 0;
    it.it_struct.num_elements = argc - 1;
    it.it_struct.elements = malloc(it.it_struct.num_elements *
                                   sizeof(it.it_struct.elements[0]));
    it.it_struct.packed = !!argv[0];
    for(int i = 0; i < it.it_struct.num_elements; i++) {
      it.it_struct.elements[i].type = argv[i + 1];
    }
    break;

  case TYPE_CODE_POINTER:
    it.it_code = IR_TYPE_POINTER;
    it.it_pointer.pointee = argv[0];
    break;

  case TYPE_CODE_FUNCTION:
    if(argc < 2)
      parser_error(iu, "%s: Invalid # of args (%d) for function type",
                   ctx, argc);

    it.it_code = IR_TYPE_FUNCTION;
    it.it_function.varargs = argv[0];
    it.it_function.return_type = argv[1];
    it.it_function.num_parameters = argc - 2;
    it.it_function.parameters =
      malloc(it.it_function.num_parameters * sizeof(int));
    for(int i = 0; i < it.it_function.num_parameters; i++)
      it.it_function.parameters[i] = argv[2 + i];
    break;

  case TYPE_CODE_METADATA:
    it.it_code = IR_TYPE_METADATA;
    break;

  case TYPE_CODE_LABEL:
    it.it_code = IR_TYPE_LABEL;
    break;

  case TYPE_CODE_OPAQUE:
    it.it_code = IR_TYPE_OPAQUE;
    break;

  case TYPE_CODE_VECTOR:
    printf("Vector of %s x %d\n",
           type_str_index(iu, argv[1]),
           (int)argv[0]);

           //    break;

  default:
    printargs(argv, argc);
    parser_error(iu, "%s: Unknown op %d", ctx, op);
  }

  VECTOR_PUSH_BACK(&iu->iu_types, it);
}




/**
 *
 */
static void
ir_enter_subblock(ir_unit_t *iu, bcbitstream_t *bs, int outer_id_width)
{
  const uint32_t blockid = read_vbr(bs, 8);
  const uint32_t inner_id_width = read_vbr(bs, 4);
  align_bits32(bs);
  /* const uint32_t blocklen = */ read_bits(bs, 32);

  ir_block_t *ib = calloc(1, sizeof(ir_block_t));

  LIST_INSERT_HEAD(&iu->iu_blocks, ib, ib_link);

  TAILQ_INIT(&ib->ib_scoped_abbrevs);
  ir_blockinfo_t *ibi = blockinfo_find(iu, blockid);

  int valuelistsize = 0;
  rec_handler_t *rh;

  switch(blockid) {
  case BITCODE_BLOCKINFO:
    rh = blockinfo_rec_handler;
    break;
  case BITCODE_MODULE:
    rh = module_rec_handler;
    break;
  case BITCODE_PARAMATTR:
    rh = paramattr_rec_handler;
    break;
  case BITCODE_PARAMATTR_GROUP:
    rh = paramattr_group_rec_handler;
    break;
  case BITCODE_CONSTANTS:
    rh = constants_rec_handler;
    break;
  case BITCODE_FUNCTION:
    valuelistsize = iu->iu_next_value;
    iu->iu_first_func_value = iu->iu_next_value;

    if(iu->iu_vstoffset) {
      bcbitstream_t vstbs = *bs;
      vstbs.bytes_offset = iu->iu_vstoffset * 4;
      vstbs.remain = 0;
      ir_parse_blocks(iu, outer_id_width, NULL, ibi, &vstbs);
      iu->iu_vstoffset = 0;
    }

    if(iu->iu_current_function == NULL) {
      iu->iu_current_function = TAILQ_FIRST(&iu->iu_functions_with_bodies);
    } else {
      iu->iu_current_function = TAILQ_NEXT(iu->iu_current_function,
                                           if_body_link);
    }

    ir_function_t *f = iu->iu_current_function;

    if(f == NULL)
      parser_error(iu, "Function body without matching function");

    function_prepare_parse(iu, f);
    rh = function_rec_handler;
    break;
  case BITCODE_VALUE_SYMTAB:
    rh = value_symtab_rec_handler;
    break;
  case BITCODE_METADATA:
    rh = metadata_rec_handler;
    break;
  case BITCODE_METADATA_ATTACHMENT:
    rh = metadata_attachment_rec_handler;
    break;
  case BITCODE_TYPES_NEW:
    rh = types_new_rec_handler;
    break;
  case BITCODE_USELIST:
  case BITCODE_METADATA_KIND_BLOCK_ID:
  case BITCODE_IDENTIFICATION_BLOCK_ID:
  case BITCODE_OPERAND_BUNDLE_TAGS_BLOCK_ID:
    rh = dummy_rec_handler;
    break;
  default:
    parser_error(iu, "Invalid block type %d", blockid);
  }

  ir_parse_blocks(iu, inner_id_width, rh, ibi, bs);

  switch(blockid) {
  case BITCODE_FUNCTION:
    function_process(iu, iu->iu_current_function);

    value_resize(iu, valuelistsize);
    break;

  case BITCODE_CONSTANTS:
    eval_constexprs(iu);
    break;

  case BITCODE_TYPES_NEW:
    types_finalize(iu);
    break;
  }

  block_destroy(ib);
}

/**
 *
 */
static void
ir_unabbrev_record(ir_unit_t *iu, rec_handler_t *rh, bcbitstream_t *bs)
{
  int i;
  const uint32_t code = read_vbr(bs, 6);
  const uint32_t numops = read_vbr(bs, 6);

  int64_t *argv = malloc(numops * sizeof(int64_t));
  for(i = 0; i < numops; i++) {
    argv[i] = read_vbr64(bs, 6);
  }

  rh(iu, code, numops, argv);
  free(argv);
}


/**
 *
 */
static int
ir_define_abbrev(ir_unit_t *iu, bcbitstream_t *bs)
{
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
static void
load_array(bcbitstream_t *bs, ir_unit_t *iu, const ir_abbrev_operand_t *type)
{
  const int arraysize = read_vbr(bs, 6);
  for(int i = 0; i < arraysize; i++) {

    int64_t a;

    switch(type->iao_type) {
    case IAOT_FIXED_WIDTH:
      a = read_bits(bs, type->iao_data);
      break;
    case IAOT_VBR:
      a = read_vbr(bs, type->iao_data);
      break;
    case IAOT_CHAR6:
      a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789._"[read_bits(bs, 6)];
      break;
    default:
      parser_error(iu, "Bad array type %d\n", type->iao_type);
    }
    VECTOR_PUSH_BACK(&iu->iu_argv, a);
  }
}

/**
 *
 */
static void
load_blob(bcbitstream_t *bs, ir_unit_t *iu)
{
  const int blobsize = read_vbr(bs, 6);
  align_bits32(bs);
  for(int i = 0; i < blobsize; i++) {
    int64_t a;
    a = read_bits(bs, 8);
    VECTOR_PUSH_BACK(&iu->iu_argv, a);
  }
  int tailpad = VMIR_ALIGN(blobsize, 4) - blobsize;
  read_bits(bs, tailpad * 8);
}

/**
 *
 */
static void
ir_dispatch_abbrev(ir_unit_t *iu, unsigned int id, rec_handler_t *rh,
                   const ir_blockinfo_t *ibi, bcbitstream_t *bs)
{
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
    int64_t a;
    switch(ia->ia_ops[i].iao_type) {
    case IAOT_LITTERAL:
      a = ia->ia_ops[i].iao_data;
      break;
    case IAOT_FIXED_WIDTH:
      a = read_bits(bs, ia->ia_ops[i].iao_data);
      break;
    case IAOT_VBR:
      a = read_vbr64(bs, ia->ia_ops[i].iao_data);
      break;
    case IAOT_ARRAY:
      assert(i == ia->ia_nops - 2);
      load_array(bs, iu, &ia->ia_ops[i + 1]);
      nops--; // Cut off last argument (which was array type)
      continue;
    case IAOT_BLOB:
      load_blob(bs, iu);
      continue;

    default:
      parser_error(iu, "Can't handle abbrevs with arg %d yet",
                           ia->ia_ops[i].iao_type);
    }
    VECTOR_PUSH_BACK(&iu->iu_argv, a);
  }

  rh(iu, iu->iu_argv.vh_p[0], iu->iu_argv.vh_length - 1,
     &iu->iu_argv.vh_p[1]);
}


/**
 *
 */
static void
ir_parse_blocks(ir_unit_t *iu, int abbrev_id_width,
                rec_handler_t *rh, const ir_blockinfo_t *ibi,
                bcbitstream_t *bs)
{
  assert(bs->remain == 0);
  while(1) {
    uint32_t id = read_bits(bs, abbrev_id_width);
    if(id == 0)
      break;
    switch(id) {
    case 1:  ir_enter_subblock(iu, bs, abbrev_id_width); break;
    case 2:  ir_define_abbrev(iu, bs);                break;
    case 3:  ir_unabbrev_record(iu, rh, bs);          break;
    default: ir_dispatch_abbrev(iu, id, rh, ibi, bs); break;
    }
  }

  align_bits32(bs);
}
