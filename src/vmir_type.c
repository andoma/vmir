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
  IR_TYPE_STRUCT,  // Must be first (0), because of forward references
  IR_TYPE_VOID,
  IR_TYPE_INT1,
  IR_TYPE_INT8,
  IR_TYPE_INT16,
  IR_TYPE_INT32,
  IR_TYPE_INT64,
  IR_TYPE_INTx,
  IR_TYPE_FLOAT,
  IR_TYPE_DOUBLE,
  IR_TYPE_ARRAY,
  IR_TYPE_POINTER,
  IR_TYPE_FUNCTION,
  IR_TYPE_METADATA,
  IR_TYPE_LABEL,
  IR_TYPE_OPAQUE,
} ir_type_code_t;


/**
 * Type
 */
typedef struct ir_type {
  ir_type_code_t it_code;

  union {

    int it_bits;  // Number of bits in IR_TYPE_INTx

    struct {
      int num_elements;
      int element_type;
    } it_array;

    struct {
      struct {
        int type;
        int offset;
      } *elements;
      char *name;
      int num_elements;
      int size;
      int alignment;
    } it_struct;

    struct {
      int pointee;
    } it_pointer;

    struct {
      int *parameters;
      int return_type;
      int num_parameters;
      int varargs;
    } it_function;

  };

} ir_type_t;


static void
type_clean(ir_type_t *it)
{
  switch(it->it_code) {
  default:
    break;
  case IR_TYPE_STRUCT:
    free(it->it_struct.name);
    free(it->it_struct.elements);
    break;
  case IR_TYPE_FUNCTION:
    free(it->it_function.parameters);
    break;
  }
}


/**
 *
 */
static int type_print(char **dst, const ir_unit_t *iu, const ir_type_t *it)
  __attribute__((warn_unused_result));
static const char *type_str_index(ir_unit_t *iu, int id);

/**
 *
 */
static ir_type_t *
type_get(ir_unit_t *iu, unsigned int id)
{
  if(id >= VECTOR_LEN(&iu->iu_types))
    parser_error(iu, "Bad type index %d", id);
  return &VECTOR_ITEM(&iu->iu_types, id);
}


/**
 *
 */
static unsigned int
type_get_pointee(ir_unit_t *iu, unsigned int id)
{
  ir_type_t *it = type_get(iu, id);
  if(it->it_code != IR_TYPE_POINTER)
    parser_error(iu, "Type (%s) (index:%d) is not a pointer",
                 type_str_index(iu, id), id);
  if(it->it_pointer.pointee == -1)
    parser_error(iu, "Attempting to dereference void pointer");
  return it->it_pointer.pointee;
}



/**
 *
 */
static int __attribute__((warn_unused_result))
type_print_id(char **dstp, const ir_unit_t *iu, int id)
{
  char tmpbuf[128];

  if(id < VECTOR_LEN(&iu->iu_types))
    return type_print(dstp, iu, &VECTOR_ITEM(&iu->iu_types, id));

  snprintf(tmpbuf, sizeof(tmpbuf), "[TypeId-%d]", id);
  return addstr(dstp, tmpbuf);
}


/**
 *
 */
static int __attribute__((warn_unused_result))
type_print(char **dst, const ir_unit_t *iu, const ir_type_t *it)
{
  char tmpbuf[128];
  const char *append = "type-???";
  int len = 0;

  switch(it->it_code) {
  case IR_TYPE_VOID:       append = "void"; break;
  case IR_TYPE_INT1:       append = "i1"; break;
  case IR_TYPE_INT8:       append = "i8"; break;
  case IR_TYPE_INT16:      append = "i16"; break;
  case IR_TYPE_INT32:      append = "i32"; break;
  case IR_TYPE_INT64:      append = "i64"; break;
  case IR_TYPE_FLOAT:      append = "float"; break;
  case IR_TYPE_DOUBLE:     append = "double"; break;
  case IR_TYPE_METADATA:   append = "metadata"; break;
  case IR_TYPE_LABEL:      append = "label"; break;
  case IR_TYPE_OPAQUE:     append = "opaque"; break;

  case IR_TYPE_INTx:
    snprintf(tmpbuf, sizeof(tmpbuf), "i%d", it->it_bits);
    return addstr(dst, tmpbuf);

  case IR_TYPE_STRUCT:
    if(it->it_struct.name != NULL) {
      len += addstr(dst, it->it_struct.name);
      return len;
    }

    snprintf(tmpbuf, sizeof(tmpbuf), "struct {");

    len += addstr(dst, tmpbuf);

    for(int i = 0; i < it->it_struct.num_elements; i++) {
      if(i > 0)
        len += addstr(dst, " ");

      len += type_print_id(dst, iu, it->it_struct.elements[i].type);

      snprintf(tmpbuf, sizeof(tmpbuf), " @ %x",
               it->it_struct.elements[i].offset);
      len += addstr(dst, tmpbuf);
    }
    len += addstr(dst, "}");
    return len;

  case IR_TYPE_ARRAY:
    len += addstr(dst, "[ ");

    len += type_print_id(dst, iu, it->it_array.element_type);

    snprintf(tmpbuf, sizeof(tmpbuf), " x %d ]", it->it_array.num_elements);
    len += addstr(dst, tmpbuf);
    return len;

  case IR_TYPE_POINTER:
    if(it->it_pointer.pointee == -1) {
      len += addstr(dst, "void*");
    } else {
      len += type_print_id(dst, iu, it->it_pointer.pointee);
      len += addstr(dst, "*");
    }
    return len;

  case IR_TYPE_FUNCTION:
    len += type_print_id(dst, iu, it->it_function.return_type);
    len += addstr(dst, " (*)(");

    for(int i = 0; i < it->it_function.num_parameters; i++) {
      if(i > 0)
        len += addstr(dst, ", ");

      len += type_print_id(dst, iu, it->it_function.parameters[i]);
    }
    len += addstr(dst, ")");
    return len;
  }

  len += addstr(dst, append);
  return len;
}



/**
 *
 */
static const char *
type_str(ir_unit_t *iu, const ir_type_t *it)
{
  int len = type_print(NULL, iu, it);
  char *dst = tmpstr(iu, len);
  const char *ret = dst;
  int x = type_print(&dst, iu, it);
  assert(x == len);
  return ret;
}


/**
 *
 */
static const char *
type_str_index(ir_unit_t *iu, int id)
{
  int l = type_print_id(NULL, iu, id);
  char *dst = tmpstr(iu, l);
  const char *ret = dst;
  int x = type_print_id(&dst, iu, id);
  assert(x == l);
  return ret;
}


/**
 *
 */
static int
type_make(ir_unit_t *iu, int type)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_types); i++) {
    ir_type_t *it = &VECTOR_ITEM(&iu->iu_types, i);
    if(it->it_code == type)
      return i;
  }

  iu->iu_types_created = 1;

  ir_type_t it;
  int r = VECTOR_LEN(&iu->iu_types);
  it.it_code = type;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  return r;
}


/**
 *
 */
static int
type_make_pointer(ir_unit_t *iu, int type, int may_create)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_types); i++) {
    ir_type_t *it = &VECTOR_ITEM(&iu->iu_types, i);
    if(it->it_code == IR_TYPE_POINTER && it->it_pointer.pointee == type)
      return i;
  }
  if(!may_create)
    return -1;

  iu->iu_types_created = 1;

  ir_type_t it;
  int r = VECTOR_LEN(&iu->iu_types);
  it.it_code = IR_TYPE_POINTER;
  it.it_pointer.pointee = type;
  VECTOR_PUSH_BACK(&iu->iu_types, it);
  return r;
}


/**
 *
 */
static int
type_find_by_code(ir_unit_t *iu, ir_type_code_t code)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_types); i++) {
    if(VECTOR_ITEM(&iu->iu_types, i).it_code == code)
      return i;
  }
  parser_error(iu, "Unable to find type class %d", code);
}



/**
 *
 */
static unsigned int
type_sizeof(ir_unit_t *iu, int index)
{
  ir_type_t *it = type_get(iu, index);
  switch(it->it_code) {
  case IR_TYPE_VOID:
    return 0;
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
    return 1;
  case IR_TYPE_INT16:
    return 2;
  case IR_TYPE_INT32:
  case IR_TYPE_FLOAT:
    return 4;
  case IR_TYPE_INT64:
  case IR_TYPE_DOUBLE:
    return 8;

  case IR_TYPE_INTx:
    if(it->it_bits <= 32)
      return 4;
    if(it->it_bits <= 64) {
      return 8;
    }
    goto bad;

  case IR_TYPE_POINTER:
    return 4;
  case IR_TYPE_STRUCT:
    return it->it_struct.size;

  case IR_TYPE_ARRAY:

    return type_sizeof(iu, it->it_array.element_type) *
      it->it_array.num_elements;

  default:
  bad:
    parser_error(iu, "Unable to compute size of type %s\n",
                 type_str(iu, it));
  }
}

/**
 *
 */
static uint32_t
type_code_mask(ir_type_code_t code)
{
  switch(code) {
  case IR_TYPE_INT1:
    return 0xff;
  case IR_TYPE_INT8:
    return 0xff;
  case IR_TYPE_INT16:
    return 0xffff;
  default:
    return 0xffffffff;
  }
}


/**
 *
 */
static unsigned int
type_bitwidth(ir_unit_t *iu, const ir_type_t *it)
{
  switch(it->it_code) {
  case IR_TYPE_VOID:
    return 0;
  case IR_TYPE_INT1:
    return 1;
  case IR_TYPE_INT8:
    return 8;
  case IR_TYPE_INT16:
    return 16;
  case IR_TYPE_INT32:
    return 32;
  case IR_TYPE_INT64:
    return 64;
  case IR_TYPE_INTx:
    return it->it_bits;

  default:
    parser_error(iu, "Unable to compute bitwidth of type %s\n",
                 type_str(iu, it));
  }
}


/**
 *
 */
static unsigned int
type_alignment(ir_unit_t *iu, int index)
{
  ir_type_t *it = type_get(iu, index);
  switch(it->it_code) {
  case IR_TYPE_VOID:
    return 0;
  case IR_TYPE_INT1:
  case IR_TYPE_INT8:
    return 1;
  case IR_TYPE_INT16:
    return 2;
  case IR_TYPE_INT32:
  case IR_TYPE_FLOAT:
    return 4;
  case IR_TYPE_INT64:
  case IR_TYPE_DOUBLE:
    return 8;
  case IR_TYPE_INTx:
    if(it->it_bits <= 32)
      return 4;
    if(it->it_bits <= 64) {
      return 8;
    }
    goto bad;
  case IR_TYPE_POINTER:
    return 4;

  case IR_TYPE_STRUCT:
    return it->it_struct.alignment;

  case IR_TYPE_ARRAY:
    return type_alignment(iu, it->it_array.element_type);

  default:
  bad:
    parser_error(iu, "Unable to compute alignment for type %s\n",
                 type_str(iu, it));
  }
}



/**
 *
 */
static void
types_new_rec_handler(struct ir_unit *iu, int op,
                      unsigned int argc, const ir_arg_t *argv)
{
  ir_type_t it;
  const char *ctx = "types";

  assert(iu->iu_types_created == 0);

  switch(op) {
  case TYPE_CODE_NUMENTRY:
    if(argc < 1)
      parser_error(iu, "%s: Short NUMENTRY record", ctx);

    VECTOR_SET_CAPACITY(&iu->iu_types, argv[0].i64);
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
    if(argv[0].i64 == 1) {
      it.it_code = IR_TYPE_INT1;
    } else if(argv[0].i64 == 8) {
      it.it_code = IR_TYPE_INT8;
    } else if(argv[0].i64 == 16) {
      it.it_code = IR_TYPE_INT16;
    } else if(argv[0].i64 == 32) {
      it.it_code = IR_TYPE_INT32;
    } else if(argv[0].i64 == 64) {
      it.it_code = IR_TYPE_INT64;
    } else if(argv[0].i64 < 64) {
      it.it_code = IR_TYPE_INTx;
      it.it_bits = argv[0].i64;
    } else {
      parser_error(iu, "%s: Integer width %d bit not supported",
                   ctx, (int)argv[0].i64);
    }
    break;
  case TYPE_CODE_ARRAY:
    it.it_code = IR_TYPE_ARRAY;
    it.it_array.num_elements = argv[0].i64;
    it.it_array.element_type = argv[1].i64;
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

    it.it_struct.num_elements = argc - 1;
    it.it_struct.elements = malloc(it.it_struct.num_elements *
                                   sizeof(it.it_struct.elements[0]));
    {
      const int packed = !!argv[0].i64;
      int offset = 0;
      int ba = 1; // Biggest alignment

      for(int i = 0; i < it.it_struct.num_elements; i++) {
        int t = argv[i + 1].i64;
        it.it_struct.elements[i].type = t;
        int s = type_sizeof(iu, t);

        if(!packed) {
          int a = type_alignment(iu ,t);
          offset = VMIR_ALIGN(offset, a);
          ba = MAX(ba, a);
        }
        it.it_struct.elements[i].offset = offset;
        offset += s;
      }
      it.it_struct.size = packed ? offset : VMIR_ALIGN(offset, ba);
      it.it_struct.alignment = ba;
    }
    break;


  case TYPE_CODE_POINTER:
    it.it_code = IR_TYPE_POINTER;
    it.it_pointer.pointee = argv[0].i64;
    break;

  case TYPE_CODE_FUNCTION:
    if(argc < 2)
      parser_error(iu, "%s: Invalid # of args (%d) for function type",
                   ctx, argc);

    it.it_code = IR_TYPE_FUNCTION;
    it.it_function.varargs = argv[0].i64;
    it.it_function.return_type = argv[1].i64;
    it.it_function.num_parameters = argc - 2;
    it.it_function.parameters =
      malloc(it.it_function.num_parameters * sizeof(int));
    for(int i = 0; i < it.it_function.num_parameters; i++)
      it.it_function.parameters[i] = argv[2 + i].i64;
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
           type_str_index(iu, argv[1].i64),
           (int)argv[0].i64);

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
type_print_list(ir_unit_t *iu)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_types); i++) {
    printf("Type-%-5d  %s\n", i, type_str_index(iu, i));
  }
}


/**
 *
 */
static int
legalize_type(const ir_type_t *ty)
{
  if(ty->it_code == IR_TYPE_INTx) {
    if(ty->it_bits <= 8)
      return IR_TYPE_INT8;
    else if(ty->it_bits <= 16)
      return IR_TYPE_INT16;
    else if(ty->it_bits <= 32)
      return IR_TYPE_INT32;
    else if(ty->it_bits <= 64)
      return IR_TYPE_INT64;
  }
  return ty->it_code;
}
