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

#include <setjmp.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <assert.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "bitcode.h"

#include <time.h>
#include <sys/time.h>

#include "vmir.h"

#include "vmir_support.c"
#include "vmir_bitstream.c"

TAILQ_HEAD(ir_abbrev_queue, ir_abbrev);
LIST_HEAD(ir_blockinfo_list, ir_blockinfo);

typedef enum {
  IAOT_LITTERAL = 0,
  IAOT_FIXED_WIDTH = 1,
  IAOT_VBR = 2,
  IAOT_ARRAY = 3,
  IAOT_CHAR6 = 4,
  IAOT_BLOB = 5,
} ia_abbrev_operand_type_t;


LIST_HEAD(ir_attr_list, ir_attr);

/**
 *
 */
typedef struct ir_blockinfo {
  LIST_ENTRY(ir_blockinfo) ib_link;
  int ib_id;
  int ib_num_abbrevs;
  struct ir_abbrev_queue ib_abbrevs;
} ir_blockinfo_t;

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

typedef struct ir_block {
  LIST_ENTRY(ir_block) ib_link;
  struct ir_abbrev_queue ib_scoped_abbrevs;
  ir_blockinfo_t *ib_blockinfo;
} ir_block_t;


LIST_HEAD(ir_block_list, ir_block);

struct ir_unit;

typedef void (rec_handler_t)(struct ir_unit *iu, int op,
                             unsigned int argc, const ir_arg_t *argv);

static void ir_parse_blocks(struct ir_unit *iu,
                            int abbrev_id_width, int bytes,
                            rec_handler_t *rh,
                            const ir_blockinfo_t *ib);

VECTOR_HEAD(ir_op_vector, struct ir_op);
VECTOR_HEAD(ir_attrset_vector, struct ir_attrset);
VECTOR_HEAD(ir_type_vector, struct ir_type);
VECTOR_HEAD(ir_value_vector, struct ir_value *);
VECTOR_HEAD(ir_instrumentation_vector, struct ir_instrumentation);

TAILQ_HEAD(ir_bb_queue, ir_bb);
TAILQ_HEAD(ir_function_queue, ir_function);
TAILQ_HEAD(ir_instr_queue, ir_instr);

LIST_HEAD(ir_bb_edge_list, ir_bb_edge);
LIST_HEAD(ir_value_instr_list, ir_value_instr);

struct ir_unit;

typedef void (vm_ext_function_t)(void *ret, const void *regs,
                                 struct ir_unit *iu);

typedef struct vmir_stats {

  int cmp_branch_combine;
  int mla_combine;
  int load_cast_combine;
  int moves_killed;

  int lea_load_combined;
  int lea_load_combined_failed;

  int vm_binop_acc;
  int vm_binop_acc_imm;
  int vm_binop_acc_acc;
  int vm_binop_acc_acc_imm;

} vmir_stats_t;



/**
 * Translation unit
 */
struct ir_unit {
  void *iu_mem;
  void **iu_vm_funcs;
  vm_ext_function_t **iu_ext_funcs;
  jmp_buf iu_err_jmpbuf;
  int iu_exit_code;
  void *iu_opaque;


  uint32_t iu_data_ptr;
  uint32_t iu_heap_start;
  void *iu_heap;
  uint32_t iu_rsize;
  uint32_t iu_asize;
  uint32_t iu_alloca_ptr;
  uint32_t iu_memsize;

  uint32_t iu_debug_flags;
  uint32_t iu_debug_flags_func;
  char *iu_debugged_function;
  struct ir_instrumentation_vector iu_instrumentation;

  char *iu_triple;
  int iu_version;

  struct ir_blockinfo_list iu_blockinfos;
  struct ir_block_list iu_blocks;

  struct ir_attr_list iu_attribute_groups;
  struct ir_attrset_vector iu_attrsets;

  struct ir_type_vector iu_types;

  struct ir_value_vector iu_values;
  int iu_next_value;
  int iu_first_func_value;
  int iu_first_call_arg;

  char *iu_current_struct_name;

  struct ir_function_queue iu_functions_with_bodies;

  int iu_current_type;

  struct ir_function *iu_current_function;
  struct ir_bb *iu_current_bb;

#define IU_MAX_TMP_STR 32
  char *iu_tmp_str[IU_MAX_TMP_STR];
  int iu_tmp_str_ptr;

  VECTOR_HEAD(, struct ir_function *) iu_functions;
  VECTOR_HEAD(, struct ir_initializer) iu_initializers;

  VECTOR_HEAD(, int) iu_branch_fixups;

  int iu_types_created;

  // Parser

  jmp_buf      iu_err_jmp;

  void *iu_text_alloc;
  void *iu_text_ptr;
  size_t iu_text_alloc_memsize;

  bcbitstream_t *iu_bs;

  VECTOR_HEAD(, ir_arg_t) iu_argv;

  char        iu_err_buf[256];
  const char *iu_err_file;
  int         iu_err_line;
  int         iu_failed;

  // Stats

  vmir_stats_t iu_stats;
};


/**
 * Attribute
 */
typedef struct ir_attr {
  LIST_ENTRY(ir_attr) ia_link;

  uint32_t ia_group_id;
  uint32_t ia_index;

  uint64_t ia_flags;

} ir_attr_t;


/**
 * Attribute Set
 */
typedef struct ir_attrset {
  int ias_size;
  const ir_attr_t **ias_list;
} ir_attrset_t;


/**
 *
 */
typedef struct ir_function {
  TAILQ_ENTRY(ir_function) if_body_link;
  unsigned int if_type;
  char *if_name;
  char if_isproto;
  char if_used;
  int if_regframe_size; // Size of all temporary registers
  int if_callarg_size;  // Size of all (non vararg) arguments
  int if_gfid;          // Global function id
  int if_vmop;          // Set if function maps directly to a VM opcode
  int if_vmop_args;     // Number of args the vmop expects

  int if_num_bbs;
  struct ir_bb_queue if_bbs;
  struct ir_bb_edge_list if_edges;

  void *if_vm_text;
  int if_vm_text_size;

  vm_ext_function_t *if_ext_func;

} ir_function_t;


/**
 *
 */
typedef struct ir_globalvar {
  TAILQ_ENTRY(ir_globalvar) ig_unit_link;
  unsigned int ig_type;
  char *ig_name;
  uint32_t ig_addr;

} ir_globalvar_t;


/**
 *
 */
typedef struct ir_initializer {
  int ii_globalvar;
  int ii_constant;
} ir_initializer_t;


/**
 *
 */
typedef struct ir_bb {
  TAILQ_ENTRY(ir_bb) ib_link;
  struct ir_instr_queue ib_instrs;
  int ib_text_offset;
  int ib_id;
  int ib_first_instr; // Only valid during liveness analysis, etc
  int ib_mark;

  struct ir_bb_edge_list ib_incoming_edges;
  struct ir_bb_edge_list ib_outgoing_edges;
} ir_bb_t;


/**
 *
 */
typedef struct ir_bb_edge {
  LIST_ENTRY(ir_bb_edge) ibe_from_link;
  LIST_ENTRY(ir_bb_edge) ibe_to_link;
  LIST_ENTRY(ir_bb_edge) ibe_function_link;
  ir_bb_t *ibe_from;
  ir_bb_t *ibe_to;
} ir_bb_edge_t;


/**
 *
 */
typedef struct ir_instrumentation {
  struct ir_function *ii_func;
  int ii_bb;
  int ii_instructions;
  int64_t ii_count;
} ir_instrumentation_t;




/**
 *
 */
typedef enum {
  // Instructions defined in bitcode
  IR_IC_UNREACHABLE,
  IR_IC_RET,
  IR_IC_BINOP,
  IR_IC_CAST,
  IR_IC_LOAD,
  IR_IC_STORE,
  IR_IC_GEP,
  IR_IC_CMP2,
  IR_IC_BR,
  IR_IC_PHI,
  IR_IC_CALL,
  IR_IC_SWITCH,
  IR_IC_ALLOCA,
  IR_IC_SELECT,
  IR_IC_VAARG,
  IR_IC_EXTRACTVAL,

  // VMIR special instructions
  IR_IC_LEA,
  IR_IC_MOVE,
  IR_IC_VMOP,
  IR_IC_STACKCOPY,
  IR_IC_STACKSHRINK,
  IR_IC_CMP_BRANCH,
  IR_IC_MLA,
} instr_class_t;


/**
 *
 */
typedef struct ir_instr {
  TAILQ_ENTRY(ir_instr) ii_link;
  struct ir_bb *ii_bb;
  int *ii_ret_values;
  struct ir_value_instr_list ii_values;
  instr_class_t ii_class;
  int ii_ret_value;  // -1 if instruction does not emit a new value
} ir_instr_t;

static void type_print_list(ir_unit_t *iu);
static void value_print_list(ir_unit_t *iu);

#define parser_error(iu, fmt...) \
  parser_error0(iu, __FILE__, __LINE__, fmt)

/**
 *
 */
static void __attribute__((noreturn))
parser_error0(ir_unit_t *iu, const char *file, int line,
              const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(iu->iu_err_buf, sizeof(iu->iu_err_buf), fmt, ap);
  va_end(ap);
  iu->iu_err_file = file;
  iu->iu_err_line = line;

  printf("%s:%d : Parser error: %s\n", file, line, iu->iu_err_buf);

  if(iu->iu_failed) {
    printf("Double failure\n");
  } else {
    iu->iu_failed = 1;
    if(0) {
      printf("=== Type list =========================\n");
      type_print_list(iu);
      printf("=== Valie list ========================\n");
      value_print_list(iu);
      printf("%s:%d : Parser error: %s\n", file, line, iu->iu_err_buf);
    }
  }

  abort();
  longjmp(iu->iu_err_jmp, 1);
}

/**
 *
 */
static char * __attribute__((warn_unused_result))
tmpstr(ir_unit_t *iu, int len)
{
  int idx = (iu->iu_tmp_str_ptr++) & (IU_MAX_TMP_STR - 1);
  free(iu->iu_tmp_str[idx]);
  iu->iu_tmp_str[idx] = malloc(len + 1);
  iu->iu_tmp_str[idx][len] = 0;
  return iu->iu_tmp_str[idx];
}


/**
 *
 */
static int __attribute__((warn_unused_result))
addstr(char **dst, const char *str)
{
  int len = strlen(str);
  if(dst != NULL) {
    memcpy(*dst, str, len);
    *dst += len;
  }
  return len;
}

#include "vmir_type.c"
#include "vmir_value.c"
#include "vmir_vm.h"
#include "vmir_instr_parse.c"
#include "vmir_function.c"
#include "vmir_transform.c"
#include "vmir_vm.c"
#include "vmir_libc.c"
#include "vmir_bitcode_parser.c"


/**
 *
 */
static void
iu_cleanup(ir_unit_t *iu)
{
  VECTOR_CLEAR(&iu->iu_branch_fixups);
  VECTOR_CLEAR(&iu->iu_initializers);
  value_resize(iu, 0);

  iu->iu_current_bb = NULL;
  iu->iu_current_function = NULL;

  for(int i = 0; i < IU_MAX_TMP_STR; i++) {
    free(iu->iu_tmp_str[i]);
    iu->iu_tmp_str[i] = NULL;
  }

  ir_blockinfo_t *ib;
  while((ib = LIST_FIRST(&iu->iu_blockinfos)) != NULL)
    blockinfo_destroy(ib);
}


/**
 *
 */
void
vmir_destroy(ir_unit_t *iu)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_functions); i++) {
    function_destroy(VECTOR_ITEM(&iu->iu_functions, i));
  }

  for(int i = 0; i < VECTOR_LEN(&iu->iu_types); i++) {
    ir_type_t *it = &VECTOR_ITEM(&iu->iu_types, i);
    type_clean(it);
  }

  free(iu->iu_vm_funcs);
  free(iu->iu_ext_funcs);

  VECTOR_CLEAR(&iu->iu_types);

  free(iu->iu_triple);
  free(iu->iu_debugged_function);
  free(iu);
}


/**
 *
 */
ir_unit_t *
vmir_create(void *membase, uint32_t memsize,
            uint32_t rsize, uint32_t asize)
{
  ir_unit_t *iu = calloc(1, sizeof(ir_unit_t));

  iu->iu_mem = membase;
  iu->iu_memsize = memsize;
  iu->iu_rsize = rsize;
  iu->iu_alloca_ptr = rsize;
  iu->iu_asize = asize;
  iu->iu_text_alloc_memsize = 1024 * 1024;
  iu->iu_text_alloc = malloc(iu->iu_text_alloc_memsize);
  return iu;
}

/**
 *
 */
int
vmir_load(ir_unit_t *iu, const uint8_t *u8, int len)
{
  bcbitstream_t bs = {0};
  bs.rdata = u8;
  bs.bytes_length = len;

  uint32_t x = read_bits(&bs, 32);

  if(x != 0xdec04342)
    return VMIR_ERR_NOT_BITCODE;

  iu->iu_bs = &bs;

  TAILQ_INIT(&iu->iu_functions_with_bodies);
  iu->iu_data_ptr = iu->iu_rsize + iu->iu_asize;

  if(setjmp(iu->iu_err_jmp)) {
    iu_cleanup(iu);
    return VMIR_ERR_LOAD_ERROR;
  }

  //  int64_t ts = get_ts();
  ir_parse_blocks(iu, 2, len - 4, NULL, NULL);
  //  printf("Parse took %"PRId64"us\n", get_ts() - ts);
  free(iu->iu_text_alloc);

  iu->iu_heap_start = VMIR_ALIGN(iu->iu_data_ptr, 4096);

  vmir_heap_init(iu);

  initialize_globals(iu, iu->iu_mem);

  initialize_libc(iu);

  iu->iu_vm_funcs  = calloc(VECTOR_LEN(&iu->iu_functions), sizeof(void *));
  iu->iu_ext_funcs = calloc(VECTOR_LEN(&iu->iu_functions), sizeof(void *));
  for(int i = 0; i < VECTOR_LEN(&iu->iu_functions); i++) {
    ir_function_t *f = VECTOR_ITEM(&iu->iu_functions, i);

    iu->iu_vm_funcs[i]  = f->if_vm_text;
    iu->iu_ext_funcs[i] = f->if_ext_func;

    if(f->if_used && f->if_vm_text == NULL && f->if_ext_func == NULL)
      parser_error(iu, "Function %s() is not defined", f->if_name);
  }

  iu_cleanup(iu);
  return 0;
}

 
/**
 *
 */
static int
instrumentation_cmp(const ir_instrumentation_t *a,
                    const ir_instrumentation_t *b)
{
  if(a->ii_count * a->ii_instructions < b->ii_count * b->ii_instructions)
    return -1;
  if(a->ii_count * a->ii_instructions > b->ii_count * b->ii_instructions)
    return 1;
  return 0;
}

/**
 *
 */
static void
vmir_dump_instrumentation(ir_unit_t *iu)
{
  VECTOR_SORT(&iu->iu_instrumentation, instrumentation_cmp);
  for(int i = 0; i < VECTOR_LEN(&iu->iu_instrumentation); i++) {
    const ir_instrumentation_t *ii = &VECTOR_ITEM(&iu->iu_instrumentation, i);
    printf("%10"PRId64" %10"PRId64" %s.%d\n",
           ii->ii_count,
           ii->ii_count * ii->ii_instructions,
           ii->ii_func->if_name, ii->ii_bb);
  }
}

static uint32_t
vmir_alloca_str(ir_unit_t *iu, const char *str)
{
  int len = strlen(str) + 1;
  uint32_t r = iu->iu_alloca_ptr;
  memcpy(iu->iu_mem + r, str, len);
  iu->iu_alloca_ptr += len;
  return r;
}


/**
 * Copy argv vector into VM space (at top of alloca stack)
 */
static uint32_t
vmir_copy_argv(ir_unit_t *iu, int argc, char **argv)
{
  uint32_t vm_argv = iu->iu_alloca_ptr;
  uint32_t *vm_argv_host = iu->iu_mem + vm_argv;
  iu->iu_alloca_ptr += (argc + 1) * sizeof(uint32_t);

  for(int i = 0; i < argc; i++) {
    vm_argv_host[i] = vmir_alloca_str(iu, argv[i]);
  }
  iu->iu_alloca_ptr = VMIR_ALIGN(iu->iu_alloca_ptr, 8);
  return vm_argv;
}

/**
 *
 */
void
vmir_run(ir_unit_t *iu, int argc, char **argv)
{
  ir_function_t *f;
  f = function_find(iu, "main");
  if(f == NULL) {
    printf("main() not found\n");
    exit(1);
  }

  int vm_argv = vmir_copy_argv(iu, argc, argv);

  uint64_t ret;
  int64_t ts = get_ts();
  int r = vm_function_call(iu, f, &ret, argc, vm_argv);
  ts = get_ts() - ts;
  printf("stopcode=%d call took %"PRId64"\n", r, ts);

  vmir_dump_instrumentation(iu);

  if(r == VM_STOP_ABORT ||
     r == VM_STOP_BAD_INSTRUCTION ||
     r == VM_STOP_UNREACHABLE)
    exit(r);
}


/**
 *
 */
void
vmir_set_debug_flags(ir_unit_t *iu, int flags)
{
  iu->iu_debug_flags = flags;
}

/**
 *
 */
void
vmir_set_debugged_function(ir_unit_t *iu, const char *function)
{
  free(iu->iu_debugged_function);
  iu->iu_debugged_function = function ? strdup(function) : NULL;
}


void
vmir_print_stats(ir_unit_t *iu)
{
  printf("       Moves killed: %d\n", iu->iu_stats.moves_killed);
  printf("  Lea+Load combined: %d\n", iu->iu_stats.lea_load_combined);
  printf(" Lea+Load comb-fail: %d\n", iu->iu_stats.lea_load_combined_failed);
  printf("Cmp+Branch combined: %d\n", iu->iu_stats.cmp_branch_combine);
  printf("   Mul+Add combined: %d\n", iu->iu_stats.mla_combine);
  printf(" Load+Cast combined: %d\n", iu->iu_stats.load_cast_combine);
  printf("     VM Reg Acc ops: %d+%d+%d+%d = %d\n",
         iu->iu_stats.vm_binop_acc,
         iu->iu_stats.vm_binop_acc_imm,
         iu->iu_stats.vm_binop_acc_acc,
         iu->iu_stats.vm_binop_acc_acc_imm,
         iu->iu_stats.vm_binop_acc +
         iu->iu_stats.vm_binop_acc_imm +
         iu->iu_stats.vm_binop_acc_acc +
         iu->iu_stats.vm_binop_acc_acc_imm);

  vmir_heap_print0(iu->iu_heap);
}
