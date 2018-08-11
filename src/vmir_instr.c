

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
  ir_valuetype_t value;  // Value must be first so we can alias on ir_instr_move
  int op;

} ir_instr_unary_t;


/**
 *
 */
typedef struct ir_instr_store {
  ir_instr_t super;
  ir_valuetype_t ptr;
  ir_valuetype_t value;
  int immediate_offset;
} ir_instr_store_t;


typedef struct ir_instr_insertval {
  ir_instr_t super;
  ir_valuetype_t src;
  ir_valuetype_t replacement;
  int num_indicies;
  int indicies[0];
} ir_instr_insertval_t;


/**
 *
 */
typedef struct ir_instr_load {
  ir_instr_t super;
  ir_valuetype_t ptr;
  int immediate_offset;
  ir_valuetype_t value_offset;
  int value_offset_multiply;

  int load_type; // Only valid when cast != -1
  int8_t cast;
} ir_instr_load_t;


/**
 *
 */
typedef struct ir_instr_binary {
  ir_instr_t super;
  int op;
  ir_valuetype_t lhs_value;
  ir_valuetype_t rhs_value;

} ir_instr_binary_t;


/**
 *
 */
typedef struct ir_instr_ternary {
  ir_instr_t super;
  ir_valuetype_t arg1;
  ir_valuetype_t arg2;
  ir_valuetype_t arg3;
} ir_instr_ternary_t;


/**
 *
 */
typedef struct ir_gep_index {
  ir_valuetype_t value;
  int type;
} ir_gep_index_t;

/**
 *
 */
typedef struct ir_instr_gep {
  ir_instr_t super;
  int num_indicies;
  ir_valuetype_t baseptr;
  ir_gep_index_t indicies[0];
} ir_instr_gep_t;


/**
 *
 */
typedef struct ir_instr_lea {
  ir_instr_t super;
  ir_valuetype_t baseptr;
  int immediate_offset;
  ir_valuetype_t value_offset;
  int value_offset_multiply;
} ir_instr_lea_t;


/**
 *
 */
typedef struct ir_instr_br {
  ir_instr_t super;
  ir_valuetype_t condition;
  int true_branch;
  int false_branch;
} ir_instr_br_t;


typedef struct ir_phi_node {
  int predecessor;
  ir_valuetype_t value;
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
  ir_valuetype_t value;
  int copy_size;
} ir_instr_arg_t;

/**
 * Shared with IR_IC_INTRINSIC
 */
typedef struct ir_instr_call {
  ir_instr_t super;
  ir_valuetype_t callee;
  int vmop;

  // the destination of the call.
  // if the instr_call is an invoke, then there are two possible destinations
  // the normal_dest which is jumped to if there is not exception thrown
  // or the unwind_dest which is jumped to if there was an exception thrown
  // if the instr_call is not an invoke, these member variables are not used.
  unsigned int normal_dest, unwind_dest;

  int argc;
  ir_instr_arg_t argv[0];
} ir_instr_call_t;

typedef ir_instr_call_t ir_instr_invoke_t;

// it is unclear exactly what this does or if it is even necessary
// the actual exception switching code is handled via BR on the type of exception
// not some language intrinsic
typedef struct ir_instr_landingpad_clause {
  unsigned int is_catch;
  unsigned int clause;
} ir_instr_landingpad_clause_t;

typedef struct ir_instr_landingpad {
  ir_instr_t super;
  unsigned int type;

  // unclear what this does
  unsigned int personality;

  // unclear what this does
  unsigned int is_clean_up;
  int num_clauses;
  ir_instr_landingpad_clause_t clauses[0];
} ir_instr_landingpad_t;

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
  uint64_t v64;
  int block;
} ir_instr_path_t;

/**
 *
 */
typedef struct ir_instr_switch {
  ir_instr_t super;
  ir_valuetype_t value;
  int defblock;
  int num_paths;
  ir_instr_path_t paths[0];
} ir_instr_switch_t;


/**
 *
 */
typedef struct ir_instr_alloca {
  ir_instr_t super;
  int size;
  ir_valuetype_t num_items_value;
  int alignment;
} ir_instr_alloca_t;


/**
 *
 */
typedef struct ir_instr_select {
  ir_instr_t super;
  ir_valuetype_t  true_value;
  ir_valuetype_t  false_value;
  ir_valuetype_t  pred;
} ir_instr_select_t;



/**
 *
 */
typedef struct ir_instr_move {
  ir_instr_t super;
  ir_valuetype_t  value;
} ir_instr_move_t;


typedef struct ir_instr_stackcopy {
  ir_instr_t super;
  ir_valuetype_t value;
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
  ir_valuetype_t lhs_value;
  ir_valuetype_t rhs_value;
  int true_branch;
  int false_branch;
} ir_instr_cmp_branch_t;


/**
 *
 */
typedef struct ir_instr_cmp_select {
  ir_instr_t super;
  int op;
  ir_valuetype_t lhs_value;
  ir_valuetype_t rhs_value;
  ir_valuetype_t true_value;
  ir_valuetype_t false_value;
} ir_instr_cmp_select_t;


typedef struct ir_instr_extractval {
  ir_instr_t super;
  ir_valuetype_t  value;
  int num_indicies;
  int indicies[0];
} ir_instr_extractval_t;


#define MAX_RESUME_VALUES 8
typedef struct ir_instr_resume {
  ir_instr_t super;

  int num_values;
  ir_valuetype_t values[0];
} ir_instr_resume_t;



/**
 *
 */
static void *
instr_create(size_t size, instr_class_t ic)
{
  ir_instr_t *ii = calloc(1, size);
  LIST_INIT(&ii->ii_values);
  ii->ii_class = ic;
  ii->ii_ret.value = -1;
  ii->ii_ret.type = -1;
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
  free(ii->ii_rets);
  free(ii->ii_succ);
  free(ii->ii_liveness);

  TAILQ_REMOVE(&ii->ii_bb->ib_instrs, ii, ii_link);
  free(ii);
}




static int
instr_print(char **dstp, ir_unit_t *iu, const ir_instr_t *ii, int flags)
{
  int len = 0;
  len += addstr(dstp, ii->ii_jit ? "J" : " ");
  if(ii->ii_ret.value < -1) {
    int num_values = -ii->ii_ret.value;
    len += addstr(dstp, "{ ");
    for(int i = 0; i < num_values; i++) {
      if(i)
        len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, ii->ii_rets[i]);
    }
    len += addstr(dstp, " } = ");
  } else if(ii->ii_ret.value != -1) {
    len += value_print_vt(dstp, iu, ii->ii_ret);
    len += addstr(dstp, " = ");
  }

  switch(ii->ii_class) {

  case IR_IC_UNREACHABLE:
    len += addstr(dstp, "unreachable");
    break;

  case IR_IC_RET:
    {
      ir_instr_unary_t *u = (ir_instr_unary_t *)ii;
      len += addstr(dstp, "ret ");
      if(u->value.value != -1)
        len += value_print_vt(dstp, iu, u->value);
    }
    break;

  case IR_IC_BINOP:
    {
      ir_instr_binary_t *b = (ir_instr_binary_t *)ii;
      const char *op = "???";
      switch(b->op) {
      case BINOP_ADD:        op = "add"; break;
      case BINOP_SUB:        op = "sub"; break;
      case BINOP_MUL:        op = "mul"; break;
      case BINOP_UDIV:       op = "udiv"; break;
      case BINOP_SDIV:       op = "sdiv"; break;
      case BINOP_UREM:       op = "urem"; break;
      case BINOP_SREM:       op = "srem"; break;
      case BINOP_SHL:        op = "shl"; break;
      case BINOP_LSHR:       op = "lshr"; break;
      case BINOP_ASHR:       op = "ashr"; break;
      case BINOP_AND:        op = "and"; break;
      case BINOP_OR:         op = "or"; break;
      case BINOP_XOR:        op = "xor"; break;
      case BINOP_ROL:        op = "rol"; break;
      case BINOP_ROR:        op = "ror"; break;
      }
      len += addstr(dstp, op);
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, b->lhs_value);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, b->rhs_value);
    }
    break;
  case IR_IC_CAST:
    {
      ir_instr_unary_t *u = (ir_instr_unary_t *)ii;
      const char *op = "???";
      switch(u->op) {
      case CAST_TRUNC:    op = "trunc"; break;
      case CAST_ZEXT:     op = "zext"; break;
      case CAST_SEXT:     op = "sext"; break;
      case CAST_FPTOUI:   op = "fptoui"; break;
      case CAST_FPTOSI:   op = "fptosi"; break;
      case CAST_UITOFP:   op = "uitofp"; break;
      case CAST_SITOFP:   op = "sitofp"; break;
      case CAST_FPTRUNC:  op = "fptrunc"; break;
      case CAST_FPEXT:    op = "fpext"; break;
      case CAST_PTRTOINT: op = "ptrtoint"; break;
      case CAST_INTTOPTR: op = "inttoptr"; break;
      case CAST_BITCAST:  op = "bitcast"; break;
      }
      len += addstr(dstp, op);
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, u->value);
    }
    break;

  case IR_IC_LOAD:
    {
      ir_instr_load_t *u = (ir_instr_load_t *)ii;
      len += addstr(dstp, "load");
      switch(u->cast) {
      case CAST_ZEXT:  len += addstr(dstp, ".zext");  break;
      case CAST_SEXT:  len += addstr(dstp, ".sext");  break;
      }
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, u->ptr);
      if(u->immediate_offset) {
        len += addstrf(dstp, " + #%x", u->immediate_offset);
      }
      if(u->value_offset.value >= 0) {
        len += addstr(dstp, " + ");
        len += value_print_vt(dstp, iu, u->value_offset);
        if(u->value_offset_multiply)
          len += addstrf(dstp, " * #0x%x", u->value_offset_multiply);
      }
    }
    break;

  case IR_IC_STORE:
    {
      ir_instr_store_t *s = (ir_instr_store_t *)ii;
      len += addstr(dstp, "store ");
      len += value_print_vt(dstp, iu, s->ptr);
      if(s->immediate_offset)
        len += addstrf(dstp, " + #%x", s->immediate_offset);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, s->value);
    }
    break;

  case IR_IC_GEP:
    {
      ir_instr_gep_t *g = (ir_instr_gep_t *)ii;
      len += addstr(dstp, "gep ");
      if(g->baseptr.value != -1)
        len += value_print_vt(dstp, iu, g->baseptr);

      for(int i = 0; i < g->num_indicies; i++) {
        len += addstr(dstp, " + ");
        len += type_print_id(dstp, iu, g->indicies[i].type);
        len += addstr(dstp, "[");
        len += value_print_vt(dstp, iu, g->indicies[i].value);
        len += addstr(dstp, "]");
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
      len += addstr(dstp, op);
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, b->lhs_value);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, b->rhs_value);
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

      len += addstr(dstp, "cmpbr.");
      len += addstr(dstp, op);
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, icb->lhs_value);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, icb->rhs_value);

      len += addstrf(dstp, " true:.%d false:.%d",
                     icb->true_branch, icb->false_branch);
    }
    break;

  case IR_IC_CMP_SELECT:
    {
      ir_instr_cmp_select_t *ics = (ir_instr_cmp_select_t *)ii;
      const char *op = "???";
      switch(ics->op) {
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

      len += addstr(dstp, "cmpselect.");
      len += addstr(dstp, op);
      len += addstr(dstp, " ");
      len += value_print_vt(dstp, iu, ics->lhs_value);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, ics->rhs_value);
      len += addstr(dstp, " true:");
      len += value_print_vt(dstp, iu, ics->true_value);
      len += addstr(dstp, " false:");
      len += value_print_vt(dstp, iu, ics->false_value);
    }
    break;

  case IR_IC_BR:
    {
      ir_instr_br_t *br = (ir_instr_br_t *)ii;
      if(br->condition.value == -1) {
        len += addstrf(dstp, "b .%d", br->true_branch);
      } else {
        len += addstr(dstp, "bcond ");
        len += value_print_vt(dstp, iu, br->condition);
        len += addstrf(dstp, ", true:.%d, false:.%d",
                       br->true_branch, br->false_branch);
      }
    }
    break;
  case IR_IC_PHI:
    {
      ir_instr_phi_t *p = (ir_instr_phi_t *)ii;
      len += addstr(dstp, "phi ");
      for(int i = 0; i < p->num_nodes; i++) {
        len += addstrf(dstp, " [.%d ", p->nodes[i].predecessor);
        len += value_print_vt(dstp, iu, p->nodes[i].value);
        len += addstr(dstp, "]");
      }
    }
    break;
  case IR_IC_INVOKE:
  case IR_IC_CALL:
  case IR_IC_VMOP:
    {
      ir_instr_call_t *p = (ir_instr_call_t *)ii;
      ir_function_t *f = value_function(iu, p->callee.value);

      if(ii->ii_class == IR_IC_INVOKE) {
        len += addstrf(dstp, "invoke normal:.%d unwind:.%d ",
                       p->normal_dest, p->unwind_dest);
      } else {

        len += addstr(dstp, ii->ii_class == IR_IC_CALL ? "call" : "vmop");
      }

      if(f != NULL) {
        len += addstr(dstp, " ");
        len += addstr(dstp, f->if_name ?: "<anon>");
      } else {
        len += addstr(dstp, " fptr in ");
        len += value_print_vt(dstp, iu, p->callee);
      }
      len += addstr(dstp, " (");
      len += type_print_id(dstp, iu, p->callee.type);
      len += addstr(dstp, ") (");
      for(int i = 0; i < p->argc; i++) {
        if(i)
          len += addstr(dstp, ", ");
        len += value_print_vt(dstp, iu, p->argv[i].value);
        if(p->argv[i].copy_size)
          len += addstrf(dstp, " (byval %d bytes)", p->argv[i].copy_size);
      }
      len += addstr(dstp, ")");
    }
    break;

  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
      len += addstr(dstp, "switch ");
      len += value_print_vt(dstp, iu, s->value);
      for(int i = 0; i < s->num_paths; i++)
        len += addstrf(dstp, " [#%"PRId64" -> .%d]",
                       s->paths[i].v64, s->paths[i].block);
      len += addstrf(dstp, " default: .%d", s->defblock);
    }
    break;
  case IR_IC_ALLOCA:
    {
      ir_instr_alloca_t *a = (ir_instr_alloca_t *)ii;
      len += addstrf(dstp, "alloca [%d * ", a->size);
      len += value_print_vt(dstp, iu, a->num_items_value);
      len += addstrf(dstp, " align: %d", a->alignment);
    }
    break;
  case IR_IC_SELECT:
    {
      ir_instr_select_t *s = (ir_instr_select_t *)ii;
      len += addstr(dstp, "select ");
      len += value_print_vt(dstp, iu, s->pred);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, s->true_value);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, s->false_value);
    }
    break;
  case IR_IC_VAARG:
    {
      ir_instr_unary_t *m = (ir_instr_unary_t *)ii;
      len += addstr(dstp, "vaarg ");
      len += value_print_vt(dstp, iu, m->value);
    }
    break;
  case IR_IC_EXTRACTVAL:
    {
      ir_instr_extractval_t *jj = (ir_instr_extractval_t *)ii;
      len += addstr(dstp, "extractval ");
      len += value_print_vt(dstp, iu, jj->value);
      for(int i = 0; i < jj->num_indicies; i++)
        len += addstrf(dstp, ":%d", jj->indicies[i]);

      len += addstr(dstp, "]");
    }
    break;
  case IR_IC_INSERTVAL:
    {
      ir_instr_insertval_t *jj = (ir_instr_insertval_t *)ii;
      len += addstr(dstp, "insertval ");
      len += value_print_vt(dstp, iu, jj->src);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, jj->replacement);
      len += addstr(dstp, " [");
      for(int i = 0; i < jj->num_indicies; i++)
        len += addstrf(dstp, ":%d", jj->indicies[i]);
      len += addstr(dstp, "]");
    }
    break;
  case IR_IC_LANDINGPAD:
    {
      len += addstr(dstp, "landingpad");
    }
    break;
  case IR_IC_RESUME:
    {
      ir_instr_resume_t *r = (ir_instr_resume_t *)ii;
      len += addstr(dstp, "resume ");
      for(int i = 0; i < r->num_values; i++) {
        if(i)
          len += addstr(dstp, ", ");
        len += value_print_vt(dstp, iu, r->values[i]);
      }
    }
    break;
  case IR_IC_LEA:
    {
      ir_instr_lea_t *l = (ir_instr_lea_t *)ii;
      len += addstr(dstp, "lea ");
      len += value_print_vt(dstp, iu, l->baseptr);
      if(l->immediate_offset)
        len += addstrf(dstp, " + #0x%x", l->immediate_offset);

      if(l->value_offset.value >= 0) {
        len += addstr(dstp, " + ");
        len += value_print_vt(dstp, iu, l->value_offset);
        if(l->value_offset_multiply)
          len += addstrf(dstp, " * #0x%x", l->value_offset_multiply);
      }
    }
    break;
  case IR_IC_MOVE:
    {
      ir_instr_move_t *m = (ir_instr_move_t *)ii;
      len += addstr(dstp, "move ");
      len += value_print_vt(dstp, iu, m->value);
    }
    break;
  case IR_IC_STACKCOPY:
    {
      ir_instr_stackcopy_t *sc = (ir_instr_stackcopy_t *)ii;
      len += addstr(dstp, "stackcopy ");
      len += value_print_vt(dstp, iu, sc->value);
      len += addstrf(dstp, "size:#0x%x", sc->size);
    }
    break;
  case IR_IC_STACKSHRINK:
    {
      ir_instr_stackshrink_t *ss = (ir_instr_stackshrink_t *)ii;
      len += addstrf(dstp, "stackshrink #0x%x", ss->size);
    }
    break;
  case IR_IC_MLA:
    {
      ir_instr_ternary_t *mla = (ir_instr_ternary_t *)ii;
      len += addstr(dstp, "mla ");
      len += value_print_vt(dstp, iu, mla->arg1);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, mla->arg2);
      len += addstr(dstp, ", ");
      len += value_print_vt(dstp, iu, mla->arg3);
    }
    break;
  }

  if(flags & 1) {
    const ir_value_instr_t *ivi;
    len += addstr(dstp, " <");
    LIST_FOREACH(ivi, &ii->ii_values, ivi_instr_link) {
      len += addstrf(dstp, "%s= ",
                     ivi->ivi_relation == IVI_INPUT ? "input" :
                     ivi->ivi_relation == IVI_OUTPUT ? "output" : "???");
      len += value_print(dstp, iu, ivi->ivi_value, NULL);
      len += addstr(dstp, " ");
    }
    len += addstr(dstp, ">");
  }
  return len;
}


/**
 *
 */
static const char *
instr_str(ir_unit_t *iu, const ir_instr_t *ii, int flags)
{
  int len = instr_print(NULL, iu, ii, flags);
  char *dst = tmpstr(iu, len);
  const char *ret = dst;
  instr_print(&dst, iu, ii, flags);
  return ret;
}


/**
 *
 */
__attribute__((unused)) static char *
instr_stra(ir_unit_t *iu, const ir_instr_t *ii, int flags)
{
  int len = instr_print(NULL, iu, ii, flags);
  char *dst = malloc(len + 1);
  char *ret = dst;
  dst[len] = 0;
  instr_print(&dst, iu, ii, flags);
  return ret;
}


__attribute__((unused)) static int
invert_pred(int pred)
{
  switch(pred) {
  default:
    abort();
  case ICMP_EQ: return ICMP_NE;
  case ICMP_NE: return ICMP_EQ;
  case ICMP_UGT: return ICMP_ULE;
  case ICMP_ULT: return ICMP_UGE;
  case ICMP_UGE: return ICMP_ULT;
  case ICMP_ULE: return ICMP_UGT;
  case ICMP_SGT: return ICMP_SLE;
  case ICMP_SLT: return ICMP_SGE;
  case ICMP_SGE: return ICMP_SLT;
  case ICMP_SLE: return ICMP_SGT;
  case FCMP_OEQ: return FCMP_UNE;
  case FCMP_ONE: return FCMP_UEQ;
  case FCMP_OGT: return FCMP_ULE;
  case FCMP_OLT: return FCMP_UGE;
  case FCMP_OGE: return FCMP_ULT;
  case FCMP_OLE: return FCMP_UGT;
  case FCMP_UEQ: return FCMP_ONE;
  case FCMP_UNE: return FCMP_OEQ;
  case FCMP_UGT: return FCMP_OLE;
  case FCMP_ULT: return FCMP_OGE;
  case FCMP_UGE: return FCMP_OLT;
  case FCMP_ULE: return FCMP_OGT;
  case FCMP_ORD: return FCMP_UNO;
  case FCMP_UNO: return FCMP_ORD;
  case FCMP_TRUE: return FCMP_FALSE;
  case FCMP_FALSE: return FCMP_TRUE;
  }
}

static int
swap_pred(int pred)
{
  switch(pred) {
  default:
    abort();
  case ICMP_EQ: case ICMP_NE:
    return pred;
  case ICMP_SGT: return ICMP_SLT;
    case ICMP_SLT: return ICMP_SGT;
    case ICMP_SGE: return ICMP_SLE;
    case ICMP_SLE: return ICMP_SGE;
    case ICMP_UGT: return ICMP_ULT;
    case ICMP_ULT: return ICMP_UGT;
    case ICMP_UGE: return ICMP_ULE;
    case ICMP_ULE: return ICMP_UGE;
    case FCMP_FALSE: case FCMP_TRUE:
    case FCMP_OEQ: case FCMP_ONE:
    case FCMP_UEQ: case FCMP_UNE:
    case FCMP_ORD: case FCMP_UNO:
      return pred;
    case FCMP_OGT: return FCMP_OLT;
    case FCMP_OLT: return FCMP_OGT;
    case FCMP_OGE: return FCMP_OLE;
    case FCMP_OLE: return FCMP_OGE;
    case FCMP_UGT: return FCMP_ULT;
    case FCMP_ULT: return FCMP_UGT;
    case FCMP_UGE: return FCMP_ULE;
    case FCMP_ULE: return FCMP_UGE;
  }
}


static int
instr_have_side_effects(const ir_instr_t *ii)
{
  switch(ii->ii_class) {
  case IR_IC_UNREACHABLE:
  case IR_IC_RET:
  case IR_IC_VAARG:
  case IR_IC_STORE:
  case IR_IC_BR:
  case IR_IC_ALLOCA:
  case IR_IC_CALL:
  case IR_IC_VMOP:
  case IR_IC_INVOKE:
  case IR_IC_RESUME:
  case IR_IC_INSERTVAL:
  case IR_IC_LANDINGPAD:
  case IR_IC_STACKCOPY:
  case IR_IC_STACKSHRINK:
  case IR_IC_CMP_BRANCH:
    return 1;

  case IR_IC_GEP:
  case IR_IC_CAST:
  case IR_IC_LOAD:
  case IR_IC_BINOP:
  case IR_IC_CMP2:
  case IR_IC_SELECT:
  case IR_IC_LEA:
  case IR_IC_SWITCH:
  case IR_IC_PHI:
  case IR_IC_MOVE:
  case IR_IC_EXTRACTVAL:
  case IR_IC_CMP_SELECT:
  case IR_IC_MLA:
    return 0;
  }
  return 1;
}
