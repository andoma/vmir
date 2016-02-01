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


static void liveness_set_succ(ir_function_t *f, ir_instr_t *ii);

/**
 *
 */
static void
registerify(ir_unit_t *iu, ir_instr_t *ii, int *vp)
{
  ir_value_t *v = value_get(iu, *vp);
  ir_instr_move_t *move;

  switch(v->iv_class) {
  case IR_VC_TEMPORARY:
  case IR_VC_REGFRAME:
    return;

  case IR_VC_GLOBALVAR:
  case IR_VC_CONSTANT:
    move = instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, ii);
    value_alloc_instr_ret(iu, v->iv_type, &move->super);
    move->value = *vp;
    *vp = move->super.ii_ret_value;
    break;

  default:
    parser_error(iu, "Unable convert %s (class %d) into register",
                 type_str_index(iu, v->iv_type),
                 v->iv_class);
  }
}

/**
 *
 */
static int
emit_interim_lea(ir_unit_t *iu, int baseptr,
                 int value_offset, int value_offset_multiply,
                 ir_instr_gep_t *gep, int type)
{
  type = type_make_pointer(iu, type, 1);
  ir_instr_lea_t *lea =
    instr_add_before(sizeof(ir_instr_lea_t), IR_IC_LEA, &gep->super);

  value_alloc_instr_ret(iu, type, &lea->super);

  lea->baseptr = baseptr;

  registerify(iu, &lea->super, &lea->baseptr);

  lea->immediate_offset = 0;
  lea->value_offset = value_offset;
  lea->value_offset_multiply = value_offset_multiply;
  return lea->super.ii_ret_value;
}


/**
 *
 */
static ir_instr_t *
replace_gep_with_lea(ir_unit_t *iu, ir_instr_gep_t *ii)
{
  int immediate_offset = 0;
  int value_offset = -1;
  int value_offset_multiply = 0;

  int baseptr = ii->baseptr;

  for(int j = 0; j < ii->num_indicies; j++) {
    int curtype = ii->indicies[j].type;
    const ir_type_t *cur = type_get(iu, curtype);
    const ir_value_t *op = value_get(iu, ii->indicies[j].value);
    int x;

    switch(cur->it_code) {
    case IR_TYPE_POINTER:

      switch(op->iv_class) {
      case IR_VC_CONSTANT:
        immediate_offset += value_get_const32(iu, op) *
          type_sizeof(iu, cur->it_pointer.pointee);
        break;

      case IR_VC_TEMPORARY:
      case IR_VC_REGFRAME:

        if(value_offset != -1)
          abort();

        value_offset = ii->indicies[j].value;
        value_offset_multiply =
          type_sizeof(iu, cur->it_pointer.pointee);
        break;
      default:
        parser_error(iu, "GEP: Can't handle class %d as pointee",
                     op->iv_class);
      }
      break;

    case IR_TYPE_STRUCT:
      switch(op->iv_class) {
      case IR_VC_CONSTANT:
        x = value_get_const32(iu, op);
        if(x >= cur->it_struct.num_elements)
          parser_error(iu, "Bad index %d info struct", x);

        immediate_offset += cur->it_struct.elements[x].offset;
        break;

      default:
        parser_error(iu, "Bad index class %d for struct",
                     op->iv_class);
      }
      break;

    case IR_TYPE_ARRAY:
      switch(op->iv_class) {
      case IR_VC_CONSTANT:
        immediate_offset += value_get_const32(iu, op) *
          type_sizeof(iu, cur->it_array.element_type);
        break;

      case IR_VC_TEMPORARY:
      case IR_VC_REGFRAME:

        if(value_offset != -1) {
          baseptr = emit_interim_lea(iu, baseptr,
                                     value_offset, value_offset_multiply,
                                     ii, curtype);
        }

        value_offset = ii->indicies[j].value;
        value_offset_multiply =
          type_sizeof(iu, cur->it_array.element_type);
        break;

      default:
        parser_error(iu, "GEP: Can't handle class %d as array index",
                     op->iv_class);
      }
      cur = type_get(iu, cur->it_array.element_type);
      break;
    default:
      parser_error(iu, "Unable to GEP for value type %d",
                   cur->it_code);
    }
  }

  ir_instr_lea_t *lea =
    instr_add_before(sizeof(ir_instr_lea_t), IR_IC_LEA, &ii->super);

  lea->super.ii_ret_value = ii->super.ii_ret_value;
  value_bind_return_value(iu, &lea->super);

  lea->baseptr = baseptr;

  registerify(iu, &lea->super, &lea->baseptr);

  lea->immediate_offset = immediate_offset;
  lea->value_offset = value_offset;
  lea->value_offset_multiply = value_offset_multiply;

  instr_destroy(&ii->super);
  return &lea->super;
}

/**
 *
 */
static void
merge_lea_into_store(ir_unit_t *iu, ir_instr_store_t *ii)
{
  ir_value_t *ptr = value_get(iu, ii->ptr);
  ir_instr_t *a = value_get_assigning_instr(iu, ptr);
  ir_instr_lea_t *lea = instr_isa(a, IR_IC_LEA);
  if(lea == NULL || lea->value_offset != -1)
    return;

  ii->offset += lea->immediate_offset;
  ii->ptr = lea->baseptr;
}


/**
 *
 */
static void
merge_lea_into_load(ir_unit_t *iu, ir_instr_load_t *ii)
{
  ir_value_t *ptr = value_get(iu, ii->ptr);
  ir_instr_t *a = value_get_assigning_instr(iu, ptr);
  ir_instr_lea_t *lea = instr_isa(a, IR_IC_LEA);
  if(lea == NULL)
    return;

  assert(ii->immediate_offset == 0);
  int off = lea->immediate_offset;
  if(off < INT16_MIN || off > INT16_MAX) {
    iu->iu_stats.lea_load_combined_failed++;
    return;
  }

  ii->immediate_offset += lea->immediate_offset;
  assert(ii->value_offset < 0);
  ii->value_offset = lea->value_offset;
  ii->value_offset_multiply = lea->value_offset_multiply;
  ii->ptr = lea->baseptr;

  iu->iu_stats.lea_load_combined++;
}


/**
 *
 */
static ir_instr_t *
replace_single_path_phi(ir_unit_t *iu, ir_instr_phi_t *ii)
{
  if(ii->num_nodes != 1)
    return &ii->super;

  ir_instr_move_t *move =
    instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, &ii->super);

  move->super.ii_ret_value = ii->super.ii_ret_value;
  value_bind_return_value(iu, &move->super);

  move->value = ii->nodes[0].value;

  instr_destroy(&ii->super);
  return &move->super;
}


/**
 *
 */
static ir_instr_t *
replace_call_with_intrinsic(ir_unit_t *iu, ir_instr_call_t *ii,
                            ir_function_t *self)
{
  ir_function_t *f = value_function(iu, ii->callee);
  if(f == NULL)
    return &ii->super;

  int op = f->if_vmop;

  if(op == 0)
    return &ii->super;

  switch(op) {
  case VM_NOP:
    {
      ir_instr_t *next = TAILQ_NEXT(&ii->super, ii_link);
      instr_destroy(&ii->super);
      return next;
    }
  case VM_VASTART:
    {
      ir_instr_call_t *c =
        instr_add_before(sizeof(ir_instr_call_t) +
                         sizeof(ir_instr_arg_t) * 2,
                         IR_IC_CALL, &ii->super);

      c->callee = ii->callee;
      c->argc = 2;
      c->argv[0] = ii->argv[0];
      c->argv[1].value = value_create_const32(iu, self->if_callarg_size);
      c->argv[1].copy_size = 0;

      instr_destroy(&ii->super);
      ii = c;
      break;
    }
  }

  if(ii->argc < f->if_vmop_args)
    parser_error(iu, "Too few arguments for vmop %s", f->if_name);

  ii->argc = f->if_vmop_args;

  // All arguments must be passed as a register
  for(int i = 0; i < ii->argc; i++) {
    if(ii->argv[i].copy_size) {
      parser_error(iu, "help with vmop registerify");
    }
    registerify(iu, &ii->super, &ii->argv[i].value);
  }

  // We just reuse the call struct for this
  ii->super.ii_class = IR_IC_VMOP;
  return &ii->super;
}


/**
 * We only support left-hand side of binary op in register
 * This could be relaxed for commutative binops
 */
static void
binop_prep_args(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  registerify(iu, &ii->super, &ii->lhs_value);
}


/**
 *
 */
static void
binop_transform_cast(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  if(ii->op == CAST_BITCAST) {
    ir_type_t *srcty = type_get(iu, value_get_type(iu, ii->value));
    ir_type_t *dstty = type_get(iu, value_get_type(iu, ii->super.ii_ret_value));

    if(srcty->it_code == IR_TYPE_POINTER && dstty->it_code == IR_TYPE_POINTER)
      ii->super.ii_class = IR_IC_MOVE;
  }
}

/**
 *
 */
static void
replace_instructions(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *bb;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link) {
    ir_instr_t *ii;
    TAILQ_FOREACH(ii, &bb->ib_instrs, ii_link) {
      if(ii->ii_class == IR_IC_GEP)
        ii = replace_gep_with_lea(iu, (ir_instr_gep_t *)ii);
      if(ii->ii_class == IR_IC_STORE)
        merge_lea_into_store(iu, (ir_instr_store_t *)ii);
      if(ii->ii_class == IR_IC_LOAD)
        merge_lea_into_load(iu, (ir_instr_load_t *)ii);
      if(ii->ii_class == IR_IC_PHI)
        ii = replace_single_path_phi(iu, (ir_instr_phi_t *)ii);
      if(ii->ii_class == IR_IC_CALL)
        ii = replace_call_with_intrinsic(iu, (ir_instr_call_t *)ii, f);
      if(ii->ii_class == IR_IC_BINOP)
        binop_prep_args(iu, (ir_instr_binary_t *)ii);
      if(ii->ii_class == IR_IC_CAST)
        binop_transform_cast(iu, (ir_instr_unary_t *)ii);
    }
  }
}


/**
 *
 */
static void
instr_verify_output(ir_unit_t *iu, ir_instr_t *ii)
{
  ir_value_instr_t *ivi = LIST_FIRST(&ii->ii_values);

  if(ii->ii_ret_value != -1) {
    for(; ivi != NULL; ivi = LIST_NEXT(ivi, ivi_instr_link)) {
      if(ivi->ivi_relation == IVI_OUTPUT) {
        break;
      }
    }
    if(ivi == NULL) {
      instr_print(iu, ii, 1);
      printf("\n");
      parser_error(iu, "Instruction output mismatch");
    } else {
      ivi = LIST_NEXT(ivi, ivi_instr_link);
    }
  }
  for(; ivi != NULL; ivi = LIST_NEXT(ivi, ivi_instr_link)) {
    if(ivi->ivi_relation == IVI_OUTPUT) {
      instr_print(iu, ii, 1);
      printf("\n");
      parser_error(iu, "Instruction output mismatch");
    }
  }
}


/**
 *
 */
static void
instr_bind_input(ir_unit_t *iu, int value, ir_instr_t *ii)
{
  if(value == -1)
    return;
  ir_value_t *iv = value_get(iu, value);
  if(iv->iv_class != IR_VC_TEMPORARY)
    return;
  value_bind_instr(iv, ii, IVI_INPUT);
}


/**
 *
 */
static void
function_bind_instr_inputs(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *bb;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link) {
    ir_instr_t *ii;
    TAILQ_FOREACH(ii, &bb->ib_instrs, ii_link) {

      instr_verify_output(iu, ii);

      switch(ii->ii_class) {
      case IR_IC_UNREACHABLE:
        break;
      case IR_IC_RET:
      case IR_IC_CAST:
      case IR_IC_VAARG:
        instr_bind_input(iu, ((ir_instr_unary_t *)ii)->value, ii);
        break;
      case IR_IC_LOAD:
        instr_bind_input(iu, ((ir_instr_load_t *)ii)->ptr, ii);
        if(((ir_instr_load_t *)ii)->value_offset >= 0)
          instr_bind_input(iu, ((ir_instr_load_t *)ii)->value_offset, ii);
        break;

      case IR_IC_BINOP:
      case IR_IC_CMP2:
        instr_bind_input(iu, ((ir_instr_binary_t *)ii)->lhs_value, ii);
        instr_bind_input(iu, ((ir_instr_binary_t *)ii)->rhs_value, ii);
        break;
      case IR_IC_STORE:
        instr_bind_input(iu, ((ir_instr_store_t *)ii)->value, ii);
        instr_bind_input(iu, ((ir_instr_store_t *)ii)->ptr, ii);
        break;
      case IR_IC_BR:
        instr_bind_input(iu, ((ir_instr_br_t *)ii)->condition, ii);
        break;
      case IR_IC_ALLOCA:
        instr_bind_input(iu, ((ir_instr_alloca_t *)ii)->num_items_value, ii);
        break;
      case IR_IC_SELECT:
        instr_bind_input(iu, ((ir_instr_select_t *)ii)->pred, ii);
        instr_bind_input(iu, ((ir_instr_select_t *)ii)->true_value, ii);
        instr_bind_input(iu, ((ir_instr_select_t *)ii)->false_value, ii);
        break;
      case IR_IC_LEA:
        instr_bind_input(iu, ((ir_instr_lea_t *)ii)->baseptr, ii);
        instr_bind_input(iu, ((ir_instr_lea_t *)ii)->value_offset, ii);
        break;
      case IR_IC_CALL:
      case IR_IC_VMOP:
        {
          ir_instr_call_t *p = (ir_instr_call_t *)ii;
          instr_bind_input(iu, p->callee, ii);
          for(int i = 0; i < p->argc; i++)
            instr_bind_input(iu, p->argv[i].value, ii);
        }
        break;
      case IR_IC_SWITCH:
        {
          ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
          instr_bind_input(iu, s->value, ii);
        }
        break;
      case IR_IC_PHI:
        {
          ir_instr_phi_t *p = (ir_instr_phi_t *)ii;
          for(int i = 0; i < p->num_nodes; i++)
            instr_bind_input(iu, p->nodes[i].value, ii);
        }
        break;
      case IR_IC_MOVE:
        {
          ir_instr_move_t *p = (ir_instr_move_t *)ii;
          instr_bind_input(iu, p->value, ii);
        }
        break;
      case IR_IC_EXTRACTVAL:
        {
          ir_instr_extractval_t *e = (ir_instr_extractval_t *)ii;
          instr_bind_input(iu, e->value, ii);
        }
        break;
      default:
        parser_error(iu, "Unable to bind input values on instr-class %d",
                     ii->ii_class);
      }
    }
  }
}


/**
 *
 */
static void
eliminate_dead_code(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *ib;

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    ir_instr_t *ii, *iip;
    ir_value_instr_t *ivi;
    for(ii = TAILQ_LAST(&ib->ib_instrs, ir_instr_queue); ii != NULL; ii = iip) {
      iip = TAILQ_PREV(ii, ir_instr_queue, ii_link);
      if(ii->ii_ret_value == -1 ||
         ii->ii_class == IR_IC_VMOP ||
         ii->ii_class == IR_IC_VAARG ||
         ii->ii_class == IR_IC_CALL)
        continue;

      ir_value_t *output = value_get(iu, ii->ii_ret_value);

      LIST_FOREACH(ivi, &output->iv_instructions, ivi_value_link) {
        if(ivi->ivi_relation == IVI_INPUT)
          break; // Someone is using our output for input ->
      }
      if(ivi != NULL)
        continue; // -> thus continue

      instr_destroy(ii);
      output->iv_class = IR_VC_DEAD;
    }
  }
}


/**
 * Adjust branch instruction at end of 'from' that jumpts to 'bb' to
 * instead jump to 'nb'
 */
static void
bb_change_branch(ir_bb_t *from, ir_bb_t *to, ir_bb_t *nb, ir_function_t *f)
{
  ir_instr_t *ii;

  ii = TAILQ_LAST(&from->ib_instrs, ir_instr_queue);
  switch(ii->ii_class) {
  case IR_IC_BR:
    {
      ir_instr_br_t *b = (ir_instr_br_t *)ii;
      if(b->true_branch == to->ib_id)
        b->true_branch = nb->ib_id;

      if(b->condition != -1) {
        if(b->false_branch == to->ib_id)
          b->false_branch = nb->ib_id;
      }
    }
    break;
  case IR_IC_CMP_BRANCH:
    {
      ir_instr_cmp_branch_t *icb = (ir_instr_cmp_branch_t *)ii;
      if(icb->true_branch == to->ib_id)
        icb->true_branch = nb->ib_id;

      if(icb->false_branch == to->ib_id)
        icb->false_branch = nb->ib_id;
    }
    break;
  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
      if(s->defblock == to->ib_id)
        s->defblock = nb->ib_id;

      for(int i = 0; i < s->num_paths; i++)
        if(s->paths[i].block == to->ib_id)
          s->paths[i].block = nb->ib_id;
    }
    break;
  case IR_IC_RET:
    break;
  default:
    abort();
  }

  if(ii->ii_succ != NULL) {
    free(ii->ii_succ);
    liveness_set_succ(f, ii);
  }
}





LIST_HEAD(phi_lift_edge_list, phi_lift_edge);
LIST_HEAD(phi_lift_node_list, phi_lift_node);

/**
 *
 */
typedef struct phi_lift_node {
  LIST_ENTRY(phi_lift_node) pln_link;
  struct phi_lift_edge_list pln_src;
  struct phi_lift_edge *pln_dst;
  int pln_value;
} phi_lift_node_t;


typedef struct phi_lift_edge {
  LIST_ENTRY(phi_lift_edge) ple_link;
  LIST_ENTRY(phi_lift_edge) ple_src_link;
  phi_lift_node_t *ple_src;
  phi_lift_node_t *ple_dst;
} phi_lift_egde_t;



/**
 *
 */
static phi_lift_node_t *
phi_lift_node_find(struct phi_lift_node_list *nodes, int value)
{
  phi_lift_node_t *pln;
  LIST_FOREACH(pln, nodes, pln_link)
    if(pln->pln_value == value)
      return pln;
  return NULL;
}


/**
 *
 */
static void
phi_lift_node_init(struct phi_lift_node_list *nodes, phi_lift_node_t *pln,
                   int value)
{
  pln->pln_value = value;
  LIST_INSERT_HEAD(nodes, pln, pln_link);
  LIST_INIT(&pln->pln_src);
  pln->pln_dst = NULL;
}


/**
 *
 */
static void
exit_ssa_edge(ir_unit_t *iu, ir_function_t *f, ir_bb_t *bb,
              ir_bb_edge_t *ibe)
{
  phi_lift_node_t *dst, *src;
  phi_lift_egde_t *ple, *ple_next;
  ir_instr_t *ii;
  struct phi_lift_node_list nodes;
  struct phi_lift_edge_list edges;

  LIST_INIT(&nodes);
  LIST_INIT(&edges);
  ir_bb_t *prebb = ibe->ibe_from;
  const int predecessor = prebb->ib_id;

  TAILQ_FOREACH(ii, &bb->ib_instrs, ii_link) {
    if(ii->ii_class != IR_IC_PHI)
      break;

    ir_instr_phi_t *iip = (ir_instr_phi_t *)ii;
    for(int i = 0; i < iip->num_nodes; i++) {
      if(iip->nodes[i].predecessor != predecessor)
        continue;

      if(iip->super.ii_ret_value == iip->nodes[i].value)
        continue;

      dst = phi_lift_node_find(&nodes, iip->super.ii_ret_value);
      if(dst == NULL) {
        dst = alloca(sizeof(phi_lift_node_t));
        phi_lift_node_init(&nodes, dst, iip->super.ii_ret_value);
      }

      src = phi_lift_node_find(&nodes, iip->nodes[i].value);
      if(src == NULL) {
        src = alloca(sizeof(phi_lift_node_t));
        phi_lift_node_init(&nodes, src, iip->nodes[i].value);
      }
      if(dst->pln_dst != NULL)
        parser_error(iu, "Multiple PHI entries point to same register");

      ple = alloca(sizeof(phi_lift_egde_t));
      ple->ple_src = src;
      ple->ple_dst = dst;
      LIST_INSERT_HEAD(&src->pln_src, ple, ple_src_link);
      dst->pln_dst = ple;
      LIST_INSERT_HEAD(&edges,        ple, ple_link);
    }
  }

  if(LIST_FIRST(&edges) == NULL)
    return;

  // First moves where destination is not also a source
  ir_instr_t *last = TAILQ_LAST(&prebb->ib_instrs, ir_instr_queue);


  while(1) {
    int progress = 0;

    for(ple = LIST_FIRST(&edges); ple != NULL; ple = ple_next) {
      ple_next = LIST_NEXT(ple, ple_link);
      if(LIST_FIRST(&ple->ple_dst->pln_src) != NULL)
        continue;

      ir_instr_move_t *m =
        instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, last);
      m->super.ii_ret_value = ple->ple_dst->pln_value;
      m->value = ple->ple_src->pln_value;

      value_bind_return_value(iu, &m->super);
      instr_bind_input(iu, m->value, &m->super);


      progress = 1;
      LIST_REMOVE(ple, ple_link);
      LIST_REMOVE(ple, ple_src_link);
      LIST_REMOVE(ple->ple_dst, pln_link);
      if(LIST_FIRST(&ple->ple_src->pln_src) == NULL)
        LIST_REMOVE(ple->ple_src, pln_link);
    }

    if(LIST_FIRST(&edges) == NULL)
      return;

    if(!progress)
      break;
  }



  while(1) {
    phi_lift_node_t *start = LIST_FIRST(&nodes);
    if(start == NULL)
      break;
    // Add a move to temporary register to resolve cycle

    ir_value_t *b = value_get(iu, start->pln_value);
    ir_instr_move_t *tmp_move =
      instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, last);
    tmp_move->super.ii_ret_value = value_alloc_temporary(iu, b->iv_type);
    tmp_move->value = start->pln_value;
    value_bind_return_value(iu, &tmp_move->super);
    instr_bind_input(iu, tmp_move->value, &tmp_move->super);

    phi_lift_node_t *cur = start;
    while(1) {
      phi_lift_node_t *src = cur->pln_dst->ple_src;
      if(src == start)
        break;

      ir_instr_move_t *m =
        instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, last);
      m->super.ii_ret_value = cur->pln_value;
      m->value = src->pln_value;
      value_bind_return_value(iu, &m->super);
      instr_bind_input(iu, m->value, &m->super);

      LIST_REMOVE(cur, pln_link);
      cur = src;
    }

    ir_instr_move_t *m =
      instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, last);
    m->super.ii_ret_value = cur->pln_value;
    m->value = tmp_move->super.ii_ret_value;
    value_bind_return_value(iu, &m->super);
    instr_bind_input(iu, m->value, &m->super);
    LIST_REMOVE(cur, pln_link);
  }
}

/**
 *
 */
static void
exit_ssa_bb(ir_unit_t *iu, ir_function_t *f, ir_bb_t *bb)
{
  ir_bb_edge_t *ibe;
  ir_instr_t *ii;

  LIST_FOREACH(ibe, &bb->ib_incoming_edges, ibe_to_link)
    exit_ssa_edge(iu, f, bb, ibe);

  // Delete PHI instructions
  while((ii = TAILQ_FIRST(&bb->ib_instrs)) != NULL &&
        ii->ii_class == IR_IC_PHI)
    instr_destroy(ii);
}


/**
 *
 */
static void
exit_ssa(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *bb;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link)
    exit_ssa_bb(iu, f, bb);
}


/**
 *
 */
static void
remove_empty_bb(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *ib, *nb, *next;

  for(ib = TAILQ_FIRST(&f->if_bbs); ib != NULL; ib = next) {
    next = TAILQ_NEXT(ib, ib_link);

    ir_instr_t *ii = TAILQ_FIRST(&ib->ib_instrs);
    if(ii->ii_class != IR_IC_BR)
      continue;

    ir_instr_br_t *b = (ir_instr_br_t *)ii;
    ir_bb_edge_t *ibe, *n;
    if(b->condition != -1)
      continue;

    nb = bb_find(f, b->true_branch);
    assert(nb != NULL);

    if(nb == ib)
      continue; /* Unconditional branch to itself
                 * ie, an infinite loop, still legal though
                 */

    for(ibe = LIST_FIRST(&ib->ib_incoming_edges); ibe != NULL; ibe = n) {
      n = LIST_NEXT(ibe, ibe_to_link);
      bb_change_branch(ibe->ibe_from, ib, nb, f);

      ibe->ibe_to = nb;
      LIST_REMOVE(ibe, ibe_to_link);
      LIST_INSERT_HEAD(&nb->ib_incoming_edges, ibe, ibe_to_link);
    }
    TAILQ_REMOVE(&f->if_bbs, ib, ib_link);
    bb_destroy(ib);
  }
}


/**
 *
 */
static void
cfg_add_edge(ir_function_t *f, ir_bb_t *from, int bb, int mark)
{
  ir_bb_t *to = bb_find(f, bb);
  if(mark) {
    if(to->ib_mark)
      return;
    to->ib_mark = 1;
  }
  ir_bb_edge_t *ibe = malloc(sizeof(ir_bb_edge_t));
  LIST_INSERT_HEAD(&f->if_edges,             ibe, ibe_function_link);

  ibe->ibe_from = from;
  LIST_INSERT_HEAD(&from->ib_outgoing_edges, ibe, ibe_from_link);

  ibe->ibe_to   = to;
  LIST_INSERT_HEAD(&to->ib_incoming_edges,   ibe, ibe_to_link);
}


/**
 *
 */
static void
unmark_outgoing_blocks(ir_bb_t *bb)
{
  ir_bb_edge_t *c;
  LIST_FOREACH(c, &bb->ib_outgoing_edges, ibe_from_link) {
    assert(c->ibe_to->ib_mark == 1);
    c->ibe_to->ib_mark = 0;
  }
}


/**
 *
 */
static void
construct_cfg(ir_function_t *f)
{
  ir_bb_t *bb;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link) {
    ir_instr_t *ii = TAILQ_LAST(&bb->ib_instrs, ir_instr_queue);
    switch(ii->ii_class) {
    case IR_IC_BR:
      {
        ir_instr_br_t *b = (ir_instr_br_t *)ii;
        cfg_add_edge(f, bb, b->true_branch, 1);
        if(b->condition != -1)
          cfg_add_edge(f, bb, b->false_branch, 1);
      }
      break;
    case IR_IC_SWITCH:
      {
        ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
        cfg_add_edge(f, bb, s->defblock, 1);
        for(int i = 0; i < s->num_paths; i++)
          cfg_add_edge(f, bb, s->paths[i].block, 1);
      }
      break;
    case IR_IC_RET:
    case IR_IC_UNREACHABLE:
      break;
    default:
      abort();
    }

    unmark_outgoing_blocks(bb);
  }
}


/**
 *
 */
static void
break_critical_edge(ir_function_t *f, ir_bb_edge_t *ibe)
{
  ir_bb_t *from = ibe->ibe_from;
  ir_bb_t *to   = ibe->ibe_to;
  ir_bb_t *nb   = bb_add(f, from);

  // Add a single branch instruction to new basic block
  ir_instr_br_t *br = instr_add(nb, sizeof(ir_instr_br_t), IR_IC_BR);
  br->condition = -1;
  br->true_branch = to->ib_id;

  // Hook up existing edge to new bb
  LIST_REMOVE(ibe, ibe_to_link);
  ibe->ibe_to   = nb;
  LIST_INSERT_HEAD(&nb->ib_incoming_edges,   ibe, ibe_to_link);

  // Create new edge from new bb to target bb
  cfg_add_edge(f, nb, to->ib_id, 0);

  // Adjust final instrction of previous bb to point to new bb
  bb_change_branch(from, to, nb, f);

  ir_instr_t *ii;
  // Adjust phi of target bb to point to new bb
  TAILQ_FOREACH(ii, &to->ib_instrs, ii_link) {
    if(ii->ii_class != IR_IC_PHI)
      break;
    ir_instr_phi_t *p = (ir_instr_phi_t *)ii;

    for(int i = 0; i < p->num_nodes; i++) {
      if(p->nodes[i].predecessor == from->ib_id)
        p->nodes[i].predecessor = nb->ib_id;
    }
  }
}


/**
 *
 */
static void
break_crtitical_edges(ir_function_t *f)
{
  ir_bb_edge_t *ibe;
  LIST_FOREACH(ibe, &f->if_edges, ibe_function_link) {
    // If first instruction in destination block is not a phi
    if(TAILQ_FIRST(&ibe->ibe_to->ib_instrs)->ii_class != IR_IC_PHI)
      continue;

    ir_bb_t *from = ibe->ibe_from;
    int count = 0;
    ir_bb_edge_t *c;
    LIST_FOREACH(c, &from->ib_outgoing_edges, ibe_from_link) {
      count++;
      if(count >= 2)
        break;
    }
    if(count < 2)
      continue;

    break_critical_edge(f, ibe);
  }
}



/**
 *
 */
static void
liveness_set_succ(ir_function_t *f, ir_instr_t *ii)
{
  switch(ii->ii_class) {
  case IR_IC_RET:
  case IR_IC_UNREACHABLE:
    ii->ii_num_succ = 0;
    break;

  case IR_IC_CAST:
  case IR_IC_VAARG:
  case IR_IC_LOAD:
  case IR_IC_BINOP:
  case IR_IC_CMP2:
  case IR_IC_STORE:
  case IR_IC_ALLOCA:
  case IR_IC_SELECT:
  case IR_IC_LEA:
  case IR_IC_MOVE:
  case IR_IC_VMOP:
  case IR_IC_CALL:
  case IR_IC_STACKCOPY:
  case IR_IC_STACKSHRINK:
  case IR_IC_MLA:
    /* -1 just means that we have one successor and it's the next instruction
     * Note that this is different from ii_num_suc == 1 where we have one
     * successor and it's NOT the next instruction (unconditional branch)
     */
    ii->ii_num_succ = -1;
    break;

  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;

      ii->ii_num_succ = 1 + s->num_paths;
      ii->ii_succ = malloc(sizeof(ir_bb_t *) * ii->ii_num_succ);
      ii->ii_succ[0] = bb_find(f, s->defblock);

      for(int i = 0; i < s->num_paths; i++)
        ii->ii_succ[i + 1] = bb_find(f, s->paths[i].block);
    }
    break;

  case IR_IC_BR:
    {
      ir_instr_br_t *b = (ir_instr_br_t *)ii;

      ii->ii_num_succ = 1;
      if(b->condition != -1)
        ii->ii_num_succ = 2;

      ii->ii_succ = malloc(sizeof(ir_bb_t *) * ii->ii_num_succ);
      ii->ii_succ[0] = bb_find(f, b->true_branch);
      if(b->condition != -1)
        ii->ii_succ[1] = bb_find(f, b->false_branch);
    }
    break;

  case IR_IC_CMP_BRANCH:
    {
      ir_instr_cmp_branch_t *icb = (ir_instr_cmp_branch_t *)ii;

      ii->ii_num_succ = 2;
      ii->ii_succ = malloc(sizeof(ir_bb_t *) * ii->ii_num_succ);
      ii->ii_succ[0] = bb_find(f, icb->true_branch);
      ii->ii_succ[1] = bb_find(f, icb->false_branch);
    }
    break;

  default:
    printf("Cant set successor for op %d\n", ii->ii_class);
    abort();
  }
}

static void
liveness_set_value(uint32_t *bs, ir_unit_t *iu, int value)
{
  ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, value);
  if(iv->iv_class != IR_VC_TEMPORARY)
    return;

  value -= iu->iu_first_func_value;
  assert(value >= 0);

  bitset(bs, value);
}

static void
liveness_set_gen(ir_instr_t *ii, ir_unit_t *iu, uint32_t *bs)
{
  switch(ii->ii_class) {
  case IR_IC_UNREACHABLE:
  case IR_IC_STACKSHRINK:
    break;

  case IR_IC_RET:
    if(((ir_instr_unary_t *)ii)->value != -1)
      liveness_set_value(bs, iu, ((ir_instr_unary_t *)ii)->value);
    break;

  case IR_IC_CAST:
  case IR_IC_VAARG:
    liveness_set_value(bs, iu, ((ir_instr_unary_t *)ii)->value);
    break;
  case IR_IC_LOAD:
    liveness_set_value(bs, iu, ((ir_instr_load_t *)ii)->ptr);
    if(((ir_instr_load_t *)ii)->value_offset >= 0)
      liveness_set_value(bs, iu, ((ir_instr_load_t *)ii)->value_offset);
    break;

  case IR_IC_BINOP:
  case IR_IC_CMP2:
    liveness_set_value(bs, iu, ((ir_instr_binary_t *)ii)->lhs_value);
    liveness_set_value(bs, iu, ((ir_instr_binary_t *)ii)->rhs_value);
    break;
  case IR_IC_CMP_BRANCH:
    liveness_set_value(bs, iu, ((ir_instr_cmp_branch_t *)ii)->lhs_value);
    liveness_set_value(bs, iu, ((ir_instr_cmp_branch_t *)ii)->rhs_value);
    break;
  case IR_IC_STORE:
    liveness_set_value(bs, iu, ((ir_instr_store_t *)ii)->value);
    liveness_set_value(bs, iu, ((ir_instr_store_t *)ii)->ptr);
    break;
  case IR_IC_BR:
    if(((ir_instr_br_t *)ii)->condition != -1)
      liveness_set_value(bs, iu, ((ir_instr_br_t *)ii)->condition);
    break;
  case IR_IC_ALLOCA:
    liveness_set_value(bs, iu, ((ir_instr_alloca_t *)ii)->num_items_value);
    break;
  case IR_IC_SELECT:
    liveness_set_value(bs, iu, ((ir_instr_select_t *)ii)->pred);
    liveness_set_value(bs, iu, ((ir_instr_select_t *)ii)->true_value);
    liveness_set_value(bs, iu, ((ir_instr_select_t *)ii)->false_value);
    break;
  case IR_IC_LEA:
    {
      ir_instr_lea_t *lea = (ir_instr_lea_t *)ii;
      liveness_set_value(bs, iu, lea->baseptr);
      if(lea->value_offset != -1)
        liveness_set_value(bs, iu, lea->value_offset);
    }
    break;
  case IR_IC_CALL:
  case IR_IC_VMOP:
    {
      ir_instr_call_t *p = (ir_instr_call_t *)ii;
      liveness_set_value(bs, iu, p->callee);
      for(int i = 0; i < p->argc; i++)
        liveness_set_value(bs, iu, p->argv[i].value);
    }
    break;
  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
      liveness_set_value(bs, iu, s->value);
    }
    break;
  case IR_IC_MOVE:
    {
      ir_instr_move_t *p = (ir_instr_move_t *)ii;
      liveness_set_value(bs, iu, p->value);
    }
    break;
  case IR_IC_STACKCOPY:
    {
      ir_instr_stackcopy_t *sc = (ir_instr_stackcopy_t *)ii;
      liveness_set_value(bs, iu, sc->value);
    }
    break;
  case IR_IC_MLA:
    {
      liveness_set_value(bs, iu, ((ir_instr_ternary_t *)ii)->arg1);
      liveness_set_value(bs, iu, ((ir_instr_ternary_t *)ii)->arg2);
      liveness_set_value(bs, iu, ((ir_instr_ternary_t *)ii)->arg3);
    }
    break;
  default:
    printf("liveness_set_gen: can't handle instruction class %d\n",
           ii->ii_class);
    abort();
  }
}


/**
 *
 */
static void
instr_replace_value(ir_unit_t *iu, int *p, int from, int to)
{
  if(*p == from)
    *p = to;
}


/**
 *
 */
static void
instr_replace_values(ir_instr_t *ii, ir_unit_t *iu, int from, int to)
{
  if(ii->ii_ret_value < -1) {
    for(int i = 0; i < -ii->ii_ret_value; i++) {
      instr_replace_value(iu, &ii->ii_ret_values[i], from, to);
    }
  } else {
    instr_replace_value(iu, &ii->ii_ret_value, from, to);
  }

  switch(ii->ii_class) {
  case IR_IC_UNREACHABLE:
  case IR_IC_STACKSHRINK:
    break;

  case IR_IC_RET:
  case IR_IC_CAST:
  case IR_IC_VAARG:
    instr_replace_value(iu, &((ir_instr_unary_t *)ii)->value, from, to);
    break;
  case IR_IC_LOAD:
    instr_replace_value(iu, &((ir_instr_load_t *)ii)->ptr, from, to);
    instr_replace_value(iu, &((ir_instr_load_t *)ii)->value_offset, from, to);
    break;

  case IR_IC_BINOP:
  case IR_IC_CMP2:
    instr_replace_value(iu, &((ir_instr_binary_t *)ii)->lhs_value, from, to);
    instr_replace_value(iu, &((ir_instr_binary_t *)ii)->rhs_value, from, to);
    break;
  case IR_IC_CMP_BRANCH:
    instr_replace_value(iu, &((ir_instr_cmp_branch_t *)ii)->lhs_value, from, to);
    instr_replace_value(iu, &((ir_instr_cmp_branch_t *)ii)->rhs_value, from, to);
    break;
  case IR_IC_STORE:
    instr_replace_value(iu, &((ir_instr_store_t *)ii)->value, from, to);
    instr_replace_value(iu, &((ir_instr_store_t *)ii)->ptr, from, to);
    break;
  case IR_IC_BR:
    instr_replace_value(iu, &((ir_instr_br_t *)ii)->condition, from, to);
    break;
  case IR_IC_ALLOCA:
    instr_replace_value(iu, &((ir_instr_alloca_t *)ii)->num_items_value, from, to);
    break;
  case IR_IC_SELECT:
    instr_replace_value(iu, &((ir_instr_select_t *)ii)->pred, from, to);
    instr_replace_value(iu, &((ir_instr_select_t *)ii)->true_value, from, to);
    instr_replace_value(iu, &((ir_instr_select_t *)ii)->false_value, from, to);
    break;
  case IR_IC_LEA:
    instr_replace_value(iu, &((ir_instr_lea_t *)ii)->baseptr, from, to);
    instr_replace_value(iu, &((ir_instr_lea_t *)ii)->value_offset, from, to);
    break;
  case IR_IC_CALL:
  case IR_IC_VMOP:
    {
      ir_instr_call_t *p = (ir_instr_call_t *)ii;
      instr_replace_value(iu, &p->callee, from, to);
      for(int i = 0; i < p->argc; i++)
        instr_replace_value(iu, &p->argv[i].value, from, to);
    }
    break;
  case IR_IC_SWITCH:
    {
      ir_instr_switch_t *s = (ir_instr_switch_t *)ii;
      instr_replace_value(iu, &s->value, from, to);
    }
    break;
  case IR_IC_MOVE:
    {
      ir_instr_move_t *p = (ir_instr_move_t *)ii;
      instr_replace_value(iu, &p->value, from, to);
    }
    break;
  case IR_IC_STACKCOPY:
    {
      ir_instr_stackcopy_t *sc = (ir_instr_stackcopy_t *)ii;
      instr_replace_value(iu, &sc->value, from, to);
    }
    break;
  case IR_IC_MLA:
    instr_replace_value(iu, &((ir_instr_ternary_t *)ii)->arg1, from, to);
    instr_replace_value(iu, &((ir_instr_ternary_t *)ii)->arg2, from, to);
    instr_replace_value(iu, &((ir_instr_ternary_t *)ii)->arg3, from, to);
    break;
  default:
    abort();
  }
}



/**
 *
 */
static uint32_t *
tribitmtx_alloc(int size)
{
  if(size == 0)
    return NULL;
  size--;
  int bits = (size * size + size) / 2 + size + 1;
  int words = (bits + 31) / 32;
  return calloc(words, sizeof(int));
}

/**
 *
 */
static int __inline
tribitmtx_pos(const uint32_t *mtx, int x, int y)
{
  if(x > y) {
    int tmp = x;
    x = y;
    y = tmp;
  }
  return (y * y + y) / 2 + x;
}


/**
 *
 */
static int __inline
tribitmtx_get(const uint32_t *mtx, int x, int y)
{
  return bitchk(mtx, tribitmtx_pos(mtx, x, y));
}

/**
 *
 */
static void __inline
tribitmtx_set(uint32_t *mtx, int x, int y)
{
  bitset(mtx, tribitmtx_pos(mtx, x, y));
}


/**
 *
 */
static void __inline
tribitmtx_clr(uint32_t *mtx, int x, int y)
{
  bitclr(mtx, tribitmtx_pos(mtx, x, y));
}

typedef struct value_info {
  unsigned int value;
  unsigned int score;
  int class;
} value_info_t;

static int
value_info_cmp(const void *A, const void *B)
{
  const value_info_t *a = (const value_info_t *)A;
  const value_info_t *b = (const value_info_t *)B;
  return a->score - b->score;
}


#define RA_CLASSES 3
#define RA_CLASS_MACHINEREG_32  0
#define RA_CLASS_REGFRAME_32    1
#define RA_CLASS_REGFRAME_64    2



/**
 *
 */
static void
reg_alloc(ir_unit_t *iu, const uint32_t *mtx, int temp_values, int ffv,
          ir_function_t *f)
{
  int num_vertices = 0;
  int graph_degree = 0;

  value_info_t *vi = malloc(temp_values * sizeof(value_info_t));

  for(int i = 0; i < temp_values; i++) {
    const ir_value_t *iv = value_get(iu, i + ffv);
    if(iv->iv_class != IR_VC_TEMPORARY)
      continue;

    int s = value_regframe_size(iu, iv->iv_type);
    if(s == 8) {
      vi[num_vertices].class = RA_CLASS_REGFRAME_64;
    } else {
      if(iv->iv_jit)
        vi[num_vertices].class = RA_CLASS_MACHINEREG_32;
      else
        vi[num_vertices].class = RA_CLASS_REGFRAME_32;
    }
    int score = iv->iv_edges;

    ir_value_instr_t *ivi;
    LIST_FOREACH(ivi, &iv->iv_instructions, ivi_value_link) {
      if(ivi->ivi_instr->ii_class == IR_IC_BINOP)
        score--;
    }

    vi[num_vertices].value = i;
    vi[num_vertices].score = score;
    graph_degree = MAX(graph_degree, iv->iv_edges);
    num_vertices++;
  }

  qsort(vi, num_vertices, sizeof(value_info_t), value_info_cmp);

  // Color graph and use color to allocate register

  uint32_t *colortab[RA_CLASSES];
  int class_reg_size[RA_CLASSES];
  const int degree_words = (graph_degree + 32) / 32;
  for(int i = 0; i < RA_CLASSES; i++) {
    colortab[i] = malloc(degree_words * sizeof(uint32_t));
  }

  class_reg_size[RA_CLASS_MACHINEREG_32] = 0;
  class_reg_size[RA_CLASS_REGFRAME_32] = 4;
  class_reg_size[RA_CLASS_REGFRAME_64] = 8;

  int *colors = malloc(sizeof(int) * temp_values);
  memset(colors, 0xff, sizeof(int) * temp_values);
  for(int i = 0; i < num_vertices; i++) {
    const int val_index = vi[i].value;
    const int class = vi[i].class;

    memset(colortab[class], 0xff, degree_words * sizeof(uint32_t));

    int x = 0;
    const int vivi = (val_index * val_index + val_index) / 2;

    for(; x < val_index; x++) {
      if(bitchk(mtx, vivi + x)) {
        int c = colors[x];
        if(c >= 0)
          bitclr(colortab[class], c);
      }
    }

    for(; x < temp_values; x++) {
      int xx = (x * x + x) / 2;
      if(bitchk(mtx, val_index + xx)) {
        int c = colors[x];
        if(c >= 0)
          bitclr(colortab[class], c);
      }
    }


    for(int j = 0 ; j < degree_words; j++) {
      int c = __builtin_ffs(colortab[class][j]);
      if(c == 0)
        continue;
      c = c - 1 + j * 32;
      colors[val_index] = c;
      break;
    }
  }

  if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC)
    printf("%s: Reg allocation, %d temporaries",
           f->if_name, temp_values);


#ifdef JIT_MACHINE_REGS
  for(int c = 0; c < RA_CLASS_REGFRAME_32; c++) {

    int regframe_slots = 0;
    int machine_regs_used = 0;
    const int rsize = 4;

    for(int i = 0; i < num_vertices; i++) {
      const int val_index = vi[i].value;
      if(vi[i].class != c)
        continue;
      const int color = colors[val_index];
      ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val_index + ffv);

      if(color < JIT_MACHINE_REGS) {
        iv->iv_class = IR_VC_MACHINEREG;
        iv->iv_reg = color;
        machine_regs_used = MAX(color + 1, machine_regs_used);
      } else {
        // Not enough machine regs, put value in regframe instead
        iv->iv_class = IR_VC_REGFRAME;
        const int rfcol = color - JIT_MACHINE_REGS;
        regframe_slots = MAX(regframe_slots, rfcol + 1);
        iv->iv_reg = f->if_regframe_size + rfcol * rsize;
      }
    }
    f->if_regframe_size += regframe_slots * rsize;

    if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC)
      printf(", %d machine regs (%d spilled)",
             machine_regs_used, regframe_slots);
  }
#endif

  for(int c = RA_CLASS_REGFRAME_32; c < RA_CLASSES; c++) {
    const int rsize = class_reg_size[c];
    int regframe_slots = 0;

    f->if_regframe_size = VMIR_ALIGN(f->if_regframe_size, rsize);

    for(int i = 0; i < num_vertices; i++) {
      const int val_index = vi[i].value;
      if(vi[i].class != c)
        continue;
      const int color = colors[val_index];
      ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, val_index + ffv);
      iv->iv_class = IR_VC_REGFRAME;
      iv->iv_reg = f->if_regframe_size + color * rsize;
      regframe_slots = MAX(regframe_slots, color + 1);
    }
    f->if_regframe_size += regframe_slots * rsize;

    if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC)
      printf(", %d rf%d", regframe_slots, rsize);
  }

  if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC)
    printf("\n");

  for(int i = 0; i < RA_CLASSES; i++) {
    free(colortab[i]);
  }
  free(vi);
}

/**
 *
 */
static void
liveness_update(ir_function_t *f, int setwords, int ffv)
{
  uint32_t *new_in  = alloca(setwords * sizeof(uint32_t));
  uint32_t *new_out = alloca(setwords * sizeof(uint32_t));
  ir_bb_t *ib;
  ir_instr_t *ii;
  int rounds = 0;
  while(1) {

    int stable = 1;

    // Liveness analysis reach stable state a lot faster if iterating
    // backwards

    for(ib = TAILQ_LAST(&f->if_bbs, ir_bb_queue); ib != NULL;
        ib = TAILQ_PREV(ib, ir_bb_queue, ib_link)) {

      for(ii = TAILQ_LAST(&ib->ib_instrs, ir_instr_queue); ii != NULL;
          ii = TAILQ_PREV(ii, ir_instr_queue, ii_link)) {

        const uint32_t *o;

        if(ii->ii_num_succ == -1) {
          ir_instr_t *succ = TAILQ_NEXT(ii, ii_link);
          o = succ->ii_liveness + setwords * 2;
        } else {
          memset(new_out, 0, setwords * sizeof(uint32_t));

          for(int j = 0; j < ii->ii_num_succ; j++) {
            ir_bb_t *ib = ii->ii_succ[j];
            ir_instr_t *succ = TAILQ_FIRST(&ib->ib_instrs);
            assert(succ != NULL);
            const uint32_t *in = succ->ii_liveness + setwords * 2;
            bitset_or(new_out, in, setwords);
          }
          o = new_out;
        }

        memcpy(new_in, o, setwords * sizeof(uint32_t));
        if(ii->ii_ret_value < -1) {
          // Multiple return values
          for(int j = 0; j < -ii->ii_ret_value; j++) {
            bitclr(new_in, ii->ii_ret_values[j] - ffv);
          }
        } else if(ii->ii_ret_value >= 0) {
          bitclr(new_in, ii->ii_ret_value - ffv);
        }

        uint32_t       *out = ii->ii_liveness;
        const uint32_t *gen = ii->ii_liveness + setwords;
        uint32_t       *in  = ii->ii_liveness + setwords * 2;

        bitset_or(new_in, gen, setwords);

        if(!memcmp(out, o,       setwords * sizeof(uint32_t)) &&
           !memcmp(in,  new_in,  setwords * sizeof(uint32_t)))
          continue;

        stable = 0;
        memcpy(out, o,       setwords * sizeof(uint32_t));
        memcpy(in,  new_in,  setwords * sizeof(uint32_t));
      }
    }
    rounds++;
    if(stable)
      break;
  }
}



/**
 *
 */
static void __attribute__((unused))
print_liveout(ir_unit_t *iu, ir_function_t *f, int temp_values, int ffv)
{
  ir_bb_t *ib;
  ir_instr_t *ii;

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
      instr_print(iu, ii, 0);
      printf("\n");
      for(int j = 0; j < temp_values; j++)
        if(bitchk(ii->ii_liveness, j))
          printf("\tLiveout: %s\n", value_str_id(iu, j + ffv));
    }
  }
}


/**
 *
 */
static void
coalesce(ir_unit_t *iu,
         int setwords, int temp_values,
         int ffv, ir_function_t *f)
{
  // Interference Matrix
  uint32_t *mtx = tribitmtx_alloc(temp_values);
  ir_bb_t *ib;
  ir_instr_t *ii, *iin;

  /*
   * Any non-move instruction that defines variable 'a' add
   * interference edges for (a,{liveout})
   *
   * Any move instruction a <- b add interference for (a, {liveout} - b)
   *
   */
  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
      if(ii->ii_ret_value == -1)
        continue;

      int num_ret_values;
      const int *ret_values;
      if(ii->ii_ret_value < -1) {
        ret_values = ii->ii_ret_values;
        num_ret_values = -ii->ii_ret_value;
      } else {
        ret_values = &ii->ii_ret_value;
        num_ret_values = 1;
      }
      int v = -1;

      if(ii->ii_class == IR_IC_MOVE)
        v = ((ir_instr_move_t *)ii)->value - ffv;

      const uint32_t *out = ii->ii_liveness;

      for(int a = 0; a < num_ret_values; a++) {
        int x = ret_values[a];
        ir_value_t *xval = value_get(iu, x);
        x-= ffv;
        int edges = 0;
        for(int j = 0; j < setwords; j++) {
          uint32_t w = out[j];
          while(w) {
            int b = ffs(w) - 1;
            int y = (j << 5) + b;
            w &= ~(1 << b);
            if(y != x && y != v) {
              if(!tribitmtx_get(mtx, x, y)) {
                tribitmtx_set(mtx, x, y);
                edges++;
                iu->iu_values.vh_p[y + ffv]->iv_edges++;
              }
            }
          }
        }
        xval->iv_edges += edges;
      }
    }
  }

  /*
   * Find values that can be coalesced.
   * Search for moves between two registers that do not interfere with
   * each other. For such cases we can say the registers are basically
   * the same, so we merge then. This process is called coalescing
   */

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    for(ii = TAILQ_FIRST(&ib->ib_instrs); ii != NULL; ii = iin) {
      iin = TAILQ_NEXT(ii, ii_link);

      if(ii->ii_class == IR_IC_MOVE) {
        unsigned int v = ((ir_instr_move_t *)ii)->value;
        if(v < ffv)
          continue;
        ir_value_t *src = VECTOR_ITEM(&iu->iu_values, v);
        if(src->iv_class != IR_VC_TEMPORARY)
          continue;
        assert(ii->ii_ret_value >= 0);
        ir_value_t *dst = VECTOR_ITEM(&iu->iu_values, ii->ii_ret_value);

        if(dst == src) {
          /*
           * Move from -> to same register
           * This happens when we coalesce two registers that are used
           * by a move different than the one that initiated the merge.
           * We could detect that when this happens but destroying
           * any instruction other than the current one will break
           * the TAILQ traversal
           */
          instr_destroy(ii);
          iu->iu_stats.moves_killed++;
          continue;
        }

        assert(dst->iv_class == IR_VC_TEMPORARY);

        if(!tribitmtx_get(mtx, ii->ii_ret_value - ffv, v - ffv)) {
          ir_value_t *killed = src;
          ir_value_t *saved = dst;

          if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC) {
            printf("Merging value %s -> %s based on instr: ",
                   value_str(iu, killed),  value_str(iu, saved));
            instr_print(iu, ii, 1);
            printf("\n");
          }

          ir_value_instr_t *ivi, *ivin;
          for(ivi = LIST_FIRST(&killed->iv_instructions); ivi != NULL;
              ivi = ivin) {
            ivin = LIST_NEXT(ivi, ivi_value_link);

            if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC) {
              printf("\t Pre altering instruction ");
              instr_print(iu, ivi->ivi_instr, 1);
              printf("\n");
            }

            instr_replace_values(ivi->ivi_instr, iu, killed->iv_id,
                                 saved->iv_id);
            LIST_REMOVE(ivi, ivi_value_link);
            ivi->ivi_value = saved;
            LIST_INSERT_HEAD(&saved->iv_instructions, ivi, ivi_value_link);

#ifdef VMIR_VM_JIT
            if(!(iu->iu_debug_flags_func & VMIR_DBG_DISABLE_JIT)) {
              memset(ivi->ivi_instr->ii_liveness + setwords,
                     0, setwords * sizeof(uint32_t));
              liveness_set_gen(ivi->ivi_instr, iu,
                               ivi->ivi_instr->ii_liveness + setwords);
            }
#endif
            if(iu->iu_debug_flags_func & VMIR_DBG_DUMP_REGALLOC) {
              printf("\tPost altering instruction ");
              instr_print(iu, ivi->ivi_instr, 1);
              printf("\n");
            }
          }

          // Merge nodes in interference matrix
          for(int i = 0; i < temp_values; i++) {
            if(tribitmtx_get(mtx, killed->iv_id - ffv, i)) {
              tribitmtx_clr(mtx, killed->iv_id - ffv, i);

              if(!tribitmtx_get(mtx, saved->iv_id - ffv, i)) {
                tribitmtx_set(mtx, saved->iv_id - ffv, i);
                saved->iv_edges++;
              } else {
                iu->iu_values.vh_p[i + ffv]->iv_edges--;
              }
            }
          }

          killed->iv_edges = 0;
          killed->iv_class = IR_VC_DEAD;
          iu->iu_stats.moves_killed++;
          instr_destroy(ii);
        }
      }
    }
  }

  remove_empty_bb(iu, f);

#ifdef VMIR_VM_JIT
  if(!(iu->iu_debug_flags_func & VMIR_DBG_DISABLE_JIT)) {
    liveness_update(f, setwords, ffv);

    if(0)
      print_liveout(iu, f, temp_values, ffv);
    jit_analyze(iu, f);
  }
#endif

  reg_alloc(iu, mtx, temp_values, ffv, f);
  free(mtx);
}


/**
 *
 */
static void
liveness_analysis(ir_unit_t *iu, ir_function_t *f)
{
  /* First function value is the value index for the first argument
   * or first temporary in case of functions with no arguments
   */
  const int ffv = iu->iu_first_func_value;
  int temp_values = iu->iu_next_value - ffv;

  // words needed for the value sets
  int setwords = (temp_values + 31) / 32;

  ir_bb_t *ib;
  ir_instr_t *ii;

  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
      ii->ii_liveness = calloc(1, sizeof(uint32_t) * setwords * 3);
      liveness_set_gen(ii, iu, ii->ii_liveness + setwords);
      liveness_set_succ(f, ii);
    }
  }

  liveness_update(f, setwords, ffv);

  if(0)
    print_liveout(iu, f, temp_values, ffv);

  coalesce(iu, setwords, temp_values, ffv, f);
}


/**
 *
 */
static int
prepare_call(ir_unit_t *iu, ir_function_t *f, ir_instr_call_t *ii)
{
  int callpos = 0;
  int stackgrowth = 0;
  for(int i = 0; i < ii->argc; i++) {
    ir_value_t *a = value_get(iu, ii->argv[i].value);
    int size = value_regframe_size(iu, a->iv_type);

    callpos += size;
    int ca_index = value_alloc_call_arg(iu, a->iv_type, -callpos);

    if(ii->argv[i].copy_size) {
      a = value_get(iu, ii->argv[i].value);
      ir_instr_stackcopy_t *stackcopy =
        instr_add_before(sizeof(ir_instr_stackcopy_t), IR_IC_STACKCOPY,
                         &ii->super);
      stackcopy->super.ii_ret_value = ca_index;
      stackcopy->value = ii->argv[i].value;
      stackcopy->size = ii->argv[i].copy_size;
      stackgrowth += stackcopy->size;

    } else {
      ir_instr_move_t *move =
        instr_add_before(sizeof(ir_instr_move_t), IR_IC_MOVE, &ii->super);
      move->super.ii_ret_value = ca_index;
      move->value = ii->argv[i].value;
    }

    ii->argv[i].value = ca_index;
  }

  ir_function_t *callee = value_function(iu, ii->callee);
  if(callee != NULL)
    callee->if_used = 1;

  if(stackgrowth > 0) {
    ir_instr_stackshrink_t *ss =
      instr_add_after(sizeof(ir_instr_stackshrink_t), IR_IC_STACKSHRINK,
                      &ii->super);
      ss->super.ii_ret_value = -1;
      ss->size = stackgrowth;
  }
  return callpos;
}


/**
 *
 */
static int
prepare_calls(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *bb;

  iu->iu_first_call_arg = iu->iu_next_value;
  int max_call_arg_size = 0;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link) {
    ir_instr_t *ii;
    TAILQ_FOREACH(ii, &bb->ib_instrs, ii_link) {
      if(ii->ii_class == IR_IC_CALL) {
        int s = prepare_call(iu, f, (ir_instr_call_t *)ii);
        max_call_arg_size = MAX(max_call_arg_size, s);
      }
    }
  }

  return max_call_arg_size;
}


/**
 *
 */
static void
value_alloc_registers(ir_unit_t *iu, ir_function_t *f, int call_arg_size)
{
#if 0
  for(int i = iu->iu_first_func_value; i < iu->iu_next_value; i++) {
    ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, i);
    if(iv->iv_class != IR_VC_TEMPORARY)
      continue;
    value_make_regframe_space(iu, iv);
    iv->iv_class = IR_VC_REGFRAME;
  }
#endif

  f->if_regframe_size += call_arg_size;

  for(int i = iu->iu_first_func_value; i < iu->iu_next_value; i++) {
    ir_value_t *iv = VECTOR_ITEM(&iu->iu_values, i);
    if(iv->iv_class != IR_VC_CALL_ARGUMENT)
      continue;
    iv->iv_reg += f->if_regframe_size;
    iv->iv_class = IR_VC_REGFRAME;
  }
}


/**
 *
 */
static ir_instr_t *
combine_get_upstream_instruction(ir_unit_t *iu, int value, ir_instr_t *target)
{
  ir_value_t *iv = value_get(iu, value);
  if(iv->iv_class != IR_VC_TEMPORARY)
    return NULL;

  ir_instr_t *upstream = NULL;
  ir_value_instr_t *ivi;
  LIST_FOREACH(ivi, &iv->iv_instructions, ivi_value_link) {
    switch(ivi->ivi_relation) {
    case IVI_OUTPUT:
      if(upstream != NULL)
        parser_error(iu, "Multiplte writes to temporary in instr-combine");
      upstream = ivi->ivi_instr;
      break;
    case IVI_INPUT:
      if(ivi->ivi_instr != target)
        return NULL; // Other instruction is using the value
      break;
    }
  }

  return upstream;
}


/**
 *
 */
static void
combine_branch_with_compare(ir_unit_t *iu, ir_instr_br_t *br)
{
  ir_instr_t *iip;
  if(br->condition == -1)
    return;

  iip = combine_get_upstream_instruction(iu, br->condition, &br->super);
  if(iip == NULL || iip->ii_class != IR_IC_CMP2)
    return;
  ir_instr_binary_t *cmp = (ir_instr_binary_t *)iip;
  if(!(cmp->op >= FIRST_ICMP_PREDICATE &&
       cmp->op <=  LAST_ICMP_PREDICATE))
    return;

  ir_value_t *lhs = value_get(iu, cmp->lhs_value);
  // This check could be relaxed if we do swapPred() in vm
  if(lhs->iv_class != IR_VC_TEMPORARY &&
     lhs->iv_class != IR_VC_REGFRAME)
    return;
  ir_type_t *ty = type_get(iu, lhs->iv_type);
  if(!(ty->it_code == IR_TYPE_INT8 ||
       ty->it_code == IR_TYPE_INT32 ||
       ty->it_code == IR_TYPE_POINTER))
    return;

  assert(iip->ii_ret_value == br->condition);

  ir_instr_cmp_branch_t *icb =
    instr_add_after(sizeof(ir_instr_cmp_branch_t), IR_IC_CMP_BRANCH,
                    &br->super);

  icb->op = cmp->op;
  icb->lhs_value = cmp->lhs_value;
  icb->rhs_value = cmp->rhs_value;
  icb->true_branch = br->true_branch;
  icb->false_branch = br->false_branch;

  instr_bind_input(iu, cmp->lhs_value, &icb->super);
  instr_bind_input(iu, cmp->rhs_value, &icb->super);

  value_get(iu, br->condition)->iv_class = IR_VC_DEAD;

  instr_destroy(&br->super);
  instr_destroy(iip);

  iu->iu_stats.cmp_branch_combine++;
}

/**
 *
 */
static void
combine_binop_add_mul(ir_unit_t *iu, ir_instr_binary_t *add,
                      ir_instr_binary_t *mul, int side)
{

  const ir_value_t *a1 = value_get(iu, mul->lhs_value);
  const ir_type_t *ty = type_get(iu, a1->iv_type);
  if(ty->it_code != IR_TYPE_INT32)
    return;

  ir_value_t *a2 = value_get(iu, mul->rhs_value);
  const int arg3 = side ? add->lhs_value : add->rhs_value;
  ir_value_t *a3 = value_get(iu, arg3);

  assert(a1->iv_type == a2->iv_type);
  assert(a1->iv_type == a3->iv_type);

  if(a1->iv_class != IR_VC_TEMPORARY && a1->iv_class != IR_VC_REGFRAME)
    return;
  if(a2->iv_class != IR_VC_TEMPORARY && a2->iv_class != IR_VC_REGFRAME)
    return;
  if(a3->iv_class != IR_VC_TEMPORARY && a3->iv_class != IR_VC_REGFRAME)
    return;

  ir_instr_ternary_t *mla =
    instr_add_after(sizeof(ir_instr_ternary_t), IR_IC_MLA,
                    &add->super);

  mla->super.ii_ret_value = add->super.ii_ret_value;
  mla->arg1 = mul->lhs_value;
  mla->arg2 = mul->rhs_value;
  mla->arg3 = arg3;

  instr_bind_input(iu, mla->arg1, &mla->super);
  instr_bind_input(iu, mla->arg2, &mla->super);
  instr_bind_input(iu, mla->arg3, &mla->super);
  value_bind_return_value(iu, &mla->super);

  value_get(iu, mul->super.ii_ret_value)->iv_class = IR_VC_DEAD;

  instr_destroy(&add->super);
  instr_destroy(&mul->super);

  iu->iu_stats.mla_combine++;
}


/**
 *
 */
static void
combine_binop_add(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  ir_instr_t *lhs, *rhs;

  lhs = combine_get_upstream_instruction(iu, ii->lhs_value, &ii->super);
  if(lhs != NULL && lhs->ii_class == IR_IC_BINOP &&
     ((ir_instr_binary_t *)lhs)->op == BINOP_MUL) {
    combine_binop_add_mul(iu, ii, (ir_instr_binary_t *)lhs, 0);
    return;
  }

  rhs = combine_get_upstream_instruction(iu, ii->rhs_value, &ii->super);
  if(rhs != NULL && rhs->ii_class == IR_IC_BINOP &&
     ((ir_instr_binary_t *)rhs)->op == BINOP_MUL) {
    combine_binop_add_mul(iu, ii, (ir_instr_binary_t *)rhs, 1);
    return;
  }
}


/**
 *
 */
static void
combine_binop_load_cast(ir_unit_t *iu, ir_instr_unary_t *cast,
                        ir_instr_load_t *load)
{
#if 0
  printf("cast combine\n");
  instr_print(iu, &load->super, 1);
  printf("\n");
  instr_print(iu, &cast->super, 1);
  printf("\n");
#endif
  ir_value_t *kill = value_get(iu, load->super.ii_ret_value);
  load->cast = cast->op;
  load->load_type = kill->iv_type;
  load->super.ii_ret_value = cast->super.ii_ret_value;

  instr_bind_clear(&load->super);
  instr_bind_input(iu, load->ptr, &load->super);
  if(load->value_offset >= 0)
    instr_bind_input(iu, load->value_offset, &load->super);
  value_bind_return_value(iu, &load->super);

  kill->iv_class = IR_VC_DEAD;
  instr_destroy(&cast->super);
  iu->iu_stats.load_cast_combine++;
}


/**
 *
 */
static void
combine_binop_cast(ir_unit_t *iu, ir_instr_unary_t *ii)
{
  ir_instr_t *u;

  if(ii->op != CAST_ZEXT && ii->op != CAST_SEXT)
    return;
  ir_value_t *v = value_get(iu, ii->super.ii_ret_value);
  ir_type_t *ty = type_get(iu, v->iv_type);
  if(ty->it_code != IR_TYPE_INT32)
    return;

  u = combine_get_upstream_instruction(iu, ii->value, &ii->super);
  if(u != NULL && u->ii_class == IR_IC_LOAD) {
    ir_instr_load_t *load = (ir_instr_load_t *)u;
    ir_value_t *ptr = value_get(iu, load->ptr);
    if(ptr->iv_class != IR_VC_TEMPORARY &&
       ptr->iv_class != IR_VC_REGFRAME)
      return;
    combine_binop_load_cast(iu, ii, load);
    return;
  }
}


/**
 *
 */
static void
combine_binop(ir_unit_t *iu, ir_instr_binary_t *ii)
{
  if(ii->op == BINOP_ADD)
    combine_binop_add(iu, ii);
}

/**
 *
 */
static void
combine_instructions(ir_unit_t *iu, ir_function_t *f)
{
  ir_bb_t *bb;
  TAILQ_FOREACH(bb, &f->if_bbs, ib_link) {
    ir_instr_t *ii, *iin;
    ii = TAILQ_LAST(&bb->ib_instrs, ir_instr_queue);
    if(ii->ii_class == IR_IC_BR)
      combine_branch_with_compare(iu, (ir_instr_br_t *)ii);

    for(ii = TAILQ_FIRST(&bb->ib_instrs); ii != NULL; ii = iin) {
      iin = TAILQ_NEXT(ii, ii_link);
      if(ii->ii_class == IR_IC_BINOP)
        combine_binop(iu, (ir_instr_binary_t *)ii);
      if(ii->ii_class == IR_IC_CAST)
        combine_binop_cast(iu, (ir_instr_unary_t *)ii);
    }
  }
}



/**
 *
 */
static void
registrate_aggregate(ir_unit_t *iu, ir_value_t *iv, int num_values)
{
  const int *values = iv->iv_data;
  assert(num_values > 1);

  ir_value_instr_t *ivi;
  while((ivi = LIST_FIRST(&iv->iv_instructions)) != NULL) {
    const int rel = ivi->ivi_relation;
    ir_instr_t *ii = ivi->ivi_instr;
    ivi_destroy(ivi);

    switch(rel) {
    case IVI_OUTPUT:
      // Instructions writing to this value get a multiple return value array
      ii->ii_ret_values = malloc(sizeof(int) * num_values);
      memcpy(ii->ii_ret_values, values, sizeof(int) * num_values);
      ii->ii_ret_value = -num_values;

      for(int i = 0; i < num_values; i++)
        value_bind_instr(value_get(iu, values[i]), ii, IVI_OUTPUT);
      break;

    case IVI_INPUT:
      // Deal with instructions reading from this value, currently
      // we only deal with extractval by transforming it into a move
      // (which in turn will most likely get eliminated by register coalescing
      // later on)
      switch(ii->ii_class) {
      case IR_IC_EXTRACTVAL:
        {
          ir_instr_extractval_t *iie = (ir_instr_extractval_t *)ii;

          if(iie->num_indicies != 1) {
            parser_error(iu, "Unable to legalize extractval with %d indicies",
                         iie->num_indicies);
          }

          ii->ii_class = IR_IC_MOVE;
          int v = values[iie->indicies[0]];
          ((ir_instr_move_t *)ii)->value = v;
          value_bind_instr(value_get(iu, v), ii, IVI_INPUT);
        }
        break;

      default:
        parser_error(iu, "Unable to legalize aggregate value as input to %d",
                     ii->ii_class);
        break;
      }
    }
  }
  // The old temporary aggregate value should no longer be used for anything
  iv->iv_class = IR_VC_DEAD;
}

/**
 *
 */
static void
legalize_casts(ir_unit_t *iu, ir_value_t *iv)
{
  ir_value_instr_t *ivi;
  LIST_FOREACH(ivi, &iv->iv_instructions, ivi_value_link) {
    ir_instr_t *ii = ivi->ivi_instr;
    switch(ivi->ivi_relation) {
    case IVI_OUTPUT:
      switch(ii->ii_class) {
      default:
        break;
      case IR_IC_CAST:
        {
          ir_instr_unary_t *iiu = (ir_instr_unary_t *)ii;
          if(iiu->op == CAST_TRUNC) {
            ir_value_t *src = value_get(iu, iiu->value);
            if(src->iv_type == iv->iv_type) {
              ii->ii_class = IR_IC_MOVE;
            }
          }
        }
        break;
      }
      break;
    default:
      break;
    }
  }
}

/**
 * This function transforms temporary values which the VM does not support
 */
static void
legalize_values(ir_unit_t *iu, ir_function_t *f)
{
  for(int i = iu->iu_first_func_value; i < iu->iu_next_value; i++) {
    ir_value_t *iv = value_get(iu, i);
    if(iv->iv_class != IR_VC_TEMPORARY)
      continue;
    ir_type_t *ty = type_get(iu, iv->iv_type);
    int *values;
    int num_values;
    switch(ty->it_code) {
    default:
      continue;

    case IR_TYPE_INTx:
      if(ty->it_bits <= 8)
        iv->iv_type = type_make(iu, IR_TYPE_INT8);
      else if(ty->it_bits <= 16)
        iv->iv_type = type_make(iu, IR_TYPE_INT16);
      else if(ty->it_bits <= 32)
        iv->iv_type = type_make(iu, IR_TYPE_INT32);
      else if(ty->it_bits <= 64)
        iv->iv_type = type_make(iu, IR_TYPE_INT64);
      else
        parser_error(iu, "Unable to legalize int%d -- too wide",
                     ty->it_bits);
      legalize_casts(iu, iv);
      break;

    case IR_TYPE_STRUCT:
      num_values = ty->it_struct.num_elements;
      iv->iv_data = values = malloc(sizeof(int) * num_values);
      for(int j = 0; j < num_values; j++) {
        values[j] = value_alloc_temporary(iu, ty->it_struct.elements[j].type);
      }
      registrate_aggregate(iu, iv, num_values);
      break;
    }
  }
}


/**
 *
 */
static void
transform_function(ir_unit_t *iu, ir_function_t *f)
{
  replace_instructions(iu, f);

  function_bind_instr_inputs(iu, f);

  construct_cfg(f);

  break_crtitical_edges(f);

  combine_instructions(iu, f);

  exit_ssa(iu, f);

  eliminate_dead_code(iu, f);

  legalize_values(iu, f);

  liveness_analysis(iu, f);

  int cs = prepare_calls(iu, f);

  value_alloc_registers(iu, f, cs);
}
