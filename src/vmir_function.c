


static ir_bb_t *
bb_make(ir_function_t *f)
{
  ir_bb_t *ib = calloc(1, sizeof(ir_bb_t));
  TAILQ_INIT(&ib->ib_instrs);
  ib->ib_id = f->if_num_bbs++;
  return ib;
}

/**
 *
 */
static ir_bb_t *
bb_add(ir_function_t *f, ir_bb_t *after)
{
  ir_bb_t *ib = bb_make(f);
  if(after != NULL)
    TAILQ_INSERT_AFTER(&f->if_bbs, after, ib, ib_link);
  else
    TAILQ_INSERT_TAIL(&f->if_bbs, ib, ib_link);
  return ib;
}


/**
 *
 */
static ir_bb_t *
bb_add_before(ir_function_t *f, ir_bb_t *before)
{
  ir_bb_t *ib = bb_make(f);
  TAILQ_INSERT_BEFORE(before, ib, ib_link);
  return ib;
}


/**
 *
 */
__attribute__((unused))
static ir_bb_t *
bb_add_named(ir_function_t *f, ir_bb_t *after, const char *name)
{
  ir_bb_t *ib = bb_add(f, after);
  ib->ib_name = strdup(name);
  return ib;
}


/**
 *
 */
static void
cfg_create_edge(ir_function_t *f, ir_bb_t *from, ir_bb_t *to)
{
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
static ir_bb_t *
bb_find(ir_function_t *f,  int id)
{
  ir_bb_t *ib;
  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    if(ib->ib_id == id)
      return ib;
  }
  return NULL;
}



/**
 *
 */
static void
ibe_destroy(ir_bb_edge_t *ibe)
{
  LIST_REMOVE(ibe, ibe_from_link);
  LIST_REMOVE(ibe, ibe_to_link);
  LIST_REMOVE(ibe, ibe_function_link);
  free(ibe);
}


/**
 *
 */
static void
ibe_destroy_list(struct ir_bb_edge_list *list)
{
  ir_bb_edge_t *ibe;
  while((ibe = LIST_FIRST(list)) != NULL)
    ibe_destroy(ibe);
}


/**
 *
 */
static void
bb_destroy(ir_bb_t *ib, ir_function_t *f)
{
  ir_instr_t *ii;

  TAILQ_REMOVE(&f->if_bbs, ib, ib_link);

  ibe_destroy_list(&ib->ib_incoming_edges);
  ibe_destroy_list(&ib->ib_outgoing_edges);

  while((ii = TAILQ_FIRST(&ib->ib_instrs)) != NULL) {
    instr_destroy(ii);
  }
  free(ib->ib_name);
  free(ib);
}




/**
 *
 */
static void
function_prepare_parse(ir_unit_t *iu, ir_function_t *f)
{
  if(iu->iu_debugged_function != NULL &&
     strcmp(iu->iu_debugged_function, f->if_name))
    iu->iu_debug_flags_func = 0;
  else
    iu->iu_debug_flags_func = iu->iu_debug_flags;

  f->if_regframe_size = 8; // Make space for temporary register for VM use
  f->if_callarg_size = 0;

  ir_type_t *it = type_get(iu, f->if_type);

  for(int i = 0; i < it->it_function.num_parameters; i++)
    value_alloc_function_arg(iu, it->it_function.parameters[i]);
}


/**
 *
 */
static void
function_print(ir_unit_t *iu, ir_function_t *f, const char *what)
{
  printf("\nDump of %s function %s (%s)%s\n", what,
         f->if_name, type_str_index(iu, f->if_type),
         f->if_full_jit ? ", Fully JITed" : "");
  ir_bb_t *ib;
  TAILQ_FOREACH(ib, &f->if_bbs, ib_link) {
    ir_instr_t *ii;
    printf(".%d:%s%s%s%s%s", ib->ib_id,
           ib->ib_name ? " \"" : "",
           ib->ib_name ?: "",
           ib->ib_name ? "\"" : "",
           ib->ib_jit ? " (JIT)" : "",
           ib->ib_only_jit_sucessors ? " (Only JIT succ)" : "");

    ir_bb_edge_t *ibe;
    LIST_FOREACH(ibe, &ib->ib_incoming_edges, ibe_to_link) {
      printf(" pred:%d", ibe->ibe_from->ib_id);
    }
    printf("\n");
    TAILQ_FOREACH(ii, &ib->ib_instrs, ii_link) {
      printf("\t%s\n", instr_str(iu, ii, 0));
    }
    printf("\t\t");
    LIST_FOREACH(ibe, &ib->ib_outgoing_edges, ibe_from_link) {
      printf(" next:%d", ibe->ibe_to->ib_id);
    }
    printf("\n");
  }
}




/**
 *
 */
ir_function_t *
vmir_find_function(ir_unit_t *iu, const char *name)
{
  for(int i = 0; i < VECTOR_LEN(&iu->iu_functions); i++) {
    ir_function_t *f = VECTOR_ITEM(&iu->iu_functions, i);
    if(f->if_name != NULL && !strcmp(f->if_name, name))
      return f;
  }
  return NULL;
}


/**
 *
 */
static void
function_remove_bb(ir_function_t *f)
{
  ir_bb_t *ib;
  while((ib = TAILQ_FIRST(&f->if_bbs)) != NULL) {
    bb_destroy(ib, f);
  }
}


/**
 *
 */
static void
function_destroy(ir_function_t *f)
{
  function_remove_bb(f);
  free(f->if_name);
  free(f->if_vm_text);
  free(f->if_instr_backrefs);
  free(f);
}

