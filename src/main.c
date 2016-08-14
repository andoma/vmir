#include <sys/time.h>
#include <getopt.h>

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "vmir.h"

static void
usage(const char *argv0)
{
  printf("\n");
  printf("Usage ... %s [OPTIONS] <file.bc>\n", argv0);
  printf("\n");
  printf("  -f FUNCTION         Function to diagnose [ALL]\n");
  printf("  -l                  Dump lowered function(s)\n");
  printf("  -p                  Dump parsed function(s)\n");
  printf("  -i                  List all functions\n");
  printf("  -n                  Don't try to run code\n");
  printf("\n");
}

static int64_t
get_ts(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}




static void
dump_stats(ir_unit_t *iu)
{
  const vmir_stats_t *s = vmir_get_stats(iu);

  printf("\n");
  printf(" Memory usage stats\n");
  printf("\n");
  printf("       VM code size: %d\n", s->vm_code_size);
  printf("      JIT code size: %d\n", s->jit_code_size);
  printf("          Data size: %d\n", s->data_size);
  printf("     Peak heap size: %d\n", s->peak_heap_size);
  printf("   Peak stack usage: %d\n", s->peak_stack_size);
  printf("\n");
  printf(" Code transformation stats\n");
  printf("\n");
  printf("       Moves killed: %d\n", s->moves_killed);
  printf("  Lea+Load combined: %d\n", s->lea_load_combined);
  printf(" Lea+Load comb-fail: %d\n", s->lea_load_combined_failed);
  printf("Cmp+Branch combined: %d\n", s->cmp_branch_combine);
  printf("Cmp+Select combined: %d\n", s->cmp_select_combine);
  printf("   Mul+Add combined: %d\n", s->mla_combine);
  printf(" Load+Cast combined: %d\n", s->load_cast_combine);
  printf("\n");
}



/**
 *
 */
int
main(int argc, char **argv)
{
  int debug_flags = 0;
  int run = 1;
  const char *debugged_function = NULL;
  int opt;
  const char *argv0 = argv[0];
  int print_stats = 0;
  while((opt = getopt(argc, argv, "plidf:nhrbsjI")) != -1) {
    switch(opt) {
    case 'p':
      debug_flags |= VMIR_DBG_DUMP_PARSED_FUNCTION;
      break;
    case 'l':
      debug_flags |= VMIR_DBG_DUMP_LOWERED_FUNCTION;
      break;
    case 'i':
      debug_flags |= VMIR_DBG_LIST_FUNCTIONS;
      break;
    case 'd':
      debug_flags |= VMIR_DBG_DUMP_DEV;
      break;
    case 'r':
      debug_flags |= VMIR_DBG_DUMP_REGALLOC;
      break;
    case 'b':
      debug_flags |= VMIR_DBG_BB_INSTRUMENT;
      break;
    case 'j':
      debug_flags |= VMIR_DBG_DISABLE_JIT;
      break;
    case 'I':
      debug_flags |= VMIR_DBG_IGNORE_UNRESOLVED_FUNCTIONS;
      break;
    case 'f':
      debugged_function = optarg;
      break;
    case 'h':
      usage(argv0);
      exit(0);
    case 'n':
      run = 0;
      break;
    case 's':
      print_stats = 1;
      break;
    default:
      usage(argv0);
      exit(1);
    }
  }

  if(optind >= argc) {
    fprintf(stderr, "Need .bc file to parse/run\n");
    exit(1);
  }

  argc -= optind;
  argv += optind;

  int fd = open(argv[0], O_RDONLY);
  if(fd == -1) {
    perror("open");
    exit(1);
  }

  struct stat st;
  if(fstat(fd, &st)) {
    perror("stat");
    exit(1);
  }

  uint8_t *buf = malloc(st.st_size);
  if(read(fd, buf, st.st_size) != st.st_size) {
    perror("read");
    exit(1);
  }
  close(fd);

#define MB(x) ((x) * 1024 * 1024)

  void *mem = malloc(MB(64));

  ir_unit_t *iu = vmir_create(mem, MB(64), MB(1), MB(1), NULL);

  vmir_set_debug_flags(iu, debug_flags);
  vmir_set_debugged_function(iu, debugged_function);

  if(vmir_load(iu, buf, st.st_size)) {
    free(mem);
    vmir_destroy(iu);
    return -1;
  }

  if(run) {
    int64_t ts = get_ts();
    vmir_run(iu, NULL, argc, argv);
    ts = get_ts() - ts;
    if(print_stats)
      printf("main() executed for %d ms\n", (int)(ts / 1000LL));
  }

  if(print_stats)
    dump_stats(iu);

  vmir_instrumentation_dump(iu);

  free(mem);

  vmir_destroy(iu);

  return 0;
}
