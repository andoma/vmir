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
  while((opt = getopt(argc, argv, "plidf:nhrbs")) != -1) {
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

  ir_unit_t *iu = vmir_create(mem, MB(64), MB(1), MB(1));

  vmir_set_debug_flags(iu, debug_flags);
  vmir_set_debugged_function(iu, debugged_function);

  if(vmir_load(iu, buf, st.st_size)) {
    free(mem);
    vmir_destroy(iu);
    return -1;
  }

  if(print_stats)
    vmir_print_stats(iu);

  if(run)
    vmir_run(iu, argc, argv);

  free(mem);

  vmir_destroy(iu);

  return 0;
}
