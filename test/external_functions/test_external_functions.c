
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "../../src/vmir.h"

//--------------------------------
// the function and its wrapper
//--------------------------------

void print (const char *message)
{
	printf("%s\n", message);
}

static void
print_W(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vm_ptr(&rf, iu);
  print(str);
}

//----------------------------------
// the function resolver
//----------------------------------

typedef struct {
  const char *name;
  vm_ext_function_t *extfunc;
} function_tab_t;

#define FN_EXT(a, b)   { .name = a, .extfunc = b }

static const function_tab_t libc_funcs[] = {
  FN_EXT("_Z14external_printPKc", print_W)
} ;

#define VMIR_ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))

vm_ext_function_t *restricted_function_resolver(const char *fn, void *opaque)
{
  for(int i = 0; i < VMIR_ARRAYSIZE(libc_funcs); i++) {
    const function_tab_t *ft = &libc_funcs[i];
    if(!strcmp(fn, ft->name)) {
		return ft->extfunc;
    }
  }
  return 0; // what is current C these days 0 or NULL?
}

//--------------------------
// helper
//--------------------------

void readFileIntoMemory (const char *fileName, uint8_t **memory, long long *size)
{
  int fd = open(fileName, O_RDONLY);
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
	
  *memory = buf;
  *size = st.st_size;
}

//--------------------------
// main
//
// reads the scripts into memory and then the vmir
// finds the script function and executes it
//--------------------------


int main(int argc, char **argv)
{
  uint8_t *file = NULL;
  long long fileSize;
	
  char osx_is_dumb[256];
  strcpy (osx_is_dumb, __FILE__);
  strcpy (osx_is_dumb + strlen(osx_is_dumb)-2, "_script.bc");
  readFileIntoMemory(osx_is_dumb, &file, &fileSize);

#define MB(x) ((x) * 1024 * 1024)

  void *mem = malloc(MB(64));

  ir_unit_t *iu = vmir_create(mem, MB(64), MB(1), MB(1), NULL);
  vmir_set_external_function_resolver(iu, restricted_function_resolver);

  if(vmir_load(iu, file, (int)fileSize)) {
    free(mem);
    vmir_destroy(iu);
    return -1;
  }
	
  ir_function_t *f;
  f = vmir_find_function(iu, "_Z15script_functionv");

  union {
    uint32_t u32;
    uint64_t u64;
  } ret;

  int r = vm_function_call(iu, f, &ret);

  free(mem);

  vmir_destroy(iu);

  return 0;
}