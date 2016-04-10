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

#pragma once

typedef struct ir_unit ir_unit_t;


typedef enum {
  VMIR_ERR_NOT_BITCODE = -1,
  VMIR_ERR_LOAD_ERROR = -2,
  VMIR_ERR_INVALID_ARGS = -3,
  VMIR_ERR_FS_ERROR = -4,  // Add more specific errors
} vmir_errcode_t;


typedef enum {
  VMIR_FS_OPEN_READ    = 0x1,   // Open file for reading
  VMIR_FS_OPEN_WRITE   = 0x2,   // Open file for writing
  VMIR_FS_OPEN_RW      = 0x3,   // Read + Write
  VMIR_FS_OPEN_CREATE  = 0x4,   // Create file if not exist
  VMIR_FS_OPEN_TRUNC   = 0x8,   // Truncate file
  VMIR_FS_OPEN_APPEND  = 0x10,  // Position file pointer at end of file
} vmir_openflags_t;


typedef struct {
  vmir_errcode_t(*open)(void *opaque, const char *path,
                        vmir_openflags_t flags, intptr_t *fh);

  void (*close)(void *opaque, intptr_t fh);

  ssize_t (*read)(void *opaque, intptr_t fh, void *buf, size_t count);
  ssize_t (*write)(void *opaque, intptr_t fh, const void *buf, size_t count);

  int64_t (*seek)(void *opaque, intptr_t fh, int64_t offset, int whence);

} vmir_fsops_t;



/**
 * Create a new environment
 *
 * membase should point to memory allocated by the user
 * memsize is size of said memory (in bytes)
 *
 * rsize is how much of the memory that will be used for register frames
 * asize is how much of the memory that will be used for stack allocation
 * Rest of memory will be used for standard malloc()/free() heap
 *
 * Opaque is a reference passed back in various callbacks and not
 * interpreted by vmir in any way.
 */
ir_unit_t *vmir_create(void *membase, uint32_t memsize,
                       uint32_t rsize, uint32_t asize,
                       void *opaque);

typedef void (vm_ext_function_t)(void *ret, const void *regs,
                                 struct ir_unit *iu);

typedef vm_ext_function_t *(*vmir_function_resolver_t)(const char *function, void *opaque);
vm_ext_function_t *vmir_default_external_function_resolver(const char *function, void *opaque);

vmir_function_resolver_t vmir_get_external_function_resolver(ir_unit_t *);
void vmir_set_external_function_resolver(ir_unit_t *, vmir_function_resolver_t fn);

/**
 * Override defaults functions for filesystem access
 */
void vmir_set_fsops(ir_unit_t *iu, const vmir_fsops_t *ops);


/**
 * Parse bitcode and generate code, data, etc
 */
vmir_errcode_t vmir_load(ir_unit_t *iu, const uint8_t *bitcode,
                         int bitcode_len);

/**
 * Run will call main() with argc and argv as given by this call.
 *
 * Note: argv[0] is expected to be the executable name just as
 * the "normal" argv[] vector behaves. The user is responsible for
 * filling that out as well.
 */
void vmir_run(ir_unit_t *iu, int argc, char **argv);


typedef struct ir_function ir_function_t;
ir_function_t *vmir_find_function(ir_unit_t *, const char *fn);
int vm_function_call(ir_unit_t *iu, ir_function_t *f, void *out, ...);

void *vm_ptr(const void **rfp, ir_unit_t *iu);
void *vm_ptr_nullchk(const void **rfp, ir_unit_t *iu);
void vm_retptr(void *ret, void *p, const ir_unit_t *iu);


/**
 * Destroy the environment and free all resources except the memory
 * passed in to vmir_create(). THe user is responsible for freeing this
 * memory.
 *
 * After this the ir_unit is also free'd and no longer available
 */
void vmir_destroy(ir_unit_t *iu);



/**
 * Debug / trace helpers
 *
 * Used with vmir_set_debug_flags()
 */
#define VMIR_DBG_DUMP_PARSED_FUNCTION 0x1
#define VMIR_DBG_DUMP_LOWERED_FUNCTION 0x2
#define VMIR_DBG_LIST_FUNCTIONS   0x4
#define VMIR_DBG_DUMP_DEV         0x8
#define VMIR_DBG_DUMP_REGALLOC    0x10
#define VMIR_DBG_BB_INSTRUMENT    0x20
#define VMIR_DBG_DISABLE_JIT      0x40

void vmir_set_debug_flags(ir_unit_t *iu, int flags);


/**
 * Debug only a specific function. If unset (or set to NULL) any debugging
 * will be enabled for all functions.
 */
void vmir_set_debugged_function(ir_unit_t *iu, const char *function);

/**
 * Print various stats about code transformation to stdout
 */
void vmir_print_stats(ir_unit_t *iu);
