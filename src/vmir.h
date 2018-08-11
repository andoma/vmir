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
  VMIR_LOG_FAIL  = 0,
  VMIR_LOG_ERROR = 1,
  VMIR_LOG_INFO  = 2,
  VMIR_LOG_DEBUG = 3,
} vmir_log_level_t;

typedef void (vmir_logger_t)(ir_unit_t *iu, vmir_log_level_t level,
                             const char *str);

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



/**
 * Return opaque value passed to vmir_create()
 */
void *vmir_get_opaque(ir_unit_t *iu);


/**
 * Set callback for log messages
 *
 * If not set, logging will be sent to stdout
 */
void vmir_set_logger(ir_unit_t *iu, vmir_logger_t *logger);

/**
 * Set level for log messages
 *
 * Only messages with level lower or equal to this value will be
 * logged. Default is VMIR_LOG_INFO
 */
void vmir_set_log_level(ir_unit_t *iu, vmir_log_level_t level);


/**
 * Signature for external function (as returned by
 * vmir_function_resolver_t callback)
 *
 * Return 0 - Normal return
 *        1 - Exception thrown
 *   Others - Undefined
 */
typedef int (vm_ext_function_t)(void *ret,
                                const void *regs,
                                struct ir_unit *iu);


/**
 * Signature for overriding the default external function resolver
 */
typedef vm_ext_function_t *(*vmir_function_resolver_t)(const char *function,
                                                       void *opaque);

/**
 * The default external function resolver for resolving a function into
 * VMIR's built-in libc.
 */
vm_ext_function_t *vmir_default_external_function_resolver(const char *function,
                                                           void *opaque);

/**
 *
 */
vmir_function_resolver_t vmir_get_external_function_resolver(ir_unit_t *);

/**
 * Set function to call for resolving unresolved function symbols.
 *
 * Note that if using this and you want to keep the internal libc functions,
 * this function should call vmir_default_external_function_resolver() as
 * last resort to make VMIR use the built-in function for the given lookup.
 */
void vmir_set_external_function_resolver(ir_unit_t * iu,
                                         vmir_function_resolver_t fn);

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
 * Destroy the environment and free all resources except the memory
 * passed in to vmir_create(). The user is responsible for freeing this
 * memory.
 *
 * After this the ir_unit is also free'd and no longer available
 */
void vmir_destroy(ir_unit_t *iu);


/**
 * Run will call main() with argc and argv as given by this call.
 *
 * Note: argv[0] is expected to be the executable name just as
 * the "normal" argv[] vector behaves. The user is responsible for
 * filling that out as well.
 *
 * Passing 0 to argc is OK if no arguments make sense in which case
 * argv[] is not dereferenced and can thus be NULL
 *
 * *ret is used to store the return value from main() or the value
 * passed to exit() if exit was called
 *
 */
int vmir_run(ir_unit_t *iu, int *ret, int argc, char **argv);


/**
 * Dump basic block profiling to stdout
 */
void vmir_instrumentation_dump(ir_unit_t *iu);



typedef struct ir_function ir_function_t;

/**
 * Lookup a vmir function that can be called with vmir_vm_function_call()
 */
ir_function_t *vmir_find_function(ir_unit_t *, const char *fn);


/**
 * Return values from vmir_vm_function_call()
 */
#define VM_STOP_OK          0      // Returned normally
#define VM_STOP_EXIT        1      // exit() was called
#define VM_STOP_ABORT       2      // abort() was called
#define VM_STOP_UNREACHABLE 3      // Ran the 'unreachable' LLVM instruction
#define VM_STOP_BAD_INSTRUCTION 4  // Invalid instruction encoding
                                   // This is an internal error in the VM
#define VM_STOP_BAD_FUNCTION 5     // Unresolved function was called
#define VM_STOP_UNCAUGHT_EXCEPTION 6
#define VM_STOP_ACCESS_VIOLATION 7
#define VM_STOP_BAD_ARGUMENTS   8
#define VM_STOP_OUT_OF_MEMROY   9

/**
 * Call a vmir function
 *
 * out is a pointer to where the return value from the function will be stored
 * Should hold 64 or 32 bit depending on the function signature.
 *
 * Rest of arguments are parsed in based on the function signature
 *
 * See VM_STOP_ defines above for return value of this function
 */
int vmir_vm_function_call(ir_unit_t *iu, ir_function_t *f, void *out, ...);

/**
 * Pop 32bit function argument.
 */
uint32_t vmir_vm_arg32(const void **rfp);

/**
 * Pop 64bit function argument.
 */
uint64_t vmir_vm_arg64(const void **rfp);

/**
 * Pop double function argument.
 */
double vmir_vm_arg_dbl(const void **rfp);

/**
 * Pop float function argument.
 */
float vmir_vm_arg_flt(const void **rfp);

/**
 * Pop pointer function argument and convert it from VMIR address
 * space to host address.
 */
void *vmir_vm_ptr(const void **rfp, ir_unit_t *iu);

/**
 * Pop pointer function argument and convert it from VMIR address
 * space to host address. If the pointer is NULL it will still be NULL
 * after conversion.
 */
void *vmir_vm_ptr_nullchk(const void **rfp, ir_unit_t *iu);

/**
 * Pop pointer function argument that is a function
 */
ir_function_t *vmir_vm_arg_func(const void **rfp, ir_unit_t *iu);

/**
 * Return a pointer inside the VM heap and adjust it to VMIR local address
 */
void vmir_vm_retptr(void *ret, void *p, const ir_unit_t *iu);

/**
 * Return a 32bit value from an external function
 */
void vmir_vm_ret32(void *ret, uint32_t v);

/**
 * Return a 64bit value from an external function
 */
void vmir_vm_ret64(void *ret, uint64_t v);


/**
 * Copy data to VM space
 */

uint32_t vmir_mem_alloc(ir_unit_t *iu, uint32_t size, void *hostaddr);

uint32_t vmir_mem_strdup(ir_unit_t *iu, const char *str);

uint32_t vmir_mem_copy(ir_unit_t *iu, const void *data, size_t size);

void vmir_mem_free(ir_unit_t *iu, uint32_t addr);

/**
 * File descriptors
 */
#define VMIR_FD_TYPE_FILEHANDLE 1
#define VMIR_FD_TYPE_SOCKET     2
#define VMIR_FD_TYPE_USER       128

typedef void (vmir_fd_release_t)(ir_unit_t *iu, intptr_t handle);

int vmir_fd_create(ir_unit_t *iu, intptr_t handle, int type,
                   vmir_fd_release_t *relfunc);

int vmir_fd_create_fh(ir_unit_t *iu, intptr_t fh, int closable);

void vmir_fd_close(ir_unit_t *iu, int fd);

intptr_t vmir_fd_get(ir_unit_t *iu, int fd, int type);


/**
 *
 */
typedef struct {
  const char *name;
  vm_ext_function_t *extfunc;
} vmir_function_tab_t;

vm_ext_function_t *vmir_function_tab_lookup(const char *function,
                                            const vmir_function_tab_t *array,
                                            int length);


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
#define VMIR_DBG_IGNORE_UNRESOLVED_FUNCTIONS 0x80

void vmir_set_debug_flags(ir_unit_t *iu, int flags);

void vmir_set_traced_function(ir_unit_t *iu, const char *fname);

/**
 * Debug only a specific function. If unset (or set to NULL) any debugging
 * will be enabled for all functions.
 */
void vmir_set_debugged_function(ir_unit_t *iu, const char *function);

/**
 * Print various stats about code transformation to stdout
 */
void vmir_print_stats(ir_unit_t *iu);


/**
 *
 */
void vmir_walk_heap(ir_unit_t *iu,
                    void (*fn)(void *opaque, uint32_t addr, uint32_t size,
                               int inuse),
                    void *opaque);

void vmir_walk_fds(ir_unit_t *iu,
                   void (*fn)(void *opaque, int fd, int type),
                   void *opaque);

typedef struct vmir_stats {

  int vm_code_size;
  int jit_code_size;
  int data_size;
  int peak_heap_size;
  int peak_stack_size;

  int cmp_branch_combine;
  int cmp_select_combine;
  int mla_combine;
  int load_cast_combine;
  int moves_killed;

  int lea_load_combined;
  int lea_load_combined_failed;

} vmir_stats_t;

const vmir_stats_t *vmir_get_stats(ir_unit_t *iu);

