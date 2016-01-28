# VMIR - Virtual Machine for LLVM Intermediate Representation

VMIR is a standalone library written in C that can parse and execute LLVM bitcode (.bc) files.

To build VMIR just type:
```
$ make
```
... and you will end up with a vmir binary in very same directory.
The library is compiled from a single file [src/vmir.c](src/vmir.c) which in turn include other files to keep stuff somewhat separated.

### Example
Let's create a small program and run it. Type the following well known snippet into a file called helloworld.c
```
int main(void)
{
  printf("Hello world\n");
  return 0;
}
```
Then compile it
```
clang -emit-llvm -target le32-unknown-nacl -c helloworld.c -o helloworld.bc
```
And finally, run it:
```
$ ./vmir helloworld.bc
Hello world
```

### Performance

Execution is about 10x slower than if the same binary is compiled to native code. Still it's a lot faster than LLVM's own interpreter (which by all means is not intended to run code fast in any way)

Example run of [test/misc/src/sha1test.c](test/misc/src/sha1test.c)  over 64MB of random data (Core i7 3.2GHz)

Environment | Time
--- | ---
Native | 0.39s
VMIR | 4.8s
LLVM LLI | 7m 39s


### Status
VMIR currently passes the gcc torture test suite on optimization level 0, 1 and 2. Those tests can be found in [test/gcc-torture](test/gcc-torture). Use `make && ./runtest` to run the tests.


### Missing features, known bugs
* It only work on little endian machines.
* The built-in libc is lacking a lot of functions and features. This is where most work needs to be done.
* No support for vector types (Ie, code must be compiled with `-fno-vectorize -fno-slp-vectorize`).
* No good C++ STL solution. Ideas welcome...

### Compiling code for VMIR

VMIR uses the same target as Google NativeClient. There are small examples in [test/misc](test/misc).

When building bigger projects consisting of multiple files you must `llvm-link` to combine the `.bc` files into a single file.


### Embedding VMIR
Including VMIR in your own project is pretty straight forward. Just copy the files from [src/](src/) to your project but only compile [vmir.c](src/vmir.c) (it will include all other .c -files on its own). The API is defined in [vmir.h](src/vmir.h). See [src/main.c](src/main.c) for example how to load and execute binaries.

VMIR's libc also offers an option to use TLSF for memory allocation. The default built-in allocator is a very simple linear search first-fit algorithm.

Follow me on https://twitter.com/andoma
