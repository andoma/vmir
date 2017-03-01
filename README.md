# VMIR - Virtual Machine for Intermediate Representation

[![Build status](https://doozer.io/badge/andoma/vmir/buildstatus/master)](https://doozer.io/user/andoma/vmir)

VMIR is a standalone library written in C that can parse and execute:

* WebAssembly `.wasm` files
* LLVM Bitcode `.bc` files

Optionally it can generate machine code (JIT) to speed up execution significantly. JIT is currently only supported on 32 bit ARM.

VMIR is licensed under the MIT license. See [LICENSE](LICENSE).

To build VMIR just type:
```
$ make
```
... and you will end up with a VMIR binary in very same directory.
The library is compiled from a single file [src/vmir.c](src/vmir.c) which in turn include other files to keep the code somewhat separated.


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

Compiling to WebAssembly requires a bit more work than a single line. However,
there is a pre-built version of `sha1sum` included in the source repo.

````
$ echo hello | ./vmir examples/prebuilt/sha1sum.wasm
f572d396fae9206628714fb2ce00f72e94f2258f  -
````


If you're on Linux and want to go all crazy you can use VMIR to execute Bitcode
and WebAssembly directly from the command line by installing a kernel binfmt pointing to the VMIR executable:

```
echo ":vmirwasm:M::\x00\x61\x73\x6d\x01::${PWD}/vmir:" | sudo tee /proc/sys/fs/binfmt_misc/register
echo ":vmirbc:M::\x42\x43\xc0\xde::${PWD}/vmir:" | sudo tee /proc/sys/fs/binfmt_misc/register
```

And then you just simply just do:

```
$ echo hello | examples/prebuilt/sha1sum.wasm
f572d396fae9206628714fb2ce00f72e94f2258f  -
```

### Performance

Interpretation is about 10x slower (on x86) than the same binary compiled as native code. Still it's a lot faster than LLVM's own interpreter (which by all means is not intended to run code fast in any way)

Example run of [test/misc/src/sha1test.c](test/misc/src/sha1test.c)  over 64MB of random data

Environment | (Core i7 3.2GHz) | ARMv7 BCM2709 (Rpi2)
--- | --- | ---
Native | 0.39s | 3.54s
VMIR JIT | n/a | 17.5s
VMIR | 4.8s | 1m 42s
LLVM LLI | 7m 39s | n/a


### Status

VMIR currently passes the gcc torture test suite on optimization level 0, 1 and 2. Those tests can be found in [test/gcc-torture](test/gcc-torture). Use `make && ./runtest` to run the tests.


### Missing features, known bugs

* The built-in libc is lacking a lot of functions and features. This is where most work needs to be done.
* No support for vector types (Ie, code must be compiled with `-fno-vectorize -fno-slp-vectorize`).
* Not all instructions classes / value types are JITed.
* No C++ STL solution. Ideas welcome...


### Compiling C/C++ to Bitcode

VMIR uses the same target as Google NativeClient. There are small examples in [test/misc](test/misc).

When building bigger projects consisting of multiple files you must `llvm-link` to combine the `.bc` files into a single file.

### Compiling C/C++ to WebAssembly

Building for WebAssembly is a bit more involved atm. There is a document here: [docs/wasm.md](docs/wasm.md), that shows how to setup LLVM + Binaryen and the WebAssembly Binary Toolkit. Once you have that in place there are some small examples in [examples/wasm](examples/wasm) that could get you started.

### Embedding VMIR

Including VMIR in your own project is pretty straight forward. Just copy the files from [src/](src/) to your project but only compile [vmir.c](src/vmir.c) (it will include all other .c -files on its own). The API is defined in [vmir.h](src/vmir.h). See [src/main.c](src/main.c) for example how to load and execute binaries.

VMIR's libc also offers an option to use TLSF for memory allocation. The default built-in allocator is a very simple linear search first-fit algorithm.

### Wait? Wut? Why?

You might ask yourself what the purpose of VMIR actually is and why it
even exists?

As with many of these kind of project I just wanted to scratch and itch but
also be able to ship plugins written in C and C++ for another project of mine.

Now with the rise of WebAssembly I intend to focus more on that as the primary
input to VMIR mostly because it's more stable than LLVM's Bitcode, which is
not really meant to be used as a shippable object code.

Given enough time I also hope to improve the JIT engine to be able to emit
code for more architectures (In particular ARMv8 and x86_64).

Follow me on https://twitter.com/andoma
