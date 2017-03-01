
### LLVM setup


The instructions for setting up LLVM are borrowed from [here](https://gist.github.com/yurydelendik/4eeff8248aeb14ce763e)

````

# locations, e.g.
export WORKDIR=~/wasm
export INSTALLDIR=$WORKDIR/llvm-inst
mkdir -p $INSTALLDIR

# checkout LLVM
cd $WORKDIR
svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm

# checkout clang
cd $WORKDIR/llvm/tools
svn co http://llvm.org/svn/llvm-project/cfe/trunk clang

# build folder (~14 min; ~1 hour /wo -j)
mkdir $WORKDIR/llvm-build
cd $WORKDIR/llvm-build
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=$INSTALLDIR -DLLVM_TARGETS_TO_BUILD= -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=WebAssembly $WORKDIR/llvm
make -j 8

# install llvm
make install


````

### Build and install binaryen


````
cd $WORKDIR
git clone https://github.com/WebAssembly/binaryen.git
mkdir -p binaryen/build
cd binaryen/build

cmake -DCMAKE_INSTALL_PREFIX=$WORKDIR -DCMAKE_BUILD_TYPE=Debug  ..
make -j8
make install
````


### Build and install webassembly binary toolkit

````
cd $WORKDIR
git clone https://github.com/WebAssembly/wabt.git
mkdir -p wabt/build
cd wabt
git submodule update --init
cd build

cmake -DCMAKE_INSTALL_PREFIX=$WORKDIR ..
make -j8
make install

````

Once this is done you need to add the installed tools to your path:

````
export PATH=$PATH:$WORKDIR/bin
export WASM_TOOLCHAIN=$WORKDIR/llvm-inst/bin/
````

If all went fine you shold be able to compile the examples in the
[examples/wasm](../examples/wasm) folder.