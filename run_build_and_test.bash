#!/bin/bash

# Clean
./clean_build.bash

# Build
mkdir build
cd build
cmake .. 
make -j

# Run test
ctest

