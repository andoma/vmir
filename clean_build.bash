#!/bin/bash

# Clean
cd build
make clean
#make clean_extra

# Remove build dir
cd ..
rm -rf build/

