#!/bin/sh

BUILD_DIR=/io/build

if [ -d $BUILD_DIR ]; then
	rm $BUILD_DIR -rf
fi
mkdir $BUILD_DIR
cd $BUILD_DIR

/hbb/bin/cmake ..

make

