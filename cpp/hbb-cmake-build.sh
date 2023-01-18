#!/bin/sh

CURDIR=$(pwd)

docker run -t -i --rm \
  -v `pwd`:/io \
  phusion/holy-build-box-64:latest \
  /hbb_exe/activate-exec \
  bash -x -c '/io/run-cmake-hbb.sh'

strip --strip-all ./diskhasher

cd $CURDIR