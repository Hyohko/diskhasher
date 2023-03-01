#!/bin/sh

# DISKHASHER v0.1 - 2022 by Hyohko

##################################
#   GPLv3 NOTICE AND DISCLAIMER
##################################
#
# This file is part of DISKHASHER.
#
# DISKHASHER is free software: you can redistribute it
# and/or modify it under the terms of the GNU General
# Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# DISKHASHER is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General
# Public License along with DISKHASHER. If not, see
# <https://www.gnu.org/licenses/>.

BUILD_DIR=/io/build

if [ -d $BUILD_DIR ]; then
	rm $BUILD_DIR -rf
fi
mkdir $BUILD_DIR
cd $BUILD_DIR

BUILD_MODE=""
case $1 in
    release ) BUILD_MODE=Release ;;
    debug ) BUILD_MODE=Debug ;;
    * ) echo "[*] Default build mode is debug"
	BUILD_MODE=Debug
	;;
esac

/hbb/bin/cmake .. -DCMAKE_BUILD_TYPE=$BUILD_MODE
make -j
if [ $BUILD_MODE == Release ]; then
	strip $BUILD_DIR/diskhasher
fi
mv ./diskhasher $BUILD_DIR/..
rm $BUILD_DIR -rf