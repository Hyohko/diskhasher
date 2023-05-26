#!/bin/sh

# DKHASH - 2023 by Hyohko

##################################
#   GPLv3 NOTICE AND DISCLAIMER
##################################
#
# This file is part of DKHASH.
#
# DKHASH is free software: you can redistribute it
# and/or modify it under the terms of the GNU General
# Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# DKHASH is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General
# Public License along with DKHASH. If not, see
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
	strip $BUILD_DIR/dkhash
fi
mv ./dkhash $BUILD_DIR/..
rm $BUILD_DIR -rf