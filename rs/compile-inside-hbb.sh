#!/bin/sh

# DISKHASHER v0.2 - 2023 by Hyohko

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

source "$HOME/.cargo/env"
BUILD_DIR=/io

cd $BUILD_DIR
BUILD_MODE=""
case $1 in
    native )
        echo "[+] Building release mode against native CPU architecture"
        ARTIFACT=release
        export RUSTFLAGS='-C target-cpu=native'
        cargo build --release
        ;;
    release )
        echo "[+] Building release mode"
        ARTIFACT=release
        cargo build --release
        ;;
    debug )
        echo "[+] Building debug mode"
        ARTIFACT=debug
        cargo build
        ;;
    * )
        echo "[!] Must specify build [native|debug|release] to the internal"
        echo "  $0 native"
        echo "  $0 debug"
        echo "  $0 release"
        exit
        ;;
esac

ARTIFACT_FILE=$BUILD_DIR/target/$ARTIFACT/diskhasher
[ -f $ARTIFACT_FILE ] && mv $ARTIFACT_FILE $BUILD_DIR/diskhasher