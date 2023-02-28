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

source "$HOME/.cargo/env"
BUILD_DIR=/io

cd $BUILD_DIR
BUILD_MODE=""
case $1 in
    release )
		ARTIFACT=release
		cargo build --release
		;;
    debug )
		ARTIFACT=debug
		cargo build
		;;
    * ) 
		echo "[*] Default build mode is debug"
		ARTIFACT=debug
		cargo build 
		;;
esac

ARTIFACT_FILE=$BUILD_DIR/target/$ARTIFACT/diskhasher
[ -f $ARTIFACT_FILE ] && mv $ARTIFACT_FILE $BUILD_DIR/diskhasher