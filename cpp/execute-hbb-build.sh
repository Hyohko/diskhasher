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

HBB_NAME=phusion/holy-build-box-64
ACTIVATE=/hbb_exe/activate-exec
MOUNT=/io
RUNSCRIPT=$MOUNT/compile-inside-hbb.sh

if [ ! $(which docker) ]; then
    echo "This script requires docker"
    exit
fi

if [ ! "$(docker image list | grep $HBB_NAME)" ]; then
    echo "Holy Build Box 64 not found, pulling from the Internet"
    docker pull $HBB_NAME:latest
else
    while true; do
    read -p "Holy Build Box: Do you want to check for updates? " yn
    case $yn in
        [Yy]* ) docker pull $HBB_NAME:latest; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done
fi

if [ ! "$(docker ps -a -q -f name=$HBB_NAME)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=$HBB_NAME)" ]; then
        docker rm $HBB_NAME:latest
    fi
    docker run -t -i --rm \
        -v `pwd`:$MOUNT $HBB_NAME:latest \
        $ACTIVATE \
        bash -x -c $RUNSCRIPT
    strip --strip-all ./diskhasher
fi


