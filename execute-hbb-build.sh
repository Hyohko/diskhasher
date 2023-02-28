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
MY_HBB_NAME=hbb_rusty
ACTIVATE=/hbb_exe/activate-exec
MOUNT=/io
RUNSCRIPT=$MOUNT/compile-inside-hbb.sh

if [ ! $(which docker) ]; then
    echo "[!] This script requires docker or the docker alias"
    exit
fi

# podman check
if [[ $(docker --version) == *"podman"* ]]; then
    echo "[!] Building under PodMan, add the ':Z' flag to the mount command"
    MOUNT=$MOUNT:Z
fi

DISTRO=FAIL
case $1 in
    rust | rs ) DISTRO=rs ;;
    cpp ) DISTRO=cpp ;;
    * ) echo "[!] Must specify build [cpp|rust] as the first arg to this script"
        echo "  $0 rs"
        echo "  $0 cpp"
        exit;;
esac

case $2 in
    release ) BUILD_MODE=release ;;
    debug ) BUILD_MODE=debug ;;
    * ) echo "[*] Default build mode is debug";;
esac

if [ ! "$(docker image list | grep $MY_HBB_NAME)" ]; then
    echo "Rebuilding Holy Build Box for Rust, pulling from the Internet"
    docker pull $HBB_NAME:latest
    docker build -f Dockerfile -t $MY_HBB_NAME .
else
    while true; do
    read -p "Holy Build Box: Do you want to check for updates? " yn
    case $yn in
        [Yy]* )
            docker pull $HBB_NAME:latest
            docker build -f ../Dockerfile -t $MY_HBB_NAME ..
            break;;
        [Nn]* )
            break;;
        * ) echo "Please answer yes or no.";;
    esac
done
fi

if [ ! "$(docker ps -a -q -f name=$MY_HBB_NAME)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=$MY_HBB_NAME)" ]; then
        docker rm $MY_HBB_NAME:latest
    fi
    docker run -t -i --rm \
        -v `pwd`/$DISTRO:$MOUNT $MY_HBB_NAME:latest \
        $ACTIVATE \
        bash -x -c "$RUNSCRIPT $BUILD_MODE"
fi


