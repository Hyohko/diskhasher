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

# Parallel compile
MAKEFLAGS += -j8

CC := gcc
CCX := g++
COMMONFLAGS := -g -Ofast -Wall -Wextra -Wconversion \
	-fpic -ffunction-sections -fdata-sections \
	-flto -D_GLIBCXX_PARALLEL -march=native
CFLAGS := $(COMMONFLAGS) -frename-registers -fopenmp
CXXFINALFLAGS := -static-libgcc -static-libstdc++
CXXFLAGS = $(CFLAGS) -std=c++2a
LDFLAGS = -Wl,--gc-sections -pie
LIBS = -pthread

SRCS = md5.c sha1.c sha256.c kcapi-kernel-if.c kcapi-md.c kcapi-utils.c
SRCS_CPP = diskhasher.cpp hash.cpp hashclass.cpp

OBJS = $(SRCS:.c=.o)
OBJS_CPP = $(SRCS_CPP:.cpp=.o)

# define the executable file
MAIN = diskhasher

.PHONY: clean

all:    $(MAIN)
	@echo  Diskhasher finished compilation

clang: CC:=clang
clang: CCX:=clang++
clang: CFLAGS:=$(COMMONFLAGS)
clang: CXXFINALFLAGS:=-fopenmp=libomp
clang: $(MAIN)
	@echo $(MAIN) requires libomp - install using "sudo apt install libomp-dev"
	@echo Final binary is not static - most likely must compile on target machine

$(MAIN): $(OBJS) $(OBJS_CPP)
	$(CCX) $(CXXFLAGS) $(CXXFINALFLAGS) $(INCLUDES) $(LDFLAGS) $(LIBS) \
	-o $(MAIN) $(OBJS) $(OBJS_CPP)
	strip --strip-all $(MAIN)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.cpp.o:
	$(CCX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) *.o *~ $(MAIN)
