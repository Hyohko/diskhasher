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

# Parallel compile
MAKEFLAGS += -j8

INC=-I./include -I./spdlog/include
CC := gcc
CCX := g++

#COMMONFLAGS := -g -fsanitize=address -O0 -Wall -Wextra -Wconversion \

COMMONFLAGS := -g -Ofast -Wall -Wextra -Wconversion \
	-pipe -fomit-frame-pointer \
	-msse -msse2 -msse3 -mmmx -m3dnow \
	-fpic -ffunction-sections -fdata-sections \
	-flto -D_GLIBCXX_PARALLEL -march=native $(INC)
CFLAGS := $(COMMONFLAGS) -frename-registers -fopenmp
CXXFINALFLAGS := -static-libgcc -static-libstdc++
CXXFLAGS = $(CFLAGS) -std=c++2a
LDFLAGS = -Wl,--gc-sections -pie
LIBS = -pthread

SRCS = md5.c sha1.c sha256.c sha512.c kcapi-kernel-if.c kcapi-md.c kcapi-utils.c
SRCS_CPP = dkhash.cpp filehash.cpp hash.cpp

OBJS = $(SRCS:.c=.o)
OBJS_CPP = $(SRCS_CPP:.cpp=.o)

# define the executable file
MAIN = dkhash

.PHONY: clean

all:    $(MAIN)
	@echo  dkhash finished compilation

clang: CC:=clang
clang: CCX:=clang++
clang: CFLAGS:=$(COMMONFLAGS)
clang: CXXFINALFLAGS:=-fopenmp=libomp
clang: $(MAIN)
	@echo $(MAIN) requires libomp - install using "sudo apt install libomp-dev"
	@echo Final binary is not static - most likely must compile on target machine
	@$(MAKE)

$(MAIN): $(OBJS) $(OBJS_CPP)
	$(CCX) $(CXXFLAGS) $(CXXFINALFLAGS) $(INCLUDES) $(LDFLAGS) $(LIBS) \
	-o $(MAIN) $(OBJS) $(OBJS_CPP)
# strip --strip-all $(MAIN)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.cpp.o:
	$(CCX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) *.o *~ $(MAIN)
