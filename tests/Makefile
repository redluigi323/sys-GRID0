# Host tests for the virtual network shim.
#
# The shim has no Horizon dependency on purpose, so it can be built and run
# with an ordinary compiler long before a devkitPro toolchain is involved.
#
#   make          build and run
#   make cross    additionally compile for aarch64 to catch alignment and
#                 codegen problems the host build would hide

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Wshadow -Wconversion -Wno-unused-parameter \
            -fno-exceptions -fno-rtti -fsanitize=address,undefined -fno-omit-frame-pointer

SRC := test_vnet.cpp ../source/net/vnet.cpp

.PHONY: all run cross clean

all: run

test_vnet: $(SRC) ../source/net/vnet.hpp ../source/net/net.hpp ../source/net/lifetime.hpp
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)

test_nat_support: test_nat_support.c ../compat/nat/support.c
	$(CC) -std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -o $@ $^

run: test_vnet test_nat_support
	./test_vnet
	./test_nat_support

# The console is aarch64. Unaligned loads and sign-extension differences are the
# usual surprises; compiling with the cross toolchain catches most of them even
# without a way to execute the result.
cross:
	aarch64-linux-gnu-g++ -std=c++17 -O2 -Wall -Wextra -Wconversion \
		-fno-exceptions -fno-rtti -c ../source/net/vnet.cpp -o /tmp/vnet-aarch64.o
	@echo "aarch64 build OK"

clean:
	rm -f test_vnet test_nat_support
	rm -rf test_vnet.dSYM
