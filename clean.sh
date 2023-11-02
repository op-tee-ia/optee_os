# Script to build the optee-os image
# Usage: ./clean.sh
#
#!/bin/sh
#set -v -x

# set the toolchain path
export ARCH=x86_64
export CROSS_COMPILE=
export CROSS_COMPILE64=

export PLATFORM=standalonevm

make clean -j4

if [ $? -ne 0 ]; then
	echo "Error: make clean optee-os failed." && exit 1
fi

