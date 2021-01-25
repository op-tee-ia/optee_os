# Script to build the optee-os image
# Usage: ./generate_prebuilt.sh
#
#!/bin/sh
#set -v -x
TOOLCHAIN_PATH=$(cd `dirname $0`; pwd)/toolchain

# set the toolchain path
X64_TOOLCHAIN_PATH=${TOOLCHAIN_PATH}/gcc/x86_64-linux-android-4.9/bin
export PATH=$PATH:${X64_TOOLCHAIN_PATH}
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-android-
export CROSS_COMPILE64=x86_64-linux-android-

# Set below definition to overwrite default log level 1
export CFG_TEE_CORE_LOG_LEVEL=3
export DEBUG=1
export CFG_TEE_BENCHMARK=n

export PLATFORM=tgl

# You can give options to make-command.
# E.g. "build.sh -j4" for parallel compiling
make -j5

if [ $? -ne 0 ]; then
	echo "Error: make optee-os failed." && exit 1
fi

dd if=out/x86_64-plat-tgl/core/tee-pager_v2.bin ibs=1M count=1 of=tee-pager_v2_padding.bin conv=sync

