# Script to build the optee-os image
# Usage: ./build_qemu_release.sh
#
#!/bin/sh
#set -v -x

export ARCH=x86_64
export CROSS_COMPILE=
export CROSS_COMPILE64=

# Set below definition to overwrite default log level 1
export CFG_TEE_CORE_LOG_LEVEL=1
export DEBUG=0
export CFG_TEE_CORE_DEBUG=n
export CFG_TEE_BENCHMARK=n
export PLATFORM=qemu

make -j4

if [ $? -ne 0 ]; then
	echo "Error: make optee-os failed." && exit 1
fi

