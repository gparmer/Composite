#!/bin/bash

if [ $# -lt 2 ]; then
  echo "Usage: $0 <.../cos.iso > <arch: [x86_64|i386]> [debug]"
  exit 1
fi 

num_sockets=1
num_cores=16
num_threads=1
vcpus=$[${num_sockets}*${num_cores}*${num_threads}]
mem_size=9000
kvm_flag=""

arch=$2
debug_flag=$3
nic_flag=$4

if [ ! -f $1 ]
then
	echo "Cannot find the image iso"
	exit 1
fi

case ${arch} in
	x86_64 )
	;;
	i386 )
	;;
	* )
	echo "Unsupported architecture"
	exit 1
esac

if [ -e "/dev/kvm" ] && [ -r "/dev/kvm" ] && [ -w "/dev/kvm" ]
then
	kvm_flag="-enable-kvm"
fi

if [ "${debug_flag}" == "debug" ]
then
	debug_flag="-S"
	if [ "${nic_flag}" == "enable-nic" ]
	then
		nic_flag=" -netdev type=tap,id=net0,vhost=on,ifname=tap0,script=no,downscript=no -device vmxnet3,netdev=net0,mac=66:66:66:66:66:66 "
	fi
elif [ "${debug_flag}" == "enable-nic" ]
then
	debug_flag=""
	nic_flag=" -netdev type=tap,id=net0,vhost=on,ifname=tap0,script=no,downscript=no -device vmxnet3,netdev=net0,mac=66:66:66:66:66:66 "
fi

if [ "${arch}" == "x86_64" ]
then
	qemu-system-x86_64 ${kvm_flag} -cpu max -smp ${vcpus},cores=${num_cores},threads=${num_threads},sockets=${num_sockets} -m ${mem_size} -cdrom $1 -no-reboot -nographic -s ${debug_flag} -nic none ${nic_flag}
elif [ "${arch}" == "i386" ]
then
	qemu-system-i386 ${kvm_flag} -cpu max -smp ${vcpus},cores=${num_cores},threads=${num_threads},sockets=${num_sockets} -m ${mem_size} -cdrom $1 -no-reboot -nographic -s ${debug_flag} ${nic_flag}
else
	echo "Unsupported arch!"
fi
