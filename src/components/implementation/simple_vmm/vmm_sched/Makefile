# Required variables used to drive the compilation process. It is OK
# for many of these to be empty.
#
# The set of interfaces that this component exports for use by other
# components. This is a list of the interface names.
INTERFACE_EXPORTS = vmm_netio_rx vmm_netio_tx vmm_netio_shmem
# The interfaces this component is dependent on for compilation (this
# is a list of directory names in interface/)
INTERFACE_DEPENDENCIES = contigmem netshmem nic_netio_rx nic_netio_tx nic_netio_shmem sched
# The library dependencies this component is reliant on for
# compilation/linking (this is a list of directory names in lib/)
LIBRARY_DEPENDENCIES = ubench component kernel initargs vmrt shm_bm sync time ck
# Note: Both the interface and library dependencies should be
# *minimal*. That is to say that removing a dependency should cause
# the build to fail. The build system does not validate this
# minimality; that's on you!

CFILES+=devices/serial/serial.c
CFILES+=devices/vpci/vpci.c
CFILES+=devices/vpci/vpci_io.c
CFILES+=devices/vpci/virtio_net_vpci.c
CFILES+=devices/vpci/virtio_net_io.c
CFILES+=devices/vpic/vpic.c
CFILES+=devices/vrtc/vrtc.c
CFILES+=devices/vps2/vps2.c

C_OBJS+=$(CFILES:%.c=%.o)
COMP_FLAGS= -mavx -mavx2 -mfma -I$(LIBDIR)/dpdk/dpdk/build/install/include
private:
	cd guest && make && cd ..

include Makefile.subsubdir
