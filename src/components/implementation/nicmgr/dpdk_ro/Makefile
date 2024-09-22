# Required variables used to drive the compilation process. It is OK
# for many of these to be empty.
#
# The set of interfaces that this component exports for use by other
# components. This is a list of the interface names.
INTERFACE_EXPORTS = nic_netio_rx nic_netio_tx nic_netio_shmem 
# The interfaces this component is dependent on for compilation (this
# is a list of directory names in interface/)
INTERFACE_DEPENDENCIES = netshmem
# The library dependencies this component is reliant on for
# compilation/linking (this is a list of directory names in lib/)
LIBRARY_DEPENDENCIES = component dpdk shm_bm ck sync time
# Note: Both the interface and library dependencies should be
# *minimal*. That is to say that removing a dependency should cause
# the build to fail. The build system does not validate this
# minimality; that's on you!

COMP_FLAGS= -mavx -mavx2 -mfma

include Makefile.subsubdir
