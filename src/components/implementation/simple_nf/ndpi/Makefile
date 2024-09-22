# Required variables used to drive the compilation process. It is OK
# for many of these to be empty.
#
# The set of interfaces that this component exports for use by other
# components. This is a list of the interface names.
INTERFACE_EXPORTS =
# The interfaces this component is dependent on for compilation (this
# is a list of directory names in interface/)
INTERFACE_DEPENDENCIES = memmgr contigmem netshmem sched nic_netio_rx nic_netio_tx nic_netio_shmem vmm_netio_rx vmm_netio_tx vmm_netio_shmem
# The library dependencies this component is reliant on for
# compilation/linking (this is a list of directory names in lib/)
LIBRARY_DEPENDENCIES = component shm_bm netdefs posix_cap
# Note: Both the interface and library dependencies should be
# *minimal*. That is to say that removing a dependency should cause
# the build to fail. The build system does not validate this
# minimality; that's on you!

COMP_FLAGS= -DNDPI_LIB_COMPILATION
include Makefile.subsubdir
