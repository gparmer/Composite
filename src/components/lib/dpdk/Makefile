DPDK_DIR		= dpdk
DPDK_BUILD_DIR		= $(DPDK_DIR)/build
DPDK_INSTALL_DIR	= $(DPDK_BUILD_DIR)/install
DPDK_INC_DIR		= $(DPDK_INSTALL_DIR)/include
DPDK_LIBS_DIR		= $(DPDK_INSTALL_DIR)/lib

LIBRARY_OUTPUT = dpdk

OBJECT_OUTPUT =

INCLUDE_PATHS = . adapter dpdk/build/install/include

INTERFACE_DEPENDENCIES =

LIBRARY_DEPENDENCIES = component pci posix_cap posix_sched netdefs

# this is to stop non supported build target
# this will override $(OBJS) so that compiler will not compile target files under unsupported cases
ifneq ($(PLATFORM),x86_64)
override OBJS =
endif

CFILES+=$(wildcard adapter/*.c)
SFILES+=$(wildcard adapter/*.S)

include Makefile.lib

OBJS+=$(DPDK_LIBS_DIR)/*.a

CINC+=$(foreach I, $(INCLUDE_PATHS), -I$(I))

.PHONY: all config install clean distclean init build 

# This adapter include path is needed because meson build needs a absolute path name
DPDK_ADAPTER_INC = -I$(shell pwd)/adapter

DISABLED_DRIVERS=-Ddisable_drivers=common/mvep,common/mlx5,af_xdp,net/ipn3ke,net/mlx4,net/mlx5,net/mvneta,net/mvpp2,$\
	net/nfb,net/szedata2,raw/ifpga,crypto/aesni_gcm,crypto/aesni_mb,crypto/ccp,crypto/kasumi,crypto/mvsam,$\
	crypto/openssl,crypto/snow3g,crypto/zuc,compress/isal,crypto/bcmfs,crypto/caam_jr,crypto/cnxk,crypto/dpaa_sec,$\
	crypto/dpaa2_sec,crypto/nitrox,crypto/null,crypto/octeontx,crypto/octeontx2,crypto/scheduler,crypto/virtio,$\
	compress/octeontx,compress/zlib,regex/octeontx2,vdpa/ifc,event/cnxk,event/dlb2,event/dsw,event/opdl,event/skeleton,$\
	event/sw,baseband/acc100,baseband/fpga_5gnr_fec,baseband/fpga_lte_fec,baseband/null,baseband/turbo_sw,raw/cnxk_bphy,$\
	raw/dpaa2_cmdif,raw/dpaa2_qdma,raw/ioat,raw/ntb,raw/octeontx2_dma,raw/octeontx2_ep,raw/skeleton,common/cpt,common/dpaax,$\
	common/octeontx,common/octeontx2,common/cnxk,common/qat,common/sfc_efx,bus/auxiliary,bus/dpaa,bus/fslmc,$\
	bus/ifpga,net/af_packet,net/ark,net/atlantic,net/avp,net/axgbe,net/bnx2x,net/bnxt,net/bond,net/cxgbe,net/ena,net/enic,$\
	net/failsafe,net/fm10k,net/hinic,net/hns3,net/igc,net/ionic,net/ixgbe,net/kni,net/liquidio,net/memif,net/nfp,$\
	net/ngbe,net/null,net/pcap,net/qede,net/softnic,net/thunderx,net/txgbe,net/vdev_netvsc,baseband/la12xx,dma/idxd,dma/ioat,$\
	dma/skeleton,net/octeontx_ep,

MUSL_BIN_PATH = PATH=$(shell pwd)/../libc/musl-1.2.0/bin/:$(PATH)
config: 
	$(info Configing DPDK)
#	TODO: make this copy more generic so that it can be applied to different OS platforms like Fedora
	mkdir -p $(DPDK_INC_DIR);
#	Even though we have MUSL, DPDK still rely on some definitions from the GNU lib
	find /usr/lib/gcc/x86_64-linux-gnu/$(shell gcc --version | grep ^gcc | sed 's/^.* //g' | awk -F. '{print $$1}')/include/ -iname "*.h" | grep -v "std.*" | xargs cp -rft $(DPDK_INC_DIR)
	cd ../libc/musl-1.2.0/include; \
	cp -rf /usr/include/linux/ ./; \
	cp -rf /usr/include/asm-generic/ ./; \
	cp -rf /usr/include/x86_64-linux-gnu/asm/ ./; \
	cp -rf /usr/include/x86_64-linux-gnu/sys/queue.h ./sys

	cd $(DPDK_DIR);\
	$(MUSL_BIN_PATH) meson build \
	--cross-file $(shell pwd)/cross_x86_64_composite_with_musl \
	-Dmachine=default -Dc_args="-nostdlib -nostdinc -mcmodel=large -DCOMPOSITE_EXISTS $(DPDK_ADAPTER_INC)" \
	-Ddefault_library=static -Ddebug=false \
	-Doptimization=3 -Dincludedir=$(shell pwd)/$(DPDK_INC_DIR) \
	-Dprefix=$(shell pwd)/$(DPDK_INSTALL_DIR) $(DISABLED_DRIVERS)
build:
	$(info Building DPDK)
ifneq ($(PLATFORM),x86_64)
	@echo "Platform: $(PLATFORM) is not supported in DPDK"
else
	@cd $(DPDK_BUILD_DIR);\
	$(MUSL_BIN_PATH) ninja -j3;\
	meson install >> /dev/null;
	@rm -f libdpdk.a || true
endif

$(SHLIB_FILE): build $(OBJS)
CFLAGS+=-mfma -DCOMPOSITE_EXISTS -Wno-deprecated-declarations

armv7a_init:

i386_init:

x86_64_init: config build

platform_init:
	make $(PLATFORM)_init

init: platform_init

distclean:
	cd $(DPDK_BUILD_DIR) ninja clean
	cd $(DPDK_DIR); rm -rf build
	rm -f *.d *.o *.a
clean:
	$(info cleaning DPDK)
	rm -f *.d *.o *.a
