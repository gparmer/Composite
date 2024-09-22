CC := gcc -m64
LD := ld -m elf_x86_64 --nmagic
AS := as --64 -g

CFLAGS  := -g -O0 -ffreestanding -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -nostdinc -nostdlib -fno-pic -mno-red-zone -mcmodel=large -mno-sse -mno-sse2 -mgeneral-regs-only 
LDFLAGS := -nostdlib -fno-builtin -nostartfiles -nostdinc -nodefaultlibs

GUEST_ELF = guest.elf
GUEST_IMG = guest.img
GUEST_MAP = guest.map

AS_FILES = guest_realmode.S
AS_OBJS = $(patsubst %.S,%.o,$(AS_FILES))

WARNINGS += -Wall
WARNINGS += -Wcast-align
WARNINGS += -Wformat=2
WARNINGS += -Winit-self
WARNINGS += -Wnested-externs
WARNINGS += -Wno-system-headers
WARNINGS += -Wold-style-definition
WARNINGS += -Wredundant-decls
WARNINGS += -Wsign-compare
WARNINGS += -Wstrict-prototypes
WARNINGS += -Wundef
WARNINGS += -Wvolatile-register-var
WARNINGS += -Wwrite-strings
WARNINGS += -Wno-address-of-packed-member

CFLAGS += $(WARNINGS)

all: $(GUEST_IMG)

%.o: %.S
	$(CC) $(CFLAGS) -I. -o $@ -c $<

$(GUEST_IMG):$(GUEST_ELF)
	@echo "[CT] $@"
	@cp $< $@
	@objcopy  $@ -O binary

$(GUEST_ELF):$(AS_OBJS)
	@echo "[LD] $@"
	$(LD) $(LDPARAMS) -static -Map=$(GUEST_MAP) -T guest.ld -o $(GUEST_ELF) $(AS_OBJS)

clean:
	@rm -f $(GUEST_ELF) $(GUEST_IMG) $(GUEST_MAP) *.o