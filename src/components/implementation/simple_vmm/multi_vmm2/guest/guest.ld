ENTRY(guest_real_mode_entry)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)


SECTIONS
{
    . = 0x1000;

    .text BLOCK(4K) : ALIGN(4K)
    {
        *(.guest_kernel_initfn*)
        *(.text*)
        *(.rodata*)
    }

    .data BLOCK(4K) : ALIGN(4K)
    {
        KEEP(*( .init_array ));
        KEEP(*(SORT_BY_INIT_PRIORITY( .init_array.* )));
        *(.data*)
    }

    .bss BLOCK(4K) : ALIGN(4K)
    {
        *(.bss*)
    }

    /DISCARD/ :
    {
        *(.fini_array*)
        *(.comment*)
    }
}
