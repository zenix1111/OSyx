/* winrun: the Windows runtime. Linked at 1 GiB instead of the usual 4 MiB
   so its code and data stay below 4 GiB, where 32-bit (PE32) code in
   compatibility mode can reach them. PE32 images keep their own linked
   base of 4 MiB. Three W^X segments; the first also maps the ELF and
   program headers (the kernel passes their address as AT_PHDR). */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FILEHDR PHDRS FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x40000000 + SIZEOF_HEADERS;

    .text :
    {
        *(.text._start)
        *(.text .text.*)
    } :text

    . = ALIGN(4K);
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
    } :rodata

    . = ALIGN(4K);
    .data : ALIGN(4K)
    {
        *(.data .data.*)
    } :data

    .bss : ALIGN(16)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr .eh_frame.*)
        *(.note .note.*)
        *(.comment)
    }
}
