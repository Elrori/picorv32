/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.
*/

ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 0x1000
}

SECTIONS {
    .text :
    {
		*(.text.entry)
        *(.text._start)
		*(.text*)
        . = ALIGN(4);
    } > RAM

    .data :
    {
        *(.data)
        . = ALIGN(4);
    } > RAM

    .bss :
    {
        *(.bss)
        . = ALIGN(4);
    } > RAM

    _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}