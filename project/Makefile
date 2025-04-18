
RISCV_GNU_TOOLCHAIN_GIT_REVISION = 411d134
RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX = /opt/riscv32

# Give the user some easy overrides for local configuration quirks.
# If you change one of these and it breaks, then you get to keep both pieces.
SHELL = bash
PYTHON = python3
TOOLCHAIN_PREFIX = $(RISCV_GNU_TOOLCHAIN_INSTALL_PREFIX)i/bin/riscv32-unknown-elf-

picorv32.txt: picorv32.bin makehex.py
	$(PYTHON) makehex.py $< 4096 'hex' > $@
 
picorv32.hex: picorv32.bin makehex.py
	$(PYTHON) makehex.py $< 4096 'hex' > $@
 
picorv32.mif: picorv32.bin makehex.py
	$(PYTHON) makehex.py $< 4096 'mif' > $@
	
picorv32.bin: picorv32.elf
	$(TOOLCHAIN_PREFIX)objcopy -O binary $< $@
	chmod -x $@
	
picorv32.elf: irq.o start.o main.o sections.lds
	$(TOOLCHAIN_PREFIX)gcc -mabi=ilp32 -march=rv32i -ffreestanding -nostdlib -o $@ \
		-Wl,--build-id=none,-Bstatic,-T,sections.lds,-Map,sections.map,--strip-debug \
		irq.o start.o main.o -lgcc
	chmod -x $@
	
start.o: start.S
	$(TOOLCHAIN_PREFIX)gcc -c -mabi=ilp32 -march=rv32i -o $@ $<

main.o: main.c main.h
	$(TOOLCHAIN_PREFIX)gcc -c -mabi=ilp32 -march=rv32i -Os --std=c99 $(GCC_WARNS) -ffreestanding -nostdlib -o $@ $<
	
irq.o: irq.c irq.h
	$(TOOLCHAIN_PREFIX)gcc -c -mabi=ilp32 -march=rv32i -Os --std=c99 $(GCC_WARNS) -ffreestanding -nostdlib -o $@ $<

clean:
	rm -vrf *.o *.bin *.elf *.map *.hex *.mif *.txt

.PHONY: clean
