
CROSS_COMPILE = arm-none-eabi-

# Use our cross-compile prefix to set up our basic cross compile environment.
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

CFLAGS = \
	-mtune=arm7tdmi \
	-mlittle-endian \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall \
	-Wno-error=unused-function \
	-fomit-frame-pointer \
	-g \
	-O0

LDFLAGS = -nostdlib -L /usr/lib/gcc/arm-none-eabi/9.2.1 -lgcc -Map=$(basename $@).map

OBJS = tegra30_uart.o # printf.o

ENTRY_POINT_ADDRESS := 0x4000E000

# Provide the definitions used in the intermezzo stub.
DEFINES := \
	-DENTRY_POINT_ADDRESS=$(ENTRY_POINT_ADDRESS)

all: patch_irom.bin dump-sbk-via-usb.bin

%.elf: %.o $(OBJS)
	$(LD) $^ -T common.lds --defsym LOAD_ADDR=$(ENTRY_POINT_ADDRESS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.S
	$(CC) $(CFLAGS) $< -c -o $@

%.bin: %.elf
	$(OBJCOPY) -v -O binary $< $@

clean:
	rm -f *.o *.elf *.bin *.map

.PHONY: all clean
