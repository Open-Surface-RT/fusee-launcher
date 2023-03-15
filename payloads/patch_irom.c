// based on ipatch_rcm_sample.c provided by ktemkin (https://gist.github.com/ktemkin/825d5f4316f63a7c11ea851a2022415a)
// unmodified copy of original source can also be found at https://github.com/tofurky/tegra30_debrick/payload/ipatch_rcm_sample.c
// ipatch_word(), unipatch_word(), dump_word(), and dump_byte() are more or less unmodified.
// clock/uart initialization and offsets have been consolidated and modified for tegra30

// begin original header
/**
 * Proof of Concept Payload
 * prints out SBK and then enables non-secure RCM 
 *
 * (some code based on coreboot)
 * ~ktemkin
 */
// end original header

#include <stdint.h>
//#include "printf.h"
#include "tegra30_uart.h"
#include "common.h"

#define BOOTROM_START_POST_IPATCH	0xfff01008
#define DESIRED_SECURITY_MODE		3
#define IPATCH_SLOT					1
#define IROM_PATCH_ADDRESS			0xfff022ac

#define PMC_SCRATCH0				(0x50)

/* ipatch hardware */
#define IPATCH_BASE					(0x6001dc00)
#define IPATCH_SELECT				(0x0)
#define IPATCH_REGS					(0x4)
#define APBDEV_PMC_RST_STATUS_0		(0x1b4)

#define PMC_BASE					(0x7000e400)
#define APBDEV_PMC_SCRATCH42_0		(0x144)


#define GPIO_BASE (0x6000d000)
#define GPIO_PORT_A (0x000)
#define GPIO_PORT_B (0x004)
#define GPIO_PORT_BB (0x60C)
#define GPIO_CNF (0x00)
#define GPIO_OE (0x10)
#define GPIO_OUT (0x20)

// General next-stage image entry point type.
typedef void (*entry_point)(void);

void ipatch_word(uint8_t slot, uint32_t addr, uint16_t new_value);

void send_zero();

void send_one();

void send_byte(uint8_t b);

#define BOOTROM_START			0xfff00000
#define BOOTROM_SIZE_T114		0x10000




void main()
{
	entry_point start;

	ipatch_word(IPATCH_SLOT, IROM_PATCH_ADDRESS, 0x2000 | DESIRED_SECURITY_MODE);

	start = (entry_point)BOOTROM_START_POST_IPATCH;
	start();

	//uart_init();

	
	//reg_set(GPIO_BASE + GPIO_PORT_A, GPIO_CNF, 1 << 7);
	/*
	reg_set(GPIO_BASE + GPIO_PORT_A, GPIO_OE, 1 << 7);
	reg_set(GPIO_BASE + GPIO_PORT_A, GPIO_OUT, 1 << 7);
	
	//reg_set(GPIO_BASE + GPIO_PORT_B, GPIO_CNF, 1 << 6);
	reg_set(GPIO_BASE + GPIO_PORT_B, GPIO_OE, 1 << 6);
	reg_set(GPIO_BASE + GPIO_PORT_B, GPIO_OUT, 1 << 6);
	
	uart_print("hello there\r\n");
	send_byte(0x55);
	send_byte(0x55);
	send_byte(0x55);
	send_byte(0x55);
	
	uint8_t *irom_base = (uint8_t*)BOOTROM_START;
	for (uint32_t i = 0; i < BOOTROM_SIZE_T114; i++) {
		send_byte(irom_base[i]);
		for (int i = 0; i < 216000000 / 216 / 55 * 4; i++) {;}
		send_byte(irom_base[i]);
		for (int i = 0; i < 216000000 / 216 / 55 * 4; i++) {;}
		send_byte(irom_base[i]);
		
		// give uart some time to synchronize in case timing is a bit of.
		for (int i = 0; i < 216000000 / 216 / 55 * 4; i++) {;}
	}
	
	uint8_t counter = 0;
	while(1) {
		send_byte(counter++);
		//send_byte(0x55);
		for (int i = 0; i < 6000000; i++) {;}
	}
	
	
	
	//reg_set(PMC_BASE, PMC_SCRATCH0, 2);
	reg_set(PMC_BASE, 0, 0x10);
	

	while(1) {
		uart_print("Hello there :)\r\n");
		for (int i = 0; i < 600000; i++) {
			asm("nop");
		}
	}
	
	
	while(1) {
		;
	}
	*/
}

void send_byte(uint8_t b) {
	// start bit
	send_zero();
	for (int i = 0; i < 216000000 / 216 / 55; i++) {;}
	
	// data
	for (uint32_t i = 0; i < 8; i++) {
		if (b & 1) {
			send_one();
		} else {
			send_zero();
		}
		b >>= 1;
		for (int i = 0; i < 216000000 / 216 / 55; i++) {;}
	}
	
	// stop bit
	send_one();
	for (int i = 0; i < 216000000 / 216 / 55; i++) {;}
}

void send_zero() {
	reg_write(PINMUX_BASE, PINMUX_AUX_SDMMC3_DAT1_0, 0b00000100); /* tx */
	reg_write(PINMUX_BASE, PINMUX_AUX_SDMMC3_CMD_0, 0b00100100); /* rx */
}

void send_one() {
	reg_write(PINMUX_BASE, PINMUX_AUX_SDMMC3_DAT1_0, 0b00000110); /* tx */
	reg_write(PINMUX_BASE, PINMUX_AUX_SDMMC3_CMD_0, 0b00100110); /* rx */
}

/**
 * Patches over a given address in the IROM using the IPATCH hardware.
 */
void ipatch_word(uint8_t slot, uint32_t addr, uint16_t new_value)
{
	uint32_t slot_value;
	uint32_t offset;

	// Mark the relevant ipatch slot as not-in-use.
	reg_clear(IPATCH_BASE, IPATCH_SELECT, (1 << slot));

	// Compute the new patch value.
	offset = (addr & 0xFFFF) >> 1;
	slot_value = (offset << 16) | new_value;

	// Figure out the location of the slot to touch.
	reg_write(IPATCH_BASE, IPATCH_REGS + (slot * 4), slot_value);

	// Apply the new one.
	reg_set(IPATCH_BASE, IPATCH_SELECT, (1 << slot));
}
