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
#include "printf.h"
#include "common.h"

#define BOOTROM_START_POST_IPATCH	0xfff01004
#define DESIRED_SECURITY_MODE		3
#define IPATCH_SLOT					1
#define IROM_PATCH_ADDRESS			0xfff01CD4
#define PMC_SCRATCH0				(0x50)

/* ipatch hardware */
#define IPATCH_BASE					(0x6001dc00)
#define IPATCH_SELECT				(0x0)
#define IPATCH_REGS					(0x4)
#define APBDEV_PMC_RST_STATUS_0		(0x1b4)

#define PMC_BASE					(0x7000e400)
#define APBDEV_PMC_SCRATCH42_0		(0x144)


// General next-stage image entry point type.
typedef void (*entry_point)(void);

void ipatch_word(uint8_t slot, uint32_t addr, uint16_t new_value);

void main()
{
	entry_point start;
	
	printf("Hello there :)\r\n");

	reg_write(PMC_BASE, APBDEV_PMC_SCRATCH42_0, 0);


	/* Patch the getSecurityMode function to always return 3 (production non-secure). */
	printf("overriding getSecurityMode function to always return 3 (production non-secure)...\r\n");
	ipatch_word(IPATCH_SLOT, IROM_PATCH_ADDRESS, 0x2000 | DESIRED_SECURITY_MODE);

	/* Clear bit0 to indicate that this is a fresh boot, and then set bit2 to trigger RCM. */
	printf("writing PMC_SCRATCH0 to trigger RCM mode after soft reset...\r\n");
	reg_write(PMC_BASE, PMC_SCRATCH0, (1 << 1)); // wrong 2));

	printf("jumping to 0xfff01004...\r\n");
	reg_write(PMC_BASE, APBDEV_PMC_SCRATCH42_0, 0);
	/* Jump back into the bootloader immediately after ipatches are applied
	   to simulate a normal coldboot as best we can. :) */
	start = (entry_point)BOOTROM_START_POST_IPATCH;
	start();
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
