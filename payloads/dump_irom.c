#include <stdint.h>
#include "printf.h"
#include "tegra30_uart.h"
#include "common.h"

#define BOOTROM_START			0xfff00000
#define BOOTROM_SIZE_T20_30		0xC000
#define BOOTROM_SIZE_T114		0x10000

#define TEGRA_APB_MISC_BASE		0x70000000
#define APB_MISC_GP_HIDREV_0		0x804

enum tegra_chipid {
	TEGRA_CHIPID_UNKNOWN = 0,
	TEGRA_CHIPID_TEGRA2 = 0x20,
	TEGRA_CHIPID_TEGRA3 = 0x30,
	TEGRA_CHIPID_TEGRA11 = 0x35,
};

void dump_memory(uint8_t *src, uint32_t size);

void main()
{
	printf("Dump irom\r\n");
	
	uint32_t chipid_reg = reg_read(TEGRA_APB_MISC_BASE, APB_MISC_GP_HIDREV_0);
	uint32_t chipid = (chipid_reg >> 8) & 0xff;
	printf("chip_id: 0x%02x\r\n", chipid);
	switch(chipid) {
		case TEGRA_CHIPID_TEGRA2:
		case TEGRA_CHIPID_TEGRA3:
			dump_memory((uint8_t *)BOOTROM_START, BOOTROM_SIZE_T20_30);
			break;
		case TEGRA_CHIPID_TEGRA11:
			dump_memory((uint8_t *)BOOTROM_START, BOOTROM_SIZE_T114);
			break;
	}

	printf("bye.\r\n");

	while(1);
}

void dump_memory(uint8_t *src, uint32_t size) {
	printf("Dump %u Bytes from %p:\r\n", size, src);
	printf("            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\r\n");
	
	for (uint32_t i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("%p: ", &src[i]);
		}
		
		printf("%02x ", src[i]);
		
		if (i % 16 == 15) {
			printf("\r\n");
		}
	}
}
