#define _REG(base, off) *(volatile unsigned int *)((base) + (off))
#define reg_write(base, off, value) _REG(base, off) = value
#define reg_clear(base, off, value) _REG(base, off) &= ~value
#define reg_set(base, off, value) _REG(base, off) |= value
#define reg_read(base, off) _REG(base, off)
