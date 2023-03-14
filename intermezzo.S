//
// Payload launcher stub.
//

.globl _start

.section ".text"
//.section ".textrwx", "awx"
_start:
    // First, we'll need to move ourselves _out_ of the target area. 
    // We'll copy down into the IRAM.
    // the post relocation code will live at -0x1000
    ldr r0, #intermezzo_reloc_addr
    ldr r1, #post_relocation
    mov r2, #(intermezzo_end - post_relocation)
    //sub r2, r2, r1
    bl  copy

    // Jump to the start of RAM, which should now contain the post-relocation code.
    ldr r0, #intermezzo_reloc_addr
    bx  r0


.align 4
// executes at 0x40009000 // overwriting stack?
post_relocation:
    // Relocate part 1 of payload.
    ldr r0, #rcm_payload_start // 0x4000A000
    ldr r1, #payload_start // 0x4000AE40
    ldr r2, #payload_size1 // 0x4E00
    bl  copy

    // Relocated part 2 of payload
    // r0 points to right address after the first part of payload after copy
    ldr r1, #spray_end // 0x4E00
    ldr r2, #payload_size2
    bl  copy

    // Finally, jump into the relocated target.
    ldr r0, #rcm_payload_start // 0x4000A000
    bx r0


//
// Simple block copy.
//   r0 = destination address
//   r1 = source address
//   r2 = length in bytes
// Destroys r0-r3.
//
copy:

    // Copy the word...
    ldr r3, [r1], #4
    str r3, [r0], #4

    // And continue while we have words left to copy.
    subs r2, r2, #4
    bne copy

    // Once we're done, return.
    bx lr

.align 8, 0 // pad to 2^8 = 256 = 0x100

    .globl intermezzo_reloc_addr
intermezzo_reloc_addr:
    .word 0x40009000

    .globl rcm_payload_start
rcm_payload_start:
    .word 0x4000A000

    .globl payload_start
payload_start:
    .word 0x4000AE40

    .globl payload_size1
payload_size1:
    .word 0x300

    .globl spray_end
spray_end:
    .word 0x4000b000

    .globl payload_size2
payload_size2:
    .word 0x450

    .globl intermezzo_end
intermezzo_end:
