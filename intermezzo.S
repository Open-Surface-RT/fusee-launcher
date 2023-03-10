//
// Payload launcher stub.
//

.globl _start

.section ".text"
_start:

    // First, we'll need to move ourselves _out_ of the target area. 
    // We'll copy down into the IRAM.
    // the post relocation code will live at 0x40009000
    ldr r0, =INTERMEZZO_RELOCATED_ADDRESS
    ldr r1, =post_relocation
    ldr r2, =intermezzo_end
    sub r2, r2, r1
    bl  copy

    // Jump to the start of RAM, which should now contain the post-relocation code.
    ldr r0, =INTERMEZZO_RELOCATED_ADDRESS
    bx  r0


.align 4
// executes at 0x40009000 // overwriting stack?
post_relocation:

    // Next, we'll copy our payload down to the appropriate relocaiton address.
    // Relocate part 1 of payload.
    ldr r0, =RELOCATION_TARGET // 0x4000A000
    ldr r1, =PAYLOAD_START_ADDR // 0x4000AE40
    ldr r2, =BEFORE_SPRAY_LENGTH // 0x4E00
    bl  copy

    // Relocated part 2 of payload
    /*
    ldr r0, =RELOCATION_TARGET // 0x4000A000
    ldr r1, =BEFORE_SPRAY_LENGTH // 0x4E00
    add r0, r0, r1 // 0x4000EE00
    ldr r1, =STACK_SPRAY_END // 0x4000F000
    ldr r2, =AFTER_SPRAY_LENGTH
    bl  copy
    */

    // Finally, jump into the relocated target.
    ldr r0, =ENTRY_POINT_ADDRESS // 0x4000A000
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

