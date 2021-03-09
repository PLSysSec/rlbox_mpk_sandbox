/* Adapted from NaCl trampolines & springboards */

#include "trampoline_asm_inc_32.S"

/* Modify the return target of this function
 *
 * param1: sandbox frame address 0x4(%esp)
 * param2: return value 0xc(%esp)
 *
 */
.globl set_return_target
.type set_return_target,@function
.align 16
set_return_target:
_set_return_target:
        mov 0x4(%esp), %eax
        mov 0xc(%esp), %ecx
        mov %ecx, 0x4(%eax)
        ret

/* Function called in the callback trampoline.
 * This function switches to the application stack part way though
 * the execution of a C function (copying its local variables etc).
 *
 * param1: application stack (rsp2 = 0x4($esp))
 * param2: param_spill_size + return slot size (r_psize = 0xc($esp))

rs_old = esp
r_t (edx) = ebp - esp + r_psize
r_rsp2mint (eax) = rsp2 - r_t
memcpy(r_rsp2mint (eax), esp, r_t)
esp = r_rsp2mint (unspill to edx)
ebp = rsp2 - r_psize
return rs_old (ecx)
 */
 .globl save_sbx_stack_and_switch_to_app_stack
.type save_sbx_stack_and_switch_to_app_stack,@function
.align 16
save_sbx_stack_and_switch_to_app_stack:
_save_sbx_stack_and_switch_to_app_stack:
        // Save esp
        mov %esp, %ecx

        /* Compute r_t and push*/
        mov %ebp, %edx
        sub %esp, %edx
        add 0xc(%esp), %edx
        push %edx

        /* push old stack */
        push %ecx

        /* Compute r_rsp2mint and push */
        mov 0xc(%esp), %eax
        sub %edx, %eax
        push %eax

        /* Setup memcpy call */
        call memcpy@PLT
        /* Save the current sandbox stack return frame  */
        call    get_sandbox_current_thread_sbx_ctx@PLT
        movl    0x0(%eax), %ecx
        movl    %ebp, 0xc8(%ecx)
        addl    $0x8, 0xc8(%ecx)

        /* rsp2mint is now in %edx */
        pop %edx
        /* Remove old param from stack */
        pop %ecx
        /* Get val of old stack in eax return */
        pop %eax

        mov 0x4(%esp), %ebp
        sub 0xc(%esp), %ebp

        mov %edx, %esp
        ret


__x86.get_pc_thunk.ax:
        .cfi_startproc
        movl (%esp), %eax
        ret
        .cfi_endproc

.section .rodata, "a"
        /*
         * This is the memory block for "fxrstor" to read.  The only
         * contents that matter are the fcw and mxcsr words, which we
         * store separately.  The mxcsr_mask word is ignored by the
         * hardware, so there is no need to get the hardware-supplied
         * value for that.  The hardware requires that this address be
         * aligned to 16 bytes.  Align it further to 64 bytes because
         * that is the usual size of a cache line; this might help
         * performance and is very unlikely to hurt it.
         */
        .balign 64
fxrstor_default_state:
        .space 512
        /*
         * This is the memory block for "frstor" to read.  It matters that
         * some of these words have the expected nonzero values, so it's
         * not possible to reuse the fxrstor_default_state space for this
         * too.  The bit pattern below is the usual default state.
         */
frstor_default_state:
        .long 0xffff037f  /* x87 control word */
        .long 0xffff0000  /* x87 status word */
        .long 0xffffffff  /* x87 tag word */
        .long 0           /* x87 IP offset */
        .long 0           /* x87 IP selector */
        .long 0           /* x87 operand pointer offset */
        .long 0xffff0000  /* x87 operand pointer selector */
        /*
         * This is better written as: .space 108 - (. - frstor_default_state).
         * But the LLVM assembler (used on MacOS and in Clang builds on
         * Linux) is buggy and does not support that use of label arithmetic.
         * Reported as: http://llvm.org/bugs/show_bug.cgi?id=15315
         */
        .space 108 - (7 * 4)

