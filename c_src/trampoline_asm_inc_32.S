.text
.globl context_switch_to_sbx_func
.type context_switch_to_sbx_func,@function
.align 16
context_switch_to_sbx_func:
_context_switch_to_sbx_func:
        /* Stage 0: Copy all app stack parameters to sandbox stack
        expected to be completed before invocation */

        /* Stage 1: Save application register state */
        /* Load param 1 first */
        movl    0x4(%esp), %ecx
        movl    0x8(%ecx), %ecx

        /* save the esp of the application */
        movl    %esp, 0xc8(%ecx)

        /* Save the return address of the app */
        movl    0x0(%esp), %eax
        movl    %eax, 0xb8(%ecx)


        /* Callee save registers */
        movl    %ebx, 0x00(%ecx)
        movl    %ebp, 0x08(%ecx)
        movl    %edi, 0x30(%ecx)
        movl    %esi, 0x38(%ecx)

        /* fp control word is callee save */
        fnstcw  0x68(%ecx)
        /* mxcsr is caller save, but we need to clear it to prevent leaking app
         * state to sbx. But we don't have an easy way to return it to default
         * so just treat it as calee save
         */
        stmxcsr 0x70(%ecx)

        /* Stage 2: Load sandbox register state */
        /* Load param 1 first */
        movl    0x4(%esp), %ecx
        movl    0xc(%ecx), %ecx

        /* Clear non parameter gpr registers to prevents leaks */
        xor    %ebx, %ebx
        xor    %edi, %edi
        xor    %esi, %esi

        call __x86.get_pc_thunk.ax /* PIC support */

        /* Clear the x87, MMX, and SSE state. */
        fxrstor fxrstor_default_state-.(%eax)
        /* Clear the AVX state that the "fxrstor" instruction doesn't cover. */
        vzeroupper

        /* Restore the untrusted code's x87 and SSE control words. */
        fldcw   0x68(%ecx)
        ldmxcsr 0x70(%ecx)

        /* load the rsp of the sandbox and set the return address to the trampoline done label */
        movl    0xc8(%ecx), %esp

        leal    context_switch_to_sbx_func_done, %eax

        movl    %eax, 0x0(%esp)

        /* Clear scratch gpr registers */
        xor    %eax, %eax

        /* Stage 3: Perform the call */
        /* Move the target into ecx*/
        movl    0xb8(%ecx), %ecx
        jmp     *%ecx

context_switch_to_sbx_func_done:
        /* Stage 4: Restore application register state */
        /* save the return value*/
        movl    %eax, %ebx
        /* retrieve the contexts as we can't trust the current state of registers*/
        call    get_sandbox_current_thread_app_ctx@PLT
        movl    0x0(%eax), %ecx
        /* restore old return*/
        movl    %ebx, %eax

        /* Callee save registers */
        movl    0x00(%ecx), %ebx
        movl    0x08(%ecx), %ebp
        movl    0x30(%ecx), %edi
        movl    0x38(%ecx), %esi
        fldcw   0x68(%ecx)
        ldmxcsr 0x70(%ecx)

        /* load the rsp of the app -- offset by pointer as the return address has already been consumed */
        movl    0xc8(%ecx), %esp
        addl    $0x4, %esp

        /* restore the return address*/
        movl    0xb8(%ecx), %ecx
        jmp     *%ecx
        ud2


.globl context_switch_to_sbx_callback
.type context_switch_to_sbx_callback,@function
.align 16
context_switch_to_sbx_callback:
_context_switch_to_sbx_callback:
        call    get_sandbox_current_thread_sbx_ctx@PLT
        movl    0x0(%eax), %ecx

        call __x86.get_pc_thunk.ax /* PIC support */

        /* Clear the x87, MMX, and SSE state.*/
        fxrstor fxrstor_default_state-.(%eax)
        /* Clear the AVX state that the "fxrstor" instruction doesn't cover. */
        vzeroupper

        /* Restore the untrusted code's x87 and SSE control words.*/
        fldcw   0x68(%ecx)
        ldmxcsr 0x70(%ecx)

        // /* Load return registers */
        movl    0xc0(%ecx), %eax
        movl    0x40(%ecx), %edx
        fld 0x78(%ecx)

        /* Restore the stack of the sandbox */
        movl    0xc8(%ecx), %esp

        /* Move the target into ecx*/
        movl    0xb8(%ecx), %ecx
        /* we don't have to clear ecx as this only contains a pointer to the sandbox function, this is not a data leak*/
        jmp    *%ecx
        /* no return*/
        ud2
