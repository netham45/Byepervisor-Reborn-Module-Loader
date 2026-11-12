.section .text,"ax",@progbits
.global phase3_blob_init
.type phase3_blob_init,@function
phase3_blob_init:
    xorl %eax, %eax
    ret
.size phase3_blob_init, .-phase3_blob_init

.p2align 4, 0x90
.global phase3_blob_dispatch
.type phase3_blob_dispatch,@function
phase3_blob_dispatch:
    cmpl $2, %esi
    jne 1f
    movabs $0x0301060a11, %rax
    movq %rax, 0x408(%rdx)
    xorl %eax, %eax
    ret
1:
    movl $22, %eax
    ret
.size phase3_blob_dispatch, .-phase3_blob_dispatch
.section .note.GNU-stack,"",@progbits
