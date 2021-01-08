EXTERN ExFreePool : PROC
     
.CODE
     
jmp_to_ex_free_pool PROC
    jmp ExFreePool
jmp_to_ex_free_pool ENDP
     
END