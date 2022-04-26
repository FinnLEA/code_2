; Осуществляет поиск адресов функций, смещения до имен которых от регистра cbx,
; переданы в первом аргументе funcNames.
; Адреса сохраняются по соответствующим индексам в массиве funcAddress.
; void FindProcArray (in char **funcNames, out void **funcAddress, int funcCount);
FindProcArray proc CurrentStdcallNotation uses cdi funcNames:ptr byte, funcAddress:ptr byte, funcCount:cword

local i:cword
local funcName:cword
    
	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
    mov [i], 0

@@:
    mov cax, [i]
    cmp cax, [funcCount]
    jge @f
    
    mov cdi, [funcNames]
    mov cdi, [cdi + sizeof(cword) * cax]
    add cdi, cbx
	mov [funcName], cdi
    ;push cdi
    mov cdi, [funcAddress]
    lea cdi, [cdi + sizeof(cword) * cax]
    ;call FindProcAddressByName
	invoke FindProcAddressByName, [funcName]
    mov [cdi], cax
    
    inc [i]
    jmp @b
@@:

    ret

FindProcArray endp


CmpStr proc CurrentStdcallNotation str1:cword, str2:cword

ifdef _WIN64
	mov [rbp + 10h], rcx
	mov [rbp + 18h], rdx
	mov [rbp + 20h], r8
	mov [rbp + 28h], r9
endif
	
	mov cax, [str1]
	mov ccx, [str2]

	@@:
    mov dl, [cax]
    cmp dl, byte ptr [ccx]
    jne ret_false
    test dl, dl
    je ret_true
    inc cax
    inc ccx
    jmp @b

ret_false:
    xor cax, cax
	
ret_true:
	ret
	
CmpStr endp

;
; Осуществляет поиск функции по имени во всех загруженных библиотеках из PEB'а.
; void * FindProcAddressByName (char * procName);
;
FindProcAddressByName proc CurrentStdcallNotation uses cdi cbx procName:ptr byte

ifdef _WIN64
	mov [rbp + 10h], rcx
	mov [rbp + 18h], rdx
	mov [rbp + 20h], r8
	mov [rbp + 28h], r9
endif

    assume cur_seg_reg:nothing
    mov cbx, [cur_seg_reg:OFFSET_PEB]       ; cbx = ptr _PEB
    mov cbx, [cbx+OFFSET_LDR]      ; cbx = ptr _PEB_LDR_DATA
    lea cbx, [cbx+OFFSET_INIT_LIST]      ; cbx = ptr InInitializationOrderModuleList.Flink

    mov cdi, cbx            ; cdi = голова списка
    mov cbx, [cbx]          ; cbx = InInitializationOrderModuleList.Flink
    .while cbx != cdi
        ;push [procName]
        ;push cword ptr [cbx+sizeof(CLIST_ENTRY)]    ; LDR_DATA_TABLE_ENTRY.DllBase
                                    ; 10h - смещение от элемента InInitializationOrderLinks
        ;call FindProcAddress
		
		invoke FindProcAddress, cword ptr [cbx+sizeof(CLIST_ENTRY)], [procName]
        .if cax
            .break          ; в случае возврата cax будет содержать адрес функции
        .endif
        
        mov cbx, [cbx]          ; cbx = LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks.Flink
        xor cax, cax            ; обнуляем cax для возврата из функции
    .endw

    ret

FindProcAddressByName endp

;
; Осуществляет поиск адреса функции по ее имени в таблице экспорта
; void *FindProcAddress (void *baseLib, char *procName)
;
FindProcAddress proc CurrentStdcallNotation uses cdi csi cbx baseLib:ptr byte, procName:ptr byte

local functionsArray:cword
local namesArray:cword
local nameOcdinalsArray:cword

	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cbx, [baseLib]
    
    mov eax, [cbx].IMAGE_DOS_HEADER.e_lfanew    ; cax = offset PE header
    
    ; esi = rva export directory
    mov esi, [cbx + cax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add csi, cbx                ; esi = va export directory
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add cax, cbx
    mov [functionsArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    add cax, cbx
    mov [namesArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOcdinals
    add cax, cbx
    mov [nameOcdinalsArray], cax
    
    xor edi, edi

@@:
        cmp edi, [csi].IMAGE_EXPORT_DIRECTORY.NumberOfNames      ; cdi < IMAGE_EXPORT_DIRECTORY.NumberOfNames
        
        ; после сравнения строк на предыдущей итерации eax=0
        jge find_ret

        mov cax, [namesArray]
        mov eax, [cax+cdi*sizeof(dword)]
        add cax, cbx
		invoke CmpStr, cax, [procName]
        test cax, cax
        jne  @f

        inc edi
        jmp @b
@@:
    
    mov cax, [nameOcdinalsArray]
    movzx cdi, word ptr [cax+cdi*sizeof(word)]
    mov cax, [functionsArray]
    mov eax, [cax+cdi*sizeof(dword)]
    add cax, cbx
    
find_ret:
    
    ret

FindProcAddress endp
