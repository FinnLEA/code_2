
LoadPeFile proc CurrentStdcallNotation uses cdi filename:ptr byte, pe:ptr byte, filesize:cword

	local comp64:cword
	local comp64_2:cword
	local pCurrNtHead:cword
	
	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cdi, [pe]
    assume cdi: ptr PeHeaders
	
    mov cax, [filename]
    mov [cdi].filename, cax
    
	; открываем файл (получаем файловый дескриптор)
    invoke64 sc_CreateFileA, [filename], GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov [cdi].fd, cax
    .if [cdi].fd == INVALID_HANDLE_VALUE
		invoke sc_printf, addr [cbx + msg_pe_open_error]
		invoke sc_GetLastError
		invoke sc_printf, addr [cbx + strFormatInt], cax
        xor cax, cax
        ret
    .endif
    
    .if [filesize]
        mov cax, [filesize]
        mov [cdi].filesize, cax
    .else
        invoke sc_GetFileSize, [cdi].fd, 0
        mov [cdi].filesize, cax
    .endif
    
	; создаем проекцию файла в память
	mov ccx, [cdi].fd
	mov cdx, [cdi].filesize
	mov [comp64], ccx
	mov [comp64_2], cdx
    invoke sc_CreateFileMappingA, [comp64], 0, PAGE_EXECUTE_READWRITE, 0, [comp64_2], 0
    mov [cdi].mapd, cax
    .if cax == 0
		mov cdx, [cdi].fd
        invoke sc_CloseHandle, cdx
        invoke sc_printf, addr [cbx + msg_pe_create_mapping_error]
        xor cax, cax
        ret
    .endif
    
	; отображаем проекцию в память
	mov ccx, [cdi].mapd
    invoke sc_MapViewOfFile, ccx, FILE_MAP_READ or FILE_MAP_WRITE or 20h, 0, 0, 0
    mov [cdi].mem, cax
    .if cax == 0
		mov cdx, [cdi].fd
        invoke sc_CloseHandle, cdx
		mov cdx, [cdi].mapd
        invoke sc_CloseHandle, cdx
        invoke sc_printf, addr [cbx + msg_pe_mapping_error]
        xor cax, cax
        ret
    .endif
	
	; указатель на заголовок PE
	mov cdx, [pe]
	mov cax, [cdx].PeHeaders.mem
	mov [cdx].PeHeaders.doshead, cax
	
	movzx eax, word ptr [cax].IMAGE_DOS_HEADER.e_magic
	.if eax != IMAGE_DOS_SIGNATURE
		invoke UnloadPeFile, addr [pe]
		xor cax, cax
		ret
	.endif
	
	; указатель на NT заголовок
	DbgBreak
	mov cdx, [pe]
	mov cax, [cdx].PeHeaders.mem
	mov cdx, [cdx].PeHeaders.doshead
	lea cdx, [cdx].IMAGE_DOS_HEADER.e_lfanew
	mov edx, dword ptr [cdx]
	add cax, cdx
	mov cdx, [pe]
	mov [cdx].PeHeaders.nthead, cax
	mov eax, dword ptr [cax]
	
	.if eax != IMAGE_NT_SIGNATURE
		invoke UnloadPeFile, addr [pe]
		xor cax, cax
		ret
	.endif
	
	; определение формата РЕ
	mov cax, [pe]
	mov cax, [cax].PeHeaders.nthead
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	lea cax, [cax].IMAGE_OPTIONAL_HEADER.Magic
	movzx cax, word ptr [cax]
	
	.if ax == IMAGE_NT_OPTIONAL_HDR64_MAGIC
		mov cdi, [pe]
		mov byte ptr [cdi].PeHeaders.isPe64, 1
		mov cdx, [cdi].PeHeaders.nthead
		mov [cdi].PeHeaders.nthead64, cdx
		mov [cdi].PeHeaders.nthead, 0
		mov [pCurrNtHead], cdx
		
		lea cdx, [cdx].IMAGE_NT_HEADERS64.OptionalHeader
		mov ecx, dword ptr [cdx].IMAGE_OPTIONAL_HEADER64.ImageBase
		lea cax, [cdi].PeHeaders.ib
		mov [cax].U_ADDR.addr_.val32.lo, ecx
		
		lea cdx, [cdx].IMAGE_OPTIONAL_HEADER64.ImageBase
		lea cdx, [cdx + 4]
		mov ecx, dword ptr [cdx]
		mov [cax].U_ADDR.addr_.val32.hi, ecx
	.elseif ax == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		mov cdi, [pe]
		mov byte ptr [cdi].PeHeaders.isPe64, 0
		mov [cdi].PeHeaders.nthead64, 0
		mov ccx, [cdi].PeHeaders.nthead
		mov [pCurrNtHead], ccx

		lea cdx, [ccx].IMAGE_NT_HEADERS32.OptionalHeader
		mov ecx, dword ptr [cdx].IMAGE_OPTIONAL_HEADER32.ImageBase
		lea cax, [cdi].PeHeaders.ib
		mov [cax].U_ADDR.addr_.val32.lo, ecx
		mov [cax].U_ADDR.addr_.val32.hi, 0
	.else
		invoke sc_printf, addr [cbx + msg_pe_format_error]
		xor eax, eax
		ret
	.endif

	
	;mov cax, [pe]
	mov cax, [pCurrNtHead]
	lea cax, [cax].IMAGE_NT_HEADERS.OptionalHeader
	;mov cdx, [pe]
	mov cdx, [pCurrNtHead]
	lea cdx, [cdx].IMAGE_NT_HEADERS.FileHeader
	lea cdx, [cdx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
	movzx ecx, word ptr [cdx]
	add cax, ccx
	mov cdx, [pe]
	mov [cdx].PeHeaders.sections, cax
	
	mov cdx, [pCurrNtHead]
	lea cdx, [cdx].IMAGE_NT_HEADERS.FileHeader
	movzx eax, word ptr [cdx].IMAGE_FILE_HEADER.NumberOfSections
	mov cdx, [pe]
	mov [cdx].PeHeaders.countSec, eax

    
    mov cax, 1
    ret    

LoadPeFile endp


UnloadPeFile proc CurrentStdcallNotation pe:cword

	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

	mov cax, cword ptr [pe]
	mov cdx, [cax].PeHeaders.mem
	invoke sc_UnmapViewOfFile, cdx
	
	mov cax, cword ptr [pe]
	mov cdx, [cax].PeHeaders.fd
	invoke sc_CloseHandle, cdx
	
	mov cax, cword ptr [pe]
	mov cdx, [cax].PeHeaders.mapd
	invoke sc_CloseHandle, cdx
	
	ret
	
UnloadPeFile endp


AlignToTop proc CurrentStdcallNotation uses cbx cdi csi cdx value:cword, alignv:cword

	local maskv:cword
	
	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cax, cword ptr [alignv]
	dec cax
	not cax
	mov [maskv], cax
	
	mov cax, cword ptr [value]
	add cax, cword ptr [alignv]
	dec cax
	and cax, cword ptr [maskv]
	ret

AlignToTop endp

AlignToBottom proc CurrentStdcallNotation value:cword, alignv:cword

	local maskv:cword
	
	ifdef _WIN64 
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cax, cword ptr [alignv]
	dec cax
	not cax
	mov [maskv], cax
	
	mov cax, cword ptr [value]
	and cax, cword ptr [maskv]
	ret
	
AlignToBottom endp

;
; Возвращает файловое смещение по RVA.
;
RvaToOffset proc CurrentStdcallNotation uses ccx cdx cdi rva:dword, pe:cword, secInd:cword

	local currentSection:cword
	local numberOfSections:dword
	local pCurrNtHead:cword
	local is_x64:byte
	
	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
	mov cdx, [pe]
	.if byte ptr [cdx].PeHeaders.isPe64 == 1
		mov cax, [cdx].PeHeaders.nthead64
		lea cax, [cax].IMAGE_NT_HEADERS64.OptionalHeader
		mov eax, [cax].IMAGE_OPTIONAL_HEADER64.SizeOfImage
	.else
		mov cax, [cdx].PeHeaders.nthead
		lea cax, [cax].IMAGE_NT_HEADERS32.OptionalHeader
		mov eax, [cax].IMAGE_OPTIONAL_HEADER32.SizeOfImage
	.endif

	; if (rva > SizeOfImage) return 0;
	.if [rva] > eax
		mov cax, 0
		ret
	.endif
	
	mov cdx, [pe]
	mov cdi, [cdx].PeHeaders.sections
	mov ecx, [cdx].PeHeaders.countSec
	mov [numberOfSections], ecx
	
	xor ecx, ecx
	.while ecx != [numberOfSections]
	
        xor cax, cax
		mov eax, ecx
		imul cax, IMAGE_SIZEOF_SECTION_HEADER
		add cax, cdi
		mov [currentSection], cax
		
		xor cdx, cdx
		mov edx, [cax].IMAGE_SECTION_HEADER.Misc.VirtualSize
		mov eax, [cax].IMAGE_SECTION_HEADER.VirtualAddress
		add cdx, cax

		.if [rva] >= eax && [rva] <= edx
		;if [rva] >= VirtualAddress && [rva] <= VirtualSize + VirtualAddress
			;return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
			mov eax, [rva]
			mov cdx, [currentSection]
			mov edi, [cdx].IMAGE_SECTION_HEADER.VirtualAddress
			sub cax, cdi
			mov edi, [cdx].IMAGE_SECTION_HEADER.PointerToRawData
			add cax, cdi
			.if [secInd] != NULL
				mov cdi, [secInd]
				mov dword ptr [cdi], ecx 
			.endif
			ret

		.endif

		inc ecx
    .endw
	
	xor cax, cax
	ret
RvaToOffset endp

msg_pe_open_error:
db "Error: Failed to open file", 10, 0
msg_pe_create_mapping_error:
db "Error: Failed to create fie mapping", 10, 0
msg_pe_mapping_error:
db "Error: Failed to mapping file", 10, 0
msg_pe_format_error:
db "Warning: PE format not support", 10, 0
