

Stdcall0_x86 typedef proto Stdcall
Stdcall1_x86 typedef proto Stdcall :dword
Stdcall2_x86 typedef proto Stdcall :dword, :dword
Stdcall3_x86 typedef proto Stdcall :dword, :dword, :dword
Stdcall4_x86 typedef proto Stdcall :dword, :dword, :dword, :dword
Stdcall5_x86 typedef proto Stdcall :dword, :dword, :dword, :dword, :dword
Stdcall6_x86 typedef proto Stdcall :dword, :dword, :dword, :dword, :dword, :dword
Stdcall7_x86 typedef proto Stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword
Stdcall8_x86 typedef proto Stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
Stdcall9_x86 typedef proto Stdcall :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
;StdcallVararg typedef proto CurrentStdcallNotation :vararg
CdeclVararg typedef proto CurrentCdeclNotation :vararg

DefineStdcallVarargProto macro name:req
    sc_&name equ <StdcallVararg ptr [cbx + p_&name]>
endm

DefineStdcallProto_x86 macro name:req, count:req
    sc_&name equ <Stdcall_x86&count ptr ebx + p_&name]>
endm

DefineStdcallProto_x64
    sc_&name equ <Stdcall&count ptr rbx + p_&name]>
	
DefineCProto_x86 macro name:req
    sc_&name equ <CdeclVararg ptr [ebx + p_&name]>
endm

DefineStr macro name:req
    ;@CatStr(str,name) db "@CatStr(,name)", 0
    str_&name db "&name&", 0
endm

DefineStrOffsets macro name:req, strNames:vararg
    name:
    for i, <&strNames>
        qword offset str_&i
    endm
    name&Count = ($ - name) / sizeof(qword)
endm

DefinePointers macro name:req, namePointers:vararg
    name:
    for i, <&namePointers>
        p_&i qword 0
    endm
endm

DefineFuncNamesAndPointers macro funcNames:vararg
    for i, <&funcNames>
        DefineStr i
    endm
    DefineStrOffsets procNames, funcNames
    DefinePointers procPointers, funcNames
endm