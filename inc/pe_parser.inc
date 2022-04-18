PeHeaders struct

    filename 	cword   ?   ;˜˜˜ ˜˜˜˜˜

    fd          HANDLE  ?   ;˜˜˜˜˜ ˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜
    mapd        HANDLE  ?   ;˜˜˜˜˜ ˜˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜
    mem	        cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ ˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜
    filesize    cword   ?   ;˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜ ˜˜˜˜˜

    doshead     cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ DOS ˜˜˜˜˜˜˜˜˜
    nthead      cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ NT ˜˜˜˜˜˜˜˜˜

    impdir      cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ ˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜
    sizeImpdir  DWORD   ?   ;˜˜˜˜˜˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜
    countImpdes DWORD   ?   ;˜˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜˜ ˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜

    expdir      cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜
    sizeExpdir  DWORD   ?   ;˜˜˜˜˜˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜˜˜

    sections    cword   ?   ;˜˜˜˜˜˜˜˜˜ ˜˜ ˜˜˜˜˜˜˜ ˜˜˜˜˜˜ (˜˜ ˜˜˜˜˜˜ ˜˜˜˜˜˜˜)
    countSec    DWORD   ?   ;˜˜˜˜˜˜˜˜˜˜ ˜˜˜˜˜˜

PeHeaders ends

Space struct
    startRVA	DWORD	?
    endRVA		DWORD	?
    startRAW	DWORD	?
    endRAW		DWORD	?
    isize		DWORD	?
Space ends

SC_PARAMS struct
    startRVA        DWORD ?
    sizeCurrSc      DWORD ?
    globalSize      DWORD ?
SC_PARAMS ends

LoadPeFile proto CurrentStdcallNotation :ptr byte, :ptr byte, :cword
UnloadPeFile proto CurrentStdcallNotation :cword
AlignToTop proto CurrentStdcallNotation :cword, :cword
AlignToBottom proto CurrentStdcallNotation :cword, :cword
RvaToOffset proto CurrentStdcallNotation :cword, :cword 

