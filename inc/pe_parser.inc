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

; typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
    ; DWORD      Size;
    ; DWORD      TimeDateStamp;
    ; WORD       MajorVersion;
    ; WORD       MinorVersion;
    ; DWORD      GlobalFlagsClear;
    ; DWORD      GlobalFlagsSet;
    ; DWORD      CriticalSectionDefaultTimeout;
    ; ULONGLONG  DeCommitFreeBlockThreshold;
    ; ULONGLONG  DeCommitTotalFreeThreshold;
    ; ULONGLONG  LockPrefixTable;                // VA
    ; ULONGLONG  MaximumAllocationSize;
    ; ULONGLONG  VirtualMemoryThreshold;
    ; ULONGLONG  ProcessAffinityMask;
    ; DWORD      ProcessHeapFlags;
    ; WORD       CSDVersion;
    ; WORD       DependentLoadFlags;
    ; ULONGLONG  EditList;                       // VA
;     ULONGLONG  SecurityCookie;                 // VA
;     ULONGLONG  SEHandlerTable;                 // VA
;     ULONGLONG  SEHandlerCount;
;     ULONGLONG  GuardCFCheckFunctionPointer;    // VA
;     ULONGLONG  GuardCFDispatchFunctionPointer; // VA
;     ULONGLONG  GuardCFFunctionTable;           // VA
;     ULONGLONG  GuardCFFunctionCount;
;     DWORD      GuardFlags;
;     IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
;     ULONGLONG  GuardAddressTakenIatEntryTable; // VA
;     ULONGLONG  GuardAddressTakenIatEntryCount;
;     ULONGLONG  GuardLongJumpTargetTable;       // VA
;     ULONGLONG  GuardLongJumpTargetCount;
;     ULONGLONG  DynamicValueRelocTable;         // VA
;     ULONGLONG  CHPEMetadataPointer;            // VA
;     ULONGLONG  GuardRFFailureRoutine;          // VA
;     ULONGLONG  GuardRFFailureRoutineFunctionPointer; // VA
;     DWORD      DynamicValueRelocTableOffset;
;     WORD       DynamicValueRelocTableSection;
;     WORD       Reserved2;
;     ULONGLONG  GuardRFVerifyStackPointerFunctionPointer; // VA
;     DWORD      HotPatchTableOffset;
;     DWORD      Reserved3;
;     ULONGLONG  EnclaveConfigurationPointer;     // VA
;     ULONGLONG  VolatileMetadataPointer;         // VA
;     ULONGLONG  GuardEHContinuationTable;        // VA
;     ULONGLONG  GuardEHContinuationCount;
; } IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

; typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
;     WORD    Flags;          // Flags to indicate if CI information is available, etc.
;     WORD    Catalog;        // 0xFFFF means not available
;     DWORD   CatalogOffset;
;     DWORD   Reserved;       // Additional bitmask to be defined later
; } IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

IMAGE_LOAD_CONFIG_CODE_INTEGRITY struct
    Flags   WORD ?
    Catalog WORD ?
    CatalogOffset   DWORD ?
    Reserved    DWORD ?
IMAGE_LOAD_CONFIG_CODE_INTEGRITY ends

SE_HANDLER_TABLE struct
    entry1  cword ?
    entry2  cword ?
    entry3  cword ?
    entry4  cword ?
SE_HANDLER_TABLE ends

IMAGE_LOAD_CONFIG_DIRECTORY_FULL	struct 
    Characteristics	DWORD	?
    TimeDateStamp	DWORD	?
    MajorVersion	WORD	?
    MinorVersion	WORD	?
    GlobalFlagsClear	DWORD	?
    GlobalFlagsSet	DWORD	?
    CriticalSectionDefaultTimeout	DWORD	?
    DeCommitFreeBlockThreshold	cword	?
    DeCommitTotalFreeThreshold	cword	?
    LockPrefixTable	cword	?
    MaximumAllocationSize	cword	?
    VirtualMemoryThreshold	cword	?
    ProcessAffinityMask	cword	?
    ProcessHeapFlags	cword	?
    CSDVersion	WORD	?
    Reserved1	WORD	?
    EditList	cword	?
    SecurityCookie  cword ?             ; handle in reloc
    SEHandlerTable  cword ?          ;  handle in reloc                 // VA
    SEHandlerCount  cword ?      ;
    GuardCFCheckFunctionPointer     cword ? ;   ; handle in reloc  // VA
    GuardCFDispatchFunctionPointer  cword ?  ; // VA
    GuardCFFunctionTable    cword ? ;           // VA
    GuardCFFunctionCount    cword ? ;
    GuardFlags  DWORD ? ;
    CodeIntegrity   IMAGE_LOAD_CONFIG_CODE_INTEGRITY <>
    GuardAddressTakenIatEntryTable  cword ?; // VA
    GuardAddressTakenIatEntryCount  cword ?;
    GuardLongJumpTargetTable    cword ?;       // VA
    GuardLongJumpTargetCount    cword ? ;
    DynamicValueRelocTable      cword ?;         // VA
    CHPEMetadataPointer         cword ?;            // VA
    GuardRFFailureRoutine       cword ? ;          // VA
    GuardRFFailureRoutineFunctionPointer    cword ?; // VA
    DynamicValueRelocTableOffset DWORD ?;
    DynamicValueRelocTableSection WORD ?;
    Reserved2   WORD ?;
    GuardRFVerifyStackPointerFunctionPointer cword ?; // VA
    HotPatchTableOffset DWORD ?;
    Reserved3 DWORD ?;
    EnclaveConfigurationPointer cword ?;     // VA
    VolatileMetadataPointer cword ?;          // VA
    GuardEHContinuationTable cword ?;        // VA
    GuardEHContinuationCount cword ?;
IMAGE_LOAD_CONFIG_DIRECTORY_FULL	ends

LoadPeFile proto CurrentStdcallNotation :ptr byte, :ptr byte, :cword
UnloadPeFile proto CurrentStdcallNotation :cword
AlignToTop proto CurrentStdcallNotation :cword, :cword
AlignToBottom proto CurrentStdcallNotation :cword, :cword
; 
RvaToOffset proto CurrentStdcallNotation :DWORD, :cword, :cword 