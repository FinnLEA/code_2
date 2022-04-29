LH_ADDR struct
    lo  DWORD ?
    hi  DWORD ?
LH_ADDR ends 

U_ADDR struct 
    union addr_
        val64 qword ?
        val32 LH_ADDR <>
    ends
U_ADDR ends

PeHeaders struct

    filename 	cword   ?   ; 

    fd          HANDLE  ?   ;  
    mapd        HANDLE  ?   ;  
    mem	        cword   ?   ;    
    filesize    cword   ?   ;   

    doshead     cword   ?   ;  DOS 
    nthead      cword   ?   ;  NT 
    nthead64    cword   ?

    impdir      cword   ?   ;     
    sizeImpdir  DWORD   ?   ;  
    countImpdes DWORD   ?   ;    

    expdir      cword   ?   ;   
    sizeExpdir  DWORD   ?   ;  

    sections    cword   ?   ;    (  )
    countSec    DWORD   ?   ; 

    fileAligment DWORD  ?
    sectionAligment DWORD ?

    ib          U_ADDR <>
    isPe64      byte    ?

PeHeaders ends

SC_PARAMS struct
    startRVA        DWORD ? ; RVA начала шеллкода
    targetSecRVA    DWORD ? ; VA начала нужной кодовой секции
    scSize          DWORD ? ; чистый размер шеллкода (без вырвнивания) 
    alScSize        DWORD ? ; размер шеллкода с выравниванием до страницы
    f_diff          DWORD ? ; разница для сдвига (файловое выр-ие)
    v_diff          DWORD ? ; разница для сдвига (виртуальное выр-ие)
    f_Size          DWORD ? ; размер шеллкода выравненный по FileAligment
    v_Size          DWORD ? ; размер шеллкода выравненный по SectionAligment
    SizeOfTargetSec DWORD ? ; оригинальный VirtualSize кодовой секции
    originalEP      DWORD ? ; оригинальная точка входа
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

IMAGE_LOAD_CONFIG_DIRECTORY_FULL64	struct 
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
IMAGE_LOAD_CONFIG_DIRECTORY_FULL64	ends

IMAGE_LOAD_CONFIG_DIRECTORY_FULL32	struct 
    Characteristics	DWORD	?
    TimeDateStamp	DWORD	?
    MajorVersion	WORD	?
    MinorVersion	WORD	?
    GlobalFlagsClear	DWORD	?
    GlobalFlagsSet	DWORD	?
    CriticalSectionDefaultTimeout	DWORD	?
    DeCommitFreeBlockThreshold	DWORD	?
    DeCommitTotalFreeThreshold	DWORD	?
    LockPrefixTable	DWORD	?
    MaximumAllocationSize	DWORD	?
    VirtualMemoryThreshold	DWORD	?
    ProcessAffinityMask	DWORD	?
    ProcessHeapFlags	DWORD	?
    CSDVersion	WORD	?
    Reserved1	WORD	?
    EditList	DWORD	?
    SecurityCookie  DWORD ?             ; handle in reloc
    SEHandlerTable  DWORD ?          ;  handle in reloc                 // VA
    SEHandlerCount  DWORD ?      ;
    GuardCFCheckFunctionPointer     DWORD ? ;   ; handle in reloc  // VA
    GuardCFDispatchFunctionPointer  DWORD ?  ; // VA
    GuardCFFunctionTable    DWORD ? ;           // VA
    GuardCFFunctionCount    DWORD ? ;
    GuardFlags  DWORD ? ;
    CodeIntegrity   IMAGE_LOAD_CONFIG_CODE_INTEGRITY <>
    GuardAddressTakenIatEntryTable  DWORD ?; // VA
    GuardAddressTakenIatEntryCount  DWORD ?;
    GuardLongJumpTargetTable    DWORD ?;       // VA
    GuardLongJumpTargetCount    DWORD ? ;
    DynamicValueRelocTable      DWORD ?;         // VA
    CHPEMetadataPointer         DWORD ?;            // VA
    GuardRFFailureRoutine       DWORD ? ;          // VA
    GuardRFFailureRoutineFunctionPointer    DWORD ?; // VA
    DynamicValueRelocTableOffset DWORD ?;
    DynamicValueRelocTableSection WORD ?;
    Reserved2   WORD ?;
    GuardRFVerifyStackPointerFunctionPointer DWORD ?; // VA
    HotPatchTableOffset DWORD ?;
    Reserved3 DWORD ?;
    EnclaveConfigurationPointer DWORD ?;     // VA
    VolatileMetadataPointer DWORD ?;          // VA
    GuardEHContinuationTable DWORD ?;        // VA
    GuardEHContinuationCount DWORD ?;
IMAGE_LOAD_CONFIG_DIRECTORY_FULL32	ends

LoadPeFile proto CurrentStdcallNotation :ptr byte, :ptr byte, :cword
UnloadPeFile proto CurrentStdcallNotation :cword
AlignToTop proto CurrentStdcallNotation :cword, :cword
AlignToBottom proto CurrentStdcallNotation :cword, :cword
; 
RvaToOffset proto CurrentStdcallNotation :DWORD, :cword, :cword 