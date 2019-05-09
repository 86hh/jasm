pebImageBase                    equ     8
pebLdr                          equ     0ch
ldrInLoadOrderModuleList        equ     0ch
mlDllBase                       equ     18h

IActiveScript_QueryInterface    equ     0
AddRef                          equ     8

CLSCTX_INPROC_SERVER            equ     1

COINIT_APARTMENTTHREADED        equ     2

E_NOINTERFACE                   equ     80004002h
E_NOTIMPL                       equ     80004001h 

SCRIPTTEXT_ISEXPRESSION         equ     20h

SCRIPTSTATE_CONNECTED           equ     2

struc IActiveScript_vtable
        .iaQueryInterface:  resd 1
        .iaAddRef:          resd 1
        .iaRelease:         resd 1
        .iaSetScriptSite:   resd 1 
        .iaGetScriptSite:   resd 1 
        .iaSetScriptState:  resd 1 
        .iaGetScriptState:  resd 1 
        .iaClose:           resd 1
endstruc

struc IActiveScriptParse32_vtable
        .iaQueryInterface:  resd 1
        .iaAddRef:          resd 1
        .iaRelease:         resd 1
        .iaInitNew:         resd 1
        .iaAddScriptlet:    resd 1
        .iaParseScriptText: resd 1
ends

struc comcrcstk
        .oCoUninitialize:     resd 1
        .oCoInitializeEx:     resd 1
        .oCoCreateInstance:   resd 1
endstruc
        
struc   krncrcstk
        .kLoadLibraryA:       resd 1
endstruc

struc   mzhdr
        .mzsig     :    resw    1               ;00
        .mzpagemod :    resw    1               ;02
        .mzpagediv :    resw    1               ;04
        .mzrelocs  :    resw    1               ;06
        .mzhdrsize :    resw    1               ;08
        .mzminalloc:    resw    1               ;0A
        .mzmaxalloc:    resw    1               ;0C
        .mzss      :    resw    1               ;0E
        .mzsp      :    resw    1               ;10
        .mzchksum  :    resw    1               ;12
        .mzip      :    resw    1               ;14
        .mzcs      :    resw    1               ;16
        .mzreloff  :    resw    1               ;18
        .mzfiller  :    resb    22h             ;1A
        .mzlfanew  :    resd    1               ;3C
endstruc

struc   coffhdr
        .pemachine   :  resw    1               ;04
        .pesectcount :  resw    1               ;06
        .petimedate  :  resd    1               ;08
        .pesymbrva   :  resd    1               ;0C
        .pesymbcount :  resd    1               ;10
        .peopthdrsize:  resw    1               ;14
        .peflags     :  resw    1               ;16
endstruc

struc   pedir
        .dirrva :       resd    1
        .dirsize:       resd    1
endstruc

struc   pehdr
        .pesig        : resd    1               ;000
        .pecoff       : resb    coffhdr_size
        .pemagic      : resw    1               ;018
        .pemajorlink  : resb    1               ;01A
        .peminorlink  : resb    1               ;01B
        .pecodesize   : resd    1               ;01C
        .peidatasize  : resd    1               ;020
        .peudatasize  : resd    1               ;024
        .peentrypoint : resd    1               ;028
        .pecodebase   : resd    1               ;02C
        .pedatabase   : resd    1
        .peimagebase  : resd    1               ;030
        .pesectalign  : resd    1               ;038
        .pefilealign  : resd    1               ;03C
        .pemajoros    : resw    1               ;040
        .peminoros    : resw    1               ;042
        .pemajorimage : resw    1               ;044
        .peminorimage : resw    1               ;046
        .pemajorsubsys: resw    1               ;048
        .peminorsubsys: resw    1               ;04A
        .pereserved   : resd    1               ;04C
        .peimagesize  : resd    1               ;050
        .pehdrsize    : resd    1               ;054
        .pechksum     : resd    1               ;058
        .pesubsys     : resw    1               ;05C
        .pedllflags   : resw    1               ;05E
        .pestackmax   : resd    1               ;060
        .pestacksize  : resd    1               ;068
        .peheapmax    : resd    1               ;070
        .peheapsize   : resd    1               ;078
        .peldrflags   : resd    1               ;080
        .pervacount   : resd    1               ;084
        .peexport     : resb    pedir_size      ;088
        .peimport     : resb    pedir_size      ;090
        .persrc       : resb    pedir_size      ;098
        .peexcpt      : resb    pedir_size      ;0A0
        .pesecurity   : resb    pedir_size      ;0A8
        .pereloc      : resb    pedir_size      ;0B0
        .pedebug      : resb    pedir_size      ;0B8
        .pearch       : resb    pedir_size      ;0C0
        .peglobal     : resb    pedir_size      ;0C8
        .petls        : resb    pedir_size      ;0D0
        .peconfig     : resb    pedir_size      ;0D8
        .pebound      : resb    pedir_size      ;0E0
        .peiat        : resb    pedir_size      ;0E8
        .pedelay      : resb    pedir_size      ;0F0
        .pecom        : resb    pedir_size      ;0F8
        .persrv       : resb    pedir_size
endstruc

struc   peexp
        .expflags    :  resd    1
        .expdatetime :  resd    1
        .expmajorver :  resw    1
        .expminorver :  resw    1
        .expdllrva   :  resd    1
        .expordbase  :  resd    1
        .expadrcount :  resd    1
        .expnamecount:  resd    1
        .expadrrva   :  resd    1
        .expnamerva  :  resd    1
        .expordrva   :  resd    1
endstruc