bits32

%include "jsm.inc"

;scripthost      db     "JScript\CLSID", 0

krnnames        db      "LoadLibraryA", 0

olenames        db      "CoCreateInstance", 0
                db      "CoInitializeEx"  , 0
                db      "CoUninitialize"  , 0

global _main
section .text
_main:
        push    ebx
        mov     edx, comcrcstk_size >> 2
        mov     ebx, olenames
        mov     edi, comcrcbegin
        call    create_crcs
        mov     edx, krncrcstk_size >> 2
        mov     ebx, krnnames
        mov     edi, krncrcbegin
        call    create_crcs
        pop     ebx
        jmp     entry

create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [ebx]
        push    8
        pop     ecx

create_inner:
        shr     eax, 1
        jnc     create_skip
        xor     eax, 0edb88320h

create_skip:
        loop    create_inner
        inc     ebx
        cmp     byte [ebx], cl
        jne     create_outer
        not     eax
        stosd
        inc     ebx
        dec     edx
        jne     create_crcs
        ret

;-----------------------------------------------------------------------------
;this is the entry
;-----------------------------------------------------------------------------

entry:
        xor     eax, eax

;disabled for fast fail

;       fs push dword [eax]
;       fs mov  dword [eax], esp
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin:
        times   krncrcstk_size >> 2 dd 0
        db      0

;-----------------------------------------------------------------------------
;get OLE32 APIs
;-----------------------------------------------------------------------------

        call    load_fwdll
        db      "api-ms-win-core-com-l1-1-1", 0
                                            ;forwarder chain from ole32.dll
load_fwdll:
        call    load_ole32
        db      "ole32", 0

load_ole32:
        call    dword [esp + 8 + krncrcstk.kLoadLibraryA]
        xchg    ebp, eax
        call    dword [esp + 4 + krncrcstk.kLoadLibraryA]
        test    eax, eax
        cmovne  ebp, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

comcrcbegin:
        times   comcrcstk_size >> 2 dd 0
        db      0

        mov     ebp, esp

;-----------------------------------------------------------------------------
;initialize IActiveScript, IActiveScriptParser support
;-----------------------------------------------------------------------------

        xor     ebx, ebx
        push    ebx
        push    esp
        call    skip_iid
        db      0e1h, 02ah, 01ah, 0bbh, 0f9h, 0a4h, 0cfh, 011h, 08fh, 020h, 000h, 080h, 05fh, 02ch, 0d0h, 064h

skip_iid:
        pop     edi
        push    edi
        push    CLSCTX_INPROC_SERVER
        push    ebx
        call    skip_guid
        db      060h, 0c2h, 014h, 0f4h, 0c0h, 06ah, 0cfh, 011h, 0b6h, 0d1h, 000h, 0aah, 000h, 0bbh, 0bbh, 058h

skip_guid:
        push    COINIT_APARTMENTTHREADED
        push    ebx
        call    dword [ebp + comcrcstk.oCoInitializeEx]
        call    dword [ebp + comcrcstk.oCoCreateInstance]
        pop     esi
        push    ebx
        push    esp
        inc     dword [edi]                  ;RIIDs differ by one bit
        push    edi
        push    esi
        mov     eax, dword [esi]
        call    dword [eax + IActiveScript_vtable.iaQueryInterface]
        dec     dword [edi]                  ;restore bit

;-----------------------------------------------------------------------------
;initialize new script engine
;-----------------------------------------------------------------------------

        pop     edi
        push    edi
        mov     eax, dword [edi]
        call    dword [eax + IActiveScriptParse32_vtable.iaInitNew]
        call    skip_methods

methods_table:

;-----------------------------------------------------------------------------
;HRESULT (STDMETHODCALLTYPE *QueryInterface)(IActiveScriptSite *this, REFIID riid, void **ppvObject);
;-----------------------------------------------------------------------------

mQueryInterface:
        mov     eax, E_NOTIMPL 
        retn    0ch

;-----------------------------------------------------------------------------
;ULONG (STDMETHODCALLTYPE *AddRef)(IActiveScriptSite *this);     
;ULONG (STDMETHODCALLTYPE *Release)(IActiveScriptSite *this);
;HRESULT (STDMETHODCALLTYPE *OnEnterScript)(IActiveScriptSite *this);
;HRESULT (STDMETHODCALLTYPE *OnLeaveScript)(IActiveScriptSite *this);
;-----------------------------------------------------------------------------

mAddRef:
mRelease:
mOnEnterScript:
mOnLeaveScript:
        xor     eax, eax
        retn    4
   
;-----------------------------------------------------------------------------
;HRESULT (STDMETHODCALLTYPE *GetLCID)(IActiveScriptSite *this, LCID *plcid);
;HRESULT (STDMETHODCALLTYPE *GetDocVersionString)(IActiveScriptSite *this, BSTR *pbstrVersion);
;-----------------------------------------------------------------------------

mGetLCID:
mGetDocVersionString:
        mov     eax, E_NOTIMPL 
        retn    8

;-----------------------------------------------------------------------------
;HRESULT (STDMETHODCALLTYPE *OnScriptTerminate)(IActiveScriptSite *this, const VARIANT *pvarResult, const EXCEPINFO *pexcepinfo);
;-----------------------------------------------------------------------------

mOnScriptTerminate:
        xor     eax, eax
        retn    0ch

;-----------------------------------------------------------------------------
;HRESULT (STDMETHODCALLTYPE *OnStateChange)(IActiveScriptSite *this, SCRIPTSTATE ssScriptState);
;HRESULT (STDMETHODCALLTYPE *OnScriptError)(IActiveScriptSite *this, IActiveScriptError *pscripterror);
;-----------------------------------------------------------------------------

mOnStateChange:
mOnScriptError:
        xor     eax, eax
        retn    8

;-----------------------------------------------------------------------------
;create virtual table in stack
;-----------------------------------------------------------------------------

skip_methods:
        pop     eax
        lea     edx, dword [eax + mOnLeaveScript - methods_table]
        push    edx
        push    edx                          ;OnEnterScript
        lea     ecx, dword [eax + mOnScriptError - methods_table]
        push    ecx
        push    ecx                          ;OnStateChange
        lea     ecx, dword [eax + mOnScriptTerminate - methods_table]
        push    ecx
        lea     ecx, dword [eax + mGetDocVersionString - methods_table]
        push    ecx
        push    ebx                          ;GetItemInfo
        push    ecx                          ;GetLCID
        push    edx                          ;Release
        push    edx                          ;AddRef
        push    eax                          ;QueryInterface
        push    esp                          ;vtbl
        push    esp
        push    esi
        mov     eax, dword [esi]
        call    dword [eax + IActiveScript_vtable.iaSetScriptSite]
        push    ebx
        push    ebx
        push    SCRIPTTEXT_ISEXPRESSION
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        call    skip_script
        dw      "n", "e", "w", " ", "A", "c", "t", "i", "v", "e", "X", "O", "b", "j", "e", "c", "t"
        dw      "(", '"', "W", "S", "c", "r", "i", "p", "t", ".", "S" , "h", "e", "l", "l", '"', ")"
        dw      ".", "P", "o", "p", "u", "p", "(", '"', "H", "e", "l", "l", "o", " ", "w", "o", "r", "l", "d", '"', ")", 0;

skip_script:
        push    edi
        mov     eax, dword [edi]
        call    dword [eax + IActiveScriptParse32_vtable.iaParseScriptText]
        push    SCRIPTSTATE_CONNECTED
        push    esi
        mov     eax, dword [esi]
        call    dword [eax + IActiveScript_vtable.iaSetScriptState]
        push    edi
        mov     eax, dword [edi]
        call    dword [eax + IActiveScriptParse32_vtable.iaRelease]
        push    esi
        mov     eax, dword [esi]
        call    dword [eax + IActiveScript_vtable.iaRelease]

;toDo:
;release all here
int3

init_kernel32:
        mov     eax, dword [ebx + pebLdr]    ;ebx = fs:[30h] at start time
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    esi, eax
        lodsd
        mov     ebp, dword [eax + mlDllBase]

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi
        mov     ebx, ebp
        mov     eax, dword [ebp + mzhdr.mzlfanew]
        add     ebx, dword [ebp + eax + pehdr.peexport + pedir.dirrva]
        cdq

walk_names:
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword [ebx + peexp.expnamerva]
        add     edi, dword [eax + edx * 4]
        or      eax, -1

crc_outer:
        xor     al, byte [edi]
        push    8
        pop     ecx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword [ebx + peexp.expordrva]
        movzx   edi, word [edi + edx * 2]
        add     eax, dword [ebx + peexp.expadrrva]
        mov     eax, dword [eax + edi * 4]
        add     eax, ebp
        push    eax
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names
        inc     esi
        jmp     esi