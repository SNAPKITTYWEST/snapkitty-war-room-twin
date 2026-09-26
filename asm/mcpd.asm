; SPDX-License-Identifier: AGPL-3.0-or-later
;
; ccgui-asm-bridge
; Copyright (C) 2026 SnapKitty Collective
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU Affero General Public License as published
; by the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU Affero General Public License for more details.
;
; You should have received a copy of the GNU Affero General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>.

; ============================================================================
; mcpd.asm — pure x86-64 assembly TCP MCP server. No libc, Linux syscalls only.
;
; Fork-gut of ahmad-parr-dev/jetbrains-cc-gui: the valuable core of ai-bridge
;   1. daemon.js        NDJSON JSON-RPC discipline  -> \n-delimited JSON-RPC 2.0
;   2. channel-manager  tool dispatch table        -> MCP tools/list + tools/call
;   3. permission-safety path gate                 -> policy_check (tmp rewrite,
;                                                     root containment,
;                                                     dangerous-path screen)
;   4. mcp-protocol.js  initialize handshake       -> initialize method
; rebuilt at the syscall layer. Assemble: nasm -f elf64 ; link: ld.
; ============================================================================
default rel

%define SYS_read          0
%define SYS_write         1
%define SYS_close         3
%define SYS_pipe          22
%define SYS_dup2          33
%define SYS_getcwd        79
%define SYS_fork          57
%define SYS_execve        59
%define SYS_wait4         61
%define SYS_exit          60
%define SYS_socket        41
%define SYS_bind          49
%define SYS_listen        50
%define SYS_accept        43
%define SYS_setsockopt    54
%define SYS_rt_sigaction  13

%macro SC0 1
    mov rax, %1
    syscall
%endmacro
%macro SC1 2
    mov rax, %1
    mov rdi, %2
    syscall
%endmacro

section .data
    ; ---- method / tool names ----
    m_initialize: db "initialize",0
    m_ping:       db "ping",0
    m_tools_list: db "tools/list",0
    m_tools_call: db "tools/call",0
    m_notif_pfx:  db "notifications/",0
    t_echo:       db "bridge.echo",0
    t_identity:   db "bridge.identity",0
    t_policy:     db "bridge.policy_check",0
    t_exec:       db "bridge.exec",0
    t_read:       db "bridge.read_file",0
    t_write:      db "bridge.write_file",0
    t_list:       db "bridge.list_dir",0
    t_sysinfo:    db "bridge.system_info",0

    ; ---- JSON keys ----
    k_id:        db "id",0
    k_method:    db "method",0
    k_params:    db "params",0
    k_name:      db "name",0
    k_arguments: db "arguments",0
    k_path:      db "path",0
    k_cmd:       db "command",0
    k_args:      db "args",0
    k_content:   db "content",0

    ; ---- JSON fragments ----
    j_rpc_id:    db '{"jsonrpc":"2.0","id":',0
    j_result:    db ',"result":',0
    j_err_pfx:   db ',"error":{"code":',0
    j_msg_pfx:   db ',"message":"',0
    j_msg_sfx:   db '"}}',0
    j_close:     db '}',0
    j_nl:        db 10
    empty_obj:   db '{}',0
    echo_pfx:    db '{"echo":',0
    ident_a:     db '{"name":"mcpd-asm","version":"0.1.0","transport":"tcp","arch":"x86-64","syscalls":"raw","root":"',0
    ident_b:     db '"}',0
    pol_a:       db '{"verdict":"',0
    pol_b:       db '","path":"',0
    pol_c:       db '"}',0
    read_a:      db '{"content":"',0
    read_b:      db '","bytes":',0
    write_a:     db '{"bytes":',0
    write_b:     db ',"path":"',0
    list_a:      db '{"path":"',0
    list_b:      db '","entries":[',0
    list_c:      db ']}',0
    ent_a:       db '{"name":"',0
    ent_b:       db '","type":"',0
    ent_c:       db '"}',0
    sys_a:       db '{"sysname":"',0
    sys_b:       db '","nodename":"',0
    sys_c:       db '","release":"',0
    sys_d:       db '","version":"',0
    sys_e:       db '","machine":"',0
    e_io:        db "I/O error",0
    t_file:      db "file",0
    t_dir:       db "dir",0
    t_other:     db "other",0
    exec_a:      db '{"stdout":"',0
    exec_b:      db '","exit_code":',0
    init_result: db '{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mcpd-asm","version":"0.1.0"}}',0

    ; ---- tools/list payload ----
    tl_a: db '{"tools":[{"name":"bridge.echo","description":"Echo back the arguments object","inputSchema":{"type":"object"}},',0
    tl_b: db '{"name":"bridge.identity","description":"Report server identity and configuration","inputSchema":{"type":"object"}},',0
    tl_c: db '{"name":"bridge.policy_check","description":"Permission gate ported from ai-bridge permission-safety.js: tmp-path rewrite, root containment, dangerous-path screen","inputSchema":{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}},',0
    tl_d: db '{"name":"bridge.exec","description":"Execute a command with every argument passed through the permission gate","inputSchema":{"type":"object","required":["command"],"properties":{"command":{"type":"string"},"args":{"type":"array","items":{"type":"string"}}}}},',0
    tl_e: db '{"name":"bridge.read_file","description":"Read a file through the permission gate","inputSchema":{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}},',0
    tl_f: db '{"name":"bridge.write_file","description":"Write a file through the permission gate","inputSchema":{"type":"object","required":["path","content"],"properties":{"path":{"type":"string"},"content":{"type":"string"}}}},',0
    tl_g: db '{"name":"bridge.list_dir","description":"List a directory through the permission gate","inputSchema":{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}},',0
    tl_h: db '{"name":"bridge.system_info","description":"Report kernel and machine information","inputSchema":{"type":"object"}}]}',0

    ; ---- errors / verdicts ----
    e_parse:    db "Parse error",0
    e_invalid:  db "Invalid Request",0
    e_no_method: db "Method not found",0
    e_no_tool:  db "Unknown tool",0
    e_bad_params: db "Invalid params",0
    e_internal: db "Internal error",0
    e_blk_pfx:  db "Policy blocked: ",0
    v_ok:        db "ok",0
    v_rewritten: db "rewritten",0
    v_blocked:   db "blocked",0

    ; ---- permission-safety port: tmp prefixes ----
    tmp1: db "/tmp",0
    tmp2: db "/var/tmp",0
    tmp3: db "/private/tmp",0

    ; ---- permission-safety port: dangerous patterns (substring match) ----
    dp_etc:    db "/etc/",0
    dp_system: db "/System/",0
    dp_usr:    db "/usr/",0
    dp_bin:    db "/bin/",0
    dp_sbin:   db "/sbin/",0
    ; home-relative patterns, $HOME prepended at runtime
    hp_ssh:    db "/.ssh/",0
    hp_aws:    db "/.aws/",0
    hp_gnupg:  db "/.gnupg/",0
    hp_kube:   db "/.kube/",0
    hp_docker: db "/.docker/",0
    hp_config: db "/.config/",0
    hp_local:  db "/.local/",0
    hp_creds:  db "/.claude/.credentials.json",0

    home_eq:  db "HOME=",0
    banner_a: db "mcpd-asm: listening on 127.0.0.1:",0
    banner_b: db " root=",0
    fatal_msg: db "mcpd-asm: fatal startup failure",10,0
    one_dd:   dd 1

section .bss
    rbuf:        resb 16384
    rlen:        resq 1
    outbuf:      resb 65536
    outpos:      resq 1
    id_buf:      resb 256
    id_len:      resq 1
    id_present:  resq 1
    method_buf:  resb 128
    method_len:  resq 1
    name_buf:    resb 128
    name_len:    resq 1
    tmp_str:     resb 8192
    args_start:  resq 1
    args_len:    resq 1
    exec_argv:   resq 66
    exec_args:   resb 16384
    exec_cursor: resq 1
    cap_buf:     resb 16384
    cap_len:     resq 1
    exit_code:   resq 1
    wstatus:     resd 1
    root_buf:    resb 4096
    root_len:    resq 1
    home_buf:    resb 4096
    home_len:    resq 1
    work_buf:    resb 8192
    work2_buf:   resb 8192
    norm_buf:    resb 8192
    final_path:  resb 8192
    final_path_len: resq 1
    seg_stack:   resq 512
    pat_tmp:     resb 8192
    numbuf:      resb 32
    sa_buf:      resb 32
    sock_addr:   resb 16
    pipefd:      resd 2
    listen_fd:   resq 1
    conn_fd:     resq 1
    port_num:    resq 1
    envp_empty:  resq 1
    file_buf:    resb 65536
    file_len:    resq 1
    dent_buf:    resb 32768
    path_nt:     resb 8192
    uname_buf:   resb 390

section .text
global _start
; ============================================================================
; small utilities. Convention: rbx, r12-r15 callee-saved; rax return; others free.
; ============================================================================

; strlen(rdi=cstr) -> rax
strlen:
    xor eax, eax
.l: cmp byte [rdi+rax], 0
    je .d
    inc rax
    jmp .l
.d: ret

; memeq(rdi, rsi, rdx=len) -> rax 1/0
memeq:
    test rdx, rdx
    jz .yes
.l: mov al, [rdi]
    cmp al, [rsi]
    jne .no
    inc rdi
    inc rsi
    dec rdx
    jnz .l
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; memcpy(rdi=dst, rsi=src, rdx=len). Clobbers rcx/rsi/rdi.
memcpy:
    mov rcx, rdx
    rep movsb
    ret

; streq(rdi=ptr, rsi=len, rdx=cstr) -> rax 1/0
streq:
    push rbx
    push r12
    mov r12, rdi
    mov rbx, rsi
    mov rdi, rdx
    call strlen
    cmp rax, rbx
    jne .no
    mov rdi, r12
    mov rsi, rdx
    mov rdx, rbx
    call memeq
    pop r12
    pop rbx
    ret
.no:
    xor eax, eax
    pop r12
    pop rbx
    ret

; starts_with(rdi=ptr, rsi=len, rdx=prefix cstr) -> rax 1/0
starts_with:
    push rbx
    push r12
    push r13
    mov r12, rdi         ; ptr
    mov r13, rsi         ; len
    mov rbx, rdx         ; prefix cstr
    mov rdi, rdx
    call strlen          ; rax = plen
    cmp rax, r13
    ja .no
    mov rdx, rax
    mov rdi, r12
    mov rsi, rbx
    call memeq           ; memeq preserves rbx
    pop r13
    pop r12
    pop rbx
    ret
.no:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

; atoi(rdi=cstr) -> rax
atoi:
    xor eax, eax
.l: movzx ecx, byte [rdi]
    test cl, cl
    jz .d
    cmp cl, '0'
    jb .d
    cmp cl, '9'
    ja .d
    imul rax, rax, 10
    sub cl, '0'
    add rax, rcx
    inc rdi
    jmp .l
.d: ret
; ============================================================================
; output buffer builders (outbuf, 64K)
; ============================================================================
out_reset:
    mov qword [outpos], 0
    ret

; out_reserve(rdx=len) -> rax = write ptr or 0 if no room (truncates)
out_reserve:
    mov rax, [outpos]
    lea rcx, [rax+rdx]
    cmp rcx, 65000
    ja .full
    lea rax, [outbuf]
    add rax, [outpos]
    add qword [outpos], rdx
    ret
.full:
    xor eax, eax
    ret

; out_c(al=char)
out_c:
    push rax
    movzx edx, al
    push rdx
    mov rdx, 1
    call out_reserve
    pop rdx
    test rax, rax
    jz .d
    mov [rax], dl
.d: pop rax
    ret

; out_str(rdi=cstr)
out_str:
    push rdi
    call strlen
    mov rsi, rax
    pop rdi
    jmp out_mem

; out_mem(rdi=ptr, rsi=len)
out_mem:
    push rbx
    push r12
    mov r12, rdi
    mov rbx, rsi
    mov rdx, rsi
    call out_reserve
    test rax, rax
    jz .d
    mov rdi, rax
    mov rsi, r12
    mov rdx, rbx
    call memcpy
.d: pop r12
    pop rbx
    ret

; out_u64(rax=val)
out_u64:
    push rbx
    push r12
    mov rbx, rax
    lea r12, [numbuf+32]
    test rbx, rbx
    jnz .l
    dec r12
    mov byte [r12], '0'
    jmp .w
.l: xor edx, edx
    mov rax, rbx
    mov ecx, 10
    div ecx
    add dl, '0'
    dec r12
    mov [r12], dl
    mov rbx, rax
    test rbx, rbx
    jnz .l
.w: lea rdi, [numbuf+32]
    mov rsi, rdi
    sub rsi, r12       ; len
    mov rdi, r12
    call out_mem
    pop r12
    pop rbx
    ret

; out_i64(rax=val)
out_i64:
    test rax, rax
    jns .p
    push rax
    mov al, '-'
    call out_c
    pop rax
    neg rax
.p: jmp out_u64

; out_esc(rdi=ptr, rsi=len): JSON string escaping (", \, \n, \r, \t; drop other <0x20)
out_esc:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    xor ebx, ebx
.l: cmp rbx, r13
    jae .d
    mov al, [r12+rbx]
    inc rbx
    cmp al, '"'
    je .q
    cmp al, '\'
    je .bs
    cmp al, 10
    je .n
    cmp al, 13
    je .r
    cmp al, 9
    je .t
    cmp al, 0x20
    jb .l              ; drop other controls
    call out_c
    jmp .l
.q: mov al, '\'
    call out_c
    mov al, '"'
    call out_c
    jmp .l
.bs:
    mov al, '\'
    call out_c
    mov al, '\'
    call out_c
    jmp .l
.n: mov al, '\'
    call out_c
    mov al, 'n'
    call out_c
    jmp .l
.r: mov al, '\'
    call out_c
    mov al, 'r'
    call out_c
    jmp .l
.t: mov al, '\'
    call out_c
    mov al, 't'
    call out_c
    jmp .l
.d: pop r13
    pop r12
    pop rbx
    ret

; write_all(rdi=fd, rsi=ptr, rdx=len)
write_all:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
.l: test rbx, rbx
    jz .d
    mov rax, SYS_write
    mov rdi, r12
    mov rsi, r13
    mov rdx, rbx
    syscall
    test rax, rax
    jle .d
    add r13, rax
    sub rbx, rax
    jmp .l
.d: pop r13
    pop r12
    pop rbx
    ret
; ============================================================================
; JSON field scanners (pragmatic: key search + local grammar, not a full parser)
; ============================================================================

; find_key(rdi=ptr, rsi=len, rdx=key cstr) -> rax = value ptr (after ':' + ws), 0 if none
find_key:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi         ; base (unused, kept for clarity)
    mov r14, rdx         ; key
    mov rdi, rdx
    call strlen
    mov r15, rax         ; keylen
    lea rbx, [r12+rsi]   ; end
    mov r10, r12         ; p
.scan:
    cmp r10, rbx
    jae .nf
    cmp byte [r10], '"'
    jne .adv
    lea rax, [r10+1+r15]
    cmp rax, rbx
    ja .adv
    cmp byte [rax], '"'
    jne .adv
    lea rdi, [r10+1]
    mov rsi, r14
    mov rdx, r15
    call memeq
    test rax, rax
    jz .adv
    lea r10, [r10+1+r15+1]
.ws1:
    cmp r10, rbx
    jae .nf
    mov al, [r10]
    cmp al, ' '
    je .w1a
    cmp al, 9
    je .w1a
    cmp al, 13
    je .w1a
    jmp .colon
.w1a:
    inc r10
    jmp .ws1
.colon:
    cmp byte [r10], ':'
    jne .scan            ; not a key colon; keep scanning from here
    inc r10
.ws2:
    cmp r10, rbx
    jae .nf
    mov al, [r10]
    cmp al, ' '
    je .w2a
    cmp al, 9
    je .w2a
    cmp al, 13
    je .w2a
    jmp .found
.w2a:
    inc r10
    jmp .ws2
.found:
    mov rax, r10
    jmp .done
.adv:
    inc r10
    jmp .scan
.nf:
    xor eax, eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; extract_string(rdi=vptr, rsi=vend, rdx=dest, rcx=cap)
;   -> rax = pos after closing quote (0 on fail), rdx = unescaped len
extract_string:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp rdi, rsi
    jae .fail
    cmp byte [rdi], '"'
    jne .fail
    mov r12, rdi
    inc r12              ; p
    mov r13, rdx         ; d
    mov r14, rcx         ; cap
    xor r15d, r15d       ; len
.loop:
    cmp r12, rsi
    jae .fail
    mov al, [r12]
    cmp al, '"'
    je .done
    cmp al, '\'
    je .esc
    cmp r15, r14
    jae .fail
    mov [r13], al
    inc r13
    inc r12
    inc r15
    jmp .loop
.esc:
    inc r12
    cmp r12, rsi
    jae .fail
    mov al, [r12]
    cmp al, 'n'
    jne .e1
    mov al, 10
    jmp .emit
.e1:
    cmp al, 'r'
    jne .e2
    mov al, 13
    jmp .emit
.e2:
    cmp al, 't'
    jne .e3
    mov al, 9
    jmp .emit
.e3:
    cmp al, 'b'
    jne .e4
    mov al, 8
    jmp .emit
.e4:
    cmp al, 'f'
    jne .e5
    mov al, 12
    jmp .emit
.e5:
    cmp al, 'u'
    jne .e6
    ; \uXXXX -> '?' (documented simplification)
    add r12, 4
    cmp r12, rsi
    ja .fail
    mov al, '?'
    jmp .emit
.e6:
    ; \" \\ \/ and anything else -> literal char
.emit:
    cmp r15, r14
    jae .fail
    mov [r13], al
    inc r13
    inc r12
    inc r15
    jmp .loop
.done:
    inc r12
    mov rax, r12
    mov rdx, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fail:
    xor eax, eax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; capture_scalar(rdi=vptr, rsi=vend) -> rax = endpos (exclusive)
capture_scalar:
    push rbx
    mov rbx, rsi         ; end
    cmp rdi, rbx
    jae .d
    cmp byte [rdi], '"'
    je .str
.raw:
    mov rax, rdi
.l: cmp rax, rbx
    jae .d
    mov cl, [rax]
    cmp cl, ','
    je .d
    cmp cl, '}'
    je .d
    cmp cl, ']'
    je .d
    cmp cl, ' '
    je .d
    cmp cl, 9
    je .d
    cmp cl, 10
    je .d
    cmp cl, 13
    je .d
    inc rax
    jmp .l
.str:
    mov rax, rdi
    inc rax
.sl: cmp rax, rbx
    jae .d
    mov cl, [rax]
    cmp cl, '\'
    je .se
    cmp cl, '"'
    je .se2
    inc rax
    jmp .sl
.se: add rax, 2
    jmp .sl
.se2:
    inc rax
.d: pop rbx
    ret

; capture_balanced(rdi=vptr, rsi=vend) -> rax = pos after matching close, 0 on fail
; handles nested {} [] and strings with escapes
capture_balanced:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    cmp r12, r13
    jae .fail
    mov al, [r12]
    cmp al, '{'
    je .obj
    cmp al, '['
    je .arr
    jmp .fail
.obj:
    mov bl, '}'
    jmp .go
.arr:
    mov bl, ']'
.go:
    xor ecx, ecx         ; depth
    mov r10, r12         ; p
.lp: cmp r10, r13
    jae .fail
    mov al, [r10]
    cmp al, '"'
    je .str
    cmp al, '{'
    je .op
    cmp al, '['
    je .op
    cmp al, '}'
    je .cl
    cmp al, ']'
    je .cl
    inc r10
    jmp .lp
.op: inc ecx
    inc r10
    jmp .lp
.cl: dec ecx
    inc r10
    test ecx, ecx
    jnz .lp
    ; depth hit 0: verify closer matches opener
    cmp al, bl
    jne .fail
    mov rax, r10
    jmp .done
.str:
    inc r10
.sl2:
    cmp r10, r13
    jae .fail
    mov al, [r10]
    cmp al, '\'
    je .se
    cmp al, '"'
    je .sq
    inc r10
    jmp .sl2
.se: add r10, 2
    jmp .sl2
.sq: inc r10
    jmp .lp
.fail:
    xor eax, eax
.done:
    pop r13
    pop r12
    pop rbx
    ret

; contains(rdi=hay, rsi=haylen, rdx=needle, rcx=needlelen) -> rax 1/0
contains:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi         ; hay
    mov r13, rsi         ; haylen
    mov r14, rdx         ; needle
    mov r15, rcx         ; needlelen
    test r15, r15
    jz .yes
    cmp r15, r13
    ja .no
    mov rax, r13
    sub rax, r15         ; last start
    xor ebx, ebx         ; i
.l: cmp rbx, rax
    ja .no
    lea rdi, [r12+rbx]
    mov rsi, r14
    mov rdx, r15
    call memeq
    test rax, rax
    jnz .yes
    inc rbx
    jmp .l
.yes:
    mov eax, 1
    jmp .d
.no:
    xor eax, eax
.d: pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; ============================================================================
; response builders
; ============================================================================

; resp_result_begin: '{"jsonrpc":"2.0","id":<id>,"result":'
resp_result_begin:
    call out_reset
    lea rdi, [j_rpc_id]
    call out_str
    mov rdi, id_buf
    mov rsi, [id_len]
    call out_mem
    lea rdi, [j_result]
    call out_str
    ret

; resp_end: '}'
resp_end:
    lea rdi, [j_close]
    jmp out_str

; resp_error(rdi=code i64, rsi=msg cstr): full error response
resp_error:
    push rdi
    push rsi
    call out_reset
    lea rdi, [j_rpc_id]
    call out_str
    mov rdi, id_buf
    mov rsi, [id_len]
    call out_mem
    lea rdi, [j_err_pfx]
    call out_str
    pop rsi              ; msg
    pop rax              ; code -> rax for out_i64
    push rsi
    call out_i64
    lea rdi, [j_msg_pfx]
    call out_str
    pop rdi
    call out_str
    lea rdi, [j_msg_sfx]
    jmp out_str

; ============================================================================
; handlers
; ============================================================================
h_initialize:
    call resp_result_begin
    lea rdi, [init_result]
    call out_str
    jmp resp_end

h_ping:
    call resp_result_begin
    lea rdi, [empty_obj]
    call out_str
    jmp resp_end

h_tools_list:
    call resp_result_begin
    lea rdi, [tl_a]
    call out_str
    lea rdi, [tl_b]
    call out_str
    lea rdi, [tl_c]
    call out_str
    lea rdi, [tl_d]
    call out_str
    lea rdi, [tl_e]
    call out_str
    lea rdi, [tl_f]
    call out_str
    lea rdi, [tl_g]
    call out_str
    lea rdi, [tl_h]
    call out_str
    jmp resp_end

h_call_echo:
    call resp_result_begin
    lea rdi, [echo_pfx]
    call out_str
    cmp qword [args_start], 0
    je .noargs
    mov rdi, [args_start]
    mov rsi, [args_len]
    call out_mem
    jmp .close
.noargs:
    lea rdi, [empty_obj]
    call out_str
.close:
    lea rdi, [j_close]
    call out_str
    jmp resp_end

h_call_identity:
    call resp_result_begin
    lea rdi, [ident_a]
    call out_str
    mov rdi, root_buf
    mov rsi, [root_len]
    call out_esc
    lea rdi, [ident_b]
    call out_str
    jmp resp_end

h_call_policy:
    push rbx
    push r12
    push r13
    cmp qword [args_start], 0
    je .badparams
    mov rdi, [args_start]
    mov rsi, [args_len]
    mov r13, rdi
    add r13, rsi         ; r13 = args end
    lea rdx, [k_path]
    call find_key        ; rdi=ptr, rsi=len
    test rax, rax
    jz .badparams
    mov rdi, rax
    mov rsi, r13         ; vend
    lea rdx, [tmp_str]
    mov rcx, 8191
    call extract_string
    test rax, rax
    jz .badparams
    mov r12, rdx         ; path len
    lea rdi, [tmp_str]
    mov rsi, r12
    call policy_check    ; rax = verdict 0/1/2
    mov rbx, rax
    call resp_result_begin
    lea rdi, [pol_a]
    call out_str
    cmp rbx, 1
    je .rw
    cmp rbx, 2
    je .bl
    lea rdi, [v_ok]
    jmp .vok
.rw:
    lea rdi, [v_rewritten]
    jmp .vok
.bl:
    lea rdi, [v_blocked]
.vok:
    call out_str
    lea rdi, [pol_b]
    call out_str
    mov rdi, final_path
    mov rsi, [final_path_len]
    call out_esc
    lea rdi, [pol_c]
    call out_str
    call resp_end
    pop r13
    pop r12
    pop rbx
    ret
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
    pop r13
    pop r12
    pop rbx
    ret

section .data
    tmp_table: dq tmp1, tmp2, tmp3, 0
    dp_table:  dq dp_etc, dp_system, dp_usr, dp_bin, dp_sbin, 0
    hp_table:  dq hp_ssh, hp_aws, hp_gnupg, hp_kube, hp_docker, hp_config, hp_local, hp_creds, 0

section .text

; basename_of(rdi=ptr, rsi=len) -> rax=ptr, rdx=len
basename_of:
    mov rax, rdi
    add rax, rsi
    mov rdx, rsi
.b: cmp rax, rdi
    je .d
    dec rax
    cmp byte [rax], '/'
    je .found
    jmp .b
.found:
    inc rax
    mov rdx, rdi
    add rdx, rsi
    sub rdx, rax
.d: ret

; normalize(rdi=in, rsi=inlen, rdx=out) -> rax=outlen. in must be absolute.
; lexically resolves '.' and '..' (never escapes root '/').
normalize:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi         ; in
    mov r13, rsi         ; inlen
    mov r14, rdx         ; out
    lea r15, [r14]       ; o (segments each emit their own leading '/')
    xor ebx, ebx         ; segcount
    lea r10, [r12+1]     ; p
    lea r11, [r12+r13]   ; end
.seg:
    cmp r10, r11
    jae .done
    mov rax, r10
.find:
    cmp rax, r11
    jae .got
    cmp byte [rax], '/'
    je .got
    inc rax
    jmp .find
.got:                    ; segment = [r10, rax)
    mov rcx, rax
    sub rcx, r10
    jz .next             ; empty (//)
    cmp rcx, 1
    jne .notdot
    cmp byte [r10], '.'
    je .next
.notdot:
    cmp rcx, 2
    jne .push
    cmp word [r10], 0x2e2e
    jne .push
    test ebx, ebx        ; ".." above root -> stay
    jz .next
    dec ebx
    mov r15, [seg_stack+rbx*8]
    jmp .next
.push:
    cmp ebx, 512
    jae .next
    mov [seg_stack+rbx*8], r15
    mov byte [r15], '/'
    inc r15
    mov rdi, r15
    mov rsi, r10
    mov rdx, rcx
    push rcx
    call memcpy
    pop rcx
    add r15, rcx
    inc ebx
.next:
    mov r10, rax
    cmp r10, r11
    jae .done
    inc r10
    jmp .seg
.done:
    test ebx, ebx
    jnz .have
    mov byte [r15], '/'
    inc r15
.have:
    mov rax, r15
    sub rax, r14
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; dangerous_hit(rdi=ptr, rsi=len) -> rax 1 if any dangerous pattern is a substring
; port of permission-safety.js isDangerousPath (includes semantics, ~ pre-expanded)
dangerous_hit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    lea r14, [dp_table]
.dl:
    mov rdx, [r14]
    test rdx, rdx
    jz .home
    mov rdi, rdx
    call strlen
    mov rcx, rax
    mov rdi, r12
    mov rsi, r13
    call contains
    test rax, rax
    jnz .hit
    add r14, 8
    jmp .dl
.home:
    mov rax, [home_len]
    test rax, rax
    jz .no
    lea r14, [hp_table]
.hl:
    mov r15, [r14]       ; hpart
    test r15, r15
    jz .no
    ; pat_tmp = home + hpart
    lea rdi, [pat_tmp]
    lea rsi, [home_buf]
    mov rdx, [home_len]
    call memcpy
    mov rdi, r15
    call strlen          ; rax = hpart len
    lea rdi, [pat_tmp]
    add rdi, [home_len]
    mov rsi, r15
    mov rdx, rax
    call memcpy
    mov rcx, [home_len]
    add rcx, rax
    lea rdx, [pat_tmp]
    mov rdi, r12
    mov rsi, r13
    call contains
    test rax, rax
    jnz .hit
    add r14, 8
    jmp .hl
.hit:
    mov eax, 1
    jmp .d
.no:
    xor eax, eax
.d:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; policy_check(rdi=ptr, rsi=len) -> rax verdict: 0 ok, 1 rewritten, 2 blocked
; final path -> final_path / final_path_len
; port of permission-safety.js rewriteToolInputPaths + isDangerousPath, with the
; rewritten path verified against root containment (isPathInWorkingDirectory).
policy_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    xor ebx, ebx         ; rewritten flag
    cmp r13, 8000
    ja .blocked_empty
    test r13, r13
    jz .blocked_empty
    lea rdi, [work_buf]
    mov rsi, r12
    mov rdx, r13
    call memcpy
    mov byte [work_buf+r13], 0

    ; ---- expand leading ~/ ----
    cmp byte [work_buf], '~'
    jne .no_tilde
    cmp byte [work_buf+1], '/'
    jne .no_tilde
    mov rax, [home_len]
    test rax, rax
    jz .no_tilde
    lea rdi, [norm_buf]  ; scratch for tail
    lea rsi, [work_buf+1]
    mov rdx, r13
    dec rdx
    call memcpy
    mov r10, rdx         ; taillen
    lea rdi, [work_buf]
    lea rsi, [home_buf]
    mov rdx, [home_len]
    call memcpy
    lea rdi, [work_buf]
    add rdi, [home_len]
    lea rsi, [norm_buf]
    mov rdx, r10
    call memcpy
    mov rax, [home_len]
    add rax, r10
    mov r13, rax
    mov byte [work_buf+r13], 0
.no_tilde:

    ; ---- dangerous screen on expanded raw path ----
    lea rdi, [work_buf]
    mov rsi, r13
    call dangerous_hit
    test rax, rax
    jnz .blocked_raw

    ; ---- tmp prefix rewrite -> project root ----
    lea r14, [tmp_table]
.tloop:
    mov r15, [r14]
    test r15, r15
    jz .no_tmp
    lea rdi, [work_buf]
    mov rsi, r13
    mov rdx, r15
    call starts_with
    test rax, rax
    jz .tnext
    mov rdi, r15
    call strlen          ; rax = plen (rdx preserved by strlen? no: rdx was prefix;
                         ; strlen uses rdi/rax only -> r15 still holds prefix)
    cmp r13, rax
    je .dorewrite
    cmp byte [work_buf+rax], '/'
    jne .tnext
.dorewrite:
    lea r10, [work_buf]
    add r10, rax         ; rest ptr
    mov r11, r13
    sub r11, rax         ; rest len
.strip:
    test r11, r11
    jz .basen
    cmp byte [r10], '/'
    jne .gotrest
    inc r10
    dec r11
    jmp .strip
.basen:
    lea rdi, [work_buf]
    mov rsi, r13
    call basename_of
    mov r10, rax
    mov r11, rdx
.gotrest:
    lea rdi, [work2_buf]
    lea rsi, [root_buf]
    mov rdx, [root_len]
    call memcpy
    lea rax, [work2_buf]
    add rax, [root_len]
    mov byte [rax], '/'
    lea rdi, [work2_buf]
    add rdi, [root_len]
    inc rdi
    mov rsi, r10
    mov rdx, r11
    call memcpy
    mov rax, [root_len]
    inc rax
    add rax, r11
    mov r13, rax
    lea rdi, [work_buf]
    lea rsi, [work2_buf]
    mov rdx, r13
    call memcpy
    mov byte [work_buf+r13], 0
    mov ebx, 1
    jmp .no_tmp
.tnext:
    add r14, 8
    jmp .tloop
.no_tmp:

    ; ---- absolutize relative paths against root ----
    cmp byte [work_buf], '/'
    je .abs
    lea rdi, [work2_buf]
    lea rsi, [root_buf]
    mov rdx, [root_len]
    call memcpy
    lea rax, [work2_buf]
    add rax, [root_len]
    mov byte [rax], '/'
    lea rdi, [work2_buf]
    add rdi, [root_len]
    inc rdi
    lea rsi, [work_buf]
    mov rdx, r13
    call memcpy
    mov rax, [root_len]
    inc rax
    add rax, r13
    mov r13, rax
    lea rdi, [work_buf]
    lea rsi, [work2_buf]
    mov rdx, r13
    call memcpy
    mov byte [work_buf+r13], 0
.abs:

    ; ---- normalize ----
    lea rdi, [work_buf]
    mov rsi, r13
    lea rdx, [norm_buf]
    call normalize
    mov r13, rax         ; normlen

    ; ---- containment ----
    mov rax, [root_len]
    cmp r13, rax
    jb .blocked_norm
    lea rdi, [norm_buf]
    lea rsi, [root_buf]
    mov rdx, rax
    call memeq
    test rax, rax
    jz .blocked_norm
    cmp r13, [root_len]
    je .contained
    mov rax, [root_len]
    cmp byte [norm_buf+rax], '/'
    jne .blocked_norm
.contained:

    ; ---- dangerous screen on normalized path ----
    lea rdi, [norm_buf]
    mov rsi, r13
    call dangerous_hit
    test rax, rax
    jnz .blocked_norm

    ; ---- verdict ----
    lea rdi, [final_path]
    lea rsi, [norm_buf]
    mov rdx, r13
    call memcpy
    mov [final_path_len], r13
    test ebx, ebx
    jz .done
    mov eax, 1
    jmp .done
.blocked_norm:
    lea rdi, [final_path]
    lea rsi, [norm_buf]
    mov rdx, r13
    call memcpy
    mov [final_path_len], r13
    mov eax, 2
    jmp .done
.blocked_raw:
    lea rdi, [final_path]
    lea rsi, [work_buf]
    mov rdx, r13
    call memcpy
    mov [final_path_len], r13
    mov eax, 2
    jmp .done
.blocked_empty:
    mov qword [final_path_len], 0
    mov eax, 2
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; ============================================================================
; bridge.exec: policy-gated fork/execve with stdout capture
; ============================================================================

; exec_emit(rdi=ptr, rsi=len): copy NUL-terminated string to exec_args cursor.
; -> rax = dest ptr
exec_emit:
    push rbx
    mov rbx, rsi
    mov rax, [exec_cursor]
    mov rdx, rbx
    mov rsi, rdi
    mov rdi, rax
    call memcpy
    mov rax, [exec_cursor]
    mov byte [rax+rbx], 0
    add qword [exec_cursor], rbx
    inc qword [exec_cursor]
    pop rbx
    ret

; parse_args_array(rdi=ptr at '[', rsi=end)
; -> rax = argc (>=0), -1 parse error, -2 policy blocked (final_path has culprit)
; fills exec_argv[1..], strings appended at exec_cursor
parse_args_array:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi         ; p
    mov r13, rsi         ; end
    inc r12              ; past '['
    xor ebx, ebx         ; argc
.loop:
    ; skip ws and commas
.ws: cmp r12, r13
    jae .perr
    mov al, [r12]
    cmp al, ' '
    je .wsa
    cmp al, 9
    je .wsa
    cmp al, 10
    je .wsa
    cmp al, 13
    je .wsa
    cmp al, ','
    je .wsa
    jmp .tok
.wsa:
    inc r12
    jmp .ws
.tok:
    cmp byte [r12], ']'
    je .done
    cmp byte [r12], '"'
    jne .perr
    mov rdi, r12
    mov rsi, r13
    lea rdx, [tmp_str]
    mov rcx, 8191
    call extract_string
    test rax, rax
    jz .perr
    mov r12, rax          ; p = endpos
    mov r14, rdx          ; len
    ; only gate path-like args (contain '/' or start with '.'/'~');
    ; plain tokens pass through unchanged
    xor ecx, ecx
    cmp r14, 0
    je .use_raw_arg
    mov al, [tmp_str]
    cmp al, '.'
    je .gate_arg
    cmp al, '~'
    je .gate_arg
.scan_arg:
    cmp rcx, r14
    jae .use_raw_arg
    cmp byte [tmp_str+rcx], '/'
    je .gate_arg
    inc rcx
    jmp .scan_arg
.gate_arg:
    lea rdi, [tmp_str]
    mov rsi, r14
    call policy_check
    cmp rax, 2
    je .blocked
    lea rdi, [final_path]
    mov rsi, [final_path_len]
    jmp .emit_arg
.use_raw_arg:
    lea rdi, [tmp_str]
    mov rsi, r14
.emit_arg:
    call exec_emit        ; rax = dest ptr
    lea r14, [exec_argv+8]
    mov [r14+rbx*8], rax
    inc rbx
    cmp rbx, 64
    jae .perr
    jmp .loop
.done:
    mov rax, rbx
    jmp .out
.perr:
    mov rax, -1
    jmp .out
.blocked:
    mov rax, -2
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; do_exec: exec_argv is NULL-terminated. -> cap_buf/cap_len, exit_code
do_exec:
    push rbx
    push r12
    push r13
    lea rdi, [pipefd]
    mov rax, SYS_pipe
    syscall
    test rax, rax
    js .err
    mov rax, SYS_fork
    syscall
    test rax, rax
    jz .child
    js .err
    mov r12, rax         ; child pid (unused, kept for clarity)
    ; parent: close write end
    mov edi, [pipefd+4]
    mov rax, SYS_close
    syscall
    mov qword [cap_len], 0
.rd:
    mov rax, [cap_len]
    cmp rax, 16383
    jae .crd
    mov edi, [pipefd]
    lea rsi, [cap_buf]
    add rsi, [cap_len]
    mov rdx, 16383
    sub rdx, [cap_len]
    mov rax, SYS_read
    syscall
    test rax, rax
    jle .crd
    add [cap_len], rax
    jmp .rd
.crd:
    mov edi, [pipefd]
    mov rax, SYS_close
    syscall
    mov rax, SYS_wait4
    mov rdi, -1
    lea rsi, [wstatus]
    xor edx, edx
    xor r10d, r10d
    syscall
    mov eax, [wstatus]
    mov ecx, eax
    and ecx, 0x7f
    jz .exited
    add ecx, 128
    mov [exit_code], rcx
    jmp .out
.exited:
    shr eax, 8
    and eax, 0xff
    mov [exit_code], rax
    jmp .out
.err:
    mov qword [cap_len], 0
    mov qword [exit_code], 127
.out:
    pop r13
    pop r12
    pop rbx
    ret
.child:
    mov edi, [pipefd]
    mov rax, SYS_close
    syscall
    mov edi, [pipefd+4]
    mov esi, 1
    mov rax, SYS_dup2
    syscall
    mov edi, [pipefd+4]
    mov esi, 2
    mov rax, SYS_dup2
    syscall
    mov edi, [pipefd+4]
    mov rax, SYS_close
    syscall
    mov rdi, [exec_argv]
    lea rsi, [exec_argv]
    lea rdx, [envp_empty]
    mov rax, SYS_execve
    syscall
    mov rax, SYS_exit
    mov rdi, 127
    syscall

h_call_exec:
    push rbx
    push r12
    push r13
    cmp qword [args_start], 0
    je .badparams
    mov rdi, [args_start]
    mov rsi, [args_len]
    mov r13, rdi
    add r13, rsi         ; r13 = args end
    lea rdx, [k_cmd]
    call find_key        ; rdi=ptr, rsi=len
    test rax, rax
    jz .badparams
    mov rdi, rax
    mov rsi, r13         ; vend
    lea rdx, [tmp_str]
    mov rcx, 8191
    call extract_string
    test rax, rax
    jz .badparams
    mov r12, rdx         ; cmd len
    ; gate cmd
    lea rdi, [tmp_str]
    mov rsi, r12
    call policy_check
    cmp rax, 2
    je .blocked_cmd
    ; argv[0] = gated cmd
    lea rax, [exec_args]
    mov [exec_cursor], rax
    lea rdi, [final_path]
    mov rsi, [final_path_len]
    call exec_emit
    mov [exec_argv], rax
    ; args array (optional)
    mov rdi, [args_start]
    mov rsi, [args_len]
    lea rdx, [k_args]
    call find_key        ; rdi=ptr, rsi=len
    test rax, rax
    jz .noargs
    mov r12, rax
    cmp byte [r12], '['
    jne .badparams
    mov rdi, r12
    mov rsi, r13
    call parse_args_array
    cmp rax, -2
    je .blocked_arg
    cmp rax, -1
    je .badparams
    mov rbx, rax         ; argc
    jmp .haveargs
.noargs:
    xor ebx, ebx
.haveargs:
    lea rax, [exec_argv+8]
    mov qword [rax+rbx*8], 0
    call do_exec
    call resp_result_begin
    lea rdi, [exec_a]
    call out_str
    mov rdi, cap_buf
    mov rsi, [cap_len]
    call out_esc
    lea rdi, [exec_b]
    call out_str
    mov rax, [exit_code]
    call out_u64
    lea rdi, [j_close]
    call out_str
    call resp_end
    jmp .out
.blocked_cmd:
    jmp .blocked
.blocked_arg:
    ; final_path holds the blocked arg
.blocked:
    call out_reset
    lea rdi, [j_rpc_id]
    call out_str
    mov rdi, id_buf
    mov rsi, [id_len]
    call out_mem
    lea rdi, [j_err_pfx]
    call out_str
    mov rax, 44001
    call out_i64
    lea rdi, [j_msg_pfx]
    call out_str
    lea rdi, [e_blk_pfx]
    call out_str
    mov rdi, final_path
    mov rsi, [final_path_len]
    call out_esc
    lea rdi, [j_msg_sfx]
    call out_str
    jmp .out
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
.out:
    pop r13
    pop r12
    pop rbx
    ret
; ============================================================================
; ============================================================================
; bridge.read_file / bridge.write_file / bridge.list_dir / bridge.system_info
; ============================================================================

; nullterm_final_path: copy final_path[0..final_path_len] to path_nt + NUL
; clobbers rax, rdi, rsi, rdx
nullterm_final_path:
    lea rdi, [path_nt]
    lea rsi, [final_path]
    mov rdx, [final_path_len]
    call memcpy
    mov rax, [final_path_len]
    mov byte [path_nt+rax], 0
    ret

; blocked_44001: emit {"error":{"code":44001,"message":"Policy blocked: <final_path>"}}
; uses current id_buf/id_len
blocked_44001:
    call out_reset
    lea rdi, [j_rpc_id]
    call out_str
    mov rdi, id_buf
    mov rsi, [id_len]
    call out_mem
    lea rdi, [j_err_pfx]
    call out_str
    mov rax, 44001
    call out_i64
    lea rdi, [j_msg_pfx]
    call out_str
    lea rdi, [e_blk_pfx]
    call out_str
    mov rdi, final_path
    mov rsi, [final_path_len]
    call out_esc
    lea rdi, [j_msg_sfx]
    call out_str
    ret

; extract_path_arg -> rax=1 ok (r12=len, tmp_str has path, r13=args end), rax=0 bad
; clobbers rdi, rsi, rdx
extract_path_arg:
    cmp qword [args_start], 0
    je .bad
    mov rdi, [args_start]
    mov rsi, [args_len]
    mov r13, rdi
    add r13, rsi
    lea rdx, [k_path]
    call find_key
    test rax, rax
    jz .bad
    mov rdi, rax
    mov rsi, r13
    lea rdx, [tmp_str]
    mov rcx, 8191
    call extract_string
    test rax, rax
    jz .bad
    mov r12, rdx
    mov rax, 1
    ret
.bad:
    xor rax, rax
    ret

; gate_path: policy_check tmp_str[r12], -> rax=verdict (0 ok,1 rewritten,2 blocked)
; on blocked, final_path holds culprit
gate_path:
    lea rdi, [tmp_str]
    mov rsi, r12
    call policy_check
    ret

; ---- bridge.read_file ----
h_call_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call extract_path_arg
    test rax, rax
    jz .badparams
    call gate_path
    cmp rax, 2
    je .blocked
    call nullterm_final_path
    mov rax, 257            ; openat
    mov rdi, -100           ; AT_FDCWD
    lea rsi, [path_nt]
    xor rdx, rdx            ; O_RDONLY
    syscall
    cmp rax, 0
    jl .ioerr
    mov r14, rax            ; fd
    xor rbx, rbx            ; total
.rl:
    cmp rbx, 65535
    jge .done
    mov rax, 0              ; read
    mov rdi, r14
    lea rsi, [file_buf+rbx]
    mov rdx, 65535
    sub rdx, rbx
    syscall
    cmp rax, 0
    jle .done
    add rbx, rax
    jmp .rl
.done:
    mov [file_len], rbx
    mov rax, 3              ; close
    mov rdi, r14
    syscall
    call resp_result_begin
    lea rdi, [read_a]
    call out_str
    mov rdi, file_buf
    mov rsi, rbx
    call out_esc
    lea rdi, [read_b]
    call out_str
    mov rax, rbx
    call out_u64
    lea rdi, [j_close]
    call out_str
    call resp_end
    jmp .out
.blocked:
    call blocked_44001
    jmp .out
.ioerr:
    mov rdi, -32603
    lea rsi, [e_io]
    call resp_error
    jmp .out
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- bridge.write_file ----
h_call_write:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call extract_path_arg
    test rax, rax
    jz .badparams
    mov r15, r12            ; save path len (r12 gets clobbered)
    ; extract content string -> file_buf
    mov rdi, [args_start]
    mov rsi, [args_len]
    lea rdx, [k_content]
    call find_key
    test rax, rax
    jz .badparams
    mov rdi, rax
    ; r13 still = args end from extract_path_arg
    mov rsi, r13
    lea rdx, [file_buf]
    mov rcx, 60000
    call extract_string
    test rax, rax
    jz .badparams
    mov r14, rdx            ; content len
    ; restore path into tmp_str for gating (extract_string overwrote tmp_str? no, used file_buf)
    mov r12, r15
    call gate_path
    cmp rax, 2
    je .blocked
    call nullterm_final_path
    mov rax, 257            ; openat
    mov rdi, -100
    lea rsi, [path_nt]
    mov rdx, 577            ; O_WRONLY|O_CREAT|O_TRUNC = 1+64+512
    mov r10, 420            ; 0644
    syscall
    cmp rax, 0
    jl .ioerr
    mov r15, rax            ; fd
    xor rbx, rbx            ; written
.wl:
    cmp rbx, r14
    jge .wdone
    mov rax, 1              ; write
    mov rdi, r15
    lea rsi, [file_buf+rbx]
    mov rdx, r14
    sub rdx, rbx
    syscall
    cmp rax, 0
    jle .werr
    add rbx, rax
    jmp .wl
.wdone:
    mov rax, 3
    mov rdi, r15
    syscall
    call resp_result_begin
    lea rdi, [write_a]
    call out_str
    mov rax, rbx
    call out_u64
    lea rdi, [write_b]
    call out_str
    mov rdi, final_path
    mov rsi, [final_path_len]
    call out_esc
    lea rdi, [pol_c]
    call out_str
    call resp_end
    jmp .out
.werr:
    mov rax, 3
    mov rdi, r15
    syscall
.ioerr:
    mov rdi, -32603
    lea rsi, [e_io]
    call resp_error
    jmp .out
.blocked:
    call blocked_44001
    jmp .out
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---- bridge.list_dir ----
h_call_list:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call extract_path_arg
    test rax, rax
    jz .badparams
    call gate_path
    cmp rax, 2
    je .blocked
    call nullterm_final_path
    mov rax, 257            ; openat
    mov rdi, -100
    lea rsi, [path_nt]
    mov rdx, 65536          ; O_DIRECTORY
    xor r10, r10
    syscall
    cmp rax, 0
    jl .ioerr
    mov r14, rax            ; fd
    call resp_result_begin
    lea rdi, [list_a]
    call out_str
    mov rdi, final_path
    mov rsi, [final_path_len]
    call out_esc
    lea rdi, [list_b]
    call out_str
    xor r15, r15            ; first-entry flag (0 = first)
.dl:
    mov rax, 217            ; getdents64
    mov rdi, r14
    lea rsi, [dent_buf]
    mov rdx, 32768
    syscall
    cmp rax, 0
    jle .ddone
    mov rbx, rax            ; bytes
    lea r12, [dent_buf]     ; cursor
    lea r13, [dent_buf+rbx] ; end
.el:
    cmp r12, r13
    jge .dl
    movzx eax, word [r12+16] ; d_reclen
    test rax, rax
    jz .dl                  ; safety
    mov r10, r12
    add r10, rax            ; next = cursor + reclen ; save
    lea rdi, [r12+19]       ; d_name
    ; skip "." and ".."
    cmp byte [rdi], '.'
    jne .emit
    cmp byte [rdi+1], 0
    je .next
    cmp byte [rdi+1], '.'
    jne .emit
    cmp byte [rdi+2], 0
    je .next
.emit:
    cmp r15, 0
    je .nofirst
    mov al, ','
    call out_c
.nofirst:
    mov r15, 1
    lea rdi, [ent_a]
    call out_str
    lea rdi, [r12+19]
    call out_str_esc_cstr   ; name (null-terminated, escaped)
    lea rdi, [ent_b]
    call out_str
    movzx eax, byte [r12+18] ; d_type
    cmp al, 4
    je .isdir
    cmp al, 8
    je .isfile
    lea rdi, [t_other]
    jmp .dtype_done
.isdir:
    lea rdi, [t_dir]
    jmp .dtype_done
.isfile:
    lea rdi, [t_file]
.dtype_done:
    call out_str
    lea rdi, [ent_c]
    call out_str
.next:
    mov r12, r10
    jmp .el
.ddone:
    mov rax, 3
    mov rdi, r14
    syscall
    lea rdi, [list_c]
    call out_str
    call resp_end
    jmp .out
.blocked:
    call blocked_44001
    jmp .out
.ioerr:
    mov rdi, -32603
    lea rsi, [e_io]
    call resp_error
    jmp .out
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; out_str_esc_cstr(rdi=cstr): output escaped null-terminated string
out_str_esc_cstr:
    push rdi
    call strlen             ; rax = len
    mov rsi, rax
    pop rdi
    jmp out_esc

; ---- bridge.system_info ----
h_call_sysinfo:
    push rbx
    push r12
    mov rax, 63             ; uname
    lea rdi, [uname_buf]
    syscall
    cmp rax, 0
    jl .ioerr
    call resp_result_begin
    lea rdi, [sys_a]
    call out_str
    lea rdi, [uname_buf]
    call out_str_esc_cstr
    lea rdi, [sys_b]
    call out_str
    lea rdi, [uname_buf+65]
    call out_str_esc_cstr
    lea rdi, [sys_c]
    call out_str
    lea rdi, [uname_buf+130]
    call out_str_esc_cstr
    lea rdi, [sys_d]
    call out_str
    lea rdi, [uname_buf+195]
    call out_str_esc_cstr
    lea rdi, [sys_e]
    call out_str
    lea rdi, [uname_buf+260]
    call out_str_esc_cstr
    lea rdi, [pol_c]
    call out_str
    call resp_end
    jmp .out
.ioerr:
    mov rdi, -32603
    lea rsi, [e_io]
    call resp_error
.out:
    pop r12
    pop rbx
    ret

; tools/call dispatcher
; ============================================================================
h_tools_call:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; r12 = line ptr, r13 = line len, r14 = line end (set by caller? no - recompute)
    ; caller: handle_line sets r12/r13/r14 before calling. We receive via those.
    ; find params object
    mov rdi, r12
    mov rsi, r13
    lea rdx, [k_params]
    call find_key
    test rax, rax
    jz .badparams
    mov r15, rax         ; params val ptr
    mov rdi, rax
    mov rsi, r14         ; line end
    call capture_balanced
    test rax, rax
    jz .parseerr
    mov rbx, rax         ; params end
    sub rbx, r15         ; params len
    ; tool name within params
    mov rdi, r15
    mov rsi, rbx
    lea rdx, [k_name]
    call find_key
    test rax, rax
    jz .badparams
    mov rdi, rax
    mov rsi, r15
    add rsi, rbx         ; vend = params end
    lea rdx, [name_buf]
    mov rcx, 127
    call extract_string
    test rax, rax
    jz .badparams
    mov [name_len], rdx
    ; arguments object (optional)
    mov qword [args_start], 0
    mov rdi, r15
    mov rsi, rbx
    lea rdx, [k_arguments]
    call find_key            ; rax = val ptr
    test rax, rax
    jz .dispatch
    mov [args_start], rax
    mov rdi, rax
    mov rsi, r15
    add rsi, rbx             ; vend = params end
    call capture_balanced    ; rax = endpos
    test rax, rax
    jz .parseerr
    sub rax, [args_start]
    mov [args_len], rax
.dispatch:
    lea rdx, [t_echo]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .echo
    lea rdx, [t_identity]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .ident
    lea rdx, [t_policy]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .pol
    lea rdx, [t_exec]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .exec
    lea rdx, [t_read]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .read
    lea rdx, [t_write]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .write
    lea rdx, [t_list]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .list
    lea rdx, [t_sysinfo]
    mov rdi, name_buf
    mov rsi, [name_len]
    call streq
    test rax, rax
    jnz .sysinfo
    mov rdi, -32602
    lea rsi, [e_no_tool]
    call resp_error
    jmp .out
.echo:
    call h_call_echo
    jmp .out
.ident:
    call h_call_identity
    jmp .out
.pol:
    call h_call_policy
    jmp .out
.exec:
    call h_call_exec
    jmp .out
.read:
    call h_call_read
    jmp .out
.write:
    call h_call_write
    jmp .out
.list:
    call h_call_list
    jmp .out
.sysinfo:
    call h_call_sysinfo
    jmp .out
.badparams:
    mov rdi, -32602
    lea rsi, [e_bad_params]
    call resp_error
    jmp .out
.parseerr:
    mov rdi, -32700
    lea rsi, [e_parse]
    call resp_error
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; handle_line(rdi=ptr, rsi=len)
; ============================================================================
handle_line:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi         ; line ptr
    mov r13, rsi         ; line len
    test r13, r13
    jz .ret
    cmp byte [r12+r13-1], 13
    jne .ns
    dec r13
.ns:
    test r13, r13
    jz .ret
    lea r14, [r12+r13]   ; line end
    ; ---- id (optional; absent => notification, no reply) ----
    mov qword [id_present], 0
    mov rdi, r12
    mov rsi, r13
    lea rdx, [k_id]
    call find_key
    test rax, rax
    jz .noid
    mov r15, rax
    mov rdi, rax
    mov rsi, r14
    call capture_scalar
    mov rdx, rax
    sub rdx, r15
    cmp rdx, 255
    ja .noid
    test rdx, rdx
    jz .noid
    lea rdi, [id_buf]
    mov rsi, r15
    call memcpy
    mov [id_len], rdx
    mov qword [id_present], 1
.noid:
    ; ---- method ----
    mov rdi, r12
    mov rsi, r13
    lea rdx, [k_method]
    call find_key
    test rax, rax
    jz .badreq
    mov rdi, rax
    mov rsi, r14
    lea rdx, [method_buf]
    mov rcx, 127
    call extract_string
    test rax, rax
    jz .badreq
    mov [method_len], rdx
    ; ---- dispatch ----
    lea rdx, [m_initialize]
    mov rdi, method_buf
    mov rsi, [method_len]
    call streq
    test rax, rax
    jnz .d_init
    lea rdx, [m_ping]
    mov rdi, method_buf
    mov rsi, [method_len]
    call streq
    test rax, rax
    jnz .d_ping
    lea rdx, [m_tools_list]
    mov rdi, method_buf
    mov rsi, [method_len]
    call streq
    test rax, rax
    jnz .d_list
    lea rdx, [m_tools_call]
    mov rdi, method_buf
    mov rsi, [method_len]
    call streq
    test rax, rax
    jnz .d_call
    ; notifications/* -> silent
    lea rdx, [m_notif_pfx]
    mov rdi, method_buf
    mov rsi, [method_len]
    call starts_with
    test rax, rax
    jnz .ret
    mov rdi, -32601
    lea rsi, [e_no_method]
    call resp_error
    jmp .write
.d_init:
    call h_initialize
    jmp .write
.d_ping:
    call h_ping
    jmp .write
.d_list:
    call h_tools_list
    jmp .write
.d_call:
    call h_tools_call
    jmp .write
.badreq:
    mov rdi, -32600
    lea rsi, [e_invalid]
    call resp_error
.write:
    cmp qword [id_present], 0
    je .ret
    mov rdi, [conn_fd]
    lea rsi, [outbuf]
    mov rdx, [outpos]
    call write_all
    mov rdi, [conn_fd]
    lea rsi, [j_nl]
    mov rdx, 1
    call write_all
.ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; serve_conn(rdi=fd)
; ============================================================================
serve_conn:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, rdi         ; fd
    mov [conn_fd], rdi
    mov qword [rlen], 0
.rd:
    mov rax, [rlen]
    cmp rax, 16383
    jae .done
    mov rdi, r15
    lea rsi, [rbuf]
    add rsi, [rlen]
    mov rdx, 16383
    sub rdx, [rlen]
    mov rax, SYS_read
    syscall
    test rax, rax
    jz .done             ; EOF
    js .rd               ; EINTR -> retry (blocking socket)
    add [rlen], rax
    xor r12d, r12d       ; line start offset
    mov r13, [rlen]
.scan:
    mov r14, r12         ; scan position starts at line start
.scan2:
    cmp r14, r13
    jae .compact
    lea rax, [rbuf]
    add rax, r14
    cmp byte [rax], 10
    jne .adv
    ; line = [r12, rax)
    lea rbx, [rax+1]
    sub rbx, rbuf        ; next start offset = (rax - rbuf) + 1
    push rbx
    lea rdi, [rbuf]
    add rdi, r12         ; line start
    mov rsi, rax
    sub rsi, rdi         ; line length
    call handle_line
    pop r12              ; advance line start
    jmp .scan
.adv:
    inc r14
    jmp .scan2
.compact:
    test r12, r12
    jz .rd               ; nothing consumed; keep buffer as-is
    mov rax, r13
    sub rax, r12
    jz .zer
    lea rdi, [rbuf]
    lea rsi, [rbuf]
    add rsi, r12
    mov rdx, rax
    call memcpy
.zer:
    mov [rlen], rax
    jmp .rd
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; _start
; ============================================================================
_start:
    mov rbx, [rsp]            ; argc
    lea r12, [rsp+8]          ; argv
    mov qword [port_num], 7341
    cmp rbx, 2
    jl .noport
    mov rdi, [r12+8]          ; argv[1]
    call atoi
    cmp rax, 1
    jl .noport
    cmp rax, 65535
    ja .noport
    mov [port_num], rax
.noport:
    ; envp scan for HOME=
    lea r13, [r12+rbx*8+8]
.senv:
    mov rdi, [r13]
    test rdi, rdi
    jz .nohome
    push rdi
    call strlen              ; rax = env len
    pop rdi
    mov r15, rax             ; save len (starts_with clobbers rsi)
    mov rsi, rax
    lea rdx, [home_eq]
    call starts_with
    test rax, rax
    jz .snext
    mov rax, r15
    sub rax, 5               ; home dir len
    cmp rax, 4095
    ja .snext
    mov r14, rax
    mov rdi, [r13]
    add rdi, 5               ; src = env+5
    mov rsi, rdi
    lea rdi, [home_buf]      ; dst
    mov rdx, r14
    call memcpy
    mov [home_len], r14
    jmp .nohome
.snext:
    add r13, 8
    jmp .senv
.nohome:
    ; ignore SIGPIPE (client disconnects mid-write must not kill us)
    mov qword [sa_buf], 1
    mov qword [sa_buf+8], 0
    mov qword [sa_buf+16], 0
    mov qword [sa_buf+24], 0
    mov rax, SYS_rt_sigaction
    mov rdi, 13
    lea rsi, [sa_buf]
    xor edx, edx
    mov r10, 8
    syscall
    ; root = getcwd
    lea rdi, [root_buf]
    mov rsi, 4096
    mov rax, SYS_getcwd
    syscall
    test rax, rax
    js .fatal
    dec rax                  ; syscall returns len+1 (includes NUL)
    mov [root_len], rax
    ; socket
    mov rax, SYS_socket
    mov rdi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test rax, rax
    js .fatal
    mov [listen_fd], rax
    ; setsockopt(SO_REUSEADDR)
    mov rax, SYS_setsockopt
    mov rdi, [listen_fd]
    mov rsi, 1
    mov rdx, 2
    lea r10, [one_dd]
    mov r8d, 4
    syscall
    ; bind 127.0.0.1:port
    mov word [sock_addr], 2
    mov ax, [port_num]
    xchg al, ah
    mov [sock_addr+2], ax
    mov dword [sock_addr+4], 0x0100007F
    mov qword [sock_addr+8], 0
    mov rax, SYS_bind
    mov rdi, [listen_fd]
    lea rsi, [sock_addr]
    mov rdx, 16
    syscall
    test rax, rax
    js .fatal
    ; listen
    mov rax, SYS_listen
    mov rdi, [listen_fd]
    mov esi, 16
    syscall
    test rax, rax
    js .fatal
    ; banner -> stderr
    call out_reset
    lea rdi, [banner_a]
    call out_str
    mov rax, [port_num]
    call out_u64
    lea rdi, [banner_b]
    call out_str
    mov rdi, root_buf
    mov rsi, [root_len]
    call out_mem
    mov al, 10
    call out_c
    mov rdi, 2
    lea rsi, [outbuf]
    mov rdx, [outpos]
    call write_all
    ; accept loop
.accept:
    mov rax, SYS_accept
    mov rdi, [listen_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .accept
    mov rbx, rax
    mov rdi, rax
    call serve_conn
    mov rax, SYS_close
    mov rdi, rbx
    syscall
    jmp .accept
.fatal:
    mov rdi, 2
    lea rsi, [fatal_msg]
    mov rdx, 31
    call write_all
    mov rax, SYS_exit
    mov rdi, 1
    syscall
