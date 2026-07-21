#include "textflag.h"

#define SYS_WRITE 1
#define SYS_FCHDIR 81
#define SYS_UMASK 95
#define SYS_SETPGID 109
#define SYS_GETPPID 110
#define SYS_PRCTL 157
#define SYS_EXIT_GROUP 231
#define SYS_DUP3 292
#define SYS_EXECVEAT 322
#define SYS_CLONE3 435
#define SYS_CLOSE_RANGE 436

#define PR_SET_PDEATHSIG 1
#define PR_SET_NO_NEW_PRIVS 38
#define SIGKILL 9
#define AT_EMPTY_PATH 0x1000
#define CLOSE_RANGE_CLOEXEC 4

// func rawRuntimeClone3(clone *runtimeCloneArgs, child *runtimeChildSpec) (pid uintptr, errno syscall.Errno)
TEXT ·rawRuntimeClone3(SB),NOSPLIT,$8-32
	MOVQ clone+0(FP), DI
	MOVQ $88, SI
	MOVQ $SYS_CLONE3, AX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JLS clone_ok
	MOVQ $-1, pid+16(FP)
	NEGQ AX
	MOVQ AX, errno+24(FP)
	RET

clone_ok:
	TESTQ AX, AX
	JZ child
	MOVQ AX, pid+16(FP)
	MOVQ $0, errno+24(FP)
	RET

child:
	MOVQ child+8(FP), R12

	MOVQ $SYS_PRCTL, AX
	MOVQ $PR_SET_PDEATHSIG, DI
	MOVQ $SIGKILL, SI
	XORQ DX, DX
	XORQ R10, R10
	XORQ R8, R8
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_GETPPID, AX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error
	MOVL 40(R12), R13
	CMPQ AX, R13
	JE parent_alive
	MOVQ $-3, AX
	JMP child_error

parent_alive:
	MOVQ $SYS_SETPGID, AX
	XORQ DI, DI
	XORQ SI, SI
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_PRCTL, AX
	MOVQ $PR_SET_NO_NEW_PRIVS, DI
	MOVQ $1, SI
	XORQ DX, DX
	XORQ R10, R10
	XORQ R8, R8
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_FCHDIR, AX
	MOVL 32(R12), DI
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_UMASK, AX
	MOVQ $077, DI
	SYSCALL

	MOVQ $SYS_DUP3, AX
	MOVL 0(R12), DI
	XORQ SI, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 4(R12), DI
	MOVQ $1, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 8(R12), DI
	MOVQ $2, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 12(R12), DI
	MOVQ $3, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 16(R12), DI
	MOVQ $4, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 20(R12), DI
	MOVQ $5, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_DUP3, AX
	MOVL 24(R12), DI
	MOVQ $6, SI
	XORQ DX, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_CLOSE_RANGE, AX
	MOVQ $7, DI
	MOVQ $0xffffffff, SI
	MOVQ $CLOSE_RANGE_CLOEXEC, DX
	SYSCALL
	CMPQ AX, $0xfffffffffffff001
	JHI child_error

	MOVQ $SYS_EXECVEAT, AX
	MOVL 28(R12), DI
	MOVQ 64(R12), SI
	MOVQ 48(R12), DX
	MOVQ 56(R12), R10
	MOVQ $AT_EMPTY_PATH, R8
	SYSCALL

child_error:
	NEGQ AX
	MOVL AX, errcode-8(SP)
	MOVQ $SYS_WRITE, AX
	MOVL 36(R12), DI
	LEAQ errcode-8(SP), SI
	MOVQ $4, DX
	SYSCALL

child_exit:
	MOVQ $SYS_EXIT_GROUP, AX
	MOVQ $253, DI
	SYSCALL
	JMP child_exit
