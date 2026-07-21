#include "textflag.h"

#define SYS_DUP3 24
#define SYS_FCHDIR 50
#define SYS_WRITE 64
#define SYS_EXIT_GROUP 94
#define SYS_SETPGID 154
#define SYS_UMASK 166
#define SYS_PRCTL 167
#define SYS_GETPPID 173
#define SYS_EXECVEAT 281
#define SYS_CLONE3 435
#define SYS_CLOSE_RANGE 436

#define PR_SET_PDEATHSIG 1
#define PR_SET_NO_NEW_PRIVS 38
#define SIGKILL 9
#define AT_EMPTY_PATH 0x1000
#define CLOSE_RANGE_CLOEXEC 4

// func rawRuntimeClone3(clone *runtimeCloneArgs, child *runtimeChildSpec) (pid uintptr, errno syscall.Errno)
TEXT ·rawRuntimeClone3(SB),NOSPLIT,$8-32
	MOVD clone+0(FP), R0
	MOVD $88, R1
	MOVD $SYS_CLONE3, R8
	SVC
	CMN $4095, R0
	BCC clone_ok
	MOVD $-1, R1
	MOVD R1, pid+16(FP)
	NEG R0, R0
	MOVD R0, errno+24(FP)
	RET

clone_ok:
	CBZ R0, child
	MOVD R0, pid+16(FP)
	MOVD ZR, errno+24(FP)
	RET

child:
	MOVD child+8(FP), R19

	MOVD $PR_SET_PDEATHSIG, R0
	MOVD $SIGKILL, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD $SYS_PRCTL, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVD $SYS_GETPPID, R8
	SVC
	CMN $4095, R0
	BCS child_error
	MOVWU 40(R19), R20
	CMP R20, R0
	BEQ parent_alive
	MOVD $-3, R0
	B child_error

parent_alive:
	MOVD ZR, R0
	MOVD ZR, R1
	MOVD $SYS_SETPGID, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVD $PR_SET_NO_NEW_PRIVS, R0
	MOVD $1, R1
	MOVD ZR, R2
	MOVD ZR, R3
	MOVD ZR, R4
	MOVD $SYS_PRCTL, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 32(R19), R0
	MOVD $SYS_FCHDIR, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVD $077, R0
	MOVD $SYS_UMASK, R8
	SVC

	MOVWU 0(R19), R0
	MOVD $0, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 4(R19), R0
	MOVD $1, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 8(R19), R0
	MOVD $2, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 12(R19), R0
	MOVD $3, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 16(R19), R0
	MOVD $4, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 20(R19), R0
	MOVD $5, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 24(R19), R0
	MOVD $6, R1
	MOVD ZR, R2
	MOVD $SYS_DUP3, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVD $7, R0
	MOVD $0xffffffff, R1
	MOVD $CLOSE_RANGE_CLOEXEC, R2
	MOVD $SYS_CLOSE_RANGE, R8
	SVC
	CMN $4095, R0
	BCS child_error

	MOVWU 28(R19), R0
	MOVD 64(R19), R1
	MOVD 48(R19), R2
	MOVD 56(R19), R3
	MOVD $AT_EMPTY_PATH, R4
	MOVD $SYS_EXECVEAT, R8
	SVC

child_error:
	NEG R0, R0
	MOVW R0, errcode-8(SP)
	MOVWU 36(R19), R0
	MOVD $errcode-8(SP), R1
	MOVD $4, R2
	MOVD $SYS_WRITE, R8
	SVC

child_exit:
	MOVD $253, R0
	MOVD $SYS_EXIT_GROUP, R8
	SVC
	B child_exit
