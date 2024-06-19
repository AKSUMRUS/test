package syz_analyzer

import "github.com/google/syzkaller/pkg/ipc"

type ProgramArgs struct {
	Pool, VM int
	TaskID   string
	Info     *ipc.ProgInfo
	Hanged   bool
	Error    []byte
}

type ProgramResults struct {
	Prog []byte
	ID   string
}
