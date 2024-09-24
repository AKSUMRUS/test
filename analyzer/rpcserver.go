package main

import (
	"github.com/google/syzkaller/pkg/rpctype"
	syz_analyzer "github.com/google/syzkaller/syz-analyzer"
	"net"
)

// RPCServer realises logic of communication with virtual machines.
type RPCServer struct {
	analyzer *Analyzer
	port     int
}

// createRPCServer initialises RPC server.
func createRPCServer(analyzer *Analyzer) (*RPCServer, error) {
	server := &RPCServer{
		analyzer: analyzer,
	}
	rpc, err := rpctype.NewRPCServer(analyzer.addr, "Analyzer", server)
	if err != nil {
		return nil, err
	}
	server.port = rpc.Addr().(*net.TCPAddr).Port

	go rpc.Serve()
	return server, nil
}

// NextProgram gets result of previous execution and returns next program.
func (server *RPCServer) NextProgram(args *syz_analyzer.ProgramArgs, res *syz_analyzer.ProgramResults) error {
	server.analyzer.AddProgramResult(args)

	nextProgramID, nextProgram, err := server.analyzer.NextProgram(vmKey(args.Pool, args.VM))

	if err != nil {
		return err
	}

	res.ID = nextProgramID
	res.Prog = nextProgram

	return nil
}
