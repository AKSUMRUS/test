package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	_ "net/http/pprof"
	"os"
	"path/filepath"
)

const InfinityFlag = -1

func main() {
	var configs tool.CfgsFlag
	flag.Var(&configs, "configs", "list of configuration files for kernels divided by comma")
	flagDebug := flag.Bool("debug", false, "Print debug info from virtual machines")
	flagRepeats := flag.Int("repeat", InfinityFlag, "how many times reproducers will be run on each virtual machine (infinite if empty)")
	flagAddress := flag.String("address", "10.10.2.95:8080", "address for the http server.")
	flagData := flag.String("data", "", "path current data in json file, if exists")
	flag.Parse()

	if len(configs) == 0 {
		log.Errorf("There are no configs for virtual machines")
		flag.Usage()
		os.Exit(-1)
	}

	if len(flag.Args()) == 0 {
		log.Errorf("There are no reproducers for testing")
		os.Exit(-1)
	}

	pools := make(map[int]*PoolInfo)
	for idx, config := range configs {
		var err error
		pool := &PoolInfo{}
		pool.config, err = mgrconfig.LoadFile(config)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pool.pool, err = vm.Create(pool.config, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pool.reporter, err = report.NewReporter(pool.config)
		if err != nil {
			log.Fatalf("failed to create reporter for pool %d: %v", idx, err)
		}
		pools[idx] = pool
	}

	config := pools[0].config

	addr := config.RPC

	programs := loadPrograms(config.Target, flag.Args())

	exe := config.SysTarget.ExeExtension
	runnerBin := filepath.Join(config.Syzkaller, "bin", config.Target.OS+"_"+config.Target.Arch, "syz-runner"+exe)
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", runnerBin)
	}

	executorBin := config.ExecutorBin
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", executorBin)
	}

	analyzer := &Analyzer{
		pools:       pools,
		programs:    make(map[string]*prog.Prog),
		target:      config.Target,
		addr:        addr,
		runnerBin:   runnerBin,
		executorBin: executorBin,
		tasksQueue:  &TasksQueue{queue: make(map[int]*VMInfo)},
	}

	analyzer.AddTasks(programs, *flagRepeats)

	server, err := createRPCServer(analyzer)
	if err != nil {
		log.Fatalf("%v", err)
	}
	analyzer.server = server

	analyzer.initialiseStatistics(*flagData)

	analyzer.initialiseInstances()

	monitor := MakeMonitor(analyzer)

	go monitor.listenAndServe(*flagAddress)

	select {}
}

// loadPrograms loads syz-lang programs from list of files.
func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, filePath := range files {
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Fatalf("can't read repro file: %v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "number of loaded programs: %d", len(progs))
	return progs
}

// Hash returns a sha256 hash of the string.
func Hash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return hash
}

// ProgramHash returns a sha256 hash of the program.
func ProgramHash(program *prog.Prog) string {
	hasher := sha256.New()
	hasher.Write(program.Serialize())
	hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return hash
}

// vmKey converts poolId and vmId to virtual machine key.
func vmKey(poolId, vmId int) int {
	return poolId*1000 + vmId
}
