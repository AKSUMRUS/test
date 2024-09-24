package main

import (
	"errors"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	syz_analyzer "github.com/google/syzkaller/syz-analyzer"
	"github.com/google/syzkaller/vm"
	"math/rand"
	"os"
	"os/signal"
	"sync"
)

type PoolInfo struct {
	config   *mgrconfig.Config
	reporter *report.Reporter
	pool     *vm.Pool
}

type Analyzer struct {
	pools        map[int]*PoolInfo
	server       *RPCServer
	programs     map[string]*prog.Prog
	target       *prog.Target
	addr         string
	runnerBin    string
	executorBin  string
	vmStopChan   chan bool
	statistics   *Statistics
	tasksQueue   *TasksQueue
	tasksQueueMu sync.Mutex
}

// onInterruptListener asks Statistics object to report
// execution statistics when an os.Interrupt occurs and Exit().
func (analyzer *Analyzer) onInterruptListener() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	go func() {
		<-signalChan
		defer os.Exit(0)

		analyzer.statistics.Print()
	}()
}

// initialiseStatistics creates Statistics object.
func (analyzer *Analyzer) initialiseStatistics(flagData string) {
	analyzer.statistics = MakeStatistics(len(analyzer.pools), flagData, &analyzer.programs)

	analyzer.onInterruptListener()
}

// initialiseInstances initialises all virtual machines.
func (analyzer *Analyzer) initialiseInstances() {
	for poolID, pool := range analyzer.pools {
		count := pool.pool.Count()
		for vmID := 0; vmID < count; vmID++ {
			go func(pool *PoolInfo, poolID, vmID int) {
				for {
					analyzer.createInstance(pool, poolID, vmID)
				}
			}(pool, poolID, vmID)
		}
	}
}

// createInstance creates instances of each virtual machine.
func (analyzer *Analyzer) createInstance(pool *PoolInfo, poolID, vmID int) {
	instance, err := pool.pool.Create(vmID)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer instance.Close()

	port, err := instance.Forward(analyzer.server.port)
	if err != nil {
		log.Fatalf("%v with port %s\n", err, port)
	}

	runnerBin, err := instance.Copy(analyzer.runnerBin)
	if err != nil {
		log.Fatalf("%v", err)
	}
	_, err = instance.Copy(analyzer.executorBin)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// TODO: add new-env variable
	command := fmt.Sprintf("%s -os=%s -arch=%s -addr=%s -pool=%d -vm=%d", runnerBin, pool.config.TargetOS, pool.config.TargetArch, port, poolID, vmID)
	outc, errc, err := instance.Run(pool.config.Timeouts.VMRunningTime, analyzer.vmStopChan, command)
	if err != nil {
		log.Fatalf("%v", err)
	}

	report := instance.MonitorExecution(outc, errc, pool.reporter, vm.ExitTimeout)

	log.Logf(0, "%s", report.String())
	log.Logf(0, "reboot the VM in pool %d", poolID)
}

// AddTasks adds list of programs to every virtual machine.
func (analyzer *Analyzer) AddTasks(programs []*prog.Prog, repeat int) {
	for _, program := range programs {
		programID := ProgramHash(program)
		analyzer.programs[programID] = program
	}

	for poolID, pool := range analyzer.pools {
		count := pool.pool.Count()
		for vmID := 0; vmID < count; vmID++ {
			analyzer.AddTasksByID(vmKey(poolID, vmID), programs, repeat)
		}
	}
}

// AddTasksByID adds list of programs to the certain virtual machine.
func (analyzer *Analyzer) AddTasksByID(vmID int, programs []*prog.Prog, repeat int) {
	analyzer.tasksQueueMu.Lock()
	defer analyzer.tasksQueueMu.Unlock()

	for _, program := range programs {
		analyzer.tasksQueue.push(vmID, &Task{
			program:    program,
			id:         ProgramHash(program),
			isInfinite: repeat == InfinityFlag,
			repeat:     repeat,
		})
	}
}

func (analyzer *Analyzer) StopTask(taskID string) error {
	analyzer.tasksQueueMu.Lock()
	defer analyzer.tasksQueueMu.Unlock()
	return analyzer.tasksQueue.stop(taskID)
}

// RunTask runs existing task in statistics data.
func (analyzer *Analyzer) RunTask(taskID string) error {
	analyzer.tasksQueueMu.Lock()
	defer analyzer.tasksQueueMu.Unlock()
	data, ok := analyzer.statistics.results[taskID]
	if !ok {
		return errors.New("there is no such task")
	}

	entry := analyzer.target.ParseLog([]byte(data.program))
	// We should parse only one program
	if len(entry) != 1 {
		return errors.New("wrong program format")
	}
	program := entry[0].P
	task := &Task{
		id:         taskID,
		program:    program,
		isInfinite: true,
	}

	analyzer.tasksQueue.pushAll(task)
	return nil
}

// AddProgramResult gets result of program execution by virtual machine.
func (analyzer *Analyzer) AddProgramResult(args *syz_analyzer.ProgramArgs) {
	if args.TaskID != "" {
		analyzer.statistics.addResult(args)
	}
}

func (analyzer *Analyzer) IsRunning(taskID string) bool {
	return analyzer.tasksQueue.contains(taskID)
}

// NextProgram returns next program for execution by virtual machine.
func (analyzer *Analyzer) NextProgram(vmID int) (string, []byte, error) {
	analyzer.tasksQueueMu.Lock()

	queue := analyzer.tasksQueue
	if queue.isEmpty(vmID) {
		analyzer.tasksQueueMu.Unlock()
		queue.wait(vmID)
		analyzer.tasksQueueMu.Lock()
	}

	defer analyzer.tasksQueueMu.Unlock()

	task, err := queue.getAndPop(vmID)

	analyzer.Mutate(task.program)

	if err != nil {
		return "", nil, err
	}
	nextProgram := task.program.Serialize()
	return task.id, nextProgram, err
}

func (analyzer *Analyzer) Mutate(program *prog.Prog) {
	// TODO: rewrite failNth mutation
	for _, call := range program.Calls {
		failNth := call.Props.FailNth
		if failNth > 0 {
			failNth = rand.Intn(20) + 10
		}
		call.Props.FailNth = failNth
	}
}
