package main

import (
	"encoding/json"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	syz_analyzer "github.com/google/syzkaller/syz-analyzer"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Statistics realises logic of obtaining and storing data from executions.
type Statistics struct {
	totalRuns      int
	successfulRuns int
	errorRuns      int
	programs       *map[string]*prog.Prog
	results        map[string]*Result
	statsWrite     io.Writer
	pools          int
	mu             sync.Mutex
}

type Result struct {
	program        string
	totalRuns      int
	successfulRuns int
	errorRuns      int
	errors         map[string]*ErrorInfo
}

type ErrorInfo struct {
	error string
	pools []int
	count int
}

func MakeStatistics(pools int, data string, programs *map[string]*prog.Prog) *Statistics {
	stats := &Statistics{
		results:  make(map[string]*Result),
		programs: programs,
		pools:    pools,
	}

	var sw io.Writer

	if data == "" {
		sw = os.Stdout
	} else {
		currentDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatalf("failed to create stats file: %v", err)
		}
		file := filepath.Join(currentDir, data)
		if _, err = os.Stat(file); err != nil {
			sw, err = os.Create(file)
			if err != nil {
				log.Fatalf("failed to create stats file: %v", err)
			}
		} else {
			stats.LoadData(file)
			sw, err = os.OpenFile(file, os.O_WRONLY, 0666)
			if err != nil {
				log.Fatalf("failed to open stats file: %v", err)
			}
		}
	}

	stats.statsWrite = sw

	return stats
}

// LoadData converts and adds json file to current statistics.
func (stats *Statistics) LoadData(jsonFile string) {
	file, err := os.Open(jsonFile)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)

	var jsonStats StatisticsJSON
	err = json.Unmarshal(byteValue, &jsonStats)
	if err != nil {
		log.Fatalf("%v", err)
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.totalRuns += jsonStats.TotalRuns
	stats.successfulRuns += jsonStats.SuccessfulRuns
	stats.errorRuns += jsonStats.ErrorRuns
	for programId, result := range jsonStats.Results {
		if stats.results[programId] == nil {
			stats.results[programId] = &Result{
				program: result.Program,
			}
		}

		currentResult := stats.results[programId]
		currentResult.totalRuns += result.TotalRuns
		currentResult.successfulRuns += result.SuccessfulRuns
		currentResult.errorRuns += result.ErrorRuns
		for errorId, info := range result.Errors {
			if currentResult.errors == nil {
				currentResult.errors = make(map[string]*ErrorInfo)
			}
			if currentResult.errors[errorId] == nil {
				currentResult.errors[errorId] = &ErrorInfo{
					error: info.Error,
				}
			}
			currentError := currentResult.errors[errorId]
			currentError.count += info.Count
		}
	}
}

// addResult processes the  result of program execution.
func (stats *Statistics) addResult(result *syz_analyzer.ProgramArgs) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.totalRuns++

	program := (*stats.programs)[result.TaskID]
	programId := result.TaskID
	if stats.results[programId] == nil {
		stats.results[programId] = &Result{
			program: string(program.Serialize()),
		}
	}

	stats.results[programId].totalRuns++

	if result.Error != nil {
		output := string(result.Error[:])
		errorId := Hash(output)

		if stats.results[programId].errors == nil {
			stats.results[programId].errors = make(map[string]*ErrorInfo)
		}

		if stats.results[programId].errors[errorId] == nil {
			stats.results[programId].errors[errorId] = &ErrorInfo{
				error: output,
				pools: make([]int, stats.pools),
			}
		}

		stats.errorRuns++
		stats.results[programId].errorRuns++
		stats.results[programId].errors[errorId].pools[result.Pool]++
		stats.results[programId].errors[errorId].count++
	} else {
		stats.successfulRuns++
		stats.results[programId].successfulRuns++
	}
}

// Print prints analyse results to the io.Writer.
func (stats *Statistics) Print() {
	data := stats.JSON()
	jsonData, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		log.Errorf("can't save data to json: %v", err)
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	_, err = stats.statsWrite.Write(jsonData)
	if err != nil {
		log.Errorf("%v", err)
	}
}

type StatisticsJSON struct {
	TotalRuns      int
	SuccessfulRuns int
	ErrorRuns      int
	Results        map[string]*ResultJSON
}

type ResultJSON struct {
	Program        string
	TotalRuns      int
	SuccessfulRuns int
	ErrorRuns      int
	Errors         map[string]*ErrorInfoJSON
}

type ErrorInfoJSON struct {
	Error string
	Pools []int
	Count int
}

// JSON renders the StatisticsJSON object.
func (stats *Statistics) JSON() StatisticsJSON {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	data := StatisticsJSON{
		TotalRuns:      stats.totalRuns,
		SuccessfulRuns: stats.successfulRuns,
		ErrorRuns:      stats.errorRuns,
		Results:        make(map[string]*ResultJSON),
	}

	for programId, result := range stats.results {
		data.Results[programId] = &ResultJSON{
			Program:        result.program,
			TotalRuns:      result.totalRuns,
			SuccessfulRuns: result.successfulRuns,
			ErrorRuns:      result.errorRuns,
			Errors:         make(map[string]*ErrorInfoJSON),
		}
		for errorId, info := range result.errors {
			data.Results[programId].Errors[errorId] = &ErrorInfoJSON{
				Error: info.error,
				Pools: info.pools,
				Count: info.count,
			}
		}
	}

	return data
}
