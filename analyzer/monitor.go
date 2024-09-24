package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"io"
	"net/http"
)

// Monitor provides json data of the syz-analyze results.
type Monitor struct {
	analyzer *Analyzer
	stats    *Statistics
}

// MakeMonitor creates the Monitor instance with Statistics.
func MakeMonitor(analyzer *Analyzer) *Monitor {
	monitor := &Monitor{
		stats:    analyzer.statistics,
		analyzer: analyzer,
	}
	monitor.initHandling()
	return monitor
}

// enableCors allows another computers to communicate with the server.
func enableCors(writer *http.ResponseWriter) {
	(*writer).Header().Set("Access-Control-Allow-Origin", "*")
}

// listenAndServe starts the server.
func (monitor *Monitor) listenAndServe(addr string) error {
	log.Logf(0, "Monitor the results at http://%s", addr)
	return http.ListenAndServe(addr, nil)
}

// initHandling registers handles for the monitoring.
func (monitor *Monitor) initHandling() {
	http.Handle("/api/stats.json", monitor.Stats())
	http.Handle("/api/add_task", monitor.addTask())
	http.Handle("/api/stop_task", monitor.stopTask())
	http.Handle("/api/run_task", monitor.runTask())
	http.Handle("/api/is_running", monitor.isRunning())

	http.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Write([]byte(baseStr))
	})
}

func (monitor *Monitor) stopTask() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		enableCors(&writer)
		id := request.FormValue("id")
		analyzer := monitor.analyzer

		err := analyzer.StopTask(id)
		if err != nil {
			http.Error(writer, err.Error(), 500)
		}
	})
}

func (monitor *Monitor) runTask() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		enableCors(&writer)
		id := request.FormValue("id")
		analyzer := monitor.analyzer
		err := analyzer.RunTask(id)
		if err != nil {
			http.Error(writer, err.Error(), 500)
		}
	})
}

func (monitor *Monitor) addTask() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		enableCors(&writer)
		request.ParseMultipartForm(10 << 20)

		file, _, err := request.FormFile("reproducer")

		if err != nil {
			http.Error(writer, err.Error(), 500)
			return
		}

		defer file.Close()

		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, file); err != nil {
			http.Error(writer, err.Error(), 500)
			return
		}
		analyzer := monitor.analyzer

		entries := analyzer.target.ParseLog(buf.Bytes())
		programs := make([]*prog.Prog, 0)

		for _, entry := range entries {
			programs = append(programs, entry.P)
		}

		analyzer.AddTasks(programs, InfinityFlag)
	})
}

func (monitor *Monitor) isRunning() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		enableCors(&writer)
		taskID := request.FormValue("id")
		isRunning := monitor.analyzer.IsRunning(taskID)
		_, err := fmt.Fprintf(writer, "%t", isRunning)
		if err != nil {
			log.Errorf("%v", err)
		}
	})
}

// Stats provides general response for statistics.
func (monitor *Monitor) Stats() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		enableCors(&writer)
		writer.Header().Set("Content-Type", "application/json")
		data := monitor.stats.JSON()

		response, err := json.MarshalIndent(
			data,
			"",
			"\t",
		)
		if err != nil {
			http.Error(writer, err.Error(), 500)
			return
		}

		writer.Write(response)
	})
}

const baseStr = `
<html>
<body> 
<a href="/api/stats.json">show stats</a> 
<form action="/api/add_task" method="post" enctype="multipart/form-data">
	<p><input type="file" name="reproducer">
	<p><button type="submit">Submit task</button>
</form> 
<div> to stop task type: /api/stop_task?id={task_id}</div> 
</body>
</html>
`
