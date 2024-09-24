package main

import (
	"errors"
	"fmt"
	"github.com/google/syzkaller/prog"
	"log"
	"sync"
)

// TasksQueue realises a queue of tasks for each virtual machine.
type TasksQueue struct {
	queue map[int]*VMInfo
}

type VMInfo struct {
	tasks     []*Task
	isWaiting bool
	wg        sync.WaitGroup
}

type Task struct {
	program    *prog.Prog
	id         string
	isInfinite bool
	repeat     int
}

// push adds task to execution queue of vm.
func (tq *TasksQueue) push(vmID int, task *Task) {
	if tq.queue[vmID] == nil {
		tq.queue[vmID] = &VMInfo{
			tasks:     make([]*Task, 0),
			isWaiting: false,
		}
	}
	info := tq.queue[vmID]

	info.tasks = append(info.tasks, task)

	if info.isWaiting {
		info.isWaiting = false
		info.wg.Done()
	}
}

// pushAll adds task to execution queue of every wm.
func (tq *TasksQueue) pushAll(task *Task) {
	for vmID := range tq.queue {
		tq.push(vmID, task)
	}
}

func (tq *TasksQueue) contains(taskID string) bool {
	contains := false
	for _, info := range tq.queue {
		for _, task := range info.tasks {
			if task.id == taskID {
				contains = true
				break
			}
		}
		if contains {
			break
		}
	}

	return contains
}

// stop deletes task from execution queue of every vm.
func (tq *TasksQueue) stop(taskID string) error {
	isStopped := false
	for vmID, info := range tq.queue {
		for index, queueTask := range info.tasks {
			if queueTask.id == taskID {
				if index == 0 {
					tq.queue[vmID].tasks = info.tasks[index+1:]
				} else if index == len(info.tasks)-1 {
					tq.queue[vmID].tasks = info.tasks[:index]
				} else {
					tasks := info.tasks
					tq.queue[vmID].tasks = tasks[:index]
					tq.queue[vmID].tasks = append(tq.queue[vmID].tasks, tasks[index+1:]...)
				}
				isStopped = true
				break
			}
		}
	}
	if !isStopped {
		return errors.New("there is no such task in tasks queue")
	}
	return nil
}

// getAndPop returns an id of task for execution by vm.
func (tq *TasksQueue) getAndPop(vmID int) (*Task, error) {
	if tq.queue[vmID] == nil || len(tq.queue[vmID].tasks) == 0 {
		err := fmt.Errorf("tasks queue of vm %d is empty", vmID)
		return nil, err
	}
	task := tq.queue[vmID].tasks[0]
	tq.queue[vmID].tasks = tq.queue[vmID].tasks[1:]

	if task.isInfinite {
		tq.push(vmID, task)
	} else if task.repeat > 0 {
		task.repeat--
		tq.push(vmID, task)
	} else {
		log.Printf("task %s is finished", task.id)
	}

	return task, nil
}

// wait pauses the process until tasks queue of the vmID is empty.
func (tq *TasksQueue) wait(vmID int) {
	info := tq.queue[vmID]
	info.isWaiting = true
	info.wg.Add(1)
	info.wg.Wait()
}

// isEmpty checks whether tasks of vm are done.
func (tq *TasksQueue) isEmpty(vmID int) bool {
	if tq.queue[vmID] == nil {
		return true
	}
	return len(tq.queue[vmID].tasks) == 0
}
