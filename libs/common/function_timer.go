package common

import (
	"fmt"
	"github.com/tendermint/tendermint/libs/log"
	"runtime/debug"
	"time"
)

//----------------------------------------
// Function timer can be placed anywhere in a function to determine
// how long it takes to complete. Usage:
//
// // Allow this function to take 10ms
// timer := cmn.NewFunctionTimer(10, "enterPropose", cs.Logger)
// defer timer.Finish()

type FunctionTimer struct {
	startTime      time.Time
	timerName      string
	expectedTimeMs int64
	Logger         log.Logger
	stackDisabled  bool
}

// Note the logger can be nil in which case it will fall back to fmt.Print messages
func NewFunctionTimer(expectedTime int64, timerName string, logger log.Logger) (fn *FunctionTimer) {

	fnTimer := FunctionTimer{
		startTime:      time.Now(),
		timerName:      timerName,
		expectedTimeMs: expectedTime,
		Logger:         logger,
		stackDisabled:  true,
	}

	return &fnTimer
}

func (fn *FunctionTimer) Finish() {
	timeElapsed := time.Now().Sub(fn.startTime).Milliseconds()
	if timeElapsed >= fn.expectedTimeMs {

		stack := string(debug.Stack())

		if fn.stackDisabled {
			stack = "Disabled"
		}

		errorString := fmt.Sprintf("Expected function %v to take %vms but instead took %vms.\nStack: %v", fn.timerName, fn.expectedTimeMs, timeElapsed, stack)

		if fn.Logger == nil {
			fmt.Println(errorString)
		} else {
			fn.Logger.Debug(errorString)
		}
	}
}
