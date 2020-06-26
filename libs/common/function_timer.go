package common

import (
	"time"
	"fmt"
	"github.com/tendermint/tendermint/libs/log"
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
}

// Note the logger can be nil in which case it will fall back to fmt.Print messages
func NewFunctionTimer(expectedTime int64, timerName string, logger log.Logger) (fn* FunctionTimer) {

	fnTimer := FunctionTimer{
		startTime : time.Now(),
		timerName : timerName,
		expectedTimeMs : expectedTime,
		Logger : logger,
	}

	return &fnTimer
}

func (fn* FunctionTimer) Finish() {
	timeElapsed := time.Now().Sub(fn.startTime).Milliseconds()
	if timeElapsed >= fn.expectedTimeMs {

		errorString := fmt.Sprintf("Expected function %v to take %vms but instead took %vms", fn.timerName, fn.expectedTimeMs, timeElapsed)

		if fn.Logger == nil {
			fmt.Println(errorString)
		} else {
			fn.Logger.Error(errorString)
		}
	}
}
