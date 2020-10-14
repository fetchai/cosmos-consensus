package beacon

import (
	"time"

	"github.com/tendermint/tendermint/cpp"
	"github.com/tendermint/tendermint/libs/log"
)

const (
	LevelDebug          = 0
	LevelInfo           = 1
	LevelError          = 2
	CollectTickInterval = 10000
)

type NativeLoggingCollector struct {
	sink log.Logger
	quit chan int
}

type nativeLogMessage struct {
	Level  int
	Module string
	Text   string
}

func dispatchLogMessage(c *NativeLoggingCollector, m *nativeLogMessage) bool {

	// empty messages are simply ignored
	if m == nil {
		return false
	}

	switch m.Level {
	case LevelDebug:
		c.sink.Debug(m.Text, "module", m.Module)
	case LevelInfo:
		c.sink.Info(m.Text, "module", m.Module)
	case LevelError:
		c.sink.Error(m.Text, "module", m.Module)
	}

	return true
}

func processNativeLogMessages(c *NativeLoggingCollector) bool {
	for {

		// check the quit signal
		select {
		case <-c.quit:
			return true

		default:

			// get the next logging message
			if !dispatchLogMessage(c, getNextNativeLogMessage()) {
				time.Sleep(CollectTickInterval)
				continue
			}
		}
	}
}

func getNextNativeLogMessage() *nativeLogMessage {
	if !cpp.HasPendingLogs() {
		return nil
	}

	msg := &nativeLogMessage{
		Level:  cpp.PeekNextLogLevel(),
		Module: cpp.PeekNextLogModule(),
		Text:   cpp.PeekNextLogMessage(),
	}

	cpp.PopNextLog()

	return msg
}

func NewNativeLoggingCollector(l log.Logger) *NativeLoggingCollector {
	return &NativeLoggingCollector{
		sink: l,
		quit: make(chan int),
	}
}

func (c *NativeLoggingCollector) Start() {

	// start the native log processing library
	go processNativeLogMessages(c)
}

func (c *NativeLoggingCollector) Stop() {
	c.quit <- 1 // trigger the stop
}
