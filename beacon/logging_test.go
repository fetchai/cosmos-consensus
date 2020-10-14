package beacon

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/mcl_cpp"
)

type bufferedLogMessage struct {
	Text  string
	Level int
}

type bufferedLogger struct {
	Messages []bufferedLogMessage
	mtx      sync.Mutex
}

func NewBufferedLogger() *bufferedLogger {
	return &bufferedLogger{
		Messages: make([]bufferedLogMessage, 0),
	}
}

func (l *bufferedLogger) addMessage(msg bufferedLogMessage) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.Messages = append(l.Messages, msg)
}

func (l *bufferedLogger) Debug(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text:  msg,
		Level: LevelDebug,
	})
}

func (l *bufferedLogger) Info(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text:  msg,
		Level: LevelInfo,
	})

}

func (l *bufferedLogger) Error(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text:  msg,
		Level: LevelError,
	})

}

func (l *bufferedLogger) With(...interface{}) log.Logger {
	return l
}

func (l *bufferedLogger) numMessages() int {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	return len(l.Messages)
}

func TestNativeSinkCollection(t *testing.T) {
	assert.False(t, mcl_cpp.HasPendingLogs())

	// use test binding to emulate the native code generating a log message (this is always an error message)
	mcl_cpp.SendTestLogMessage("foo bar is a baz")

	// check that the logs are valid
	assert.True(t, mcl_cpp.HasPendingLogs())
	assert.Equal(t, LevelError, mcl_cpp.PeekNextLogLevel())
	assert.Equal(t, "test", mcl_cpp.PeekNextLogModule())
	assert.Equal(t, "foo bar is a baz", mcl_cpp.PeekNextLogMessage())

	// check the final state of the logging queue
	mcl_cpp.PopNextLog()

	// check invalid calls
	assert.False(t, mcl_cpp.HasPendingLogs())
	assert.Equal(t, -1, mcl_cpp.PeekNextLogLevel())
	assert.Equal(t, "", mcl_cpp.PeekNextLogModule())
	assert.Equal(t, "", mcl_cpp.PeekNextLogMessage())
}

func TestLoggingSink(t *testing.T) {
	assert.False(t, mcl_cpp.HasPendingLogs())

	// create the logger and the sink
	sink := NewBufferedLogger()
	collector := NewNativeLoggingCollector(sink)

	// use test binding to emulate the native code generating a log message (this is always an error message)
	mcl_cpp.SendTestLogMessage("foo bar is a baz")

	// start the logger
	collector.Start()

	for i := 0; i < 20; i++ {
		if sink.numMessages() > 0 {
			break
		}

		time.Sleep(CollectTickInterval)
	}

	// check that the messages have made it to the sink
	assert.Equal(t, 1, sink.numMessages())

	// wait for the
	assert.Equal(t, LevelError, sink.Messages[0].Level)
	assert.Equal(t, "foo bar is a baz", sink.Messages[0].Text)

	collector.Stop()
}
