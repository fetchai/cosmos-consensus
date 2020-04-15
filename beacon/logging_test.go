package beacon

import (
	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	"testing"
	"time"
)

type bufferedLogMessage struct {
	Text  string
	Level int
}

type bufferedLogger struct {
	Messages []bufferedLogMessage
}

func NewBufferedLogger() *bufferedLogger {
	return &bufferedLogger{
		[]bufferedLogMessage{},
	}
}

func (l *bufferedLogger) addMessage(msg bufferedLogMessage) {
	l.Messages = append(l.Messages, msg)
}

func (l *bufferedLogger) Debug(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text: msg,
		Level: LevelDebug,
	})
}

func (l *bufferedLogger) Info(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text: msg,
		Level: LevelInfo,
	})

}

func (l *bufferedLogger) Error(msg string, _ ...interface{}) {
	l.addMessage(bufferedLogMessage{
		Text: msg,
		Level: LevelError,
	})

}

func (l *bufferedLogger) With(...interface{}) log.Logger {
	return l
}

func TestNativeSinkCollection(t *testing.T) {
	assert.False(t, HasPendingLogs())

	// use test binding to emulate the native code generating a log message (this is always an error message)
	SendTestLogMessage("foo bar is a baz")

	// check that the logs are valid
	assert.True(t, HasPendingLogs())
	assert.Equal(t, LevelError, PeekNextLogLevel())
	assert.Equal(t, "test", PeekNextLogModule())
	assert.Equal(t, "foo bar is a baz", PeekNextLogMessage())

	// check the final state of the logging queue
	PopNextLog()

	// check invalid calls
	assert.False(t, HasPendingLogs())
	assert.Equal(t, -1, PeekNextLogLevel())
	assert.Equal(t, "", PeekNextLogModule())
	assert.Equal(t, "", PeekNextLogMessage())
}

func TestLoggingSink(t *testing.T) {
	assert.False(t, HasPendingLogs())

	// create the logger and the sink
	sink := NewBufferedLogger()
	collector := NewNativeLoggingCollector(sink)

	// use test binding to emulate the native code generating a log message (this is always an error message)
	SendTestLogMessage("foo bar is a baz")

	// start the logger
	collector.Start()

	for i := 0; i < 20; i++ {
		if len(sink.Messages) > 0 {
			break
		}

		time.Sleep(CollectTickInterval)
	}

	// check that the messages have made it to the sink
	assert.Equal(t, 1, len(sink.Messages))

	// wait for the
	assert.Equal(t, LevelError, sink.Messages[0].Level)
	assert.Equal(t, "foo bar is a baz", sink.Messages[0].Text)

	collector.Stop()
}
