package camo

import (
	"fmt"
	"os"
)

const (
	// LogLevelNull ...
	LogLevelNull = iota
	// LogLevelFatal ...
	LogLevelFatal
	// LogLevelPanic ...
	LogLevelPanic
	// LogLevelError ...
	LogLevelError
	// LogLevelWarn ...
	LogLevelWarn
	// LogLevelInfo ...
	LogLevelInfo
	// LogLevelDebug ...
	LogLevelDebug
	// LogLevelTrace ...
	LogLevelTrace
)

// LogLevelTexts ...
var LogLevelTexts = map[int]string{
	LogLevelNull:  "NULL",
	LogLevelFatal: "FATAL",
	LogLevelPanic: "PANIC",
	LogLevelError: "ERROR",
	LogLevelWarn:  "WARN",
	LogLevelInfo:  "INFO",
	LogLevelDebug: "DEBUG",
	LogLevelTrace: "TRACE",
}

// LogLevelValues ...
var LogLevelValues map[string]int

func init() {
	LogLevelValues = make(map[string]int, len(LogLevelTexts))
	for k, v := range LogLevelTexts {
		LogLevelValues[v] = k
	}
}

// Logger ...
type Logger interface {
	Level() int
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
	Panic(v ...interface{})
	Panicf(format string, v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Warn(v ...interface{})
	Warnf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Trace(v ...interface{})
	Tracef(format string, v ...interface{})
}

// stdLogger ...
type stdLogger interface {
	Output(calldepth int, s string) error
}

// LevelLogger ...
type LevelLogger struct {
	logger stdLogger
	level  int
}

// NewLogger ...
func NewLogger(l stdLogger, level int) *LevelLogger {
	return &LevelLogger{
		logger: l,
		level:  level,
	}
}

// Level ...
func (l *LevelLogger) Level() int {
	if l == nil {
		return LogLevelNull
	}
	return l.level
}

func (l *LevelLogger) output(level int, calldepth int, v ...interface{}) {
	if level > l.Level() {
		return
	}
	_ = l.logger.Output(calldepth+1, LogLevelTexts[level]+" "+fmt.Sprintln(v...))
}

func (l *LevelLogger) outputf(level int, calldepth int, format string, v ...interface{}) {
	if level > l.Level() {
		return
	}
	_ = l.logger.Output(calldepth+1, LogLevelTexts[level]+" "+fmt.Sprintf(format, v...))
}

// Log ...
func (l *LevelLogger) Log(level int, v ...interface{}) {
	l.output(level, 2, v...)
}

// Logf ...
func (l *LevelLogger) Logf(level int, format string, v ...interface{}) {
	l.outputf(level, 2, format, v...)
}

// Fatal ...
func (l *LevelLogger) Fatal(v ...interface{}) {
	l.output(LogLevelFatal, 2, v...)
	os.Exit(1)
}

// Fatalf ...
func (l *LevelLogger) Fatalf(format string, v ...interface{}) {
	l.outputf(LogLevelFatal, 2, format, v...)
	os.Exit(1)
}

// Panic ...
func (l *LevelLogger) Panic(v ...interface{}) {
	s := fmt.Sprintln(v...)
	l.output(LogLevelPanic, 2, s)
	panic(s)
}

// Panicf ...
func (l *LevelLogger) Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	l.output(LogLevelPanic, 2, s)
	panic(s)
}

// Error ...
func (l *LevelLogger) Error(v ...interface{}) {
	l.output(LogLevelError, 2, v...)
}

// Errorf ...
func (l *LevelLogger) Errorf(format string, v ...interface{}) {
	l.outputf(LogLevelError, 2, format, v...)
}

// Warn ...
func (l *LevelLogger) Warn(v ...interface{}) {
	l.output(LogLevelWarn, 2, v...)
}

// Warnf ...
func (l *LevelLogger) Warnf(format string, v ...interface{}) {
	l.outputf(LogLevelWarn, 2, format, v...)
}

// Info ...
func (l *LevelLogger) Info(v ...interface{}) {
	l.output(LogLevelInfo, 2, v...)
}

// Infof ...
func (l *LevelLogger) Infof(format string, v ...interface{}) {
	l.outputf(LogLevelInfo, 2, format, v...)
}

// Debug ...
func (l *LevelLogger) Debug(v ...interface{}) {
	l.output(LogLevelDebug, 2, v...)
}

// Debugf ...
func (l *LevelLogger) Debugf(format string, v ...interface{}) {
	l.outputf(LogLevelDebug, 2, format, v...)
}

// Trace ...
func (l *LevelLogger) Trace(v ...interface{}) {
	l.output(LogLevelTrace, 2, v...)
}

// Tracef ...
func (l *LevelLogger) Tracef(format string, v ...interface{}) {
	l.outputf(LogLevelTrace, 2, format, v...)
}
