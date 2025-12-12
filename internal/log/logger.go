package log

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Level represents the logging level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel = LevelInfo
	levelNames   = map[Level]string{
		LevelDebug: "DEBUG",
		LevelInfo:  "INFO",
		LevelWarn:  "WARN",
		LevelError: "ERROR",
	}
)

// Init initializes the logger with the specified level
func Init(level string) {
	switch strings.ToLower(level) {
	case "debug":
		currentLevel = LevelDebug
	case "info":
		currentLevel = LevelInfo
	case "warn", "warning":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout)
}

// GetLevel returns the current log level as a string
func GetLevel() string {
	return levelNames[currentLevel]
}

// IsDebugEnabled returns true if debug logging is enabled
func IsDebugEnabled() bool {
	return currentLevel <= LevelDebug
}

func logf(level Level, format string, args ...interface{}) {
	if level < currentLevel {
		return
	}
	prefix := levelNames[level]
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", prefix, msg)
}

func logln(level Level, args ...interface{}) {
	if level < currentLevel {
		return
	}
	prefix := levelNames[level]
	msg := fmt.Sprint(args...)
	log.Printf("[%s] %s", prefix, msg)
}

// Debug logs a debug message
func Debug(args ...interface{}) {
	logln(LevelDebug, args...)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	logf(LevelDebug, format, args...)
}

// Info logs an info message
func Info(args ...interface{}) {
	logln(LevelInfo, args...)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	logf(LevelInfo, format, args...)
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	logln(LevelWarn, args...)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	logf(LevelWarn, format, args...)
}

// Error logs an error message
func Error(args ...interface{}) {
	logln(LevelError, args...)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	logf(LevelError, format, args...)
}

// Printf logs at info level (for compatibility)
func Printf(format string, args ...interface{}) {
	logf(LevelInfo, format, args...)
}

// Println logs at info level (for compatibility)
func Println(args ...interface{}) {
	logln(LevelInfo, args...)
}

// Fatalf logs at error level and exits
func Fatalf(format string, args ...interface{}) {
	logf(LevelError, format, args...)
	os.Exit(1)
}

// Fatal logs at error level and exits
func Fatal(args ...interface{}) {
	logln(LevelError, args...)
	os.Exit(1)
}
