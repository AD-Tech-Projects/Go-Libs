package logger

import (
	fmt "fmt"
	log "log"
	"strings"
)

type LogLevel string

const (
	DEBUG LogLevel = "DEBUG"
	HTTP  LogLevel = "HTTP"
	INFO  LogLevel = "INFO"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

func print(level LogLevel, args ...any) {
	printWithContext(level, "", args...)
}

type contextLogger struct {
	context string
}

func printWithContext(level LogLevel, context string, args ...any) {
	prefix := fmt.Sprintf("[%s]", level)
	if context != "" {
		prefix += fmt.Sprintf(" [%s]", context)
	}

	log.Println(colorize(level, prefix), parseArgsToString(args))
}

func colorize(level LogLevel, value string) string {
	const reset = "\033[0m"

	colors := map[LogLevel]string{
		DEBUG: "\033[34m",
		HTTP:  "\033[36m",
		INFO:  "\033[32m",
		WARN:  "\033[33m",
		ERROR: "\033[31m",
	}

	color, ok := colors[level]
	if !ok {
		return value
	}

	return color + value + reset
}

func parseArgsToString(value any) string {
	switch v := any(value).(type) {
	case []any:
		var strValues []string
		for _, item := range v {
			strValues = append(strValues, parseToString(item))
		}
		return strings.Join(strValues, ", ")
	default:
		return parseToString(value)
	}
}
