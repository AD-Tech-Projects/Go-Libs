package logger

import (
	fmt "fmt"
	log "log"
	strings "strings"
)

type LogLevel string

const (
	INFO  LogLevel = "INFO"
	HTTP  LogLevel = "HTTP"
	DEBUG LogLevel = "DEBUG"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

func print(level LogLevel, args ...any) {
	log.Println(fmt.Sprintf("[%s]", level), parseArgsToString(args))
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
