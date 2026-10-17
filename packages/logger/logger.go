package logger

func Info(args ...any) {
	print(INFO, args...)
}

func Http(args ...any) {
	print(HTTP, args...)
}

func Debug(args ...any) {
	print(DEBUG, args...)
}

func Warn(args ...any) {
	print(WARN, args...)
}

func Error(args ...any) {
	print(ERROR, args...)
}
