package logger

func WithContext(context string) *contextLogger {
	return &contextLogger{context: context}
}

func (l *contextLogger) Debug(args ...any) {
	printWithContext(DEBUG, l.context, args...)
}

func (l *contextLogger) Http(args ...any) {
	printWithContext(HTTP, l.context, args...)
}

func (l *contextLogger) Info(args ...any) {
	printWithContext(INFO, l.context, args...)
}

func (l *contextLogger) Warn(args ...any) {
	printWithContext(WARN, l.context, args...)
}

func (l *contextLogger) Error(args ...any) {
	printWithContext(ERROR, l.context, args...)
}
