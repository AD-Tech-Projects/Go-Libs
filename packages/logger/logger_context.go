package logger

type ContextLogger interface {
	Debug(args ...any)
	Http(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
}

func WithContext(context string) ContextLogger {
	return &loggerWithContext{context: context}
}

func (l *loggerWithContext) Debug(args ...any) {
	printWithContext(DEBUG, l.context, args...)
}

func (l *loggerWithContext) Http(args ...any) {
	printWithContext(HTTP, l.context, args...)
}

func (l *loggerWithContext) Info(args ...any) {
	printWithContext(INFO, l.context, args...)
}

func (l *loggerWithContext) Warn(args ...any) {
	printWithContext(WARN, l.context, args...)
}

func (l *loggerWithContext) Error(args ...any) {
	printWithContext(ERROR, l.context, args...)
}
