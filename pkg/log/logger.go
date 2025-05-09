package log

import (
	"context"

	"go.uber.org/zap"
)

type logCtxKey int

func IntoContext(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, logCtxKey(0), logger)
}

func FromContext(ctx context.Context) *zap.Logger {
	val := ctx.Value(logCtxKey(0))
	if val != nil {
		return val.(*zap.Logger)
	}

	zap.L().WithOptions(zap.AddCallerSkip(1)).Warn("No logger in context, passing default")
	return zap.L()
}
