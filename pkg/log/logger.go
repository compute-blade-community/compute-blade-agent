package log

import (
	"context"

	"github.com/spechtlabs/go-otel-utils/otelzap"
	"go.uber.org/zap"
)

type logCtxKey int

func IntoContext(ctx context.Context, logger *otelzap.Logger) context.Context {
	return context.WithValue(ctx, logCtxKey(0), logger)
}

func FromContext(ctx context.Context) *otelzap.Logger {
	val := ctx.Value(logCtxKey(0))
	if val != nil {
		return val.(*otelzap.Logger)
	}

	otelzap.L().WithOptions(zap.AddCallerSkip(1)).Warn("No logger in context, passing default")
	return otelzap.L()
}
