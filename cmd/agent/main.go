package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spechtlabs/go-otel-utils/otelprovider"
	"github.com/spechtlabs/go-otel-utils/otelzap"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/uptime-industries/compute-blade-agent/internal/agent"
	"github.com/uptime-industries/compute-blade-agent/internal/api"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

var (
	Version string
	Commit  string
)

var debug = pflag.BoolP("debug", "v", false, "enable verbose logging")

func main() {
	pflag.Parse()

	// Setup configuration
	viper.SetEnvPrefix("BLADE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/compute-blade-agent")

	// Load potential file configs
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	// setup logger
	var baseLogger *zap.Logger

	if debug != nil && *debug {
		baseLogger = zap.Must(zap.NewDevelopment())
	} else {
		baseLogger = zap.Must(zap.NewProduction())
	}

	zapLogger := baseLogger.With(
		zap.String("app", "compute-blade-agent"),
		zap.String("version", Version),
		zap.String("commit", Commit),
	)
	defer func() {
		_ = zapLogger.Sync()
	}()

	// Replace zap global
	undoZapGlobals := zap.ReplaceGlobals(zapLogger)

	// Redirect stdlib log to zap
	undoStdLogRedirect := zap.RedirectStdLog(zapLogger)

	// Create OpenTelemetry Log and Trace provider
	logProvider := otelprovider.NewLogger(
		otelprovider.WithLogAutomaticEnv(),
	)

	traceProvider := otelprovider.NewTracer(
		otelprovider.WithTraceAutomaticEnv(),
	)

	// Create otelLogger
	otelZapLogger := otelzap.New(zapLogger,
		otelzap.WithCaller(true),
		otelzap.WithMinLevel(zap.InfoLevel),
		otelzap.WithAnnotateLevel(zap.WarnLevel),
		otelzap.WithErrorStatusLevel(zap.ErrorLevel),
		otelzap.WithStackTrace(false),
		otelzap.WithLoggerProvider(logProvider),
	)

	// Replace global otelZap logger
	undoOtelZapGlobals := otelzap.ReplaceGlobals(otelZapLogger)
	defer undoOtelZapGlobals()

	// Cleanup Logging and Tracing
	defer func() {
		if err := traceProvider.ForceFlush(context.Background()); err != nil {
			otelzap.L().Warn("failed to flush traces")
		}

		if err := logProvider.ForceFlush(context.Background()); err != nil {
			otelzap.L().Warn("failed to flush logs")
		}

		if err := traceProvider.Shutdown(context.Background()); err != nil {
			panic(err)
		}

		if err := logProvider.Shutdown(context.Background()); err != nil {
			panic(err)
		}

		undoStdLogRedirect()
		undoZapGlobals()
	}()

	// Setup context
	baseCtx := log.IntoContext(context.Background(), otelZapLogger)
	ctx, cancelCtx := context.WithCancelCause(baseCtx)
	defer cancelCtx(context.Canceled)

	// load configuration
	var cbAgentConfig agent.ComputeBladeAgentConfig
	if err := viper.Unmarshal(&cbAgentConfig); err != nil {
		cancelCtx(err)
		log.FromContext(ctx).WithError(err).Fatal("Failed to load configuration")
	}

	// setup stop signal handlers
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		select {
		// Wait for context cancel
		case <-ctx.Done():

		// Wait for signal
		case sig := <-sigs:
			switch sig {
			case syscall.SIGTERM:
				fallthrough
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGQUIT:
				// On terminate signal, cancel context causing the program to terminate
				cancelCtx(fmt.Errorf("signal %s received", sig))

			default:
				log.FromContext(ctx).Warn("Received unknown signal", zap.String("signal", sig.String()))
			}
		}
	}()

	log.FromContext(ctx).Info("Bootstrapping compute-blade-agent")
	computebladeAgent, err := agent.NewComputeBladeAgent(ctx, cbAgentConfig)
	if err != nil {
		cancelCtx(err)
		log.FromContext(ctx).WithError(err).Fatal("Failed to create agent")
	}

	// Run agent
	computebladeAgent.RunAsync(ctx, cancelCtx)

	// Setup GRPC server
	grpcServer := api.NewGrpcApiServer(ctx,
		api.WithComputeBladeAgent(computebladeAgent),
		api.WithAuthentication(cbAgentConfig.Listen.GrpcAuthenticated),
		api.WithListenAddr(cbAgentConfig.Listen.Grpc),
		api.WithListenMode(cbAgentConfig.Listen.GrpcListenMode),
	)

	// Run gRPC API
	grpcServer.ServeAsync(ctx, cancelCtx)

	// setup prometheus endpoint
	promServer := runPrometheusEndpoint(ctx, cancelCtx, &cbAgentConfig.Listen)

	// Wait for done
	<-ctx.Done()

	// Since ctx is now done, we can no longer use it to get `log.FromContext(ctx)`
	// but we must use otelzap.L() to get a logger

	// Shut down gRPC and Prom Servers async
	var wg sync.WaitGroup

	// Shut-Down GRPC Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		otelzap.L().Info("Shutting down grpc server")
		grpcServer.GracefulStop()
	}()

	// Shut-Down Prometheus Endpoint
	wg.Add(1)
	go func() {
		defer wg.Done()

		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCtxCancel()

		otelzap.L().Info("Shutting down prometheus/pprof server")
		if err := promServer.Shutdown(shutdownCtx); err != nil {
			otelzap.L().WithError(err).Error("Failed to shutdown prometheus/pprof server")
		}
	}()

	wg.Wait()

	// Terminate accordingly
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		otelzap.L().WithError(err).Fatal("Exiting")
	} else {
		otelzap.L().Info("Exiting")
	}
}

func runPrometheusEndpoint(ctx context.Context, cancel context.CancelCauseFunc, apiConfig *api.Config) *http.Server {
	instrumentationHandler := http.NewServeMux()
	instrumentationHandler.Handle("/metrics", promhttp.Handler())
	instrumentationHandler.HandleFunc("/debug/pprof/", pprof.Index)
	instrumentationHandler.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	instrumentationHandler.HandleFunc("/debug/pprof/profile", pprof.Profile)
	instrumentationHandler.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	instrumentationHandler.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{Addr: apiConfig.Metrics, Handler: instrumentationHandler}

	// Run Prometheus Endpoint
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.FromContext(ctx).WithError(err).Error("Failed to start prometheus/pprof server")
			cancel(err)
		}
	}()

	return server
}
