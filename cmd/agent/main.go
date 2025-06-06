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

	"github.com/compute-blade-community/compute-blade-agent/internal/agent"
	"github.com/compute-blade-community/compute-blade-agent/internal/api"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	Version string
	Commit  string
	Date    string
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

	zapLogger := baseLogger.With(zap.String("app", "compute-blade-agent"))
	defer func() {
		_ = zapLogger.Sync()
	}()
	_ = zap.ReplaceGlobals(zapLogger.With(zap.String("scope", "global")))
	baseCtx := log.IntoContext(context.Background(), zapLogger)

	ctx, cancelCtx := context.WithCancelCause(baseCtx)
	defer cancelCtx(context.Canceled)

	// load configuration
	var cbAgentConfig agent.ComputeBladeAgentConfig
	if err := viper.Unmarshal(&cbAgentConfig); err != nil {
		cancelCtx(err)
		log.FromContext(ctx).Fatal("Failed to load configuration", zap.Error(err))
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

	log.FromContext(ctx).Info("Bootstrapping compute-blade-agent", zap.String("version", Version), zap.String("commit", Commit), zap.String("date", Date))
	computebladeAgent, err := agent.NewComputeBladeAgent(ctx, cbAgentConfig)
	if err != nil {
		cancelCtx(err)
		log.FromContext(ctx).Fatal("Failed to create agent", zap.Error(err))
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

	var wg sync.WaitGroup

	// Shut-Down GRPC Server
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Shutting down grpc server")
		grpcServer.GracefulStop()
	}()

	// Shut-Down Prometheus Endpoint
	wg.Add(1)
	go func() {
		defer wg.Done()

		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCtxCancel()

		if err := promServer.Shutdown(shutdownCtx); err != nil {
			log.FromContext(ctx).Error("Failed to shutdown prometheus/pprof server", zap.Error(err))
		}
	}()

	wg.Wait()

	// Wait for context cancel
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Fatal("Exiting", zap.Error(err))
	} else {
		log.FromContext(ctx).Info("Exiting")
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
			log.FromContext(ctx).Error("Failed to start prometheus/pprof server", zap.Error(err))
			cancel(err)
		}
	}()

	return server
}
