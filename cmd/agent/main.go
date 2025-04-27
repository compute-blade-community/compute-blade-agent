package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	bladeapiv1alpha1 "github.com/uptime-induestries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-induestries/compute-blade-agent/internal/agent"
	"github.com/uptime-induestries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

var (
	Version string
	Commit  string
	Date    string
)

func main() {
	var wg sync.WaitGroup

	// Setup configuration
	viper.SetConfigType("yaml")

	// auto-bind environment variables
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
	switch logMode := viper.GetString("log.mode"); logMode {
	case "development":
		baseLogger = zap.Must(zap.NewDevelopment())
	case "production":
		baseLogger = zap.Must(zap.NewProduction())
	default:
		panic(fmt.Errorf("invalid log.mode: %s", logMode))
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
		log.FromContext(ctx).Error("Failed to load configuration", zap.Error(err))
		cancelCtx(err)
	}

	// setup stop signal handlers
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for context cancel or signal
		select {
		case <-ctx.Done():
		case sig := <-sigs:
			// On signal, cancel context
			cancelCtx(fmt.Errorf("signal %s received", sig))
		}
	}()

	log.FromContext(ctx).Info("Bootstrapping compute-blade-agent", zap.String("version", Version), zap.String("commit", Commit), zap.String("date", Date))
	computebladeAgent, err := agent.NewComputeBladeAgent(ctx, cbAgentConfig)
	if err != nil {
		log.FromContext(ctx).Error("Failed to create agent", zap.Error(err))
		cancelCtx(err)
		os.Exit(1)
	}

	// Run agent
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting agent")
		err := computebladeAgent.Run(ctx)
		if err != nil && err != context.Canceled {
			log.FromContext(ctx).Error("Failed to run agent", zap.Error(err))
			cancelCtx(err)
		}
	}()

	// Setup GRPC server
	// FIXME add logging middleware
	grpcServer := grpc.NewServer()
	bladeapiv1alpha1.RegisterBladeAgentServiceServer(grpcServer, agent.NewGrpcServiceFor(computebladeAgent))
	wg.Add(1)
	go func() {
		defer wg.Done()
		grpcListen, err := net.Listen("unix", viper.GetString("listen.grpc"))
		if err != nil {
			log.FromContext(ctx).Error("Failed to create grpc listener", zap.Error(err))
			cancelCtx(err)
			return
		}
		log.FromContext(ctx).Info("Starting grpc server", zap.String("address", viper.GetString("listen.grpc")))
		if err := grpcServer.Serve(grpcListen); err != nil && err != grpc.ErrServerStopped {
			log.FromContext(ctx).Error("Failed to start grpc server", zap.Error(err))
			cancelCtx(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		log.FromContext(ctx).Info("Shutting down grpc server")
		grpcServer.GracefulStop()
	}()

	// setup prometheus endpoint
	instrumentationHandler := http.NewServeMux()
	instrumentationHandler.Handle("/metrics", promhttp.Handler())
	instrumentationHandler.HandleFunc("/debug/pprof/", pprof.Index)
	instrumentationHandler.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	instrumentationHandler.HandleFunc("/debug/pprof/profile", pprof.Profile)
	instrumentationHandler.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	instrumentationHandler.HandleFunc("/debug/pprof/trace", pprof.Trace)
	server := &http.Server{Addr: ":9666", Handler: instrumentationHandler}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.FromContext(ctx).Error("Failed to start prometheus/pprof server", zap.Error(err))
			cancelCtx(err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.FromContext(ctx).Error("Failed to shutdown prometheus/pprof server", zap.Error(err))
		}
	}()

	// Wait for context cancel
	wg.Wait()
	if err := ctx.Err(); err != nil && err != context.Canceled {
		log.FromContext(ctx).Fatal("Exiting", zap.Error(err))
	} else {
		log.FromContext(ctx).Info("Exiting")
	}
}
