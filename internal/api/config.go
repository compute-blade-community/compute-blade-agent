package api

type Config struct {
	Metrics           string `mapstructure:"metrics"`
	Grpc              string `mapstructure:"grpc"`
	GrpcAuthenticated bool   `mapstructure:"authenticated"`
	GrpcListenMode    string `mapstructure:"mode"`
}
