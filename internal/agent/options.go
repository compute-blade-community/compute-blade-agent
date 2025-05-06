package agent

type GrpcApiServiceOption func(*AgentGrpcService)

func WithComputeBladeAgent(agent ComputeBladeAgent) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.agent = agent
	}
}

func WithAuthentication(enabled bool) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.authenticated = enabled
	}
}

func WithListenAddr(server string) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.listenAddr = server
	}
}

func WithListenMode(mode string) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.listenMode = mode
	}
}

func WithTCP() GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.listenMode = "tcp"
	}
}

func WithUnixSocket() GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.listenMode = "unix"
	}
}
