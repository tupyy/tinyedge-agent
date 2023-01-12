package grpc

import (
	"time"

	"github.com/tupyy/tinyedge-agent/internal/entity"
	grpcEdge "github.com/tupyy/tinyedge-controller/pkg/grpc/edge"
)

func MapConfigurationResponse(m *grpcEdge.ConfigurationResponse) entity.DeviceConfigurationMessage {
	e := entity.DeviceConfiguration{
		Heartbeat: entity.HeartbeatConfiguration{
			HardwareProfile: entity.HardwareProfileConfiguration{
				Include: true,
				Scope:   entity.FullScope,
			},
			Period: time.Duration(int(m.Configuration.HeartbeatPeriod) * int(time.Second)),
		},
		Profiles: map[string]map[string]string{},
	}

	workloads := make([]entity.Workload, 0, len(m.Workloads))
	for _, w := range m.Workloads {
		ww := *w
		pod := entity.PodWorkload{
			Name:          ww.Name,
			WKind:         entity.PodKind,
			Labels:        ww.Labels,
			Configmaps:    ww.ConfigMaps,
			Specification: ww.Spec,
			Rootless:      ww.Rootless,
			Secrets:       make(map[string]string),
		}
		for _, s := range m.Secrets {
			pod.Secrets[s.Key] = s.Value
		}
		workloads = append(workloads, pod)
	}
	return entity.DeviceConfigurationMessage{
		Configuration: e,
		Workloads:     workloads,
	}
}
