package common

import (
	"fmt"
	"strings"

	config "github.com/tupyy/tinyedge-agent/configuration"
	"github.com/tupyy/tinyedge-agent/internal/entity"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func ToPod(workload entity.PodWorkload) (*v1.Pod, error) {
	podSpec := v1.PodSpec{}
	err := yaml.Unmarshal([]byte(workload.Specification()), &podSpec)
	if err != nil {
		return nil, err
	}
	pod := v1.Pod{
		Spec: podSpec,
	}
	pod.Kind = "Pod"
	pod.Name = fmt.Sprintf("%s", workload.ID())
	pod.Labels = workload.Labels()
	var containers []v1.Container
	for _, container := range pod.Spec.Containers {
		container.Env = append(container.Env, v1.EnvVar{Name: "DEVICE_ID", Value: config.GetDeviceID()})
		containers = append(containers, container)
	}
	pod.Spec.Containers = containers
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}

	// Set the authfile label to pod, if ImageRegistry authfile is set:
	// if workload.ImageRegistryAuth != "" {
	// 	pod.Labels["io.containers.autoupdate.authfile"] = p.getAuthFilePath(workload.Name)
	// }

	// add label to identity this workload as ours
	pod.Labels["tinyedge.io"] = workload.Hash()

	return &pod, nil
}

func ToPodYaml(pod *v1.Pod, configmaps []string) ([]byte, error) {
	podYaml, err := yaml.Marshal(pod)
	if err != nil {
		return nil, err
	}

	cmYaml := ""
	if len(configmaps) > 0 {
		cmYaml = strings.Join(configmaps, "---\n")
	}

	return []byte(strings.Join([]string{string(podYaml), string(cmYaml)}, "---\n")), nil
}
