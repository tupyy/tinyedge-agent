package entity

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tupyy/tinyedge-controller/pkg/grpc/common"
)

type WorkloadKind string

const (
	PodKind WorkloadKind = "pod"
	K8SKind WorkloadKind = "k8s"
)

type Workload interface {
	ID() string
	Kind() WorkloadKind
	Hash() string
	Name() string
	Cron() string
	IsRootless() bool
	Profiles() []WorkloadProfile
	Specification() string
	ConfigMaps() []string
	Secrets() map[string]string
	String() string
}

func NewPodWorkload(w *common.Workload) PodWorkload {
	hash := createHash(w)
	secrets := make(map[string]string)
	json, _ := json.Marshal(w)

	pod := PodWorkload{
		id:            fmt.Sprintf("%s-%s", w.Name, hash[:12]),
		name:          w.Name,
		labels:        w.Labels,
		configmaps:    w.ConfigMaps,
		specification: w.Spec,
		rootless:      w.Rootless,
		secrets:       secrets,
		definition:    string(json),
	}
	return pod
}

// PodWorkload represents the workload in form of a pod.
type PodWorkload struct {
	// id - id of the workload
	id string
	// name - name of the workload
	name string
	// hash - has of the workload
	hash string
	// cron spec
	cronSpec string
	// Rootless is true if workload is to be executed in podman rootless
	rootless bool
	// secrets
	secrets map[string]string
	// configmaps
	configmaps []string
	// image registries auth file
	imageRegistryAuth string
	// Workload labels
	labels map[string]string
	// profiles
	workloadProfiles []WorkloadProfile
	// specification
	specification string
	// definition
	definition string
}

func (p PodWorkload) ID() string {
	return p.id
}

func (p PodWorkload) Name() string {
	return p.name
}

func (p PodWorkload) String() string {
	return p.definition
}

func (p PodWorkload) Kind() WorkloadKind {
	return PodKind
}

func (p PodWorkload) Profiles() []WorkloadProfile {
	return p.workloadProfiles
}

func (p PodWorkload) Hash() string {
	return p.hash
}

func (p PodWorkload) Cron() string {
	return p.cronSpec
}

func (p PodWorkload) IsRootless() bool {
	return p.rootless
}

func (p PodWorkload) Specification() string {
	return p.specification
}

func (p PodWorkload) Secrets() map[string]string {
	return p.secrets
}

func (p PodWorkload) Labels() map[string]string {
	return p.labels
}

func (p PodWorkload) ConfigMaps() []string {
	return p.configmaps
}

func (p PodWorkload) Annotations() map[string]string {
	return make(map[string]string)
}

func (p PodWorkload) ImageRegistryAuth() string {
	return p.imageRegistryAuth
}

type WorkloadProfile struct {
	Name       string
	Conditions []WorkloadCondition
}

type WorkloadCondition struct {
	Name string
	CPU  *int64
}

func createHash(w *common.Workload) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s", w.Name)

	for k, v := range w.Labels {
		fmt.Fprintf(&sb, "%s%s", k, v)
	}

	for _, c := range w.ConfigMaps {
		fmt.Fprintf(&sb, "%s", c)
	}

	fmt.Fprintf(&sb, "%s", w.Spec)
	fmt.Fprintf(&sb, "%v", w.Rootless)

	sum := sha256.Sum256(bytes.NewBufferString(sb.String()).Bytes())
	return fmt.Sprintf("%x", sum)
}
