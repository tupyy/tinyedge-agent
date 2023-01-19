package entity

import (
	"encoding/json"
	"time"
)

type DeviceConfigurationMessage struct {
	Hash string
	// configuration
	Configuration DeviceConfiguration

	// Device identifier
	DeviceID string

	// Version
	Version string

	// list of workloads
	Workloads []Workload

	// Defines the interval in seconds between the attempts to evaluate the workloads status and restart those that failed
	// Minimum: > 0
	WorkloadsMonitoringInterval time.Duration
}

func (m DeviceConfigurationMessage) String() string {
	json, err := json.Marshal(m)
	if err != nil {
		return err.Error()
	}
	return string(json)
}

type DeviceConfiguration struct {
	// Heartbeat configuration
	Heartbeat HeartbeatConfiguration

	// List of user defined mounts
	Mounts []Mount

	// Os information
	OsInformation OsInformation

	Profiles map[string]map[string]string
}

func (d DeviceConfiguration) String() string {
	json, err := json.Marshal(d)
	if err != nil {
		return err.Error()
	}
	return string(json)
}

type OsInformation struct {
	// automatically upgrade the OS image
	AutomaticallyUpgrade bool

	// the last commit ID
	CommitID string

	// the URL of the hosted commits web server
	HostedObjectsURL string
}

type Mount struct {
	// path of the device to be mounted
	Device string

	// destination directory
	Directory string

	// mount options
	Options string

	// type of the mount
	Type string
}
