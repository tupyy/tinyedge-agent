package grpc

import (
	"bytes"
	"context"
	"sync"

	"github.com/tupyy/tinyedge-agent/internal/certificate"
	"github.com/tupyy/tinyedge-agent/internal/entity"
	"go.uber.org/zap"
)

type ClientManager struct {
	l      sync.Mutex
	client *client
	// certificateSignature holds the current certificate signature
	certSignatureLock    sync.RWMutex
	certificateSignature []byte
	certManager          *certificate.Manager
	serverAddress        string
}

func New(serverAddress string, certManager *certificate.Manager) (*ClientManager, error) {
	manager := &ClientManager{
		certManager:          certManager,
		certificateSignature: certManager.Signature(),
		serverAddress:        serverAddress,
	}
	client, err := manager.createClient(serverAddress, certManager)
	if err != nil {
		return nil, err
	}

	manager.client = client
	return manager, nil
}

func (c *ClientManager) Enrol(ctx context.Context, deviceID string, enrolInfo entity.EnrolementInfo) error {
	if c.certificateChanged() {
		if err := c.reconnect(); err != nil {
			return err
		}
	}

	return c.client.Enrol(ctx, deviceID, enrolInfo)
}

func (c *ClientManager) Register(ctx context.Context, deviceID string, registerInfo entity.RegistrationInfo) (entity.RegistrationResponse, error) {
	if c.certificateChanged() {
		if err := c.reconnect(); err != nil {
			return entity.RegistrationResponse{}, err
		}
	}

	return c.client.Register(ctx, deviceID, registerInfo)
}

func (c *ClientManager) Heartbeat(ctx context.Context, deviceID string, heartbeat entity.Heartbeat) error {
	if c.certificateChanged() {
		if err := c.reconnect(); err != nil {
			return err
		}
	}
	return c.client.Heartbeat(ctx, deviceID, heartbeat)
}

func (c *ClientManager) GetConfiguration(ctx context.Context, deviceID string) (entity.DeviceConfigurationMessage, error) {
	if c.certificateChanged() {
		if err := c.reconnect(); err != nil {
			return entity.DeviceConfigurationMessage{}, err
		}
	}
	return c.client.GetConfiguration(ctx, deviceID)
}

func (c *ClientManager) Close(ctx context.Context) {
	c.client.Close(ctx)
}

func (c *ClientManager) certificateChanged() bool {
	c.certSignatureLock.RLock()
	defer c.certSignatureLock.RUnlock()
	return !bytes.Equal(c.certificateSignature, c.certManager.Signature())
}

func (c *ClientManager) reconnect() error {
	c.l.Lock()
	defer c.l.Unlock()

	if !c.certificateChanged() {
		return nil
	}

	// close old connection
	c.client.Close(context.TODO())

	newClient, err := c.createClient(c.serverAddress, c.certManager)
	if err != nil {
		return err
	}

	c.certSignatureLock.Lock()
	c.certificateSignature = c.certManager.Signature()
	c.certSignatureLock.Unlock()

	c.client = newClient
	zap.S().Debug("grpc client reconnected to server")

	return nil
}

func (c *ClientManager) createClient(serverAddress string, certManager *certificate.Manager) (*client, error) {
	tlsConfig, err := certManager.TLSConfig()
	if err != nil {
		return nil, err
	}

	client, err := newClient(serverAddress, tlsConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}
