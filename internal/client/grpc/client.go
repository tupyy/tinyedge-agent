package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	controller "github.com/tupyy/tinyedge-agent/internal/edge"
	"github.com/tupyy/tinyedge-agent/internal/entity"
	grpcCommon "github.com/tupyy/tinyedge-controller/pkg/grpc/common"
	grpcEdge "github.com/tupyy/tinyedge-controller/pkg/grpc/edge"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type client struct {
	edgeClient grpcEdge.EdgeServiceClient
	conn       *grpc.ClientConn
	mutex      sync.Mutex
}

func newClient(addr string, tls *tls.Config) (*client, error) {
	c := &client{}

	if err := c.dial(addr, tls); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *client) Close(ctx context.Context) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.conn.Close()
}

func (c *client) Enrol(ctx context.Context, deviceID string, enrolInfo entity.EnrolementInfo) error {
	req := &grpcEdge.EnrolRequest{
		DeviceId: deviceID,
	}

	ctx = c.addDeviceIdToContext(ctx, deviceID)

	resp, err := c.edgeClient.Enrol(ctx, req)
	if err != nil {
		status, ok := status.FromError(err)
		if ok {
			if strings.Contains(status.String(), "authentication handshake failed") {
				return fmt.Errorf("authorization denied %s: %w", err, controller.ErrAuthorizationDenied)
			}
			zap.S().Errorf("unable to unrol device: %v", status)
			return controller.ErrUnknown
		}
		return err
	}

	if resp.EnrolmentStatus != grpcEdge.EnrolmentStatus_ENROLED {
		return fmt.Errorf("device %q not enroled: %s", deviceID, resp.EnrolmentStatus.String())
	}

	return nil
}

func (c *client) Register(ctx context.Context, deviceID string, registerInfo entity.RegistrationInfo) (entity.RegistrationResponse, error) {
	req := &grpcEdge.RegistrationRequest{
		DeviceId:           deviceID,
		CertificateRequest: registerInfo.CertificateRequest,
	}

	ctx = c.addDeviceIdToContext(ctx, deviceID)

	resp, err := c.edgeClient.Register(ctx, req)
	if err != nil {
		status, ok := status.FromError(err)
		if ok && status.Code() == codes.PermissionDenied {
			return entity.RegistrationResponse{}, fmt.Errorf("authorization denied %s: %w", status.Message(), controller.ErrAuthorizationDenied)
		}
		zap.S().Errorf("unable to register device: %v", status)
		return entity.RegistrationResponse{}, fmt.Errorf("%w %s", controller.ErrUnknown, err.Error())
	}

	return entity.RegistrationResponse{SignedCSR: []byte(resp.GetCertificate())}, nil
}

func (c *client) Heartbeat(ctx context.Context, deviceID string, heartbeat entity.Heartbeat) error {
	ctx = c.addDeviceIdToContext(ctx, deviceID)

	req := &grpcCommon.HeartbeatInfo{
		DeviceId: deviceID,
		HardwareInfo: &grpcCommon.HardwareInfo{
			HostName: "totot",
			OsInformation: &grpcCommon.OsInformation{
				CommitId: "commit id",
			},
			SystemVendor: &grpcCommon.SystemVendor{
				Manufacturer: "test",
			},
			Interfaces: make([]*grpcCommon.Interface, 0),
		},
	}
	_, err := c.edgeClient.Heartbeat(ctx, req)
	if err != nil {
		status, ok := status.FromError(err)
		if ok {
			if status.Code() == codes.PermissionDenied {
				return fmt.Errorf("authorization denied %s: %w", status.Message(), controller.ErrAuthorizationDenied)
			}
			if strings.Contains(status.Message(), "failed to verify client certificate") {
				return controller.ErrTlsHandshakeFailed
			}
			zap.S().Errorf("unable to do heartbeat: %v", status)
			return controller.ErrUnknown
		}
		return err
	}
	return nil
}

func (c *client) GetConfiguration(ctx context.Context, deviceID string) (entity.DeviceConfigurationMessage, error) {
	ctx = c.addDeviceIdToContext(ctx, deviceID)

	conf, err := c.edgeClient.GetConfiguration(ctx, &grpcEdge.ConfigurationRequest{DeviceId: deviceID})
	if err != nil {
		status, ok := status.FromError(err)
		if ok {
			if status.Code() == codes.PermissionDenied {
				return entity.DeviceConfigurationMessage{}, fmt.Errorf("authorization denied %s: %w", err, controller.ErrAuthorizationDenied)
			}
			if strings.Contains(status.Message(), "authentication handshake failed") {
				return entity.DeviceConfigurationMessage{}, controller.ErrTlsHandshakeFailed
			}
			zap.S().Errorf("unable to get configuration: %v", status)
			return entity.DeviceConfigurationMessage{}, controller.ErrUnknown
		}
		return entity.DeviceConfigurationMessage{}, nil
	}
	return MapConfigurationResponse(conf), nil
}

func (c *client) dial(addr string, tlsConfig *tls.Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	tlsTransport := credentials.NewTLS(tlsConfig)

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(tlsTransport))
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return err
	}
	c.conn = conn
	c.edgeClient = grpcEdge.NewEdgeServiceClient(conn)
	return nil
}

func (c *client) addDeviceIdToContext(ctx context.Context, deviceID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "device_id", deviceID)
}
