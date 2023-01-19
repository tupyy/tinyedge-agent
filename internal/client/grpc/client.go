package grpc

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tupyy/tinyedge-agent/internal/certificate"
	controller "github.com/tupyy/tinyedge-agent/internal/edge"
	"github.com/tupyy/tinyedge-agent/internal/entity"
	grpcCommon "github.com/tupyy/tinyedge-controller/pkg/grpc/common"
	grpcEdge "github.com/tupyy/tinyedge-controller/pkg/grpc/edge"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Client struct {
	edgeClient           grpcEdge.EdgeServiceClient
	certManager          *certificate.Manager
	serverAddress        string
	certificateSignature []byte
	conn                 *grpc.ClientConn
	mutex                sync.Mutex
}

func New(serverAddress string, certManager *certificate.Manager) (*Client, error) {
	if certManager == nil {
		return nil, fmt.Errorf("Certificate manager is missing")
	}

	c := &Client{serverAddress: serverAddress, certManager: certManager, certificateSignature: certManager.Signature()}

	if err := c.dial(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) Close(ctx context.Context) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.conn.Close()
}

func (c *Client) Enrol(ctx context.Context, deviceID string, enrolInfo entity.EnrolementInfo) error {
	if !bytes.Equal(c.certificateSignature, c.certManager.Signature()) {
		c.conn.Close()
		c.dial()
	}

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
		}
		return err
	}

	if resp.EnrolmentStatus != grpcEdge.EnrolmentStatus_ENROLED {
		return fmt.Errorf("device %q not enroled: %s", deviceID, resp.EnrolmentStatus.String())
	}

	return nil
}

func (c *Client) Register(ctx context.Context, deviceID string, registerInfo entity.RegistrationInfo) (entity.RegistrationResponse, error) {
	if !bytes.Equal(c.certificateSignature, c.certManager.Signature()) {
		c.conn.Close()
		c.dial()
	}

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
		return entity.RegistrationResponse{}, err
	}

	return entity.RegistrationResponse{SignedCSR: []byte(resp.GetCertificate())}, nil
}

func (c *Client) Heartbeat(ctx context.Context, deviceID string, heartbeat entity.Heartbeat) error {
	if !bytes.Equal(c.certificateSignature, c.certManager.Signature()) {
		c.conn.Close()
		c.dial()
	}

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
			if strings.Contains(status.Message(), "authentication handshake failed") {
				return controller.ErrTlsHandshakeFailed
			}
		}
		return err
	}
	return nil
}

func (c *Client) GetConfiguration(ctx context.Context, deviceID string) (entity.DeviceConfigurationMessage, error) {
	if !bytes.Equal(c.certificateSignature, c.certManager.Signature()) {
		c.conn.Close()
		c.dial()
	}

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
		}
		return entity.DeviceConfigurationMessage{}, nil
	}
	return MapConfigurationResponse(conf), nil
}

func (c *Client) dial() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	tlsConfig, err := c.certManager.TLSConfig()
	if err != nil {
		return err
	}

	c.certificateSignature = c.certManager.Signature()

	tlsTransport := credentials.NewTLS(tlsConfig)

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(tlsTransport))
	conn, err := grpc.Dial(c.serverAddress, opts...)
	if err != nil {
		return err
	}
	c.conn = conn
	c.edgeClient = grpcEdge.NewEdgeServiceClient(conn)
	return nil
}

func (c *Client) addDeviceIdToContext(ctx context.Context, deviceID string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "device_id", deviceID)
}
