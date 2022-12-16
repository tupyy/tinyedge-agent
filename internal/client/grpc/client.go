package grpc

import (
	"context"
	"fmt"

	"github.com/tupyy/tinyedge-agent/internal/certificate"
	"github.com/tupyy/tinyedge-agent/internal/entity"
	grpcCommon "github.com/tupyy/tinyedge-controller/pkg/grpc/common"
	grpcEdge "github.com/tupyy/tinyedge-controller/pkg/grpc/edge"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	edgeClient  grpcEdge.EdgeServiceClient
	certManager *certificate.Manager
	conn        *grpc.ClientConn
}

func New(serverAddress string, certManager *certificate.Manager) (*Client, error) {
	if certManager == nil {
		return nil, fmt.Errorf("Certificate manager is missing")
	}

	// tlsConfig, err := certManager.TLSConfig()
	// if err != nil {
	// 	return nil, err
	// }
	// tlsTransport := credentials.NewTLS(tlsConfig)

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(serverAddress, opts...)
	if err != nil {
		return nil, err
	}
	client := grpcEdge.NewEdgeServiceClient(conn)

	return &Client{edgeClient: client, certManager: certManager}, nil
}

func (c *Client) Close(ctx context.Context) {
	c.conn.Close()
}

func (c *Client) Enrol(ctx context.Context, deviceID string, enrolInfo entity.EnrolementInfo) error {
	req := &grpcEdge.EnrolRequest{
		DeviceId: deviceID,
	}

	resp, err := c.edgeClient.Enrol(ctx, req)
	if err != nil {
		return err
	}

	if resp.EnrolmentStatus != grpcEdge.EnrolmentStatus_ENROLED {
		return fmt.Errorf("device %q not enroled: %s", deviceID, resp.EnrolmentStatus.String())
	}

	return nil
}

func (c *Client) Register(ctx context.Context, deviceID string, registerInfo entity.RegistrationInfo) (entity.RegistrationResponse, error) {
	req := &grpcEdge.RegistrationRequest{
		DeviceId:           deviceID,
		CertificateRequest: registerInfo.CertificateRequest,
	}

	_, err := c.edgeClient.Register(ctx, req)
	if err != nil {
		return entity.RegistrationResponse{}, err
	}

	return entity.RegistrationResponse{}, nil
}

func (c *Client) Heartbeat(ctx context.Context, deviceID string, heartbeat entity.Heartbeat) error {
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
		return err
	}
	return nil
}

func (c *Client) GetConfiguration(ctx context.Context, deviceID string) (entity.DeviceConfigurationMessage, error) {
	conf, err := c.edgeClient.GetConfiguration(ctx, &grpcEdge.ConfigurationRequest{DeviceId: deviceID})
	if err != nil {
		return entity.DeviceConfigurationMessage{}, nil
	}
	return MapConfigurationResponse(conf), nil
}
