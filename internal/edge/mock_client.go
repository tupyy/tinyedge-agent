// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/tupyy/tinyedge-agent/internal/edge (interfaces: Client)

// Package edge is a generated GoMock package.
package edge

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	entity "github.com/tupyy/tinyedge-agent/internal/entity"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// Enrol mocks base method.
func (m *MockClient) Enrol(arg0 context.Context, arg1 string, arg2 entity.EnrolementInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Enrol", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Enrol indicates an expected call of Enrol.
func (mr *MockClientMockRecorder) Enrol(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Enrol", reflect.TypeOf((*MockClient)(nil).Enrol), arg0, arg1, arg2)
}

// GetConfiguration mocks base method.
func (m *MockClient) GetConfiguration(arg0 context.Context, arg1 string) (entity.DeviceConfigurationMessage, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConfiguration", arg0, arg1)
	ret0, _ := ret[0].(entity.DeviceConfigurationMessage)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConfiguration indicates an expected call of GetConfiguration.
func (mr *MockClientMockRecorder) GetConfiguration(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConfiguration", reflect.TypeOf((*MockClient)(nil).GetConfiguration), arg0, arg1)
}

// Heartbeat mocks base method.
func (m *MockClient) Heartbeat(arg0 context.Context, arg1 string, arg2 entity.Heartbeat) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Heartbeat", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Heartbeat indicates an expected call of Heartbeat.
func (mr *MockClientMockRecorder) Heartbeat(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Heartbeat", reflect.TypeOf((*MockClient)(nil).Heartbeat), arg0, arg1, arg2)
}

// Register mocks base method.
func (m *MockClient) Register(arg0 context.Context, arg1 string, arg2 entity.RegistrationInfo) (entity.RegistrationResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", arg0, arg1, arg2)
	ret0, _ := ret[0].(entity.RegistrationResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Register indicates an expected call of Register.
func (mr *MockClientMockRecorder) Register(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockClient)(nil).Register), arg0, arg1, arg2)
}
