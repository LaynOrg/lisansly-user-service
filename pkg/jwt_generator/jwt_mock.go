// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/jwt_generator/jwt.go
//
// Generated by this command:
//
//	mockgen --source=pkg/jwt_generator/jwt.go --destination=pkg/jwt_generator/jwt_mock.go --package=jwt_generator
//
// Package jwt_generator is a generated GoMock package.
package jwt_generator

import (
	reflect "reflect"
	time "time"

	gomock "go.uber.org/mock/gomock"
)

// MockJwtGenerator is a mock of JwtGenerator interface.
type MockJwtGenerator struct {
	ctrl     *gomock.Controller
	recorder *MockJwtGeneratorMockRecorder
}

// MockJwtGeneratorMockRecorder is the mock recorder for MockJwtGenerator.
type MockJwtGeneratorMockRecorder struct {
	mock *MockJwtGenerator
}

// NewMockJwtGenerator creates a new mock instance.
func NewMockJwtGenerator(ctrl *gomock.Controller) *MockJwtGenerator {
	mock := &MockJwtGenerator{ctrl: ctrl}
	mock.recorder = &MockJwtGeneratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockJwtGenerator) EXPECT() *MockJwtGeneratorMockRecorder {
	return m.recorder
}

// GenerateAccessToken mocks base method.
func (m *MockJwtGenerator) GenerateAccessToken(expirationTime time.Duration, name, email, userId string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateAccessToken", expirationTime, name, email, userId)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateAccessToken indicates an expected call of GenerateAccessToken.
func (mr *MockJwtGeneratorMockRecorder) GenerateAccessToken(expirationTime, name, email, userId any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateAccessToken", reflect.TypeOf((*MockJwtGenerator)(nil).GenerateAccessToken), expirationTime, name, email, userId)
}

// GenerateRefreshToken mocks base method.
func (m *MockJwtGenerator) GenerateRefreshToken(expirationTime time.Duration, userId string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateRefreshToken", expirationTime, userId)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateRefreshToken indicates an expected call of GenerateRefreshToken.
func (mr *MockJwtGeneratorMockRecorder) GenerateRefreshToken(expirationTime, userId any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateRefreshToken", reflect.TypeOf((*MockJwtGenerator)(nil).GenerateRefreshToken), expirationTime, userId)
}

// VerifyAccessToken mocks base method.
func (m *MockJwtGenerator) VerifyAccessToken(rawJwtToken string) (*Claims, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyAccessToken", rawJwtToken)
	ret0, _ := ret[0].(*Claims)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyAccessToken indicates an expected call of VerifyAccessToken.
func (mr *MockJwtGeneratorMockRecorder) VerifyAccessToken(rawJwtToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyAccessToken", reflect.TypeOf((*MockJwtGenerator)(nil).VerifyAccessToken), rawJwtToken)
}

// VerifyRefreshToken mocks base method.
func (m *MockJwtGenerator) VerifyRefreshToken(rawJwtToken string) (*Claims, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyRefreshToken", rawJwtToken)
	ret0, _ := ret[0].(*Claims)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyRefreshToken indicates an expected call of VerifyRefreshToken.
func (mr *MockJwtGeneratorMockRecorder) VerifyRefreshToken(rawJwtToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyRefreshToken", reflect.TypeOf((*MockJwtGenerator)(nil).VerifyRefreshToken), rawJwtToken)
}
