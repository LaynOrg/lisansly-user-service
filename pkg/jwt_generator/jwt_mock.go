// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/jwt_generator/jwt.go

// Package jwt_generator is a generated GoMock package.
package jwt_generator

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
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

// GenerateToken mocks base method.
func (m *MockJwtGenerator) GenerateToken(expirationTime time.Time, email, userId string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateToken", expirationTime, email, userId)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateToken indicates an expected call of GenerateToken.
func (mr *MockJwtGeneratorMockRecorder) GenerateToken(expirationTime, email, userId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateToken", reflect.TypeOf((*MockJwtGenerator)(nil).GenerateToken), expirationTime, email, userId)
}