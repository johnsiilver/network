// Code generated by protoc-gen-go.
// source: agent.proto
// DO NOT EDIT!

/*
Package agent is a generated protocol buffer package.

It is generated from these files:
	agent.proto

It has these top-level messages:
	RawIn
	RawOut
	CmdReq
	CmdResp
	PutReq
	PutResp
	GetReq
	GetResp
*/
package agent

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type CmdReq_CmdType int32

const (
	CmdReq_UNKNOWN CmdReq_CmdType = 0
	// Indicates that the request is for a read-only command. Many read-only
	// commands can occur at one time.
	CmdReq_READ CmdReq_CmdType = 1
	// Write indicates that the request will write to the device. Only one
	// write command or raw session can be done at a time.
	CmdReq_WRITE CmdReq_CmdType = 2
)

var CmdReq_CmdType_name = map[int32]string{
	0: "UNKNOWN",
	1: "READ",
	2: "WRITE",
}
var CmdReq_CmdType_value = map[string]int32{
	"UNKNOWN": 0,
	"READ":    1,
	"WRITE":   2,
}

func (x CmdReq_CmdType) String() string {
	return proto.EnumName(CmdReq_CmdType_name, int32(x))
}
func (CmdReq_CmdType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{2, 0} }

// RawIn is the raw input to send over an input channel.  It does not
// automatically add carriage returns or anything else.  It is a pure raw
// channel, handle accordingly.
type RawIn struct {
	// The device to stream to.  This must always be included on all requests in
	// and if it doesn't match the original name the stream will break.
	Device string `protobuf:"bytes,1,opt,name=device" json:"device,omitempty"`
	// User is the user to authenticate as.
	User string `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
	// The raw input to send the router.  Remember, this is raw input.
	Input string `protobuf:"bytes,3,opt,name=input" json:"input,omitempty"`
	// Close indicates to close the raw session.  Raw sessions are never reused
	// and a raw session also blocks any CmdReq that are WRITE.
	Close bool `protobuf:"varint,4,opt,name=close" json:"close,omitempty"`
}

func (m *RawIn) Reset()                    { *m = RawIn{} }
func (m *RawIn) String() string            { return proto.CompactTextString(m) }
func (*RawIn) ProtoMessage()               {}
func (*RawIn) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// RawOut is the raw output that the router sends.  Be careful, as if you want
// a device to send output that can be paged, you need to either suspend paging
// or be prepared to respond via RawIn.
type RawOut struct {
	// The raw output from the device on stdout.
	Stdout string `protobuf:"bytes,1,opt,name=stdout" json:"stdout,omitempty"`
	// The raw output from the device on stderr.
	Stderr string `protobuf:"bytes,2,opt,name=stderr" json:"stderr,omitempty"`
}

func (m *RawOut) Reset()                    { *m = RawOut{} }
func (m *RawOut) String() string            { return proto.CompactTextString(m) }
func (*RawOut) ProtoMessage()               {}
func (*RawOut) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

// CmdReq is used to send a single command over a session.
type CmdReq struct {
	// The device to connect to (not the IP address).
	Device string `protobuf:"bytes,1,opt,name=device" json:"device,omitempty"`
	// User is the user to authenticate as.
	User string `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
	// The command to send the device.
	Cmd string `protobuf:"bytes,3,opt,name=cmd" json:"cmd,omitempty"`
	// The type of command it is.  There can only be one WRITE Cmd at a time.
	// A RawIn request holds the WRITE session until it is closed.
	CmdType CmdReq_CmdType `protobuf:"varint,4,opt,name=cmd_type,json=cmdType,enum=CmdReq_CmdType" json:"cmd_type,omitempty"`
}

func (m *CmdReq) Reset()                    { *m = CmdReq{} }
func (m *CmdReq) String() string            { return proto.CompactTextString(m) }
func (*CmdReq) ProtoMessage()               {}
func (*CmdReq) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

// CmdResp is the output from the device from a CmdReq.
type CmdResp struct {
	// The output from the command issued.
	Output string `protobuf:"bytes,1,opt,name=output" json:"output,omitempty"`
}

func (m *CmdResp) Reset()                    { *m = CmdResp{} }
func (m *CmdResp) String() string            { return proto.CompactTextString(m) }
func (*CmdResp) ProtoMessage()               {}
func (*CmdResp) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

// PutReq puts a file on the device at location path.
type PutReq struct {
	// The device to put the file on.
	Device string `protobuf:"bytes,1,opt,name=device" json:"device,omitempty"`
	// User is the user to authenticate as.
	User string `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
	// The file to put on the device.
	File []byte `protobuf:"bytes,3,opt,name=file,proto3" json:"file,omitempty"`
	// The path to put the file at, including the file name.
	Path string `protobuf:"bytes,4,opt,name=path" json:"path,omitempty"`
}

func (m *PutReq) Reset()                    { *m = PutReq{} }
func (m *PutReq) String() string            { return proto.CompactTextString(m) }
func (*PutReq) ProtoMessage()               {}
func (*PutReq) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

// Reserved for future use.
type PutResp struct {
}

func (m *PutResp) Reset()                    { *m = PutResp{} }
func (m *PutResp) String() string            { return proto.CompactTextString(m) }
func (*PutResp) ProtoMessage()               {}
func (*PutResp) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

// Requests a file on the device at path.
type GetReq struct {
	// The device to get the file from.
	Device string `protobuf:"bytes,1,opt,name=device" json:"device,omitempty"`
	// User is the user to authenticate as.
	User string `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
	// The path to the file to retrieve.
	Path string `protobuf:"bytes,3,opt,name=path" json:"path,omitempty"`
}

func (m *GetReq) Reset()                    { *m = GetReq{} }
func (m *GetReq) String() string            { return proto.CompactTextString(m) }
func (*GetReq) ProtoMessage()               {}
func (*GetReq) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

// The file at path from GetReq.
type GetResp struct {
	// The contents of the file that was retrieved.
	File []byte `protobuf:"bytes,1,opt,name=file,proto3" json:"file,omitempty"`
}

func (m *GetResp) Reset()                    { *m = GetResp{} }
func (m *GetResp) String() string            { return proto.CompactTextString(m) }
func (*GetResp) ProtoMessage()               {}
func (*GetResp) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func init() {
	proto.RegisterType((*RawIn)(nil), "RawIn")
	proto.RegisterType((*RawOut)(nil), "RawOut")
	proto.RegisterType((*CmdReq)(nil), "CmdReq")
	proto.RegisterType((*CmdResp)(nil), "CmdResp")
	proto.RegisterType((*PutReq)(nil), "PutReq")
	proto.RegisterType((*PutResp)(nil), "PutResp")
	proto.RegisterType((*GetReq)(nil), "GetReq")
	proto.RegisterType((*GetResp)(nil), "GetResp")
	proto.RegisterEnum("CmdReq_CmdType", CmdReq_CmdType_name, CmdReq_CmdType_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion2

// Client API for AgentService service

type AgentServiceClient interface {
	// RawSession opens a raw session to the device. You receive input as the device
	// displays it
	RawSession(ctx context.Context, opts ...grpc.CallOption) (AgentService_RawSessionClient, error)
	// Run allows you to issue commands over a single session and get responses
	// to each command.  If you need interactivity (such as may be needed because
	// of interactive menus), use RawSession().
	Run(ctx context.Context, opts ...grpc.CallOption) (AgentService_RunClient, error)
	// Put puts a file onto a device.
	Put(ctx context.Context, in *PutReq, opts ...grpc.CallOption) (*PutResp, error)
	// Get gets a file from the device.
	Get(ctx context.Context, in *GetReq, opts ...grpc.CallOption) (*GetResp, error)
}

type agentServiceClient struct {
	cc *grpc.ClientConn
}

func NewAgentServiceClient(cc *grpc.ClientConn) AgentServiceClient {
	return &agentServiceClient{cc}
}

func (c *agentServiceClient) RawSession(ctx context.Context, opts ...grpc.CallOption) (AgentService_RawSessionClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_AgentService_serviceDesc.Streams[0], c.cc, "/AgentService/RawSession", opts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceRawSessionClient{stream}
	return x, nil
}

type AgentService_RawSessionClient interface {
	Send(*RawIn) error
	Recv() (*RawOut, error)
	grpc.ClientStream
}

type agentServiceRawSessionClient struct {
	grpc.ClientStream
}

func (x *agentServiceRawSessionClient) Send(m *RawIn) error {
	return x.ClientStream.SendMsg(m)
}

func (x *agentServiceRawSessionClient) Recv() (*RawOut, error) {
	m := new(RawOut)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentServiceClient) Run(ctx context.Context, opts ...grpc.CallOption) (AgentService_RunClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_AgentService_serviceDesc.Streams[1], c.cc, "/AgentService/Run", opts...)
	if err != nil {
		return nil, err
	}
	x := &agentServiceRunClient{stream}
	return x, nil
}

type AgentService_RunClient interface {
	Send(*CmdReq) error
	Recv() (*CmdResp, error)
	grpc.ClientStream
}

type agentServiceRunClient struct {
	grpc.ClientStream
}

func (x *agentServiceRunClient) Send(m *CmdReq) error {
	return x.ClientStream.SendMsg(m)
}

func (x *agentServiceRunClient) Recv() (*CmdResp, error) {
	m := new(CmdResp)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentServiceClient) Put(ctx context.Context, in *PutReq, opts ...grpc.CallOption) (*PutResp, error) {
	out := new(PutResp)
	err := grpc.Invoke(ctx, "/AgentService/Put", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentServiceClient) Get(ctx context.Context, in *GetReq, opts ...grpc.CallOption) (*GetResp, error) {
	out := new(GetResp)
	err := grpc.Invoke(ctx, "/AgentService/Get", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for AgentService service

type AgentServiceServer interface {
	// RawSession opens a raw session to the device. You receive input as the device
	// displays it
	RawSession(AgentService_RawSessionServer) error
	// Run allows you to issue commands over a single session and get responses
	// to each command.  If you need interactivity (such as may be needed because
	// of interactive menus), use RawSession().
	Run(AgentService_RunServer) error
	// Put puts a file onto a device.
	Put(context.Context, *PutReq) (*PutResp, error)
	// Get gets a file from the device.
	Get(context.Context, *GetReq) (*GetResp, error)
}

func RegisterAgentServiceServer(s *grpc.Server, srv AgentServiceServer) {
	s.RegisterService(&_AgentService_serviceDesc, srv)
}

func _AgentService_RawSession_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AgentServiceServer).RawSession(&agentServiceRawSessionServer{stream})
}

type AgentService_RawSessionServer interface {
	Send(*RawOut) error
	Recv() (*RawIn, error)
	grpc.ServerStream
}

type agentServiceRawSessionServer struct {
	grpc.ServerStream
}

func (x *agentServiceRawSessionServer) Send(m *RawOut) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceRawSessionServer) Recv() (*RawIn, error) {
	m := new(RawIn)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AgentService_Run_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AgentServiceServer).Run(&agentServiceRunServer{stream})
}

type AgentService_RunServer interface {
	Send(*CmdResp) error
	Recv() (*CmdReq, error)
	grpc.ServerStream
}

type agentServiceRunServer struct {
	grpc.ServerStream
}

func (x *agentServiceRunServer) Send(m *CmdResp) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceRunServer) Recv() (*CmdReq, error) {
	m := new(CmdReq)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _AgentService_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PutReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServiceServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/AgentService/Put",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentServiceServer).Put(ctx, req.(*PutReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/AgentService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentServiceServer).Get(ctx, req.(*GetReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _AgentService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "AgentService",
	HandlerType: (*AgentServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Put",
			Handler:    _AgentService_Put_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _AgentService_Get_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RawSession",
			Handler:       _AgentService_RawSession_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "Run",
			Handler:       _AgentService_Run_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

var fileDescriptor0 = []byte{
	// 378 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x9c, 0x52, 0x4d, 0x4b, 0xc3, 0x40,
	0x10, 0x75, 0x9b, 0x36, 0x49, 0xa7, 0x45, 0xc3, 0x22, 0x12, 0x8a, 0x82, 0xdd, 0x53, 0x51, 0x08,
	0x52, 0x2f, 0x5e, 0x8b, 0x16, 0x2d, 0x42, 0x2b, 0xdb, 0x4a, 0x2f, 0x42, 0xa9, 0xc9, 0xaa, 0x81,
	0x36, 0x89, 0xf9, 0x50, 0x3c, 0xfb, 0x43, 0xfc, 0xab, 0xce, 0x7e, 0x94, 0x7a, 0xad, 0xa7, 0xcc,
	0xbc, 0xb7, 0x79, 0xf3, 0xde, 0xee, 0x40, 0x6b, 0xf9, 0x2a, 0x92, 0x32, 0xc8, 0xf2, 0xb4, 0x4c,
	0xd9, 0x02, 0x1a, 0x7c, 0xf9, 0x39, 0x4a, 0xe8, 0x11, 0xd8, 0x91, 0xf8, 0x88, 0x43, 0xe1, 0x93,
	0x53, 0xd2, 0x6b, 0x72, 0xd3, 0x51, 0x0a, 0xf5, 0xaa, 0x10, 0xb9, 0x5f, 0x53, 0xa8, 0xaa, 0xe9,
	0x21, 0x34, 0xe2, 0x24, 0xab, 0x4a, 0xdf, 0x52, 0xa0, 0x6e, 0x24, 0x1a, 0xae, 0xd2, 0x42, 0xf8,
	0x75, 0x44, 0x5d, 0xae, 0x1b, 0x76, 0x05, 0x36, 0x0e, 0x98, 0x20, 0x8f, 0x13, 0x8a, 0x32, 0x4a,
	0xf1, 0x37, 0x33, 0x41, 0x77, 0x06, 0x17, 0xf9, 0x66, 0x86, 0xe9, 0xd8, 0x0f, 0x01, 0xfb, 0x7a,
	0x1d, 0x71, 0xf1, 0xbe, 0x93, 0x39, 0x0f, 0xac, 0x70, 0x1d, 0x19, 0x6b, 0xb2, 0xa4, 0x67, 0xe0,
	0xe2, 0x67, 0x51, 0x7e, 0x65, 0xda, 0xdb, 0x7e, 0xff, 0x20, 0xd0, 0xc2, 0xf2, 0x33, 0x43, 0x98,
	0x3b, 0xa1, 0x2e, 0xd8, 0x39, 0x38, 0x06, 0xa3, 0x2d, 0x70, 0x1e, 0xc7, 0xf7, 0xe3, 0xc9, 0x7c,
	0xec, 0xed, 0x51, 0x17, 0xea, 0x7c, 0x38, 0xb8, 0xf1, 0x08, 0x6d, 0x42, 0x63, 0xce, 0x47, 0xb3,
	0xa1, 0x57, 0x63, 0x5d, 0x75, 0x98, 0x8b, 0x22, 0x93, 0x0e, 0x31, 0x4b, 0xb6, 0x0d, 0xa7, 0x3b,
	0xf6, 0x04, 0xf6, 0x43, 0x55, 0xee, 0x9a, 0x01, 0xb1, 0x97, 0x78, 0x25, 0x54, 0x88, 0x36, 0x57,
	0xb5, 0xc4, 0xb2, 0x65, 0xf9, 0xa6, 0x12, 0xe0, 0x39, 0x59, 0xb3, 0x26, 0x38, 0x4a, 0xbd, 0xc8,
	0xd8, 0x1d, 0xd8, 0xb7, 0xe2, 0x3f, 0x83, 0x94, 0xa8, 0xf5, 0x47, 0xf4, 0x04, 0x1c, 0xa5, 0x84,
	0xa9, 0x36, 0x3e, 0xc8, 0xd6, 0x47, 0xff, 0x9b, 0x40, 0x7b, 0x20, 0x37, 0x68, 0x2a, 0x72, 0xa5,
	0xdb, 0x05, 0xc0, 0x17, 0x9e, 0x8a, 0xa2, 0x88, 0xd3, 0x84, 0xda, 0x81, 0xda, 0xa7, 0x8e, 0x13,
	0xe8, 0x67, 0xef, 0x91, 0x0b, 0x42, 0x8f, 0xc1, 0xe2, 0x55, 0x42, 0x1d, 0x73, 0xed, 0x1d, 0x37,
	0x30, 0xf7, 0xa6, 0x58, 0x1f, 0x2c, 0x4c, 0x81, 0xac, 0xbe, 0x29, 0x64, 0x4d, 0x28, 0xc9, 0xa0,
	0x15, 0x64, 0x74, 0x34, 0x64, 0x8c, 0xb3, 0x67, 0x5b, 0xad, 0xef, 0xe5, 0x6f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x71, 0x47, 0x33, 0xde, 0xcd, 0x02, 0x00, 0x00,
}
