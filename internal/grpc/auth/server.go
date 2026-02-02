package auth

import (
	"context"

	ssov1 "github.com/alex-muller/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
)

type serverApi struct {
	ssov1.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) {
	ssov1.RegisterAuthServer(gRPC, &serverApi{})
}

func (a serverApi) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	return &ssov1.LoginResponse{
		Token: req.GetEmail(),
	}, nil
}

func (a serverApi) Register(
	ctx context.Context,
	request *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (a serverApi) IsAdmin(
	ctx context.Context,
	request *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	//TODO implement me
	panic("implement me")
}
