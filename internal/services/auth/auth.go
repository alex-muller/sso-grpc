package auth

import (
	"context"
)

type Auth struct{}

func (a Auth) Login(ctx context.Context, email, password string, appId int) (token string, err error) {
	//TODO implement me
	panic("implement me")
}

func (a Auth) RegisterNewUser(ctx context.Context, email, password string) (userID int64, err error) {
	//TODO implement me
	panic("implement me")
}

func (a Auth) IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error) {
	//TODO implement me
	panic("implement me")
}
