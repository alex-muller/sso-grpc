package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sso/internal/lib/logger/sl"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// New creates new Auth instance.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		log:          log,
		tokenTTL:     tokenTTL,
	}
}

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

// Login authenticates a user by verifying their email and password and generates an access token for the specified app.
//
// If the user does not exist or the password is incorrect, an error is returned.
func (a Auth) Login(ctx context.Context, email, password string, appId int) (token string, err error) {
	//TODO implement me
	panic("implement me")
}

// RegisterNewUser creates a new user account.
//
// If the email is already in use, an error is returned.
func (a Auth) RegisterNewUser(ctx context.Context, email, password string) (userID int64, err error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("bcrypt generate failed", sl.Err(err))
		return 0, fmt.Errorf(`bcrypt generate: %w`, err)
	}

	uid, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("save user failed", sl.Err(err))
		return 0, fmt.Errorf(`save user: %w`, err)
	}

	return uid, nil
}

// IsAdmin determines if the user with the given userID possesses administrative privileges.
//
// If the user does not exist, an error is returned.
func (a Auth) IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error) {
	//TODO implement me
	panic("implement me")
}
