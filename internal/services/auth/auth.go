package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user exists")
	ErrInvalidAppId       = errors.New("invalid app id")
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
	const op = "auth.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("attempting to login user")
	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return "", ErrInvalidCredentials
		}

		log.Error("user find failed", sl.Err(err))
		return "", fmt.Errorf(`user find: %w`, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))
		return "", fmt.Errorf(`%s: %w`, op, err)
	}

	app, err := a.appProvider.App(ctx, appId)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return "", ErrInvalidAppId
		}
		return "", fmt.Errorf(`%s: %w`, op, err)
	}

	log.Info("user logged in")

	token, err = jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("token creation failed", sl.Err(err))
		return "", fmt.Errorf(`%s: %w`, op, err)
	}

	return token, nil
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
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))
			return 0, ErrUserExists
		}

		log.Error("save user failed", sl.Err(err))
		return 0, fmt.Errorf(`save user: %w`, err)
	}

	return uid, nil
}

// IsAdmin determines if the user with the given userID possesses administrative privileges.
//
// If the user does not exist, an error is returned.
func (a Auth) IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error) {
	const op = "auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	isAdmin, err = a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf(`%s: %w`, op, err)
		}

		log.Error("check admin failed", sl.Err(err))
		return false, fmt.Errorf(`check admin: %w`, err)
	}
	return isAdmin, nil
}
