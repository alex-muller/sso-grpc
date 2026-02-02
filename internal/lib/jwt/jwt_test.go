package jwt

import (
	"sso/internal/domain/models"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJwt(t *testing.T) {
	user := models.User{
		ID:       1,
		Email:    "asd@dsa.com",
		PassHash: []byte("pass"),
	}

	app := models.App{
		ID:     321,
		Name:   "App Name",
		Secret: "secret",
	}

	token, err := NewToken(user, app, time.Hour)
	assert.Empty(t, err)
	assert.NotEmpty(t, token)
}
