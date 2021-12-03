package auth_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	pb "github.com/autograde/quickfeed/ag"
	"github.com/autograde/quickfeed/web/auth"
	"github.com/golang-jwt/jwt"
)

const (
	secretKey  string = "test"
	testDomain string = "www.example.com"
)

func TestJWT(t *testing.T) {
	jwtTests := []struct {
		user    *pb.User
		alg     jwt.SigningMethod
		wantId  int
		wantErr error
	}{
		{
			user:    &pb.User{ID: 1},
			wantId:  1,
			wantErr: nil,
		},
		{
			user:    &pb.User{ID: 0},
			alg:     jwt.SigningMethodRS256,
			wantId:  0,
			wantErr: jwt.ErrInvalidKey,
		},
	}

	manager := auth.JWTManager{Secret: secretKey, Domain: testDomain}
	for _, test := range jwtTests {
		claims := manager.NewClaims(test.user)

		if claims.ID != test.wantId {
			t.Errorf("want %d, got %d", test.wantId, claims.ID)
		}

		token := manager.NewJWT(claims)
		if test.alg != nil {
			token.Method = test.alg
		}
		stringed, errString := manager.GetJWTString(token)

		if !errors.Is(errString, test.wantErr) {
			t.Errorf("want %v, got %v", test.wantErr, errString)
		}

		cookie, errCookie := manager.GetJWTCookie(token)

		if !errors.Is(errCookie, test.wantErr) {
			t.Errorf("want %v, got %v", test.wantErr, errCookie)
		}

		if cookie.Value != stringed {
			t.Error("Both cookie.Value and the JWT string should be identical")
		}
	}
}

func TestExpiredJWT(t *testing.T) {
	testCases := []struct {
		id      int
		expires int64
		wantErr error
	}{
		{
			id:      1,
			expires: time.Now().Unix(),
		},
		{
			id:      1,
			expires: time.Now().Add(-time.Hour * 1).Unix(),
		},
	}
	manager := auth.JWTManager{Secret: secretKey, Domain: testDomain}
	for _, test := range testCases {
		claims := auth.QuickFeedClaims{
			ID: test.id,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: test.expires,
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		if out, err := token.SignedString([]byte(secretKey)); err != nil {
			fmt.Println(out)
		} else {
			v, err := manager.ParseToken(out)
			t.Error(v, err)
		}
	}
}
