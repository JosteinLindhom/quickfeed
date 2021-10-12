package auth

import (
	"fmt"
	"net/http"
	"time"

	pb "github.com/autograde/quickfeed/ag"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

const (
	JWTCookieName = "auth"
)

type QuickFeedClaims struct {
	ID    int  `json:"id"`
	Admin bool `json:"admin"`
	jwt.StandardClaims
}

func NewClaims(user *pb.User) *QuickFeedClaims {
	return &QuickFeedClaims{
		ID:    int(user.ID),
		Admin: user.IsAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 244).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
}

func NewJWT(claims jwt.Claims) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}

func SetJWTCookie(token *jwt.Token, context echo.Context) error {
	if tokenString, err := token.SignedString([]byte("supertesthexalegagon")); err != nil {
		return err
	} else {
		context.SetCookie(&http.Cookie{
			Name:     JWTCookieName,
			Value:    tokenString,
			Domain:   "www.xini.no",
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * 244),
		})
	}
	return nil
}

func GetJWTCookie(token *jwt.Token) (http.Cookie, error) {
	if tokenString, err := token.SignedString([]byte("supertesthexalegagon")); err != nil {
		return http.Cookie{}, err
	} else {
		return http.Cookie{
			Name:     JWTCookieName,
			Value:    tokenString,
			Domain:   "www.xini.no",
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * 244),
		}, nil
	}
}

// GetJWTString returns a complete, signed token string
func GetJWTString(token *jwt.Token) (string, error) {
	if tokenString, err := token.SignedString([]byte("supertesthexalegagon")); err != nil {
		return "", err
	} else {
		return tokenString, nil
	}
}

// ParseToken parses a token string and returns the claims, or an error if the token string is invalid.
func ParseToken(token string) (*QuickFeedClaims, error) {
	tok, err := jwt.ParseWithClaims(token, &QuickFeedClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error")
		}
		return []byte("supertesthexalegagon"), nil
	})
	if err != nil {
		return &QuickFeedClaims{}, err
	}

	if claims, ok := tok.Claims.(*QuickFeedClaims); ok && tok.Valid {
		return claims, nil
	} else {
		fmt.Println(claims)
		return &QuickFeedClaims{}, err
	}
}
