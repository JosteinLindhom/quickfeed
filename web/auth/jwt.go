package auth

import (
	"fmt"
	"net/http"
	"os"
	"time"

	pb "github.com/autograde/quickfeed/ag"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

const (
	JWTCookieName = "auth"
)

type JWTManager struct {
	Secret string
	Domain string
}

type QuickFeedClaims struct {
	ID    int  `json:"id"`
	Admin bool `json:"admin"`
	jwt.StandardClaims
}

func NewJWTManager() *JWTManager {
	return &JWTManager{
		Secret: os.Getenv("JWT_SECRET"),
		Domain: os.Getenv("DOMAIN"),
	}
}

func (j JWTManager) NewClaims(user *pb.User) *QuickFeedClaims {
	return &QuickFeedClaims{
		ID:    int(user.ID),
		Admin: user.IsAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 244).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
}

func (j JWTManager) NewJWT(claims jwt.Claims) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}

func (j JWTManager) setJWTCookie(token *jwt.Token, context echo.Context) error {
	if tokenString, err := token.SignedString([]byte(j.Secret)); err != nil {
		return err
	} else {
		context.SetCookie(&http.Cookie{
			Name:     JWTCookieName,
			Value:    tokenString,
			Domain:   j.Domain,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * 244),
		})
	}
	return nil
}

func (j JWTManager) GenAndSetJWTCookie(user *pb.User, context echo.Context, request bool) error {
	claims := j.NewClaims(user)
	token := j.NewJWT(claims)
	/*err := j.setJWTCookie(token, context)
	if err != nil {
		return err
	}*/
	if request {
		cookie, err := j.GetJWTCookie(token)
		if err != nil {
			return err
		}
		fmt.Println("Cok", cookie)
		context.Request().AddCookie(cookie)
	}
	return nil
}

func (j JWTManager) GetJWTCookie(token *jwt.Token) (*http.Cookie, error) {
	if tokenString, err := token.SignedString([]byte(j.Secret)); err != nil {
		return &http.Cookie{}, err
	} else {
		return &http.Cookie{
			Name:     JWTCookieName,
			Value:    tokenString,
			Domain:   j.Domain,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * 244),
		}, nil
	}
}

// GetJWTString returns a complete, signed token string
func (j JWTManager) GetJWTString(token *jwt.Token) (string, error) {
	if tokenString, err := token.SignedString([]byte(j.Secret)); err != nil {
		return "", err
	} else {
		return tokenString, nil
	}
}

// ParseToken parses a token string and returns the claims, or an error if the token string is invalid.
func (j JWTManager) ParseToken(token string) (*QuickFeedClaims, error) {
	tok, err := jwt.ParseWithClaims(token, &QuickFeedClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error")
		}
		return []byte(j.Secret), nil
	})
	if err != nil {
		fmt.Println(err)
		return &QuickFeedClaims{}, err
	}

	if claims, ok := tok.Claims.(*QuickFeedClaims); ok && tok.Valid {
		return claims, nil
	} else {
		fmt.Println(err)
		return &QuickFeedClaims{}, err
	}
}
