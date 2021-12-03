package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	pb "github.com/autograde/quickfeed/ag"
	"github.com/autograde/quickfeed/database"
	lg "github.com/autograde/quickfeed/log"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth/gothic"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// Session keys.
const (
	SessionKey     = "session"
	UserKey        = "user"
	Cookie         = "cookie"
	OutgoingCookie = "Set-Cookie"
)

// Query keys.
const (
	State    = "state" // As defined by the OAuth2 RFC.
	Redirect = "redirect"
)

var manager *JWTManager = NewJWTManager()

// OAuth2Logout invalidates the session for the logged in user.
func OAuth2Logout(logger *zap.SugaredLogger) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		if token, err := c.Cookie(JWTCookieName); err != nil {
			// Error if user has no auth token
		} else {
			token.Domain = manager.Domain
			token.Path = "/"
			token.Expires = time.Now()
			token.MaxAge = -1
			c.SetCookie(token)
		}
		return c.Redirect(http.StatusFound, extractRedirectURL(r, Redirect))
	}
}

// PreAuth checks the current user session and executes the next handler if none
// was found for the given provider.
func PreAuth(logger *zap.SugaredLogger, db database.Database) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie(JWTCookieName)
			if err != nil {
				logger.Error(err.Error())
				return next(c)
			}

			if claims, err := manager.ParseToken(cookie.Value); err == nil && claims.ID > 0 {
				if user, err := db.GetUser(uint64(claims.ID)); err != nil {
					logger.Error(err.Error())
					return OAuth2Logout(logger)(c)
				} else {
					logger.Debugf("User: %v", user)
				}
			} else {
				logger.Error(err.Error())
				return OAuth2Logout(logger)(c)
			}
			return next(c)
		}
	}
}

func sessionData(session *sessions.Session) string {
	if session == nil {
		return "<nil>"
	}
	out := "Values: "
	for k, v := range session.Values {
		out += fmt.Sprintf("<%s: %v>, ", k, v)
	}
	out += "Options: "
	out += fmt.Sprintf("<%s: %v>, ", "MaxAge", session.Options.MaxAge)
	out += fmt.Sprintf("<%s: %v>, ", "Path", session.Options.Path)
	out += fmt.Sprintf("<%s: %v>, ", "Domain", session.Options.Domain)
	out += fmt.Sprintf("<%s: %v>, ", "Secure", session.Options.Secure)
	out += fmt.Sprintf("<%s: %v>, ", "HttpOnly", session.Options.HttpOnly)
	out += fmt.Sprintf("<%s: %v>, ", "SameSite", session.Options.SameSite)

	return fmt.Sprintf("Session: ID=%s, IsNew=%t, %s", session.ID, session.IsNew, out)
}

// OAuth2Login tries to authenticate against an oauth2 provider.
func OAuth2Login(logger *zap.SugaredLogger, db database.Database) echo.HandlerFunc {
	return func(c echo.Context) error {
		w := c.Response()
		r := c.Request()

		provider, err := gothic.GetProviderName(r)
		if err != nil {
			logger.Error(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		var teacher int
		if strings.HasSuffix(provider, TeacherSuffix) {
			teacher = 1
		}
		logger.Debugf("Provider: %v ; Teacher: %v", provider, teacher)

		qv := r.URL.Query()
		logger.Debugf("qv: %v", qv)
		redirect := extractRedirectURL(r, Redirect)
		logger.Debugf("redirect: %v", redirect)
		// TODO: Add a random string to protect against CSRF.
		qv.Set(State, strconv.Itoa(teacher)+redirect)
		logger.Debugf("State: %v", strconv.Itoa(teacher)+redirect)
		r.URL.RawQuery = qv.Encode()
		logger.Debugf("RawQuery: %v", r.URL.RawQuery)

		url, err := gothic.GetAuthURL(w, r)
		if err != nil {
			logger.Error(err.Error())
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		logger.Debugf("Redirecting to %s to perform authentication; AuthURL: %v", provider, url)
		return c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

// OAuth2Callback handles the callback from an oauth2 provider.
func OAuth2Callback(logger *zap.SugaredLogger, db database.Database, scms *Scms) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger.Debug("OAuth2Callback: started")
		w := c.Response()
		r := c.Request()

		qv := r.URL.Query()
		logger.Debugf("qv: %v", qv)
		redirect, teacher := extractState(r, State)
		logger.Debugf("Redirect: %v ; Teacher: %t", redirect, teacher)

		provider, err := gothic.GetProviderName(r)
		if err != nil {
			logger.Error("failed to get gothic provider", zap.Error(err))
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		// Add teacher suffix if upgrading scope.
		if teacher {
			qv.Set("provider", provider+TeacherSuffix)
			logger.Debugf("Set('provider') = %v", provider+TeacherSuffix)
		}
		r.URL.RawQuery = qv.Encode()
		logger.Debugf("RawQuery: %v", r.URL.RawQuery)

		// Complete authentication.
		externalUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			logger.Error("failed to complete user authentication", zap.Error(err))
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		logger.Debugf("externalUser: %v", lg.IndentJson(externalUser))

		remoteID, err := strconv.ParseUint(externalUser.UserID, 10, 64)
		if err != nil {
			logger.Error(err.Error())
			return err
		}
		logger.Debugf("remoteID: %v", remoteID)

		// Try to get already logged in user
		if cookie, err := r.Cookie(JWTCookieName); err != nil {
			//
		} else {
			// Parse JWT
			claims, err := manager.ParseToken(cookie.Value)

			// Log user out if invalid claims found
			if err != nil || claims.ID <= 0 {
				logger.Debug("failed to get logged in user from session; logout")
				return OAuth2Logout(logger)(c)
			}

			if err := db.AssociateUserWithRemoteIdentity(
				uint64(claims.ID), provider, remoteID, externalUser.AccessToken,
			); err != nil {
				logger.Debugf("Associate failed: %d, %s, %d, %s", claims.ID, provider, remoteID, externalUser.AccessToken)
				logger.Error("failed to associate user with remote identity", zap.Error(err))
				return err
			}
			logger.Debugf("Associate: %d, %s, %d, %s", claims.ID, provider, remoteID, externalUser.AccessToken)
			if user, err := db.GetUser(uint64(claims.ID)); err != nil {
				logger.Errorf("Failed to get user: %v", err)
			} else {
				if ok := updateScm(c, logger, scms, user); !ok {
					logger.Debugf("Failed to update SCM for User: %v", user)
				}
			}
			logger.Debugf("Redirecting: %s", redirect)
			return c.Redirect(http.StatusFound, redirect)
		}
		//logger.Debugf("%s", sessionData(sess))

		remote := &pb.RemoteIdentity{
			Provider:    provider,
			RemoteID:    remoteID,
			AccessToken: externalUser.AccessToken,
		}
		// Try to get user from database.
		user, err := db.GetUserByRemoteIdentity(remote)
		switch {
		case err == nil:
			logger.Debugf("found user: %v", user)
			// found user in database; update access token
			err = db.UpdateAccessToken(remote)
			if err != nil {
				logger.Error("failed to update access token for user", zap.Error(err), zap.String("user", user.String()))
				return err
			}
			logger.Debugf("access token updated: %v", remote)

		case err == gorm.ErrRecordNotFound:
			logger.Debug("user not found in database; creating new user")
			// user not in database; create new user
			user = &pb.User{
				Name:      externalUser.Name,
				Email:     externalUser.Email,
				AvatarURL: externalUser.AvatarURL,
				Login:     externalUser.NickName,
			}
			err = db.CreateUserFromRemoteIdentity(user, remote)
			if err != nil {
				logger.Error("failed to create remote identify for user", zap.Error(err), zap.String("user", user.String()))
				return err
			}
			logger.Debugf("New user created: %v, remote: %v", user, remote)

		default:
			logger.Error("failed to fetch user for remote identity", zap.Error(err))
		}

		// in case this is a new user we need a user object with full information,
		// otherwise frontend will get user object where only name, email and url are set.
		user, err = db.GetUserByRemoteIdentity(remote)
		if err != nil {
			logger.Error(err.Error())
			return err
		}
		logger.Debugf("Fetching full user info for %v, user: %v", remote, user)

		// Create user claims
		claims := manager.NewClaims(user)

		logger.Debugf("New claims: %s", claims)
		// Generate JWT with claims
		token := manager.NewJWT(claims)
		// Set JWT cookie in context
		if err := manager.setJWTCookie(token, c); err != nil {
			logger.Debugf("Failed to set JWT cookie to context: ", zap.Error(err))
		}
		logger.Debug(c.Cookies())
		if ok := updateScm(c, logger, scms, user); !ok {
			logger.Debugf("Failed to update SCM for User: %v", user)
		}
		logger.Debugf("Redirecting: %s", redirect)
		return c.Redirect(http.StatusFound, redirect)
	}
}

// AccessControl returns an access control middleware. Given a valid context
// with sufficient access the next handler is called. Missing or invalid
// credentials results in a 401 unauthorized response.
func AccessControl(logger *zap.SugaredLogger, db database.Database, scms *Scms) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			/*sess, err := session.Get(SessionKey, c)
			if err != nil {
				logger.Error(err.Error())
				// Save fixes the session if it has been modified
				// or it is no longer valid due to newUserSess change of keys.
				if err := sess.Save(c.Request(), c.Response()); err != nil {
					logger.Error(err.Error())
					return err
				}
				return next(c)
			}
			logger.Debug(sessionData(sess))

			i, ok := sess.Values[UserKey]
			if !ok {
				return next(c)
			}

			// If type assertion fails, the recover middleware will catch the panic and log a stack trace.
			us := i.(*UserSession)
			logger.Debug(us)
			user, err := db.GetUser(us.ID)
			if err != nil {
				logger.Error(err.Error())
				// Invalidate session. This could happen if the user has been entirely remove
				// from the database, but a valid session still exists.
				if err == gorm.ErrRecordNotFound {
					logger.Error(err.Error())
					return OAuth2Logout(logger)(c)
				}
				logger.Error(echo.ErrUnauthorized.Error())
				return next(c)
			}
			c.Set(UserKey, user)
			*/
			// TODO: Add access control list.
			// - Extract endpoint.
			// - Verify whether the user has sufficient rights. This
			//   can be a simple hash map. A user should be able to
			//   access /users/:uid if the user's id is uid.
			//   - Not authorized: return c.NoContent(http.StatusUnauthorized)
			//   - Authorized: return next(c)
			return next(c)
		}
	}
}

func updateScm(ctx echo.Context, logger *zap.SugaredLogger, scms *Scms, user *pb.User) bool {
	foundSCMProvider := false
	for _, remoteID := range user.RemoteIdentities {
		scm, err := scms.GetOrCreateSCMEntry(logger.Desugar(), remoteID.GetProvider(), remoteID.GetAccessToken())
		if err != nil {
			logger.Errorf("Unknown SCM provider: %v", err)
			continue
		}
		foundSCMProvider = true
		ctx.Set(remoteID.Provider, scm)
	}
	if !foundSCMProvider {
		logger.Debugf("No SCM provider found for user %v", user)
	}
	return foundSCMProvider
}

func extractRedirectURL(r *http.Request, key string) string {
	// TODO: Validate redirect URL.

	url := r.URL.Query().Get(key)
	if url == "" {
		url = "/"
	}
	return url
}

func extractState(r *http.Request, key string) (redirect string, teacher bool) {
	// TODO: Validate redirect URL.
	url := r.URL.Query().Get(key)
	teacher = url != "" && url[:1] == "1"

	if url == "" || url[1:] == "" {
		return "/", teacher
	}
	return url[1:], teacher
}

func extractSessionCookie(w *echo.Response) string {
	// Helper function that extracts an outgoing session cookie.
	outgoingCookies := w.Header().Values(OutgoingCookie)
	for _, cookie := range outgoingCookies {
		if c := strings.Split(cookie, "="); c[0] == SessionKey {
			token := strings.Split(cookie, ";")[0]
			return token
		}
	}
	return ""
}

var (
	ErrInvalidSessionCookie = status.Errorf(codes.Unauthenticated, "Request does not contain a valid session cookie.")
	ErrContextMetadata      = status.Errorf(codes.Unauthenticated, "Could not obtain metadata from context")
)

func UserVerifier() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		meta, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, ErrContextMetadata
		}
		newMeta, err := userValidation(meta)
		if err != nil {
			return nil, err
		}
		// create new context with user id instead of cookie for use internally
		newCtx := metadata.NewIncomingContext(ctx, newMeta)
		resp, err := handler(newCtx, req)
		return resp, err
	}
}

// userValidation returns modified metadata containing a valid user.
// An error is returned if the user is not authenticated.
func userValidation(meta metadata.MD) (metadata.MD, error) {
	claims := &QuickFeedClaims{}
	for _, cookie := range meta.Get(Cookie) {
		c := strings.Fields(cookie)
		for _, token := range c {
			if strings.Contains(token, "auth") {
				jwtToken := strings.Split(token, "=")[1]
				fmt.Println("Split: ", jwtToken, manager.Secret)
				if tk, err := manager.ParseToken(jwtToken); err != nil {
					return nil, status.Errorf(codes.PermissionDenied, "Permission denied")
				} else {
					claims = tk
				}
			}
		}
		if claims.ID > 0 {
			meta.Set(UserKey, fmt.Sprint(claims.ID))
			return meta, nil
		}
	}
	return nil, ErrInvalidSessionCookie
}
