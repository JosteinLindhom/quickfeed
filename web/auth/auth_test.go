package auth_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	pb "github.com/autograde/quickfeed/ag"
	"github.com/autograde/quickfeed/internal/qtest"
	"github.com/autograde/quickfeed/web/auth"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"go.uber.org/zap"
)

const (
	loginRedirect  = "/login"
	logoutRedirect = "/logout"

	authURL   = "/auth?provider=fake&redirect=" + loginRedirect
	logoutURL = "/logout?provider=fake&redirect=" + logoutRedirect

	fakeSessionKey  = "fake"
	fakeSessionName = fakeSessionKey + gothic.SessionName
)

func init() {
	goth.UseProviders(&auth.FakeProvider{
		Callback: "/auth/fake/callback",
	})
}

func logger(t *testing.T) *zap.SugaredLogger {
	t.Helper()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	return logger.Sugar()
}

func TestOAuth2Logout(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, logoutURL, nil)
	w := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(r, w)

	if err := login(c); err != nil {
		t.Error(err)
	}

	authHandler := auth.OAuth2Logout(logger(t))
	if err := authHandler(c); err != nil {
		t.Error(err)
	}

	if cookie := c.Response().Header().Get(auth.OutgoingCookie); len(cookie) > 0 {
		if !strings.HasPrefix(cookie, auth.JWTCookieName) {
			t.Error("Response contains a Set-Cookie header for a cookie other than 'auth'.")
		}
	} else {
		t.Error("Response did not update any cookies.")
	}
	// TODO: Parse request and response header cookies and verify that response does in fact expire the cookie.
}

func TestOAuth2LoginRedirect(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(r, w)

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	authHandler := auth.OAuth2Login(logger(t), db)
	if err := authHandler(c); err != nil {
		t.Error(err)
	}
	assertCode(t, w.Code, http.StatusTemporaryRedirect)
}

func TestOAuth2CallbackBadRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(r, w)

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	authHandler := auth.OAuth2Callback(logger(t), db, auth.NewScms())
	err := authHandler(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("unexpected error type: %v", reflect.TypeOf(err))
	}
	assertCode(t, httpErr.Code, http.StatusBadRequest)
}

func TestPreAuthNoSession(t *testing.T) {
	testPreAuthLoggedIn(t, false, false, "github")
}

func TestPreAuthLoggedInNoDBUser(t *testing.T) {
	testPreAuthLoggedIn(t, true, false, "github")
}

func TestPreAuthLogged(t *testing.T) {
	testPreAuthLoggedIn(t, true, true, "github")
}

func TestPreAuthLoggedInNewIdentity(t *testing.T) {
	testPreAuthLoggedIn(t, true, true, "gitlab")
}

func testPreAuthLoggedIn(t *testing.T, haveSession, existingUser bool, newProvider string) {
	const (
		provider = "github"
		remoteID = 0
		secret   = "secret"
	)
	shouldPass := !haveSession || existingUser

	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	e := echo.New()
	rou := e.Router()
	rou.Add("GET", "/:provider", func(echo.Context) error { return nil })
	c := e.NewContext(r, w)

	if haveSession {
		if err := login(c); err != nil {
			t.Error(err)
		}
	}

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	if existingUser {
		if err := db.CreateUserFromRemoteIdentity(&pb.User{}, &pb.RemoteIdentity{
			Provider:    provider,
			RemoteID:    remoteID,
			AccessToken: secret,
		}); err != nil {
			t.Fatal(err)
		}
		c.SetParamNames("provider")
		c.SetParamValues(newProvider)
	}

	authHandler := auth.PreAuth(logger(t), db)(func(c echo.Context) error { return nil })

	if err := authHandler(c); err != nil {
		t.Error(err)
	}

	wantLocation := loginRedirect
	switch {
	case shouldPass:
		wantLocation = ""
	}
	location := w.Header().Get("Location")
	if location != wantLocation {
		t.Errorf("have Location '%v' want '%v'", location, wantLocation)
	}

	wantCode := http.StatusFound
	if shouldPass {
		wantCode = http.StatusOK
	}

	assertCode(t, w.Code, wantCode)
}

func TestOAuth2LoginAuthenticated(t *testing.T) {
	const userID = "1"

	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	qv := r.URL.Query()
	qv.Set(auth.State, r.URL.Query().Get(auth.Redirect))
	r.URL.RawQuery = qv.Encode()

	_, err := gothic.GetAuthURL(w, r)
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	c := e.NewContext(r, w)

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	authHandler := auth.OAuth2Login(logger(t), db)

	if err := authHandler(c); err != nil {
		t.Error(err)
	}

	assertCode(t, w.Code, http.StatusTemporaryRedirect)
}

func TestOAuth2CallbackNoSession(t *testing.T) {
	testOAuth2Callback(t, false, false)
}

func TestOAuth2CallbackExistingUser(t *testing.T) {
	testOAuth2Callback(t, true, false)
}

func TestOAuth2CallbackLoggedIn(t *testing.T) {
	testOAuth2Callback(t, true, true)
}

func testOAuth2Callback(t *testing.T, existingUser, haveSession bool) {
	const (
		provider = "github"
		userID   = "1"
		remoteID = 0
		secret   = "secret"
	)
	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	qv := r.URL.Query()
	qv.Set(auth.State, "0"+r.URL.Query().Get(auth.Redirect))
	r.URL.RawQuery = qv.Encode()

	store := newStore()
	gothic.Store = store

	fakeSession := auth.FakeSession{ID: userID}
	s, _ := store.Get(r, fakeSessionName)
	s.Values[fakeSessionKey] = fakeSession.Marshal()
	if err := s.Save(r, w); err != nil {
		t.Error(err)
	}

	_, err := gothic.GetAuthURL(w, r)
	if err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	c := e.NewContext(r, w)

	if haveSession {
		if err := login(c); err != nil {
			t.Error(err)
		}
	}

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	if existingUser {
		if err := db.CreateUserFromRemoteIdentity(&pb.User{}, &pb.RemoteIdentity{
			Provider:    provider,
			RemoteID:    remoteID,
			AccessToken: secret,
		}); err != nil {
			t.Fatal(err)
		}
	}

	authHandler := auth.OAuth2Callback(logger(t), db, auth.NewScms())

	if err := authHandler(c); err != nil {
		t.Error(err)
	}

	location := w.Header().Get("Location")
	if location != loginRedirect {
		t.Errorf("have Location '%v' want '%v'", location, loginRedirect)
	}

	assertCode(t, w.Code, http.StatusFound)
}

func TestAccessControl(t *testing.T) {
	const (
		provider = "github"
		remoteID = 0
		secret   = "secret"
		token    = "test"
	)

	r := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()

	store := newStore()

	e := echo.New()
	c := e.NewContext(r, w)

	db, cleanup := qtest.TestDB(t)
	defer cleanup()

	// Create a new user.
	if err := db.CreateUserFromRemoteIdentity(&pb.User{}, &pb.RemoteIdentity{
		Provider:    provider,
		RemoteID:    remoteID,
		AccessToken: secret,
	}); err != nil {
		t.Fatal(err)
	}

	m := auth.AccessControl(logger(t), db, auth.NewScms())
	protected := session.Middleware(store)(m(func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	}))

	// User is not logged in.
	if err := protected(c); err != nil {
		t.Error(err)
	}

	if err := login(c); err != nil {
		t.Error(err)
	}

	// Add cookie to mimic logged in request
	c.Request().AddCookie(&http.Cookie{Name: auth.SessionKey, Value: token})

	// User is logged in.
	if err := protected(c); err != nil {
		t.Error(err)
	}
}

func assertCode(t *testing.T, haveCode, wantCode int) {
	t.Helper()
	if haveCode != wantCode {
		t.Errorf("have status code %d want %d", haveCode, wantCode)
	}
}

type testStore struct {
	store map[*http.Request]*sessions.Session
}

func newStore() *testStore {
	return &testStore{
		make(map[*http.Request]*sessions.Session),
	}
}

func login(c echo.Context) error {
	manager := auth.JWTManager{Secret: "", Domain: testDomain}
	claims := manager.NewClaims(&pb.User{ID: 1})
	token := manager.NewJWT(claims)
	/*err := j.setJWTCookie(token, context)
	if err != nil {
		return err
	}*/
	cookie, err := manager.GetJWTCookie(token)
	if err != nil {
		return err
	}
	r := c.Request()
	r.Header.Add(auth.Cookie, cookie.String())

	return nil
}

func (ts testStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	s := ts.store[r]
	if s == nil {
		s, err := ts.New(r, name)
		return s, err
	}
	return s, nil
}

func (ts testStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s := sessions.NewSession(ts, name)
	s.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400 * 30,
	}
	ts.store[r] = s
	return s, nil
}

func (ts testStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	ts.store[r] = s
	return nil
}
