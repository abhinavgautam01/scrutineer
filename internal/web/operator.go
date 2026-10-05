package web

import (
	"crypto/subtle"
	"net/http"
)

const (
	operatorCookie = "operator"
	// Browsers cap a cookie's lifetime at 400 days; the token itself does
	// not expire, so the cookie only needs to outlive a browser restart.
	operatorCookieMaxAge = 400 * 24 * 60 * 60
)

// validOperatorToken fails closed when no token is configured, so a Server
// built without one serves nothing behind requireOperator.
func (s *Server) validOperatorToken(got string) bool {
	return s.OperatorToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.OperatorToken)) == 1
}

// requireOperator gates the browser UI and /api/v1 on the operator token,
// sent as a bearer by scripts or as the cookie /login sets for a browser.
func (s *Server) requireOperator(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r.Header.Get("Authorization"))
		if c, err := r.Cookie(operatorCookie); token == "" && err == nil {
			token = c.Value
		}
		if !s.validOperatorToken(token) {
			http.Error(w, "unauthorized: operator token required, sign in with /login?token= followed by the contents of <data>/operator-token", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// login trades the token in the printed link for the operator cookie and
// redirects so the token leaves the address bar.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !s.validOperatorToken(token) {
		http.Error(w, "unauthorized: invalid operator token", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     operatorCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   operatorCookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
