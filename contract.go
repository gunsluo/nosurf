package nosurf

import "net/http"

type Handler interface {
	http.Handler
	// RegenerateToken regenerates a CSRF token and sets the cookie.
	RegenerateToken(w http.ResponseWriter, r *http.Request) string

	// ExemptPath will not require CSRF validation but will still set the
	// cookie if it has not yet been set.
	ExemptPath(string)

	// IgnorePath will not require CSRF validation and also not set the CSRF
	// cookie, but it will set the CSRF token (if available) in the request context.
	IgnorePath(string)

	// IgnoreGlob behaves similar to IgnorePath but allows defining a glob.
	IgnoreGlob(string)

	// IgnoreGlobs behaves similar to IgnorePath but allows defining globs.
	IgnoreGlobs(...string)

	// DisablePath will not require CSRF validation and also not set the CSRF
	// cookie, and it will also not set the CSRF token in the request context.
	DisablePath(string)

	// DisableGlob behaves similar to DisablePath but allows defining a glob.
	DisableGlob(string)

	// DisableGlobs behaves similar to DisablePath but allows defining globs.
	DisableGlobs(...string)
}
