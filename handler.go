// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
)

const (
	// the name of CSRF cookie
	CookieName = "csrf_token"
	// the name of the form field
	FormFieldName = "csrf_token"
	// the name of CSRF header
	HeaderName = "X-CSRF-Token"
	// the HTTP status code for the default failure handler
	FailureCode = 400

	// Max-Age in seconds for the default base cookie. 365 days.
	MaxAge = 365 * 24 * 60 * 60
)

var safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// reasons for CSRF check failures
var (
	ErrNoReferer  = errors.New("A secure request contained no Referer or its value was malformed")
	ErrBadReferer = errors.New("A secure request's Referer comes from a different Origin" +
		" from the request's URL")
	ErrBadToken = errors.New("The CSRF token in the cookie doesn't match the one" +
		" received in a form/header.")
)

type CSRFHandler struct {
	// Handlers that CSRFHandler wraps.
	successHandler http.Handler
	failureHandler http.Handler

	// The base cookie that CSRF cookies will be built upon.
	// This should be a better solution of customizing the options
	// than a bunch of methods SetCookieExpiration(), etc.
	baseCookieFunc func(w http.ResponseWriter, r *http.Request) http.Cookie

	// Slices of paths that are exempt from CSRF checks.
	// They can be specified by...
	// ...an exact path,
	exemptPaths []string
	// ...a regexp,
	exemptRegexps []*regexp.Regexp
	// ...or a glob (as used by path.Match()).
	exemptGlobs []string
	// ...or a custom matcher function
	exemptFunc func(r *http.Request) bool

	// Slices of paths that completely ignore this middleware.
	ignorePaths []string
	// ...or a glob (as used by path.Match()).
	ignoreGlobs []string

	// Slices of paths that completely disable this middleware.
	disablePaths []string
	// ...or a glob (as used by path.Match()).
	disableGlobs []string

	// All of those will be matched against Request.URL.Path,
	// So they should take the leading slash into account
}

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(FailureCode), FailureCode)
}

// Extracts the "sent" token from the request
// and returns an unmasked version of it
func extractToken(r *http.Request) []byte {
	// Prefer the header over form value
	sentToken := r.Header.Get(HeaderName)

	// Then POST values
	if len(sentToken) == 0 {
		sentToken = r.PostFormValue(FormFieldName)
	}

	// If all else fails, try a multipart value.
	// PostFormValue() will already have called ParseMultipartForm()
	if len(sentToken) == 0 && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[FormFieldName]
		if len(vals) != 0 {
			sentToken = vals[0]
		}
	}

	return b64decode(sentToken)
}

// Constructs a new CSRFHandler that calls
// the specified handler if the CSRF check succeeds.
func New(handler http.Handler) *CSRFHandler {
	baseCookie := http.Cookie{}
	baseCookie.MaxAge = MaxAge

	csrf := &CSRFHandler{successHandler: handler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		baseCookieFunc: func(w http.ResponseWriter, r *http.Request) http.Cookie {
			return baseCookie
		},
	}

	return csrf
}

// The same as New(), but has an interface return type.
func NewPure(handler http.Handler) http.Handler {
	return New(handler)
}

func (h CSRFHandler) getCookieName(w http.ResponseWriter, r *http.Request) string {
	if name := h.baseCookieFunc(w, r).Name; name != "" {
		return name
	}

	return CookieName
}

func (h *CSRFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.IsDisabled(r) {
		h.handleSuccess(w, r)
		return
	}

	r = addNosurfContext(r)
	defer ctxClear(r)

	w.Header().Add("Vary", "Cookie")

	var realTokens [][]byte
	for _, tokenCookie := range r.Cookies() {
		if tokenCookie.Name == h.getCookieName(w, r) {
			realTokens = append(realTokens, b64decode(tokenCookie.Value))
		}
	}

	// If the length of the real token isn't what it should be,
	// it has either been tampered with,
	// or we're migrating onto a new algorithm for generating tokens,
	// or it hasn't ever been set so far.
	// In any case of those, we should regenerate it.
	//
	// As a consequence, CSRF check will fail when comparing the tokens later on,
	// so we don't have to fail it just yet.
	if len(realTokens) == 0 {
		// If we received no token (len==0), it means no CSRF cookie exists. We need to regenerate.
		if !h.IsIgnored(r) {
			h.RegenerateToken(w, r)
		}
	} else if len(realTokens) == 1 && len(realTokens[0]) != tokenLength {
		// We received one token, but it's not the right length.
		if !h.IsIgnored(r) {
			h.RegenerateToken(w, r)
		}
	} else if len(realTokens) > 1 {
		// We received multiple tokens. We need to find the correct one and set it.
		sentToken := extractToken(r)
		for _, realToken := range realTokens {
			if verifyToken(realToken, sentToken) {
				realTokens = [][]byte{realToken}
				break
			}
		}

		// We have to regenerate because we only want one CSRF cookie. This is like
		// a cleanup job!
		if !h.IsIgnored(r) {
			h.RegenerateToken(w, r)
		}
	} else {
		// We received one token, and it's the right length
		ctxSetToken(r, realTokens[0])
	}

	if h.IsIgnored(r) {
		h.handleSuccess(w, r)
		return
	}

	if sContains(safeMethods, r.Method) || h.IsExempt(r) {
		// short-circuit with a success for safe methods
		h.handleSuccess(w, r)
		return
	}

	// if the request is secure, we enforce origin check
	// for referer to prevent MITM of http->https requests
	if r.URL.Scheme == "https" {
		referer, err := url.Parse(r.Header.Get("Referer"))

		// if we can't parse the referer or it's empty,
		// we assume it's not specified
		if err != nil || referer.String() == "" {
			ctxSetReason(r, ErrNoReferer)
			h.handleFailure(w, r)
			return
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, r.URL) {
			ctxSetReason(r, ErrBadReferer)
			h.handleFailure(w, r)
			return
		}
	}

	// Finally, we check the token itself.
	sentToken := extractToken(r)

	if !verifyToken(realTokens[0], sentToken) {
		ctxSetReason(r, ErrBadToken)
		h.handleFailure(w, r)
		return
	}

	// Everything else passed, handle the success.
	h.handleSuccess(w, r)
}

// handleSuccess simply calls the successHandler.
// Everything else, like setting a token in the context
// is taken care of by h.ServeHTTP()
func (h *CSRFHandler) handleSuccess(w http.ResponseWriter, r *http.Request) {
	h.successHandler.ServeHTTP(w, r)
}

// Same applies here: h.ServeHTTP() sets the failure reason, the token,
// and only then calls handleFailure()
func (h *CSRFHandler) handleFailure(w http.ResponseWriter, r *http.Request) {
	h.failureHandler.ServeHTTP(w, r)
}

// Generates a new token, sets it on the given request and returns it
func (h *CSRFHandler) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	if ctxWasSent(r) {
		// The CSRF Cookie was set already by an earlier call to `RegenerateToken`
		// in the same request context. It therefore does not make sense to regenerate
		// it again as it will lead to two or more `Set-Cookie` instructions which will in turn
		// cause CSRF to fail depending on the resulting order of the `Set-Cookie` instructions.
		//
		// No warning is necessary as the only caller to `setTokenCookie` is `RegenerateToken`.
		return Token(r)
	}

	token := generateToken()
	h.setTokenCookie(w, r, token)

	return Token(r)
}

func (h *CSRFHandler) setTokenCookie(w http.ResponseWriter, r *http.Request, token []byte) {
	// ctxSetToken() does the masking for us
	ctxSetToken(r, token)

	cookie := h.baseCookieFunc(w, r)
	cookie.Name = h.getCookieName(w, r)
	cookie.Value = b64encode(token)

	http.SetCookie(w, &cookie)
	ctxSetSent(r)

}

// Sets the handler to call in case the CSRF check
// fails. By default it's defaultFailureHandler.
func (h *CSRFHandler) SetFailureHandler(handler http.Handler) {
	h.failureHandler = handler
}

// Sets the base cookie to use when building a CSRF token cookie
// This way you can specify the Domain, Path, HttpOnly, Secure, etc.
func (h *CSRFHandler) SetBaseCookie(cookie http.Cookie) {
	h.baseCookieFunc = func(w http.ResponseWriter, r *http.Request) http.Cookie {
		return cookie
	}
}

// Similar to SetBaseCookie but accepts a function which receives the HTTP response and HTTP request
// for potential contextualization.
func (h *CSRFHandler) SetBaseCookieFunc(f func(w http.ResponseWriter, r *http.Request) http.Cookie) {
	h.baseCookieFunc = f
}
