package nosurf

import (
	"net/http"
	pathModule "path"
)

// Disables the CSRF middleware for an exact path
// With this you should take note that Go's paths
// include a leading slash.
func (h *CSRFHandler) DisablePath(path string) {
	h.disablePaths = append(h.disablePaths, path)
}

// Checks if the given request disables this middleware
func (h *CSRFHandler) IsDisabled(r *http.Request) bool {
	path := r.URL.Path
	if sContains(h.disablePaths, path) {
		return true
	}

	// then the globs
	for _, glob := range h.disableGlobs {
		matched, err := pathModule.Match(glob, path)
		if matched && err == nil {
			return true
		}
	}

	return false
}

func (h *CSRFHandler) DisableGlob(pattern string) {
	h.disableGlobs = append(h.disableGlobs, pattern)
}

func (h *CSRFHandler) DisableGlobs(patterns ...string) {
	h.disableGlobs = append(h.disableGlobs, patterns...)
}
