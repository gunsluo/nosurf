package nosurf

import (
	"net/http"
	"testing"
)

func TestDisablePath(t *testing.T) {
	// the handler doesn't matter here, let's use nil
	hand := New(nil)
	path := "/home"
	exempt, _ := http.NewRequest("GET", path, nil)

	hand.DisablePath(path)
	if !hand.IsDisabled(exempt) {
		t.Errorf("%v is not exempt, but it should be", exempt.URL.Path)
	}

	other, _ := http.NewRequest("GET", "/faq", nil)
	if hand.IsDisabled(other) {
		t.Errorf("%v is exempt, but it shouldn't be", other.URL.Path)
	}
}

func TestDisableGlob(t *testing.T) {
	hand := New(nil)
	glob := "/nail/*"

	hand.DisableGlob(glob)

	test, _ := http.NewRequest("GET", "/nail/foo", nil)
	if !hand.IsDisabled(test) {
		t.Errorf("%v should be exempt, but it isn't.", test)
	}

	test, _ = http.NewRequest("GET", "/nail/foo/bar", nil)
	if hand.IsDisabled(test) {
		t.Errorf("%v should not be exempt, but it is.", test)
	}

	test, _ = http.NewRequest("GET", "/not-nail/foo", nil)
	if hand.IsDisabled(test) {
		t.Errorf("%v should not be exempt, but it is.", test)
	}
}
