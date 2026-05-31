// Package clean has no taint flows: untrusted input never reaches a sink.
package clean

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// Echoed only into a local computation, never into a sink.
	greeting := fmt.Sprintf("hello %s", name)
	_ = len(greeting)
	_ = w
}
