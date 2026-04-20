package tools

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
)

// PrintResponse reads and prints an HTTP response body to stdout (for debugging).
func PrintResponse(body io.ReadCloser) {
	r, _ := io.ReadAll(body)
	fmt.Println("response: " + string(r))
}

// PrintRequest dumps an HTTP request to stdout (for debugging).
func PrintRequest(req *http.Request) error {
	r, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	fmt.Println("request: " + string(r))
	return nil
}
