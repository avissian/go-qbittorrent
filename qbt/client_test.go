package qbt

import "testing"

func TestNewClient_normalizesBaseURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"adds slash", "http://localhost:8080", "http://localhost:8080/"},
		{"keeps slash", "http://localhost:8080/", "http://localhost:8080/"},
		{"empty unchanged", "", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewClient(tt.in)
			if c.URL != tt.want {
				t.Fatalf("URL: got %q, want %q", c.URL, tt.want)
			}
		})
	}
}
