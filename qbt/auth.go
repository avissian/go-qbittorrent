package qbt

import (
	"net/http"
	"net/url"

	wrapper "github.com/pkg/errors"
)

// Login authenticates against the qBittorrent Web API and stores the session cookie.
func (client *Client) Login(opts LoginOptions) (err error) {
	params := map[string]string{}

	if opts.Username != "" {
		params["username"] = opts.Username
	}
	if opts.Password != "" {
		params["password"] = opts.Password
	}

	resp, err := client.post("api/v2/auth/login", params)
	if err != nil {
		return err
	} else if resp.StatusCode == 403 {
		return wrapper.Errorf("User's IP is banned for too many failed login attempts")
	}

	// Store the session cookie for subsequent requests.
	if cookies := resp.Cookies(); len(cookies) > 0 {
		cookieURL, _ := url.Parse(client.URL)
		client.Jar.SetCookies(cookieURL, cookies)
		// Replace the HTTP client so all later requests use the cookie jar.
		client.http = &http.Client{
			Jar: client.Jar,
		}
	} else {
		return wrapper.Errorf("Could not get cookie")
	}

	client.Version, err = client.ApplicationVersion()
	if err != nil {
		return
	}

	// Mark the client as authenticated for callers.
	client.Authenticated = true

	return nil
}

// Logout ends the Web UI session.
func (client *Client) Logout() (err error) {
	resp, err := client.post("api/v2/auth/logout", nil)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		client.Authenticated = false
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}
