package qbt

import (
	"net/http"
	"net/url"

	wrapper "github.com/pkg/errors"
)

// Login logs you in to the qbittorrent client
// returns the current authentication status
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

	// add the cookie to cookie jar to authenticate later requests
	if cookies := resp.Cookies(); len(cookies) > 0 {
		cookieURL, _ := url.Parse(client.URL)
		client.Jar.SetCookies(cookieURL, cookies)
		// create a new client with the cookie jar and replace the old one
		// so that all our later requests are authenticated
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

	// change authentication status, so we know were authenticated in later requests
	client.Authenticated = true

	return nil
}

// Logout logs you out of the qbittorrent client
// returns the current authentication status
func (client *Client) Logout() (err error) {
	resp, err := client.post("api/v2/auth/logout", nil)
	if err != nil {
		return err
	}

	// change authentication status, so we know were not authenticated in later requests
	client.Authenticated = (*resp).StatusCode == 200
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}
