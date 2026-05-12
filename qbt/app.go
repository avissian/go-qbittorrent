package qbt

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	wrapper "github.com/pkg/errors"
)

// ApplicationVersion returns the qBittorrent application version string.
func (client *Client) ApplicationVersion() (version string, err error) {
	resp, err := client.post("api/v2/app/version", nil)
	if err != nil {
		return
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	version = string(buf)
	return
}

// WebAPIVersion returns the Web API version string.
func (client *Client) WebAPIVersion() (version string, err error) {
	resp, err := client.post("api/v2/app/webapiVersion", nil)
	if err != nil {
		return
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	version = string(buf)
	return
}

// BuildInfo returns linked library versions (api/v2/app/buildInfo).
func (client *Client) BuildInfo() (buildInfo BuildInfo, err error) {
	resp, err := client.get("api/v2/app/buildInfo", nil)
	if err != nil {
		return buildInfo, err
	}
	json.NewDecoder(resp.Body).Decode(&buildInfo)
	return buildInfo, err
}

// Preferences returns settings (api/v2/app/preferences).
func (client *Client) Preferences() (prefs Preferences, err error) {
	resp, err := client.get("api/v2/app/preferences", nil)
	if err != nil {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&prefs)
	return
}

// PreferencesRaw returns the raw JSON from api/v2/app/preferences without decoding into Preferences.
func (client *Client) PreferencesRaw() (prefs string, err error) {
	resp, err := client.get("api/v2/app/preferences", nil)
	if err != nil {
		return
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	prefs = string(buf)
	return
}

// SetPreferences updates settings (api/v2/app/setPreferences).
func (client *Client) SetPreferences(opts map[string]any) (err error) {
	jsonString, err := json.Marshal(opts)
	resp, err := client.post("api/v2/app/setPreferences", map[string]string{"json": string(jsonString)})
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DefaultSavePath returns the default save directory.
func (client *Client) DefaultSavePath() (path string, err error) {
	resp, err := client.get("api/v2/app/defaultSavePath", nil)
	if err != nil {
		return
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	path = string(buf)
	return
}

// Shutdown requests application exit (api/v2/app/shutdown).
func (client *Client) Shutdown() (err error) {
	resp, err := client.post("api/v2/app/shutdown", nil)
	if err != nil {
		return err
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ProcessInfo returns process-related information (api/v2/app/processInfo).
func (client *Client) ProcessInfo() (info ProcessInfo, err error) {
	resp, err := client.get("api/v2/app/processInfo", nil)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&info)
	return info, err
}

// SendTestEmail asks the application to send a test email (api/v2/app/sendTestEmail).
func (client *Client) SendTestEmail() error {
	resp, err := client.post("api/v2/app/sendTestEmail", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("sendTestEmail: unexpected status %v", sc)
	}
}

// GetDirectoryContent lists directory entries (api/v2/app/getDirectoryContent). Decode JSON as []string or []DirectoryContentFileMetadata depending on withMetadata.
func (client *Client) GetDirectoryContent(dirPath string, mode DirectoryContentMode, withMetadata bool) (json.RawMessage, error) {
	params := map[string]string{"dirPath": dirPath}
	if mode != "" {
		params["mode"] = string(mode)
	}
	if withMetadata {
		params["withMetadata"] = "true"
	}
	resp, err := client.get("api/v2/app/getDirectoryContent", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("getDirectoryContent: status %v: %s", resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

// GetFreeSpaceAtPath returns free disk space in bytes at path (api/v2/app/getFreeSpaceAtPath).
func (client *Client) GetFreeSpaceAtPath(p string) (int64, error) {
	resp, err := client.get("api/v2/app/getFreeSpaceAtPath", map[string]string{"path": p})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, wrapper.Errorf("getFreeSpaceAtPath: status %v: %s", resp.StatusCode, string(body))
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, wrapper.Wrap(err, "parse free space")
	}
	return n, nil
}

// GetFreeSpaceAtPathAction returns free disk space in bytes at path (api/v2/app/getFreeSpaceAtPathAction, API >= 2.15.2).
// Unlike GetFreeSpaceAtPath this endpoint is an "action" (POST) rather than a query.
func (client *Client) GetFreeSpaceAtPathAction(p string) (int64, error) {
	resp, err := client.post("api/v2/app/getFreeSpaceAtPathAction", map[string]string{"path": p})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, wrapper.Errorf("getFreeSpaceAtPathAction: status %v: %s", resp.StatusCode, string(body))
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, wrapper.Wrap(err, "parse free space")
	}
	return n, nil
}

// Cookies returns HTTP cookies used by the internal download manager (api/v2/app/cookies).
func (client *Client) Cookies() ([]AppCookie, error) {
	resp, err := client.get("api/v2/app/cookies", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []AppCookie
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// SetCookies replaces download-manager cookies (api/v2/app/setCookies). Pass JSON array of cookie objects (same shape as AppCookie).
func (client *Client) SetCookies(cookiesJSON string) error {
	resp, err := client.post("api/v2/app/setCookies", map[string]string{"cookies": cookiesJSON})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setCookies: status %v: %s", sc, string(body))
	}
}

// RotateAPIKey generates a new WebUI API key (api/v2/app/rotateAPIKey).
func (client *Client) RotateAPIKey() (apiKey string, err error) {
	resp, err := client.post("api/v2/app/rotateAPIKey", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", wrapper.Errorf("rotateAPIKey: status %v: %s", resp.StatusCode, string(body))
	}
	var out struct {
		APIKey string `json:"apiKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.APIKey, nil
}

// DeleteAPIKey removes the WebUI API key (api/v2/app/deleteAPIKey).
func (client *Client) DeleteAPIKey() error {
	resp, err := client.post("api/v2/app/deleteAPIKey", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("deleteAPIKey: status %v: %s", sc, string(body))
	}
}

// NetworkInterfaceList returns network interfaces (api/v2/app/networkInterfaceList).
func (client *Client) NetworkInterfaceList() ([]NetworkInterface, error) {
	resp, err := client.get("api/v2/app/networkInterfaceList", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []NetworkInterface
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// NetworkInterfaceAddressList returns IP addresses for iface (empty iface = all addresses) (api/v2/app/networkInterfaceAddressList).
func (client *Client) NetworkInterfaceAddressList(iface string) ([]string, error) {
	params := map[string]string{}
	if iface != "" {
		params["iface"] = iface
	}
	resp, err := client.get("api/v2/app/networkInterfaceAddressList", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []string
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
