package qbt

import (
	"encoding/json"
	"io"
	"strconv"

	wrapper "github.com/pkg/errors"
)

// Info returns global transfer statistics (api/v2/transfer/info).
func (client *Client) Info(opts InfoOptions) (info Info, err error) {
	resp, err := client.get("api/v2/transfer/info", nil)
	if err != nil {
		return info, err
	}
	err = json.NewDecoder(resp.Body).Decode(&info)
	return info, err
}

// AltSpeedLimitsEnabled reports whether alternative speed limits are active (api/v2/transfer/speedLimitsMode).
func (client *Client) AltSpeedLimitsEnabled() (mode bool, err error) {
	resp, err := client.get("api/v2/transfer/speedLimitsMode", nil)
	if err != nil {
		return mode, err
	}
	var decoded int
	json.NewDecoder(resp.Body).Decode(&decoded)
	mode = decoded == 1
	return mode, err
}

// ToggleAltSpeedLimits toggles alternative speed limits (api/v2/transfer/toggleSpeedLimitsMode).
func (client *Client) ToggleAltSpeedLimits() (err error) {
	resp, err := client.post("api/v2/transfer/toggleSpeedLimitsMode", nil)
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

// SetSpeedLimitsMode sets alternative speed limits on (mode != 0) or off (mode == 0) (api/v2/transfer/setSpeedLimitsMode).
func (client *Client) SetSpeedLimitsMode(mode int) error {
	resp, err := client.post("api/v2/transfer/setSpeedLimitsMode", map[string]string{"mode": strconv.Itoa(mode)})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setSpeedLimitsMode: status %v: %s", sc, string(body))
	}
}

// DlLimit returns the global download limit in bytes/s (api/v2/transfer/downloadLimit).
func (client *Client) DlLimit() (dlLimit int, err error) {
	resp, err := client.get("api/v2/transfer/downloadLimit", nil)
	if err != nil {
		return dlLimit, err
	}
	json.NewDecoder(resp.Body).Decode(&dlLimit)
	return dlLimit, err
}

// SetDlLimit sets the global download limit (api/v2/transfer/setDownloadLimit).
func (client *Client) SetDlLimit(limit int) (err error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	resp, err := client.post("api/v2/transfer/setDownloadLimit", params)
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

// UlLimit returns the global upload limit in bytes/s (api/v2/transfer/uploadLimit).
func (client *Client) UlLimit() (ulLimit int, err error) {
	resp, err := client.get("api/v2/transfer/uploadLimit", nil)
	if err != nil {
		return ulLimit, err
	}
	json.NewDecoder(resp.Body).Decode(&ulLimit)
	return ulLimit, err
}

// SetUlLimit sets the global upload limit (api/v2/transfer/setUploadLimit).
func (client *Client) SetUlLimit(limit int) (err error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	resp, err := client.post("api/v2/transfer/setUploadLimit", params)
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

// SpeedLimits holds global and alternative speed limits as returned by api/v2/transfer/getSpeedLimits (API >= 2.16.0).
type SpeedLimits struct {
	DlLimit    int64 `json:"dl_limit"`
	UpLimit    int64 `json:"up_limit"`
	AltDlLimit int64 `json:"alt_dl_limit"`
	AltUpLimit int64 `json:"alt_up_limit"`
}

// GetSpeedLimits returns global and alternative speed limits (api/v2/transfer/getSpeedLimits, API >= 2.16.0).
func (client *Client) GetSpeedLimits() (SpeedLimits, error) {
	var out SpeedLimits
	resp, err := client.get("api/v2/transfer/getSpeedLimits", nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// SetSpeedLimits sets global and alternative speed limits (api/v2/transfer/setSpeedLimits, API >= 2.16.0).
// Pass -1 for any limit to leave it unchanged.
func (client *Client) SetSpeedLimits(limits SpeedLimits) error {
	params := map[string]string{}
	if limits.DlLimit >= 0 {
		params["dl_limit"] = strconv.FormatInt(limits.DlLimit, 10)
	}
	if limits.UpLimit >= 0 {
		params["up_limit"] = strconv.FormatInt(limits.UpLimit, 10)
	}
	if limits.AltDlLimit >= 0 {
		params["alt_dl_limit"] = strconv.FormatInt(limits.AltDlLimit, 10)
	}
	if limits.AltUpLimit >= 0 {
		params["alt_up_limit"] = strconv.FormatInt(limits.AltUpLimit, 10)
	}
	resp, err := client.post("api/v2/transfer/setSpeedLimits", params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setSpeedLimits: status %v: %s", sc, string(body))
	}
}

// BanPeers bans peers by IP (api/v2/transfer/banPeers).
func (client *Client) BanPeers(peers []string) (err error) {
	opts := map[string]string{
		"peers": delimit(peers, "|"),
	}
	resp, err := client.post("api/v2/transfer/banPeers", opts)
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
