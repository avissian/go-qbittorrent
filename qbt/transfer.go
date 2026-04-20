package qbt

import (
	"encoding/json"
	"io"
	"strconv"

	wrapper "github.com/pkg/errors"
)

// Info returns info you usually see in qBt status bar.
func (client *Client) Info(opts InfoOptions) (info Info, err error) {
	resp, err := client.get("api/v2/transfer/info", nil)
	if err != nil {
		return info, err
	}
	err = json.NewDecoder(resp.Body).Decode(&info)
	return info, err
}

// AltSpeedLimitsEnabled returns info you usually see in qBt status bar.
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

// ToggleAltSpeedLimits returns info you usually see in qBt status bar.
func (client *Client) ToggleAltSpeedLimits() (err error) {
	resp, err := client.post("api/v2/transfer/toggleSpeedLimitsMode", nil)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
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

// DlLimit returns info you usually see in qBt status bar.
func (client *Client) DlLimit() (dlLimit int, err error) {
	resp, err := client.get("api/v2/transfer/downloadLimit", nil)
	if err != nil {
		return dlLimit, err
	}
	json.NewDecoder(resp.Body).Decode(&dlLimit)
	return dlLimit, err
}

// SetDlLimit returns info you usually see in qBt status bar.
func (client *Client) SetDlLimit(limit int) (err error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	resp, err := client.post("api/v2/transfer/setDownloadLimit", params)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// UlLimit returns info you usually see in qBt status bar.
func (client *Client) UlLimit() (ulLimit int, err error) {
	resp, err := client.get("api/v2/transfer/uploadLimit", nil)
	if err != nil {
		return ulLimit, err
	}
	json.NewDecoder(resp.Body).Decode(&ulLimit)
	return ulLimit, err
}

// SetUlLimit returns info you usually see in qBt status bar.
func (client *Client) SetUlLimit(limit int) (err error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	resp, err := client.post("api/v2/transfer/setUploadLimit", params)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

func (client *Client) BanPeers(peers []string) (err error) {
	opts := map[string]string{
		"peers": delimit(peers, "|"),
	}
	resp, err := client.post("api/v2/transfer/banPeers", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}
