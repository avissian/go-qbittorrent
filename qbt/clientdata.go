package qbt

import (
	"encoding/json"
	"io"

	wrapper "github.com/pkg/errors"
)

func (client *Client) ClientDataLoad(keys []string) (json.RawMessage, error) {
	if len(keys) == 0 {
		resp, err := client.get("api/v2/clientdata/load", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, wrapper.Errorf("clientdata/load: status %v: %s", resp.StatusCode, string(body))
		}
		return json.RawMessage(body), nil
	}
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	resp, err := client.post("api/v2/clientdata/load", map[string]string{"keys": string(keysJSON)})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("clientdata/load: status %v: %s", resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

// ClientDataStore persists WebUI client data (api/v2/clientdata/store). dataJSON must be a JSON object.
func (client *Client) ClientDataStore(dataJSON string) error {
	resp, err := client.post("api/v2/clientdata/store", map[string]string{"data": dataJSON})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("clientdata/store: status %v: %s", sc, string(body))
	}
}
