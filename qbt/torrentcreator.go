package qbt

import (
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"

	wrapper "github.com/pkg/errors"
)

// torrentCreatorJoinEncodedURLs mirrors the WebUI: newline-separated URLs become pipe-separated
// percent-encoded segments (see TorrentCreatorController::parseUrls).
func torrentCreatorJoinEncodedURLs(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	enc := make([]string, len(urls))
	for i, u := range urls {
		enc[i] = strings.ReplaceAll(url.QueryEscape(u), "+", "%20")
	}
	return strings.Join(enc, "|")
}

// TorrentCreatorAddTask enqueues a torrent creation job (api/v2/torrentcreator/addTask, POST).
func (client *Client) TorrentCreatorAddTask(opt TorrentCreatorAddTaskOptions) (taskID string, err error) {
	if opt.SourcePath == "" {
		return "", wrapper.New("TorrentCreatorAddTask: sourcePath is required")
	}
	params := map[string]string{
		"sourcePath": opt.SourcePath,
	}
	if opt.Private != nil {
		params["private"] = strconv.FormatBool(*opt.Private)
	}
	if opt.Format != "" {
		params["format"] = strings.ToLower(opt.Format)
	}
	if opt.PieceSize != nil {
		params["pieceSize"] = strconv.Itoa(*opt.PieceSize)
	}
	if opt.TorrentFilePath != "" {
		params["torrentFilePath"] = opt.TorrentFilePath
	}
	if opt.Comment != "" {
		params["comment"] = opt.Comment
	}
	if opt.Source != "" {
		params["source"] = opt.Source
	}
	if s := torrentCreatorJoinEncodedURLs(opt.Trackers); s != "" {
		params["trackers"] = s
	}
	if s := torrentCreatorJoinEncodedURLs(opt.URLSeeds); s != "" {
		params["urlSeeds"] = s
	}
	if opt.StartSeeding != nil {
		params["startSeeding"] = strconv.FormatBool(*opt.StartSeeding)
	}
	if opt.OptimizeAlignment != nil {
		params["optimizeAlignment"] = strconv.FormatBool(*opt.OptimizeAlignment)
	}
	if opt.PaddedFileSizeLimit != nil {
		params["paddedFileSizeLimit"] = strconv.Itoa(*opt.PaddedFileSizeLimit)
	}

	resp, err := client.post("api/v2/torrentcreator/addTask", params)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", wrapper.Errorf("torrentcreator/addTask: status %v: %s", resp.StatusCode, string(body))
	}
	var out struct {
		TaskID string `json:"taskID"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", wrapper.Wrap(err, "torrentcreator/addTask: decode response")
	}
	if out.TaskID == "" {
		return "", wrapper.Errorf("torrentcreator/addTask: empty taskID in response: %s", string(body))
	}
	return out.TaskID, nil
}

// TorrentCreatorStatus returns creation task status (api/v2/torrentcreator/status, GET).
// If taskID is empty, all tasks are returned; otherwise only that task (404 if missing).
func (client *Client) TorrentCreatorStatus(taskID string) ([]TorrentCreatorTaskStatus, error) {
	var opts map[string]string
	if taskID != "" {
		opts = map[string]string{"taskID": taskID}
	}
	resp, err := client.get("api/v2/torrentcreator/status", opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("torrentcreator/status: status %v: %s", resp.StatusCode, string(body))
	}
	var list []TorrentCreatorTaskStatus
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, wrapper.Wrap(err, "torrentcreator/status: decode response")
	}
	return list, nil
}

// TorrentCreatorTorrentFile downloads the generated .torrent for a finished task (api/v2/torrentcreator/torrentFile, GET).
func (client *Client) TorrentCreatorTorrentFile(taskID string) ([]byte, error) {
	if taskID == "" {
		return nil, wrapper.New("TorrentCreatorTorrentFile: taskID is required")
	}
	resp, err := client.get("api/v2/torrentcreator/torrentFile", map[string]string{"taskID": taskID})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("torrentcreator/torrentFile: status %v: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// TorrentCreatorDeleteTask removes a torrent creation task (api/v2/torrentcreator/deleteTask, POST).
func (client *Client) TorrentCreatorDeleteTask(taskID string) error {
	if taskID == "" {
		return wrapper.New("TorrentCreatorDeleteTask: taskID is required")
	}
	resp, err := client.post("api/v2/torrentcreator/deleteTask", map[string]string{"taskID": taskID})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("torrentcreator/deleteTask: status %v: %s", resp.StatusCode, string(body))
	}
}
