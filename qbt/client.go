// Package qbt is a client for the qBittorrent Web UI HTTP API.
// API reference: https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)
package qbt

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"strings"

	wrapper "github.com/pkg/errors"

	"golang.org/x/net/publicsuffix"
)

// delimit joins items with delimiter. The Web API expects some parameters as a single delimited string.
func delimit(items []string, delimiter string) (delimited string) {
	return strings.Join(items[:], delimiter)
}

// Client is a qBittorrent Web API HTTP client.
type Client struct {
	http          *http.Client
	URL           string
	Authenticated bool
	Jar           http.CookieJar
	Rid           uint64
	Version       string
}

// NewClient returns a client for the given Web UI base URL.
func NewClient(url string) *Client {
	client := &Client{}

	// Ensure base URL ends with "/".
	if len(url) > 0 && url[len(url)-1:] != "/" {
		url += "/"
	}

	client.URL = url

	// Cookie jar for session cookies (populated after Login).
	client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.http = &http.Client{
		Jar: client.Jar,
	}
	return client
}

// get sends GET with optional query parameters.
func (client *Client) get(endpoint string, opts map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", client.URL+endpoint, nil)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to build request")
	}

	req.Header.Set("User-Agent", "go-qbittorrent v0.1")

	// Optional query parameters.
	if opts != nil {
		query := req.URL.Query()
		for k, v := range opts {
			query.Add(k, v)
		}
		req.URL.RawQuery = query.Encode()
	}

	resp, err := client.http.Do(req)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to perform request")
	}

	return resp, nil
}

// post sends application/x-www-form-urlencoded POST with optional form fields.
func (client *Client) post(endpoint string, opts map[string]string) (*http.Response, error) {
	form := url.Values{}
	for k, v := range opts {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", client.URL+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to build request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "go-qbittorrent v0.1")

	resp, err := client.http.Do(req)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to perform request")
	}

	return resp, nil
}

// postMultipart sends POST with the given Content-Type (multipart body in buffer).
func (client *Client) postMultipart(endpoint string, buffer bytes.Buffer, contentType string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", client.URL+endpoint, &buffer)
	if err != nil {
		return nil, wrapper.Wrap(err, "error creating request")
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "go-qbittorrent v0.2")

	resp, err = client.http.Do(req)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to perform request")
	}

	return resp, nil
}

// writeOptions writes form fields into a multipart writer.
func writeOptions(writer *multipart.Writer, opts map[string]string) (err error) {
	for key, val := range opts {
		if err := writer.WriteField(key, val); err != nil {
			return err
		}
	}
	return nil
}

// postMultipartData sends multipart POST with form fields only (no file part).
func (client *Client) postMultipartData(endpoint string, opts map[string]string) (*http.Response, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	if err := writeOptions(writer, opts); err != nil {
		return nil, wrapper.Wrap(err, "failed to write options")
	}

	// Close the writer so the multipart boundary footer is written.
	if err := writer.Close(); err != nil {
		return nil, wrapper.Wrap(err, "failed to close writer")
	}

	resp, err := client.postMultipart(endpoint, buffer, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// postMultipartFile sends multipart POST with one torrent file and optional form fields.
func (client *Client) postMultipartFile(endpoint string, fileName string, opts map[string]string) (*http.Response, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	file, err := os.Open(fileName)
	if err != nil {
		return nil, wrapper.Wrap(err, "error opening file")
	}
	defer file.Close()

	writeOptions(writer, opts)

	// Part name "torrents" matches api/v2/torrents/add.
	formWriter, err := writer.CreateFormFile("torrents", path.Base(fileName))
	if err != nil {
		return nil, wrapper.Wrap(err, "error adding file")
	}

	if _, err = io.Copy(formWriter, file); err != nil {
		return nil, wrapper.Wrap(err, "error copying file")
	}

	if err := writer.Close(); err != nil {
		return nil, wrapper.Wrap(err, "failed to close writer")
	}

	resp, err := client.postMultipart(endpoint, buffer, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// postMultipartFiles uploads multiple local files as multipart/form-data (field name "torrents"; filename from path.Base).
func (client *Client) postMultipartFiles(endpoint string, filePaths []string, opts map[string]string) (*http.Response, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	if err := writeOptions(writer, opts); err != nil {
		return nil, wrapper.Wrap(err, "failed to write options")
	}
	for _, fp := range filePaths {
		file, err := os.Open(fp)
		if err != nil {
			return nil, wrapper.Wrap(err, "error opening file")
		}
		formWriter, err := writer.CreateFormFile("torrents", path.Base(fp))
		if err != nil {
			file.Close()
			return nil, wrapper.Wrap(err, "error adding file")
		}
		if _, err = io.Copy(formWriter, file); err != nil {
			file.Close()
			return nil, wrapper.Wrap(err, "error copying file")
		}
		file.Close()
	}
	if err := writer.Close(); err != nil {
		return nil, wrapper.Wrap(err, "failed to close writer")
	}
	return client.postMultipart(endpoint, buffer, writer.FormDataContentType())
}
