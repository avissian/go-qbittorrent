package qbt

/**
API v2.9.3 (qBittorrent 4.6.2)
https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)#api-v283
*/

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

// delimit puts list into a combined (single element) map with all items connected separated by the delimiter
// this is how the WEBUI API recognizes multiple items
func delimit(items []string, delimiter string) (delimited string) {
	return strings.Join(items[:], delimiter)
}

// Client creates a connection to qbittorrent and performs requests
type Client struct {
	http          *http.Client
	URL           string
	Authenticated bool
	Jar           http.CookieJar
	Rid           uint64
	Version       string
}

// NewClient creates a new client connection to qbittorrent
func NewClient(url string) *Client {
	client := &Client{}

	// ensure url ends with "/"
	if len(url) > 0 && url[len(url)-1:] != "/" {
		url += "/"
	}

	client.URL = url

	// create cookie jar
	client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.http = &http.Client{
		Jar: client.Jar,
	}
	return client
}

// get will perform a GET request with no parameters
func (client *Client) get(endpoint string, opts map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", client.URL+endpoint, nil)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to build request")
	}

	//add user-agent header to allow qbittorrent to identify us
	req.Header.Set("User-Agent", "go-qbittorrent v0.1")

	//add optional parameters that the user wants
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

// post will perform a POST request with no content-type specified
func (client *Client) post(endpoint string, opts map[string]string) (*http.Response, error) {
	// add optional parameters that the user wants
	form := url.Values{}
	for k, v := range opts {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", client.URL+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to build request")
	}

	// add the content-type so qbittorrent knows what to expect
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// add user-agent header to allow qbittorrent to identify us
	req.Header.Set("User-Agent", "go-qbittorrent v0.1")

	resp, err := client.http.Do(req)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to perform request")
	}

	return resp, nil
}

// postMultipart will perform a multiple part POST request
func (client *Client) postMultipart(endpoint string, buffer bytes.Buffer, contentType string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", client.URL+endpoint, &buffer)
	if err != nil {
		return nil, wrapper.Wrap(err, "error creating request")
	}

	// add the content-type so qbittorrent knows what to expect
	req.Header.Set("Content-Type", contentType)
	// add user-agent header to allow qbittorrent to identify us
	req.Header.Set("User-Agent", "go-qbittorrent v0.2")

	resp, err = client.http.Do(req)
	if err != nil {
		return nil, wrapper.Wrap(err, "failed to perform request")
	}

	return resp, nil
}

// writeOptions will write a map to the buffer through multipart.NewWriter
func writeOptions(writer *multipart.Writer, opts map[string]string) (err error) {
	for key, val := range opts {
		if err := writer.WriteField(key, val); err != nil {
			return err
		}
	}
	return nil
}

// postMultipartData will perform a multiple part POST request without a file
func (client *Client) postMultipartData(endpoint string, opts map[string]string) (*http.Response, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// write the options to the buffer
	// will contain the link string
	if err := writeOptions(writer, opts); err != nil {
		return nil, wrapper.Wrap(err, "failed to write options")
	}

	// close the writer before doing request to get closing line on multipart request
	if err := writer.Close(); err != nil {
		return nil, wrapper.Wrap(err, "failed to close writer")
	}

	resp, err := client.postMultipart(endpoint, buffer, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// postMultipartFile will perform a multiple part POST request with a file
func (client *Client) postMultipartFile(endpoint string, fileName string, opts map[string]string) (*http.Response, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// open the file for reading
	file, err := os.Open(fileName)
	if err != nil {
		return nil, wrapper.Wrap(err, "error opening file")
	}
	// defer the closing of the file until the end of function
	// so we can still copy its contents
	defer file.Close()

	// write the options to the buffer
	writeOptions(writer, opts)

	// create form for writing the file to and give it the filename
	formWriter, err := writer.CreateFormFile("torrents", path.Base(fileName))
	if err != nil {
		return nil, wrapper.Wrap(err, "error adding file")
	}

	// copy the file contents into the form
	if _, err = io.Copy(formWriter, file); err != nil {
		return nil, wrapper.Wrap(err, "error copying file")
	}

	// close the writer before doing request to get closing line on multipart request
	if err := writer.Close(); err != nil {
		return nil, wrapper.Wrap(err, "failed to close writer")
	}

	resp, err := client.postMultipart(endpoint, buffer, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// postMultipartFiles uploads multiple local files as multipart/form-data (field name "torrents", filename from path.Base).
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
