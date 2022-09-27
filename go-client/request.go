package client

import (
	"crypto/tls"
	"net/http"

	"github.com/pkg/errors"
)

func doRequest(tlsCfg *tls.Config,
	newRequest func() (*http.Request, error),
	queryParams map[string]string,
	headers map[string]string,
	processResponse func(*http.Response) error) error {

	var req *http.Request
	var err error

	if req, err = newRequest(); err != nil {
		return err
	}

	if queryParams != nil {
		q := req.URL.Query()
		for param, val := range queryParams {
			q.Add(param, val)
		}
		req.URL.RawQuery = q.Encode()
	}

	if headers != nil {
		for name, val := range headers {
			req.Header.Add(name, val)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return errors.Wrapf(err, "Request to %q failed", req.URL)
	}

	if resp != nil {
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				errors.Errorf("Failed to close response body")
			}
		}()
	}

	if resp.StatusCode != http.StatusOK || resp.ContentLength == 0 {
		return errors.Errorf("Request to %q failed: StatusCode = %d, ContentLength = %d", req.URL, resp.StatusCode, resp.ContentLength)
	}

	return processResponse(resp)
}
