package bridge

import (
	"bufio"
	"errors"
	"net"
	"time"
)

// ErrUnavailable means the bridge socket could not be reached. The caller can
// treat this as "no hardware method available" and fall back or refuse.
var ErrUnavailable = errors.New("humangate: fido bridge not reachable (start humangate-fido-bridge)")

// Client is a connection to the bridge helper.
type Client struct {
	sock    string
	timeout time.Duration
}

// NewClient targets a bridge socket. Empty path uses DefaultSocketPath.
func NewClient(sock string) *Client {
	if sock == "" {
		sock = DefaultSocketPath()
	}
	return &Client{sock: sock, timeout: 90 * time.Second}
}

// Do sends one request and returns the response. Each call is a fresh
// connection: a tap can take a while, so the deadline is generous.
func (c *Client) Do(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.sock, 3*time.Second)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	if err := WriteMsg(conn, &req); err != nil {
		return nil, err
	}
	var resp Response
	if err := ReadMsg(bufio.NewReader(conn), &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}

// Ping reports whether the bridge is reachable.
func (c *Client) Ping() error {
	_, err := c.Do(Request{Op: OpPing})
	return err
}
