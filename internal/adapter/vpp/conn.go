// Package vpp は govpp 経由で VPP の SRv6 SR Policy を操作する adapter。
// Programmer は control.Programmer を(暗黙的に)満たす。
package vpp

import (
	"fmt"

	"go.fd.io/govpp"
	govppapi "go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
)

// Conn は VPP binary API 接続と channel を保持する。
type Conn struct {
	conn *core.Connection
	// Channel は Programmer に注入するための公開フィールド。
	Channel govppapi.Channel
}

// Connect は VPP の API socket に接続し channel を開く。
func Connect(sock string) (*Conn, error) {
	c, err := govpp.Connect(sock)
	if err != nil {
		return nil, fmt.Errorf("connect vpp %s: %w", sock, err)
	}
	ch, err := c.NewAPIChannel()
	if err != nil {
		c.Disconnect()
		return nil, fmt.Errorf("api channel: %w", err)
	}
	return &Conn{conn: c, Channel: ch}, nil
}

// Close は channel と接続を閉じる。
func (c *Conn) Close() {
	if c.Channel != nil {
		c.Channel.Close()
	}
	if c.conn != nil {
		c.conn.Disconnect()
	}
}
