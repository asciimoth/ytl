// Copyright 2022 DomesticMoth
//
// This file is part of Ytl.
//
// Ytl is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// Ytl is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package debugstuff

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/DomesticMoth/ytl/static"
	"io"
	"net"
	"net/url"
	"time"
)

// Returns json string with passed arguments.
func FormatMockTransportInfo(
	scheme string,
	uri url.URL,
	proxy *url.URL,
	ctx_closed bool,
	key ed25519.PrivateKey,
) string {
	txtProxy := "nil"
	if proxy != nil {
		txtProxy = uri.String()
	}
	txtKey := "nil"
	if key != nil {
		txtKey = hex.EncodeToString(key)
	}
	return fmt.Sprintf(
		"{'transport name':'%s','uri':'%s','proxy':'%s','ctx closed':'%t','PrivKey':'%s'}",
		scheme, uri.String(), txtProxy, ctx_closed, txtKey,
	)
}

// Read all data from connetion up to EOF to string.
func ReadMockTransportInfo(conn net.Conn) string {
	b, err := io.ReadAll(conn)
	if err == nil {
		return ""
	}
	return string(b)
}

// Read ygg handshake pkg and then all data up to EOF to string.
func ReadMockTransportInfoAfterHeader(conn net.Conn) string {
	io.ReadFull(conn, make([]byte, 6+ed25519.PublicKeySize)) // 6 is header size
	res := make(chan string)
	go func() {
		res <- ReadMockTransportInfo(conn)
	}()
	time.Sleep(500000000)
	conn.Close()
	result := <-res
	return result
}

// Get the public key of the ygg node from the url key
// or generate a new one filled with zeros if not exists.
func getPubKeyFromUri(uri url.URL, key string) ed25519.PublicKey {
	if pubkeys, ok := uri.Query()[key]; ok && len(pubkeys) > 0 {
		for _, pubkey := range pubkeys {
			if opkey, err := hex.DecodeString(pubkey); err == nil {
				return opkey
			}
		}
	}
	return make(ed25519.PublicKey, ed25519.PublicKeySize)
}

// Get the public key of the ygg node from the url key
// or retrun nil if not exists .
func getTransportKeyFromUri(uri url.URL, key string) ed25519.PublicKey {
	if pubkeys, ok := uri.Query()[key]; ok && len(pubkeys) > 0 {
		for _, pubkey := range pubkeys {
			if opkey, err := hex.DecodeString(pubkey); err == nil {
				return opkey
			}
		}
	}
	return nil
}

// Get duration from the url key or return 0 if not exists.
func getDurationFromUri(uri url.URL, key string) time.Duration {
	if durations, ok := uri.Query()[key]; ok && len(durations) > 0 {
		for _, duration := range durations {
			d, err := time.ParseDuration(duration)
			if err == nil {
				return d
			}
		}
	}
	return 0
}

// Mock realistion fro TransportListener interface
// for for debugging needs.
type MockTransportListener struct {
	transport static.Transport
	uri       url.URL
}

func (l *MockTransportListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptConn()
	return conn.Conn, err
}

func (l *MockTransportListener) AcceptConn() (static.ConnResult, error) {
	ctx := context.Background()
	return l.transport.Connect(ctx, l.uri, nil, nil)
}

func (l *MockTransportListener) Close() error {
	return nil
}

func (l *MockTransportListener) Addr() net.Addr {
	return nil
}

// Mock realistion fro Transport interface
// for for debugging needs.
//
// Has mutable behavior controlled by url keys.
type MockTransport struct {
	Scheme    string
	SecureLvl uint
}

func (t MockTransport) GetScheme() string {
	return t.Scheme
}

// Writes result of [FormatMockTransportInfo] to returned connection
// after handshake pkg
//
// Peer key returned from opened connection
// controls by "mock_peer_key" url key.
// Transport key returned with opened connection
// controls by "mock_transport_key" url key.
// Delay before returning result
// controls by "mock_delay_conn" url key.
// Delay before writing handshake pkg to connection
// controls by "mock_delay_before_meta" url key.
// Delay before writing info string to connection
// controls by "mock_delay_after_meta" url key.
func (t MockTransport) Connect(
	ctx context.Context,
	uri url.URL,
	proxy *url.URL,
	key ed25519.PrivateKey,
) (static.ConnResult, error) {
	opponent_key := getPubKeyFromUri(uri, "mock_peer_key")
	transport_key := getTransportKeyFromUri(uri, "mock_transport_key")
	delay_conn := getDurationFromUri(uri, "mock_delay_conn")
	delay_before_meta := getDurationFromUri(uri, "mock_delay_before_meta")
	delay_after_meta := getDurationFromUri(uri, "mock_delay_after_meta")
	ctx_closed := false
	input, output := net.Pipe()
	header := []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		0, 4, // Version
	}
	wait := time.After(delay_conn)
	select {
	case <-wait:
		// Do nothing
	case <-ctx.Done():
		ctx_closed = true
		<-wait
	}
	go func() {
		time.Sleep(delay_before_meta)
		input.Write(header)
		input.Write(opponent_key)
		time.Sleep(delay_after_meta)
		input.Write([]byte(FormatMockTransportInfo(t.Scheme, uri, proxy, ctx_closed, key)))
		buf := make([]byte, 1)
		for {
			_, err := input.Read(buf)
			if err != nil {
				break
			}
		}
		input.Close()
	}()
	return static.ConnResult{
		Conn:          output,
		Pkey:          transport_key,
		SecurityLevel: t.SecureLvl,
	}, nil
}

func (t MockTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (static.TransportListener, error) {
	return &MockTransportListener{t, uri}, nil
}
