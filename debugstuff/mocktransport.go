// Ytl
// Copyright (C) 2022 DomesticMoth <silkmoth@protonmail.com>
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

import(
	"io"
	"fmt"
	"net"
	"time"
	"net/url"
	"context"
	"encoding/hex"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/static"
)

func FormatMockTransportInfo(
	scheme string,
	uri url.URL,
	proxy *url.URL,
	ctx_closed bool,
	key ed25519.PrivateKey,
)string {
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

func ReadMockTransportInfo(conn net.Conn) string {
	b, err := io.ReadAll(conn)
	if err == nil {
		return ""
	}
	return string(b)
}

func ReadMockTransportInfoAfterHeader(conn net.Conn) string {
	io.ReadFull(conn, make([]byte, 6+ed25519.PublicKeySize)) // 6 is header size
	res := make(chan string)
	go func(){
		res <- ReadMockTransportInfo(conn)
	}()
	time.Sleep(500000000)
	conn.Close()
	result := <- res
	return result
}

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

type MockTransportListener struct {
	transport static.Transport
	uri url.URL
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

type MockTransport struct{
	Scheme string
	SecureLvl uint
}

func (t MockTransport) GetScheme() string {
    return t.Scheme
}

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
		case <- wait:
			// Do nothing
		case <- ctx.Done():
			ctx_closed = true
			<- wait
	}
	go func(){
		time.Sleep(delay_before_meta)
		input.Write(header)
		input.Write(opponent_key)
		time.Sleep(delay_after_meta)
		input.Write([]byte(FormatMockTransportInfo(t.Scheme, uri, proxy, ctx_closed, key)))
		buf := make([]byte, 1)
		for {
			_, err := input.Read(buf)
			if err != nil { break }
		}
		input.Close()
	}()	
	return static.ConnResult{output, transport_key, t.SecureLvl}, nil
}

func (t MockTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (static.TransportListener, error) {
	return &MockTransportListener{t, uri}, nil
}
