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
	"fmt"
	"net"
	"time"
	"net/url"
	"context"
	"encoding/hex"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)

func formatMockTransportInfo(scheme string, uri url.URL, proxy *url.URL, ctx_closed bool)string {
	return fmt.Sprintf(
		"{'transport name': '%s', 'uri': '%s', 'proxy': '%s', 'ctx closed': '%t'}",
		scheme, uri, proxy, ctx_closed,
	)
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
	conn, _, err := l.AcceptKey()
	return conn, err
}

func (l *MockTransportListener) AcceptKey() (net.Conn, ed25519.PublicKey, error) {
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

func (t MockTransport) IsSecure() uint {
	return t.SecureLvl
}

func (t MockTransport) Connect(
		ctx context.Context,
		uri url.URL,
		proxy *url.URL,
		key ed25519.PrivateKey,
	) (net.Conn, ed25519.PublicKey, error) {
	opponent_key := getPubKeyFromUri(uri, "mock_tranport_key")
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
		input.Write([]byte(formatMockTransportInfo(t.Scheme, uri, proxy, ctx_closed)))
		buf := make([]byte, 1)
		for {
			_, err := input.Read(buf)
			if err != nil { break }
		}
		input.Close()
	}()	
	return output, nil, nil
}

func (t MockTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (static.TransportListener, error) {
	return &MockTransportListener{t, uri}, nil
}
