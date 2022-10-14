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

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"
)

func TestGetDurationFromUri(t *testing.T) {
	textDelay := "2s"
	key := "mock_delay_conn"
	delay, _ := time.ParseDuration(textDelay)
	uri, _ := url.Parse(fmt.Sprintf("scheme://addr:137?%s=%s", key, textDelay))
	res := getDurationFromUri(*uri, key)
	if res != delay {
		t.Fatalf("Wrong delay: %s %s", delay, res)
	}
}

func TestMockTransportPeerKey(t *testing.T) {
	transport := MockTransport{"scheme", 0}
	peerKey := MockPubKey()
	uri, _ := url.Parse(
		fmt.Sprintf("scheme://addr:137?mock_peer_key=%s", hex.EncodeToString(peerKey)),
	)
	res, e := transport.Connect(
		context.Background(),
		*uri,
		nil,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
	)
	if e != nil {
		t.Fatalf("Error while connecting: %s", e)
	}
	buf := make([]byte, 6) // 6 is header size
	io.ReadFull(res.Conn, buf)
	peerKeyRecv := make([]byte, len(peerKey))
	io.ReadFull(res.Conn, peerKeyRecv)
	if bytes.Compare(peerKey, peerKeyRecv) != 0 {
		t.Fatalf(
			"Wrong peer public key %s %s",
			hex.EncodeToString(peerKey),
			hex.EncodeToString(peerKeyRecv),
		)
	}
}

func TestMockTransportTransportKey(t *testing.T) {
	transport := MockTransport{"scheme", 0}
	transportKey := MockPubKey()
	uri, _ := url.Parse(
		fmt.Sprintf(
			"scheme://addr:137?mock_transport_key=%s",
			hex.EncodeToString(transportKey),
		),
	)
	res, e := transport.Connect(
		context.Background(),
		*uri,
		nil,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
	)
	if e != nil {
		t.Fatalf("Error while connecting: %s", e)
	}
	if bytes.Compare(transportKey, res.Pkey) != 0 {
		t.Fatalf(
			"Wrong transport public key %s %s",
			hex.EncodeToString(transportKey),
			hex.EncodeToString(res.Pkey),
		)
	}
}

func TestMockTransportInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMockTransportInfo in short mode.")
	}
	transport := MockTransport{"scheme", 0}
	uri, _ := url.Parse("scheme://addr:137")
	p, _ := url.Parse("socks://addr:137")
	proxys := []*url.URL{nil, p}
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for _, proxy := range proxys {
		res, e := transport.Connect(
			context.Background(),
			*uri,
			proxy,
			make(ed25519.PrivateKey, ed25519.PrivateKeySize),
		)
		if e != nil {
			t.Errorf("Error while connecting: %s", e)
		}
		io.ReadFull(res.Conn, make([]byte, 6+ed25519.PublicKeySize)) // 6 is header size
		ri := make(chan string)
		go func() {
			ri <- ReadMockTransportInfo(res.Conn)
		}()
		time.Sleep(1000000000) // Wait for all info writed to conn
		res.Conn.Close()       // Close conn
		recvInfo := <-ri
		correctInfo := FormatMockTransportInfo(
			transport.Scheme,
			*uri,
			proxy,
			false,
			pkey,
		)
		if recvInfo != correctInfo {
			t.Errorf("Wrong transport info '%s' '%s'", correctInfo, recvInfo)
		}
	}
}

func TestMockTransportCloseCTX(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestMockTransportCloseCTX in short mode.")
	}
	delay, _ := time.ParseDuration("2s")
	transport := MockTransport{"scheme", 0}
	uri, _ := url.Parse("scheme://addr:137?mock_delay_conn=2s")
	pkey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for _, closectx := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), delay*2)
		go func() {
			time.Sleep(delay / 2)
			if closectx {
				cancel()
				<-ctx.Done()
			}
		}()
		res, e := transport.Connect(
			ctx,
			*uri,
			nil,
			make(ed25519.PrivateKey, ed25519.PrivateKeySize),
		)
		if e != nil {
			t.Errorf("Error while connecting: %s", e)
		}
		io.ReadFull(res.Conn, make([]byte, 6+ed25519.PublicKeySize)) // 6 is header size
		ri := make(chan string)
		go func() {
			ri <- ReadMockTransportInfo(res.Conn)
		}()
		time.Sleep(delay * 2) // Wait for all info writed to conn
		res.Conn.Close()      // Close conn
		recvInfo := <-ri
		correctInfo := FormatMockTransportInfo(transport.Scheme, *uri, nil, closectx, pkey)
		if recvInfo != correctInfo {
			t.Errorf("Wrong transport info '%s' '%s'", correctInfo, recvInfo)
		}
	}
}
