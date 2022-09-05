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
package static

import (
	"net"
	"fmt"
	"net/url"
	"context"
	"crypto/subtle"
	"crypto/ed25519"
)

type ProtoVersion struct {
	Major uint8
	Minor uint8
}

func (e ProtoVersion) String() string {
	return fmt.Sprintf("Version{%d.%d}", e.Major, e.Minor)
}

type AllowList []ed25519.PublicKey

func (a *AllowList) IsAllow(key ed25519.PublicKey) bool {
	if a == nil { return true }
	if key == nil{ return false }
	for _, value := range *a {
		if subtle.ConstantTimeCompare(value, key) == 1 { return true }
	}
	return false
}

type TransportListener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// Accept waits for and returns the next connection with optional transport key to the listener.
	AcceptKey() (net.Conn, ed25519.PublicKey, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

type baseTransportListener struct {
	inner net.Listener
}

func (l *baseTransportListener) Accept() (net.Conn, error) {
	return l.inner.Accept()
}

func (l *baseTransportListener) AcceptKey() (net.Conn, ed25519.PublicKey, error) {
	c, e := l.inner.Accept()
	return c, nil, e
}

func (l *baseTransportListener) Close() error {
	return l.inner.Close()
}

func (l *baseTransportListener) Addr() net.Addr {
	return l.inner.Addr()
}

func ListenerToTransportListener(linstener net.Listener) TransportListener {
	return &baseTransportListener{linstener}
}

type Transport interface {
	GetScheme() string
	IsSecure() uint
	Connect(ctx context.Context, uri url.URL, proxy *url.URL, key ed25519.PrivateKey) (net.Conn, ed25519.PublicKey, error)
	Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (TransportListener, error)
}
