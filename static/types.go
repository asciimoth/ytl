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

// Package static implements interfaces, types and constants 
// used in the rest of the project modules.
//
// Through this package, the others communicate with each other.
package static

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
)

// ProtoVersion is the representation of yggdrasil protocol semantic version.
type ProtoVersion struct {
	Major uint8 // For now, it is always 0
	Minor uint8
}
 
func (e ProtoVersion) String() string {
	return fmt.Sprintf("Version{%d.%d}", e.Major, e.Minor)
}

// AllowList is a list of public keys of nodes 
// that are allowed to communicate with the current.
//
// AllowList can be equal to nil.
// This should be interpreted as a connection permission for any nodes.
type AllowList []ed25519.PublicKey

// Checks whether the passed key is in the allowed list.
//
// If AllowList is nil, it always returns true.
func (a *AllowList) IsAllow(key ed25519.PublicKey) bool {
	if a == nil {
		return true
	}
	if key == nil {
		return false
	}
	for _, value := range *a {
		if subtle.ConstantTimeCompare(value, key) == 1 {
			return true
		}
	}
	return false
}

// ConnResult contains information received
// when establishing a transport connection with another node
type ConnResult struct {
	// The connection itself
	Conn          net.Conn
	// Optional transport lvl public key (may be nil)
	Pkey          ed25519.PublicKey
	// Lvl of connection security
	// Here is most used values:
	// - ytl.static.SECURE_LVL_UNSECURE
	// - ytl.static.SECURE_LVL_ENCRYPTED
	// - ytl.static.SECURE_LVL_VERIFIED
	// - ytl.static.SECURE_LVL_ENCRYPTED_AND_VERIFIED
	SecurityLevel uint
}

// TransportListener is similar to [net.Listener]
// except extra "AcceptConn" metod.
type TransportListener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// AcceptConn waits for and returns the next connection
	// with optional transport key to the listener.
	AcceptConn() (ConnResult, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

// Simle TransportListener wrapper for regular [net.Listener].
type baseTransportListener struct {
	inner         net.Listener
	securityLevel uint
}

func (l *baseTransportListener) Accept() (net.Conn, error) {
	return l.inner.Accept()
}

func (l *baseTransportListener) AcceptConn() (ConnResult, error) {
	c, e := l.inner.Accept()
	return ConnResult{c, nil, l.securityLevel}, e
}

func (l *baseTransportListener) Close() error {
	return l.inner.Close()
}

func (l *baseTransportListener) Addr() net.Addr {
	return l.inner.Addr()
}

// Wraps regular [net.Listener] to TransportListener.
func ListenerToTransportListener(linstener net.Listener, secLvl uint) TransportListener {
	return &baseTransportListener{linstener, secLvl}
}

// Abstract interface for all transports realisations like tcp/tls/etc.
type Transport interface {
	// Returns URI scheme of current transport.
	// As example "tcp" or "tls".
	GetScheme() string
	// Establishes and returns a transport connection or returns an error.
	Connect(
		ctx context.Context, uri url.URL, 
		proxy *url.URL, key ed25519.PrivateKey,
	) (ConnResult, error)
	// Returns listener object for accepting incoming transport connections.
	Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (TransportListener, error)
}
