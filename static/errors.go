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
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/url"
)

type UnknownSchemeError struct {
	Scheme string
}

func (e UnknownSchemeError) Error() string {
	return fmt.Sprintf("Unknown scheme %s", e.Scheme)
}

func (e UnknownSchemeError) Timeout() bool { return false }

func (e UnknownSchemeError) Temporary() bool { return false }

type InvalidUriError struct {
	Err string
}

func (e InvalidUriError) Error() string {
	return fmt.Sprintf("Uri is invalid; %s", e.Err)
}

func (e InvalidUriError) Timeout() bool { return false }

func (e InvalidUriError) Temporary() bool { return false }

type IvalidPeerPublicKey struct {
	Text string
}

func (e IvalidPeerPublicKey) Error() string {
	return fmt.Sprintf("Peer public key is invalid; %s", e.Text)
}

func (e IvalidPeerPublicKey) Timeout() bool { return false }

func (e IvalidPeerPublicKey) Temporary() bool { return false }

type ConnTimeoutError struct{}

func (e ConnTimeoutError) Error() string {
	return fmt.Sprintf("Transport connetcion timeout")
}

func (e ConnTimeoutError) Timeout() bool { return true }

func (e ConnTimeoutError) Temporary() bool { return true }

type InapplicableProxyTypeError struct {
	Transport string
	Proxy     url.URL
}

func (e InapplicableProxyTypeError) Error() string {
	u := url.URL(e.Proxy)
	url := &u
	return fmt.Sprintf("Proxy type '%s' cannot use with '%s' transport", url.String(), e.Transport)
}

func (e InapplicableProxyTypeError) Timeout() bool { return false }

func (e InapplicableProxyTypeError) Temporary() bool { return false }

type UnknownProtoError struct{}

func (e UnknownProtoError) Error() string {
	return fmt.Sprintf("Unknown protocol")
}

func (e UnknownProtoError) Timeout() bool { return false }

func (e UnknownProtoError) Temporary() bool { return false }

type UnknownProtoVersionError struct {
	Expected ProtoVersion
	Received ProtoVersion
}

func (e UnknownProtoVersionError) Error() string {
	return fmt.Sprintf(
		"Expected protocol version is %d.%d but received is %d.%d",
		e.Expected.Major, e.Expected.Minor,
		e.Received.Major, e.Received.Minor,
	)
}

func (e UnknownProtoVersionError) Timeout() bool { return false }

func (e UnknownProtoVersionError) Temporary() bool { return false }

type TransportSecurityCheckError struct {
	Expected ed25519.PublicKey
	Received ed25519.PublicKey
}

func (e TransportSecurityCheckError) Error() string {
	return fmt.Sprintf(
		"Transport key is %s but node key is %s",
		hex.EncodeToString(e.Expected),
		hex.EncodeToString(e.Received),
	)
}

func (e TransportSecurityCheckError) Timeout() bool { return false }

func (e TransportSecurityCheckError) Temporary() bool { return false }

type ConnClosedByDeduplicatorError struct{}

func (e ConnClosedByDeduplicatorError) Error() string {
	return fmt.Sprintf("Connection closed by deduplicator")
}

func (e ConnClosedByDeduplicatorError) Timeout() bool { return false }

func (e ConnClosedByDeduplicatorError) Temporary() bool { return false }

type UnacceptableAddressError struct {
	Text string
}

func (e UnacceptableAddressError) Error() string {
	return fmt.Sprintf("Unacceptable address: %s", e.Text)
}

func (e UnacceptableAddressError) Timeout() bool { return false }

func (e UnacceptableAddressError) Temporary() bool { return false }
