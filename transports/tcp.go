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
package transports

import (
	"context"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/dialers"
	"github.com/DomesticMoth/ytl/static"
	"net"
	"net/url"
)

const TcpScheme = "tcp"

type TcpTransport struct{}

func (t TcpTransport) GetScheme() string {
	return TcpScheme
}

func (t TcpTransport) Connect(ctx context.Context, uri url.URL, proxy *url.URL, key ed25519.PrivateKey) (static.ConnResult, error) {
	dialer := dialers.TcpDialer{}
	conn, err := dialer.DialContext(ctx, uri, proxy)
	return static.ConnResult{
		Conn:          conn,
		Pkey:          nil,
		SecurityLevel: static.SECURE_LVL_UNSECURE,
	}, err
}

func (t TcpTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (static.TransportListener, error) {
	l, e := net.Listen(TcpScheme, uri.Host)
	return static.ListenerToTransportListener(l, static.SECURE_LVL_UNSECURE), e
}
