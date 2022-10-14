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
package dialers

import (
	"context"
	"github.com/DomesticMoth/ytl/addr"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"syscall"
	"time"
)

type TcpDialer struct {
	Timeout   time.Duration `default:"2m"`
	KeepAlive time.Duration `default:"15s"`
	Control   func(network, address string, c syscall.RawConn) error
}

func (d *TcpDialer) Dial(uri url.URL, proxy *url.URL) (net.Conn, error) {
	return d.DialContext(context.Background(), uri, proxy)
}

func (d *TcpDialer) DialContext(ctx context.Context, uri url.URL, proxy_uri *url.URL) (net.Conn, error) {
	use_proxy := false
	if proxy_uri != nil {
		use_proxy = proxy_uri.Scheme == "socks" || proxy_uri.Scheme == "socks5" || proxy_uri.Scheme == "socks5h"
	}
	if use_proxy {
		dialerdst, err := net.ResolveTCPAddr("tcp", proxy_uri.Host)
		if err != nil {
			return nil, err
		}
		if err = addr.CheckAddr(dialerdst.IP); err != nil {
			return nil, err
		}
		auth := &proxy.Auth{}
		if proxy_uri.User != nil {
			auth.User = proxy_uri.User.Username()
			auth.Password, _ = proxy_uri.User.Password()
		}
		innerDialer, err := proxy.SOCKS5("tcp", dialerdst.String(), auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, d.Timeout)
		conn, err := innerDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", uri.Host)
		cancel()
		if err != nil {
			return nil, err
		}
		laddr, _, _ := net.SplitHostPort(conn.LocalAddr().String())
		raddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if err = addr.CheckAddr(net.ParseIP(laddr)); err != nil {
			conn.Close()
			return nil, err
		}
		if err = addr.CheckAddr(net.ParseIP(raddr)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, err
	} else {
		dst, err := net.ResolveTCPAddr("tcp", uri.Host)
		if err != nil {
			return nil, err
		}
		if err = addr.CheckAddr(dst.IP); err != nil {
			return nil, err
		}
		innerDialer := net.Dialer{
			Timeout:   d.Timeout,
			KeepAlive: d.KeepAlive,
			Control:   d.Control,
		}
		ctx, cancel := context.WithTimeout(ctx, d.Timeout)
		conn, err := innerDialer.DialContext(ctx, "tcp", dst.String())
		cancel()
		return conn, err
	}
}
