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
package ytl

import (
	"net/url"
	"time"
	"context"
	"encoding/hex"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/transports"
	"github.com/DomesticMoth/ytl/ytl/static"
)

func materialise(key ed25519.PrivateKey) ed25519.PrivateKey {
	if key != nil {
		return key
	}
	_, spriv, err := ed25519.GenerateKey(nil)
	if err != nil { panic(err) }
	return spriv
}

func transportsListToMap(list []static.Transport) map[string]static.Transport{
	transports_map := make(map[string]static.Transport)
	for _, transport := range list{
		transports_map[transport.GetScheme()] = transport
	}
	return transports_map
}

type ConnManager struct{
	transports map[string]static.Transport
	key ed25519.PrivateKey
	proxyManager ProxyManager
	allowList *static.AllowList
	ctx context.Context
	dm *DeduplicationManager
}

func NewConnManagerWithTransports(
		ctx context.Context, 
		key ed25519.PrivateKey, 
		proxy *ProxyManager, 
		dm *DeduplicationManager, 
		allowList *static.AllowList,
		transports []static.Transport,
	) *ConnManager{
	transports_map := transportsListToMap(transports)
	if proxy == nil {
		p := NewProxyManager(nil, nil)
		proxy = &p
	}
	return &ConnManager{transports_map, key, *proxy, allowList, ctx, dm}
}

func NewConnManager(
		ctx context.Context, 
		key ed25519.PrivateKey, 
		proxy *ProxyManager, 
		dm *DeduplicationManager, 
		allowList *static.AllowList,
	) *ConnManager{
	return NewConnManagerWithTransports(
		ctx,
		key,
		proxy,
		dm,
		allowList,
		transports.DEFAULT_TRANSPORTS(),
	)
}

func (c * ConnManager) innerConnect(ctx context.Context, uri url.URL) (*YggConn, error) {
	var allowList *static.AllowList = nil
	if c.allowList != nil {
		allow := make(static.AllowList, len(*c.allowList))
		copy(allow, *c.allowList)
		allowList = &allow
	}
	if pubkeys, ok := uri.Query()["key"]; ok && len(pubkeys) > 0 {
		var allow static.AllowList
		if allowList == nil {
			allow = make(static.AllowList, 0)
		}else{
			allow = *allowList
		}
		for _, pubkey := range pubkeys {
			if key, err := hex.DecodeString(pubkey); err == nil {
				allow = append(allow, key)
			}
		}
		allowList = &allow
	}
	if transport, ok := c.transports[uri.Scheme]; ok {
		conn, transport_key, err := transport.Connect(ctx, uri, c.proxyManager.Get(uri), materialise(c.key))
		if allowList != nil {
			if !allowList.IsAllow(transport_key) || transport_key == nil{
				conn.Close()
				return nil, static.IvalidPeerPublicKey{
					Text: "Key received from the peer is not in the allow list",
				}
			}
		}
		return ConnToYggConn(conn, transport_key, allowList, transport.IsSecure(), c.dm), err
	}
	return nil, static.UnknownSchemeError{Scheme: uri.Scheme}
}

func (c * ConnManager) Connect(uri url.URL) (*YggConn, error) {
	return c.innerConnect(c.ctx, uri)
}

func (c * ConnManager) ConnectStr(uri string) (*YggConn, error) {
	u, err := url.Parse(uri)
	if err != nil { return nil, err }
	return c.innerConnect(c.ctx, *u)
}

func (c * ConnManager) ConnectCtx(ctx context.Context, uri url.URL) (*YggConn, error) {
	return c.innerConnect(ctx, uri)
}

func (c * ConnManager) ConnectCtxStr(ctx context.Context, uri string) (*YggConn, error) {
	u, err := url.Parse(uri)
	if err != nil { return nil, err }
	return c.innerConnect(ctx, *u)
}

func (c * ConnManager) ConnectTimeout(uri url.URL, timeout time.Duration) (*YggConn, error) {
	type Result struct{
		Conn *YggConn
		Error error
	}
    result := make(chan Result, 1)
    ctx, cancel := context.WithTimeout(c.ctx, timeout)
    go func() {
    	conn, err := c.innerConnect(ctx, uri)
        result <- Result{conn, err}
    }()
    select {
    	case <-time.After(timeout):
    		cancel()
    		go func() {
    			result := <-result
    			if result.Error == nil && result.Conn != nil{
    				result.Conn.Close()
    			}
    		}()
        	return nil, static.ConnTimeoutError{}
    	case result := <-result:
    		cancel()
        	return result.Conn, result.Error
    }
}

func (c * ConnManager) ConnectTimeoutStr(uri string, timeout time.Duration) (*YggConn, error) {
	u, err := url.Parse(uri)
	if err != nil { return nil, err }
	return c.ConnectTimeout(*u, timeout)
}

func (c * ConnManager) Listen(uri url.URL) (ygg YggListener, err error) {
	if transport, ok := c.transports[uri.Scheme]; ok {
		listener, e := transport.Listen(c.ctx, uri, c.key)
		err = e
		if err != nil { return }
		ygg = YggListener{listener, transport.IsSecure(), c.dm, c.allowList}
		return
	}
	err = static.UnknownSchemeError{Scheme: uri.Scheme}
	return
}

func (c * ConnManager) ListenStr(uri string) (ygg YggListener, err error) {
	u, e := url.Parse(uri)
	err = e
	if err != nil { return }
	return c.Listen(*u)
}
