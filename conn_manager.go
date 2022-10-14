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
	"github.com/DomesticMoth/ytl/transports"
	"github.com/DomesticMoth/ytl/static"
)

func KeyFromOptionalKey(key ed25519.PrivateKey) ed25519.PrivateKey {
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

func (c * ConnManager) ConnectCtx(ctx context.Context, uri url.URL) (*YggConn, error) {
	var allowList *static.AllowList = nil
	if c.allowList != nil {
		allow := make(static.AllowList, len(*c.allowList))
		copy(allow, *c.allowList)
		allowList = &allow
	}
	if pubkeys, ok := uri.Query()["key"]; ok && len(pubkeys) > 0 {
		allow := make(static.AllowList, 0)
		for _, pubkey := range pubkeys {
			if key, err := hex.DecodeString(pubkey); err == nil {
				allow = append(allow, key)
			}
		}
		allowList = &allow
	}
	if transport, ok := c.transports[uri.Scheme]; ok {
		conn, err := transport.Connect(
			ctx,
			uri,
			c.proxyManager.Get(uri),
			KeyFromOptionalKey(c.key),
		)
		if allowList != nil {
			if !allowList.IsAllow(conn.Pkey) || conn.Pkey == nil{
				conn.Conn.Close()
				return nil, static.IvalidPeerPublicKey{
					Text: "Key received from the peer is not in the allow list",
				}
			}
		}
		return ConnToYggConn(conn.Conn, conn.Pkey, allowList, conn.SecurityLevel, c.dm), err
	}
	return nil, static.UnknownSchemeError{Scheme: uri.Scheme}
}

func (c * ConnManager) Connect(uri url.URL) (*YggConn, error) {
	return c.ConnectCtx(c.ctx, uri)
}

func (c * ConnManager) ConnectTimeout(uri url.URL, timeout time.Duration) (*YggConn, error) {
	type Result struct{
		Conn *YggConn
		Error error
	}
    result := make(chan Result)
    ctx, cancel := context.WithTimeout(c.ctx, timeout)
    go func() {
    	conn, err := c.ConnectCtx(ctx, uri)
        result <- Result{conn, err}
    }()
    cancel_conn := func(){
 	   	cancel()
 		go func() {
 			result := <-result
 			if result.Error == nil && result.Conn != nil{
 				result.Conn.Close()
 			}
 		}()
    }
    select {
    	case <- ctx.Done():
    		cancel_conn()
        	return nil, static.ConnTimeoutError{}
    	case <- c.ctx.Done():
    		cancel()
    		cancel_conn()
        	return nil, static.ConnTimeoutError{}
    	case result := <-result:
    		cancel()
        	return result.Conn, result.Error
    }
}

func (c * ConnManager) Listen(uri url.URL) (ygg YggListener, err error) {
	if transport, ok := c.transports[uri.Scheme]; ok {
		listener, e := transport.Listen(c.ctx, uri, c.key)
		err = e
		if err != nil { return }
		ygg = YggListener{listener, c.dm, c.allowList}
		return
	}
	err = static.UnknownSchemeError{Scheme: uri.Scheme}
	return
}
