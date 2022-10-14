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
package ytl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
)

func ketToStr(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}

type connInfo struct {
	closeMethod func()
	isSecure    uint
	connId      uint64
}

type DeduplicationManager struct {
	lockChan    chan struct{}
	connections map[string]connInfo
	connId      uint64
	secureMode  bool
	blockKey    ed25519.PublicKey
}

func NewDeduplicationManager(secureMode bool, blockKey ed25519.PublicKey) *DeduplicationManager {
	lock := make(chan struct{}, 1)
	lock <- struct{}{}
	return &DeduplicationManager{lock, make(map[string]connInfo), 0, secureMode, blockKey}
}

func (d *DeduplicationManager) lock() {
	<-d.lockChan
}

func (d *DeduplicationManager) unlock() {
	d.lockChan <- struct{}{}
}

func (d *DeduplicationManager) onClose(strKey string, connId uint64) {
	d.lock()
	defer d.unlock()
	if value, ok := d.connections[strKey]; ok {
		if value.connId == connId {
			closeMethod := value.closeMethod
			delete(d.connections, strKey)
			if closeMethod != nil {
				closeMethod()
			}
		}
	}
}

func (d *DeduplicationManager) Check(key ed25519.PublicKey, isSecure uint, closeMethod func()) func() {
	d.lock()
	defer d.unlock()
	if d.blockKey != nil && bytes.Compare(d.blockKey, key) == 0 {
		return nil
	}
	strKey := ketToStr(key)
	if value, ok := d.connections[strKey]; ok {
		if !d.secureMode {
			return nil
		}
		if isSecure > value.isSecure {
			if value.closeMethod != nil {
				value.closeMethod()
				value.closeMethod = nil
			}
			connId := d.connId
			d.connId += 1
			d.connections[strKey] = connInfo{
				closeMethod,
				isSecure,
				connId,
			}
			return func() {
				d.onClose(strKey, connId)
			}
		}
		return nil
	}
	connId := d.connId
	d.connId += 1
	d.connections[strKey] = connInfo{
		closeMethod,
		isSecure,
		connId,
	}
	return func() {
		d.onClose(strKey, connId)
	}
}
