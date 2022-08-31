// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package ytl

import (
	"encoding/hex"
	"crypto/ed25519"
)

func ketToStr(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}

type connInfo struct {
	closeMethod func()
	isSecure uint
	connId uint64
}

type DeduplicationManager struct {
	lockChan chan struct{}
	connections map[string]connInfo
	connId uint64
	secureMode bool
}

func NewDeduplicationManager(secureMode bool) *DeduplicationManager {
	lock := make(chan struct{}, 1)
	lock <- struct{}{}
	return &DeduplicationManager{lock, make(map[string]connInfo), 0, secureMode}
}

func (d *DeduplicationManager) lock() {
	<- d.lockChan
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
			delete(d.connections, strKey);
			if closeMethod != nil {
				closeMethod()
			}
		}
	}
}

func (d *DeduplicationManager) Check(key ed25519.PublicKey, isSecure uint, closeMethod func()) func(){
	d.lock()
	defer d.unlock()
	strKey := ketToStr(key)
	if value, ok := d.connections[strKey]; ok {
		if !d.secureMode { return nil }
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
			return func(){
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
	return func(){
		d.onClose(strKey, connId)
	}
}
