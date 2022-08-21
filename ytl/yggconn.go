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
	"io"
	"net"
	"time"
	"bytes"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)


type YggConn struct{
	innerConn net.Conn
	transport_key ed25519.PublicKey
	allowList *static.AllowList
	secureTranport bool
	extraReadBuffChn chan []byte
	err error
	dm *DeduplicationManager
	closefn func()
	pVersion chan *static.ProtoVersion
	otherPublicKey chan ed25519.PublicKey
	isClosed chan bool
}

func ConnToYggConn(conn net.Conn, transport_key ed25519.PublicKey, allow *static.AllowList, secureTranport bool, dm *DeduplicationManager) *YggConn {
	if conn == nil {return nil}
	isClosed := make(chan bool, 1)
	isClosed <- false
	ret := YggConn{
		conn,
		transport_key,
		allow,
		secureTranport,
		make(chan []byte, 1),
		nil,
		dm,
		func(){},
		make(chan *static.ProtoVersion, 1),
		make(chan ed25519.PublicKey, 1),
		isClosed,
	}
	go ret.middleware()
	return &ret
}

func (y * YggConn) setErr(err error) {
	if y.err == nil {
		y.err = err
	}
	y.Close()
}

// TODO Rewrite this function into something more human readable
func (y * YggConn) middleware() {
	onerror := func(e error) {
		y.setErr(e)
		y.extraReadBuffChn <- nil
	}
	// Read meta header
	buf := make([]byte, len(static.META_HEADER())+2+ed25519.PublicKeySize)
	_, err := io.ReadFull(y.innerConn, buf);
	if err != nil {
		onerror(err)
		return
	}
	if bytes.Compare(static.META_HEADER(), buf[:len(static.META_HEADER())]) != 0 {
		// Unknown proto
		onerror(static.UnknownProtoError{})
		y.pVersion <- nil
		y.otherPublicKey <- nil
		return
	}
	// Return version to requesters
	version := static.ProtoVersion{
		buf[len(static.META_HEADER())],
		buf[len(static.META_HEADER())+1],
	}
	y.pVersion <- &version
	target_version := static.PROTO_VERSION()
	if version.Major != target_version.Major || version.Minor != target_version.Minor {
		// Unknown proto version
		onerror(static.UnknownProtoVersionError{
			Expected: static.PROTO_VERSION(),
			Received: version,
		})
		y.otherPublicKey <- nil
		return
	}
	key_raw := buf[len(buf)-ed25519.PublicKeySize:]
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(key, key_raw)
	y.otherPublicKey <- key
	// TODO check is key is in AllowList
	if y.transport_key != nil {
		if bytes.Compare(y.transport_key, key) != 0 {
			// Invalid transport key
			onerror(static.TransportSecurityCheckError{
				Expected: y.transport_key,
				Received: key,
			})
			return
		}
	}
	// Deduplication
	if y.dm != nil {
		closefunc := y.dm.Check(key, y.secureTranport, func(){
			e := static.ConnClosedByDeduplicatorError{}
			y.setErr(e)
		})
		if closefunc == nil {
			e := static.ConnClosedByDeduplicatorError{}
			onerror(e)
			return
		}
		y.closefn = closefunc
	}
	
	y.extraReadBuffChn <- buf
}

func (y * YggConn) GetVer() (*static.ProtoVersion, error) {
	v := <- y.pVersion
	defer func(){y.pVersion <- v}()
	if v == nil { return nil, y.err }
	return v, nil
}

func (y * YggConn) GetPublicKey() (ed25519.PublicKey, error) {
	k := <- y.otherPublicKey
	defer func(){y.otherPublicKey <- k}()
	if k == nil { return nil, y.err }
	return k, nil
}

func (y * YggConn) Close() (err error) {
	closed := <- y.isClosed
	defer func(){y.isClosed <- closed}()
	closed = true
	if y.closefn != nil && !closed{
		y.closefn()
		y.closefn = func(){}
	}
	err = y.innerConn.Close()
	if y.err != nil { err = y.err }
	return err
}

func (y * YggConn) Read(b []byte) (n int, err error) {
	buf := <- y.extraReadBuffChn
	defer func(){ y.extraReadBuffChn <- buf }()
	if buf != nil {
		err = nil
		n = copy(b, buf)
		if n >= len(buf) {
			buf = nil
		}else{
			buf = buf[n:]
		}
		return
	}
	n, err = y.innerConn.Read(b)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) Write(b []byte) (n int, err error) {
	n, err = y.innerConn.Write(b)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) LocalAddr() net.Addr {
	return y.innerConn.LocalAddr()
}

func (y * YggConn) RemoteAddr() net.Addr {
	return y.innerConn.RemoteAddr()
}

func (y * YggConn) SetDeadline(t time.Time) (err error) {
	err = y.innerConn.SetDeadline(t)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) SetReadDeadline(t time.Time) (err error) {
	err = y.innerConn.SetReadDeadline(t)
	if y.err != nil { err = y.err }
	return
}

func (y * YggConn) SetWriteDeadline(t time.Time) (err error) {
	err = y.innerConn.SetWriteDeadline(t)
	if y.err != nil { err = y.err }
	return
}

/*type YggListener struct {
	inner_listener net.Listener
}*/
