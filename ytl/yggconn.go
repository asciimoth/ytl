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
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)


type YggConn struct{
	innerConn net.Conn
	transport_key ed25519.PublicKey
	allowList *static.AllowList
	secureTranport bool
	extraReadBuffChn chan []byte
}

func ConnToYggConn(conn net.Conn, transport_key ed25519.PublicKey, allow *static.AllowList, secureTranport bool) *YggConn {
	if conn == nil {return nil}
	ret := YggConn{conn, transport_key, allow, secureTranport, make(chan []byte, 1)}
	go ret.middleware()
	return &ret
}

func (y * YggConn) middleware() {
	// Read first packet
	buff := make([]byte, 10)
	_, err := io.ReadFull(y.innerConn, buff);
	if err != nil {
		y.extraReadBuffChn <- nil
		return
	}
	// Parse first packet
	y.extraReadBuffChn <- buff
}

func (y * YggConn) Close() error {
	return y.innerConn.Close()
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
	return
}

func (y * YggConn) Write(b []byte) (n int, err error) {
	return y.innerConn.Write(b)
}

func (y * YggConn) LocalAddr() net.Addr {
	return y.innerConn.LocalAddr()
}

func (y * YggConn) RemoteAddr() net.Addr {
	return y.innerConn.RemoteAddr()
}

func (y * YggConn) SetDeadline(t time.Time) error {
	return y.innerConn.SetDeadline(t)
}

func (y * YggConn) SetReadDeadline(t time.Time) error {
	return y.innerConn.SetReadDeadline(t)
}

func (y * YggConn) SetWriteDeadline(t time.Time) error {
	return y.innerConn.SetWriteDeadline(t)
}

/*type YggListener struct {
	inner_listener net.Listener
}*/
