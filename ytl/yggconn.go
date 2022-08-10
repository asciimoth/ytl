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
	"net"
	"context"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)


type YggConn struct{
	innerConn net.Conn
	transport_key ed25519.PublicKey
	allowList *static.AllowList
	secureTranport bool
	ctx context.Context
}

func connToYggConn(ctx context.Context, conn net.Conn, transport_key ed25519.PublicKey, allow *static.AllowList, secureTranport bool) *YggConn {
	if conn == nil {return nil}
	return &YggConn{conn, transport_key, allow, secureTranport, ctx}
}

func (y * YggConn) Close() error {
	return y.innerConn.Close()
}

func (y * YggConn) Read(b []byte) (n int, err error) {
	return y.innerConn.Read(b)
}

//Write(b []byte) (n int, err error)
//LocalAddr() Addr
//RemoteAddr() Addr
//SetDeadline(t time.Time) error
//SetReadDeadline(t time.Time) error
//SetWriteDeadline(t time.Time) error

/*type YggListener struct {
	inner_listener net.Listener
}*/
