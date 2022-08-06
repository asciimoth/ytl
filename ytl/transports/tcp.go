// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package transports

import(
	"net"
	"net/url"
	"context"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/dialers"
)

const TcpScheme = "tcp"

type TcpTransport struct{}

func (t TcpTransport) GetScheme() string {
    return TcpScheme
}

func (t TcpTransport) IsSecure() bool { return false }

func (t TcpTransport) Connect(ctx context.Context, uri url.URL, proxy *url.URL, key ed25519.PrivateKey) (net.Conn, ed25519.PublicKey, error) {
	dialer := dialers.TcpDialer{}
	conn, err := dialer.DialContext(ctx, uri, proxy)
	return conn, nil, err
}

func (t TcpTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (net.Listener, error) {
	return net.Listen(TcpScheme, uri.Host)
}
