// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package static

import (
	"net"
	"fmt"
	"net/url"
	"context"
	"crypto/subtle"
	"crypto/ed25519"
)

type ProtoVersion struct {
	Major uint8
	Minor uint8
}

// Cursed hack to make struct printable
func (e ProtoVersion) Error() string {
	return fmt.Sprintf("Version{%d.%d}", e.Major, e.Minor)
}

type AllowList []ed25519.PublicKey

func (a *AllowList) IsAllow(key ed25519.PublicKey) bool {
	if a == nil || key == nil{ return true }
	for _, value := range *a {
		if subtle.ConstantTimeCompare(value, key) == 1 { return true }
	}
	return false
}

type TransportListener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// Accept waits for and returns the next connection with optional transport key to the listener.
	AcceptKey() (net.Conn, ed25519.PublicKey, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

type baseTransportListener struct {
	inner net.Listener
}

func (l *baseTransportListener) Accept() (net.Conn, error) {
	return l.inner.Accept()
}

func (l *baseTransportListener) AcceptKey() (net.Conn, ed25519.PublicKey, error) {
	c, e := l.inner.Accept()
	return c, nil, e
}

func (l *baseTransportListener) Close() error {
	return l.inner.Close()
}

func (l *baseTransportListener) Addr() net.Addr {
	return l.inner.Addr()
}

func ListenerToTransportListener(linstener net.Listener) TransportListener {
	return &baseTransportListener{linstener}
}

type Transport interface {
	GetScheme() string
	IsSecure() bool
	Connect(ctx context.Context, uri url.URL, proxy *url.URL, key ed25519.PrivateKey) (net.Conn, ed25519.PublicKey, error)
	Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (TransportListener, error)
}
