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
	"net/url"
	"context"
	"crypto/subtle"
	"crypto/ed25519"
)

type ProtoVersion struct {
	Major uint8
	Minor uint8
}

type AllowList []ed25519.PublicKey

func (a *AllowList) IsAllow(key ed25519.PublicKey) bool {
	if a == nil || key == nil{ return true }
	for _, value := range *a {
		if subtle.ConstantTimeCompare(value, key) == 1 { return true }
	}
	return false
}

type Transport interface {
	GetScheme() string
	IsSecure() bool
	Connect(ctx context.Context, uri url.URL, proxy *url.URL, key ed25519.PrivateKey) (net.Conn, ed25519.PublicKey, error)
	Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (net.Listener, error)
}
