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
	"fmt"
	"net/url"
	"encoding/hex"
	"crypto/ed25519"
)

type UnknownSchemeError struct {
	Scheme string
}

func (e UnknownSchemeError) Error() string {
	return fmt.Sprintf("Unknown scheme %s", e.Scheme)
}

type InvalidUriError struct {
	Err string
}

func (e InvalidUriError) Error() string {
	return fmt.Sprintf("Uri is invalid; %s", e.Err)
}

// TODO Strore key in ed25519.PublicKey type and convert it to string on fly in Error()
type IvalidPeerPublicKey struct{
	Text string
}

func (e IvalidPeerPublicKey) Error() string {
	return fmt.Sprintf("Peer public key is invalid; %s", e.Text)
}

type ConnTimeoutError struct {}

func (e ConnTimeoutError) Error() string {
	return fmt.Sprintf("Transport connetcion timeout")
}

func (e ConnTimeoutError) Timeout() bool { return true }

func (e ConnTimeoutError) Temporary() bool { return true }

type InapplicableProxyTypeError struct {
	Transport string
	Proxy url.URL
}

func (e InapplicableProxyTypeError) Error() string {
	u := url.URL(e.Proxy)
	url := &u
	return fmt.Sprintf("Proxy type '%s' cannot use with '%s' transport", url.String(), e.Transport)
}

type UnknownProtoError struct {}

func (e UnknownProtoError) Error() string {
	return fmt.Sprintf("Unknown protocol")
}

type UnknownProtoVersionError struct {
	Expected ProtoVersion
	Received ProtoVersion
}

func (e UnknownProtoVersionError) Error() string {
	return fmt.Sprintf(
		"Expected protocol version is %d.%d but received is %d.%d",
		e.Expected.Major, e.Expected.Minor,
		e.Received.Major, e.Received.Minor,
	)
}

type TransportSecurityCheckError struct {
	Expected ed25519.PublicKey
	Received ed25519.PublicKey
}

func (e TransportSecurityCheckError) Error() string {
	return fmt.Sprintf(
		"Transport key is %s but node key is %s",
		hex.EncodeToString(e.Expected),
		hex.EncodeToString(e.Received),
	)
}

type ConnClosedByDeduplicatorError struct {}

func (e ConnClosedByDeduplicatorError) Error() string {
	return fmt.Sprintf("Connection closed by deduplicator")
}
