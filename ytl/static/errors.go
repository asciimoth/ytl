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

func (e UnknownSchemeError) Timeout() bool { return false }

func (e UnknownSchemeError) Temporary() bool { return false }

type InvalidUriError struct {
	Err string
}

func (e InvalidUriError) Error() string {
	return fmt.Sprintf("Uri is invalid; %s", e.Err)
}

func (e InvalidUriError) Timeout() bool { return false }

func (e InvalidUriError) Temporary() bool { return false }

type IvalidPeerPublicKey struct{
	Text string
}

func (e IvalidPeerPublicKey) Error() string {
	return fmt.Sprintf("Peer public key is invalid; %s", e.Text)
}

func (e IvalidPeerPublicKey) Timeout() bool { return false }

func (e IvalidPeerPublicKey) Temporary() bool { return false }

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

func (e InapplicableProxyTypeError) Timeout() bool { return false }

func (e InapplicableProxyTypeError) Temporary() bool { return false }

type UnknownProtoError struct {}

func (e UnknownProtoError) Error() string {
	return fmt.Sprintf("Unknown protocol")
}

func (e UnknownProtoError) Timeout() bool { return false }

func (e UnknownProtoError) Temporary() bool { return false }

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

func (e UnknownProtoVersionError) Timeout() bool { return false }

func (e UnknownProtoVersionError) Temporary() bool { return false }


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

func (e TransportSecurityCheckError) Timeout() bool { return false }

func (e TransportSecurityCheckError) Temporary() bool { return false }

type ConnClosedByDeduplicatorError struct {}

func (e ConnClosedByDeduplicatorError) Error() string {
	return fmt.Sprintf("Connection closed by deduplicator")
}

func (e ConnClosedByDeduplicatorError) Timeout() bool { return false }

func (e ConnClosedByDeduplicatorError) Temporary() bool { return false }

type UnacceptableAddressError struct {
	Text string
}

func (e UnacceptableAddressError) Error() string {
	return fmt.Sprintf("Unacceptable address: %s", e.Text)
}

func (e UnacceptableAddressError) Timeout() bool { return false }

func (e UnacceptableAddressError) Temporary() bool { return false }

