// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package debugstuff

import(
	"fmt"
	"net"
	"time"
	"net/url"
	"context"
	"encoding/hex"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)

type MockTransportListener struct {
	transport static.Transport
	uri url.URL
}

func (l *MockTransportListener) Accept() (net.Conn, error) {
	conn, _, err := l.AcceptKey()
	return conn, err
}

func (l *MockTransportListener) AcceptKey() (net.Conn, ed25519.PublicKey, error) {
	ctx := context.Background()
	return l.transport.Connect(ctx, l.uri, nil, nil)
}

func (l *MockTransportListener) Close() error {
	return nil
}

func (l *MockTransportListener) Addr() net.Addr {
	return nil
}

type MockTransport struct{
	Scheme string
	SecureLvl uint
}

func (t MockTransport) GetScheme() string {
    return t.Scheme
}

func (t MockTransport) IsSecure() uint {
	return t.SecureLvl
}

func (t MockTransport) Connect(
		ctx context.Context,
		uri url.URL,
		proxy *url.URL,
		key ed25519.PrivateKey,
	) (net.Conn, ed25519.PublicKey, error) {
	opponent_key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	delay_conn := time.Second * 0
	delay_before_meta := time.Second * 0
	delay_after_meta := time.Second * 0
	if pubkeys, ok := uri.Query()["mock_tranport_key"]; ok && len(pubkeys) > 0 {
		for _, pubkey := range pubkeys {
			if opkey, err := hex.DecodeString(pubkey); err == nil {
				opponent_key = opkey
			}
		}
	}
	input, output := net.Pipe()
	header := []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		0, 4, // Version
	}
	info := fmt.Sprintf("{'transport name': '%s', 'uri': '%s', 'proxy': '%s'}", t.Scheme, uri, proxy)
	time.Sleep(delay_conn)
	go func(){
		time.Sleep(delay_before_meta)
		input.Write(header)
		input.Write(opponent_key)
		time.Sleep(delay_after_meta)
		input.Write([]byte(info))
		buf := make([]byte, 1)
		for {
			_, err := input.Read(buf)
			if err != nil { break }
		}
		input.Close()
	}()	
	return output, nil, nil
}

func (t MockTransport) Listen(ctx context.Context, uri url.URL, key ed25519.PrivateKey) (static.TransportListener, error) {
	return &MockTransportListener{t, uri}, nil
}
