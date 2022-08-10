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
	"bytes"
	"testing"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
)

func MokeKey() []byte {
	buf := MokeConnContent()
	return buf[len(buf)-ed25519.PublicKeySize:]
}

func MokeConnContent() []byte {
	return []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		0, 4, // Version
		// PublicKey
		194, 220, 146,  21, 237, 163, 168,  31,
		216,  91, 173,   6,  46, 225, 161, 231,
		146, 238,  83, 130, 131,  95, 151, 141,
		143,  73, 142,  61,  27, 142, 160, 212,
	}
}

func TestYggConnCorrectReading(t *testing.T){
	data := MokeConnContent()
	a, b := net.Pipe()
	yggcon := ConnToYggConn(
		a,
		MokeKey(),
		nil,
		false,
		nil,
	)
	go func() {
		b.Write(data)
		b.Close()
	}()
	buf := make([]byte, len(data))
	n, err := io.ReadFull(yggcon, buf)
	if err != nil {
		t.Errorf("Error while reading from yggcon '%s'", err)
		t.Errorf("Readed only %d bytes from %d", n, len(data))
	}
	buf = buf[:n]
	if bytes.Compare(data, buf) != 0 {
		t.Errorf("Readed data is not eq to writed data")
	}
	target_version := static.PROTO_VERSION()
	version, err := yggcon.GetVer()
	if err != nil {
		t.Errorf("Error while reading verdion %s", err)
	}else{
		if version.Major != target_version.Major || version.Minor != target_version.Minor {
			t.Errorf("Invalid version")
		}
	}
	key, err := yggcon.GetPublicKey()
	if err != nil {
		t.Errorf("Error while reading public key %s", err)
	}else{
		if bytes.Compare(key, MokeKey()) != 0 {
			t.Errorf("Invalid key")
		}
	}
}
