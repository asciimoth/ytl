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
)

func TestYggConnCorrectReading(t *testing.T){
	data := []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17,17,18,19,20,21,22,23,24,25,26,27,28}
	a, b := net.Pipe()
	yggcon := ConnToYggConn(
		a,
		make(ed25519.PublicKey, ed25519.PublicKeySize),
		nil,
		false,
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
		t.Errorf("Readed data is not eq to writed data [%s] [%s]", data, buf)
	}
}
