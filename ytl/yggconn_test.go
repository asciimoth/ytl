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
	"time"
	"testing"
	"encoding/hex"
	"crypto/ed25519"
	"github.com/DomesticMoth/ytl/ytl/static"
	"github.com/DomesticMoth/ytl/ytl/debugstuff"
)

type CaseTestParceMetaPackage struct {
	conn net.Conn
	err error
	version *static.ProtoVersion
	pkey ed25519.PublicKey
	buf []byte
}

func TestParceMetaPackage(t *testing.T){
	v := static.PROTO_VERSION()
	v2 := static.ProtoVersion{1,5}
	cases := []CaseTestParceMetaPackage{
		CaseTestParceMetaPackage{
			debugstuff.MockConn(),
			nil,
			&v,
			debugstuff.MockPubKey(),
			debugstuff.MockConnContent()[:38],
		},
		CaseTestParceMetaPackage{
			debugstuff.MockWrongVerConn(),
			static.UnknownProtoVersionError{
				Expected: static.PROTO_VERSION(),
				Received: v2,
			},
			&v2,
			nil,
			debugstuff.MockConnWrongVerContent()[:38],
		},
		CaseTestParceMetaPackage{
			debugstuff.MockTooShortConn(),
			static.ConnTimeoutError{},
			nil,
			nil,
			nil,
		},
	};
	for _, cse := range cases {
		err, version, pkey, buf := parceMetaPackage(cse.conn, time.Second/2)
		if err != cse.err {
			t.Errorf("Wrong err %s %s", err, cse.err);
			return
		}
		if version != nil && cse.version != nil {
			if version.Major != cse.version.Major || version.Minor != cse.version.Minor {
				t.Errorf("Wrong verison %s %s", version, cse.version);
				return
			}
		} else if version != cse.version {
			t.Errorf("Wrong verison %s %s", version, cse.version);
			return
		}
		if bytes.Compare(pkey, cse.pkey) != 0 {
			t.Errorf(
				"Wrong PublicKey %s %s", 
				hex.EncodeToString(pkey),
				hex.EncodeToString(cse.pkey),
			);
			return
		}
		if bytes.Compare(buf, cse.buf) != 0 {
			t.Errorf(
				"Wrong buf %s %s",
				hex.EncodeToString(buf),
				hex.EncodeToString(cse.buf),
			);
			return
		}
	}
}

func TestYggConnCorrectReading(t *testing.T){
	for i := 0; i < 2; i++ {
		strictMode := false
		if i > 0 { strictMode = true }
		for j := 0; j < 2; j++ {
			secure := false
			if j > 0 { secure = true }
			data := debugstuff.MockConnContent()
			a := debugstuff.MockConn()
			dm := NewDeduplicationManager(strictMode)
			yggcon := ConnToYggConn(
				a,
				debugstuff.MockPubKey(),
				nil,
				secure,
				dm,
			)
			defer yggcon.Close()
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
				if bytes.Compare(key, debugstuff.MockPubKey()) != 0 {
					t.Errorf("Invalid key")
				}
			}
		}
	}
}

func yggConnTestCollision(
		t *testing.T, 
		n1, n2 bool, // secure params for connections
		n int, // The number of the connection to be CLOSED
	) {
	dm := NewDeduplicationManager(true)
	a := debugstuff.MockConn()
	b := debugstuff.MockConn()
	yggcon1 := ConnToYggConn(
		a,
		debugstuff.MockPubKey(),
		nil,
		n1,
		dm,
	)
	yggcon2 := ConnToYggConn(
		b,
		debugstuff.MockPubKey(),
		nil,
		n2,
		dm,
	)
	defer yggcon1.Close()
	defer yggcon2.Close()
	buf := make([]byte, 1)
	var err1, err2 error
	if n == 1 {
		_, err1 = io.ReadFull(yggcon2, buf)
		_, err2 = io.ReadFull(yggcon1, buf)
	}else{
		_, err1 = io.ReadFull(yggcon1, buf)
		_, err2 = io.ReadFull(yggcon2, buf)
	}
	if err1 != nil {
		t.Errorf("Wrong conn was closed: %s", err1)
		return
	}
	if err2 == nil {
		t.Errorf("Connection was not closed")
		return
	}
	switch err2.(type) {
		case static.ConnClosedByDeduplicatorError:
		    // Ok
		default:
		    t.Errorf("Connection was not closed by deduplicator: %s", err2)
		    return
	}
}

/*func TestYggConnCollisionII(t *testing.T){
	yggConnTestCollision(t, false, false, 2)
}*/

/*func TestYggConnTestCollisionIS(t *testing.T){
	yggConnTestCollision(t, false, true, 1)
}

func TestYggConnTestCollisionSI(t *testing.T){
	yggConnTestCollision(t, true, false, 2)
}

func TestYggConnTestCollisionSS(t *testing.T){
	yggConnTestCollision(t, true, false, 2)
}*/

/*
func YggConnTestCollisionIS2(t *testing.T){
	n1 := false
	n2 := true
	n := 1
	yggConnTestCollision(t, n1, n2, n)
}*/

/*func TestYggConnDedplication(t *testing.T){
	dm := NewDeduplicationManager(true)
	data := MokeConnContent()
	a, c := net.Pipe()
	b, d := net.Pipe()
	yggcon1 := ConnToYggConn(
		a,
		MokeKey(),
		nil,
		false,
		dm,
	)
	yggcon2 := ConnToYggConn(
		b,
		MokeKey(),
		nil,
		true,
		dm,
	)
	defer yggcon1.Close()
	defer yggcon2.Close()
	defer d.Close()
	defer c.Close()
	go func() {
		c.Write(data)
	}()
	go func() {
		d.Write(data)
	}()
	buf := make([]byte, 1)
	io.ReadFull(yggcon2, buf)
	_, err := io.ReadFull(yggcon1, buf)
	if err == nil {
		t.Errorf("Connection is not closed")
		return
	}
	switch err.(type) {
		case static.ConnClosedByDeduplicatorError:
		    // Ok
		default:
		    t.Errorf("Connection is not closed by deduplicator %s", err)
		    return
	}
}*/

/*func TestYggConnDedplication2(t *testing.T){
	n1 := false
	n2 := true
	n := 1
	yggConnTestCollision(t, n1, n2, n)
	/*dm := NewDeduplicationManager(true)
	data := MokeConnContent()
	a, c := net.Pipe()
	b, d := net.Pipe()
	yggcon1 := ConnToYggConn(
		a,
		MokeKey(),
		nil,
		n1,
		dm,
	)
	yggcon2 := ConnToYggConn(
		b,
		MokeKey(),
		nil,
		n2,
		dm,
	)
	defer yggcon1.Close()
	defer yggcon2.Close()
	defer d.Close()
	defer c.Close()
	go func() {
		c.Write(data)
	}()
	go func() {
		d.Write(data)
	}()
	buf := make([]byte, 1)
	var err1, err2 error
	if n == 1 {
		_, err1 = io.ReadFull(yggcon2, buf)
		_, err2 = io.ReadFull(yggcon1, buf)
	}else{
		_, err1 = io.ReadFull(yggcon1, buf)
		_, err2 = io.ReadFull(yggcon2, buf)
	}
	if err1 != nil {
		t.Errorf("Wrong conn was closed %s", err1)
		return
	}
	if err2 == nil {
		t.Errorf("Connection was not closed")
		return
	}
	switch err2.(type) {
		case static.ConnClosedByDeduplicatorError:
		    // Ok
		default:
		    t.Errorf("Connection was not closed by deduplicator %s", err2)
	}
}*/
