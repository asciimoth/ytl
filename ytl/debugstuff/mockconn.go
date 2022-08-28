// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package debugstuff

import (
	"net"
	"crypto/ed25519"
)

func MockPubKey() []byte {
	buf := MockConnContent()
	metaPkgSize := 38
	return buf[metaPkgSize-ed25519.PublicKeySize:metaPkgSize]
}

func MockConnContent() []byte {
	return []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		0, 4, // Version
		// PublicKey
		194, 220, 146,  21, 237, 163, 168,  31,
		216,  91, 173,   6,  46, 225, 161, 231,
		146, 238,  83, 130, 131,  95, 151, 141,
		143,  73, 142,  61,  27, 142, 160, 212,
		// Some pseudo payload
		0, 1, 0, 1, 0, 1,
		2, 3, 2, 3, 2, 3,
		4, 5, 4, 5, 4, 5,
		6, 7, 6, 7, 6, 7,
		8, 9, 8, 9, 8, 9,
		0, 1, 0, 1, 0, 1,
		2, 3, 2, 3, 2, 3,
		4, 5, 4, 5, 4, 5,
		6, 7, 6, 7, 6, 7,
		8, 9, 8, 9, 8, 9,
	}
}

func MockConn() net.Conn {
	a, b := net.Pipe()
	go func(){
		buf := make([]byte, 1)
		b.Write(MockConnContent())
		for {
			_, err := b.Read(buf)
			if err != nil { break }
		}
		b.Close()
	}()
	return a
}

func MockConnWrongVerContent() []byte {
	return []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		1, 5, // Version
		// PublicKey
		194, 220, 146,  21, 237, 163, 168,  31,
		216,  91, 173,   6,  46, 225, 161, 231,
		146, 238,  83, 130, 131,  95, 151, 141,
		143,  73, 142,  61,  27, 142, 160, 212,
		// Some pseudo payload
		0, 1, 0, 1, 0, 1,
		2, 3, 2, 3, 2, 3,
		4, 5, 4, 5, 4, 5,
		6, 7, 6, 7, 6, 7,
		8, 9, 8, 9, 8, 9,
		0, 1, 0, 1, 0, 1,
		2, 3, 2, 3, 2, 3,
		4, 5, 4, 5, 4, 5,
		6, 7, 6, 7, 6, 7,
		8, 9, 8, 9, 8, 9,
	}
}

func MockWrongVerConn() net.Conn {
	a, b := net.Pipe()
	go func(){
		buf := make([]byte, 1)
		b.Write(MockConnWrongVerContent())
		for {
			_, err := b.Read(buf)
			if err != nil { break }
		}
		b.Close()
	}()
	return a
}

func MockConnTooShortContent() []byte {
	return []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		1, 5, // Version
		// PublicKey
		194, 220, 146,  21, 237, 163, 168,  31,
		216,  91, 173,   6,  46, 225, 161, 231,
		146, 238,  83,
	}
}

func MockTooShortConn() net.Conn {
	a, b := net.Pipe()
	go func(){
		buf := make([]byte, 1)
		b.Write(MockConnTooShortContent())
		for {
			_, err := b.Read(buf)
			if err != nil { break }
		}
		b.Close()
	}()
	return a
}
