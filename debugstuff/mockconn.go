// Copyright 2022 DomesticMoth
//
// This file is part of Ytl.
//
// Ytl is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// Ytl is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
package debugstuff

import (
	"crypto/ed25519"
	"net"
)

func MockPubKey() []byte {
	buf := MockConnContent()
	metaPkgSize := 38
	return buf[metaPkgSize-ed25519.PublicKeySize : metaPkgSize]
}

func MockConnContent() []byte {
	return []byte{
		109, 101, 116, 97, // 'm' 'e' 't' 'a'
		0, 4, // Version
		// PublicKey
		194, 220, 146, 21, 237, 163, 168, 31,
		216, 91, 173, 6, 46, 225, 161, 231,
		146, 238, 83, 130, 131, 95, 151, 141,
		143, 73, 142, 61, 27, 142, 160, 212,
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
	go func() {
		buf := make([]byte, 1)
		b.Write(MockConnContent())
		for {
			_, err := b.Read(buf)
			if err != nil {
				break
			}
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
		194, 220, 146, 21, 237, 163, 168, 31,
		216, 91, 173, 6, 46, 225, 161, 231,
		146, 238, 83, 130, 131, 95, 151, 141,
		143, 73, 142, 61, 27, 142, 160, 212,
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
	go func() {
		buf := make([]byte, 1)
		b.Write(MockConnWrongVerContent())
		for {
			_, err := b.Read(buf)
			if err != nil {
				break
			}
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
		194, 220, 146, 21, 237, 163, 168, 31,
		216, 91, 173, 6, 46, 225, 161, 231,
		146, 238, 83,
	}
}

func MockTooShortConn() net.Conn {
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 1)
		b.Write(MockConnTooShortContent())
		for {
			_, err := b.Read(buf)
			if err != nil {
				break
			}
		}
		b.Close()
	}()
	return a
}
