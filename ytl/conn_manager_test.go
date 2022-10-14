// Ytl
// Copyright (C) 2022 DomesticMoth <silkmoth@protonmail.com>
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
package ytl

import (
	"testing"
	"crypto/ed25519"
)

func TestKeyFromOptionalKey(t *testing.T){
	for _, opt := range []ed25519.PrivateKey{
		nil,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
	}{
		if KeyFromOptionalKey(opt) == nil {
			t.Fatalf("Key must not be nil");
		}
	}
}
