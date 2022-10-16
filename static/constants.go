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

package static

// Most useful seurity levels
const (
	SECURE_LVL_UNSECURE               uint = 0
	SECURE_LVL_ENCRYPTED                   = 1
	SECURE_LVL_VERIFIED                    = 2
	SECURE_LVL_ENCRYPTED_AND_VERIFIED      = 3
)

// Returns current supported version of yggdrasil protocol
func PROTO_VERSION() ProtoVersion {
	return ProtoVersion{0, 4}
}

// Returns static header of first pkg in yggdrasil connection
func META_HEADER() []byte {
	return []byte{'m', 'e', 't', 'a'}
}
