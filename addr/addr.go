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
package addr

import (
	"github.com/DomesticMoth/ytl/static"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"net"
)

func CheckAddr(ip net.IP) error {
	ipaddr := ip.To16()
	if ipaddr != nil {
		var addr address.Address
		var subnet address.Subnet
		copy(addr[:], ipaddr)
		copy(subnet[:], ipaddr)
		if addr.IsValid() || subnet.IsValid() {
			// Destionation addr is inside yggdrasil network
			return static.UnacceptableAddressError{
				Text: "ygg over ygg routing",
			}
		}
	}
	return nil
}
