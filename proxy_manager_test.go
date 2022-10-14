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
	"net/url"
	"testing"
	"regexp"
)

func TestProxyManager(t *testing.T){
	torProxy, _ := url.Parse("proxy://tor")
	i2pProxy, _ := url.Parse("proxy://i2p")
	//
	exampleUri, _ := url.Parse("tcp://exaple.com")
	torUri, _ := url.Parse("tcp://exaple.onion")
	i2pUri, _ := url.Parse("tcp://exaple.i2p")
	//
	mapping := []ProxyMapping{
		ProxyMapping{
			HostRegexp: *regexp.MustCompile(`\.onion$`),
			Proxy: torProxy,
		},
		ProxyMapping{
			HostRegexp: *regexp.MustCompile(`\.i2p$`),
			Proxy: i2pProxy,
		},
	}
	manager := NewProxyManager(nil, mapping)
	if manager.Get(*exampleUri) != nil {
		t.Errorf("Uri '%s' -> proxy '%s'", exampleUri, manager.Get(*exampleUri))
	}
	if manager.Get(*torUri) != torProxy {
		t.Errorf("Uri '%s' -> proxy '%s'", torUri, manager.Get(*torUri))
	}
	if manager.Get(*i2pUri) != i2pProxy {
		t.Errorf("Uri '%s' -> proxy '%s'", i2pUri, manager.Get(*i2pUri))
	}
}
