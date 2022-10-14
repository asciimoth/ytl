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
package dialers

import (
	"net"
	"net/url"
	"testing"
	"github.com/foxcpp/go-mockdns"
	"github.com/DomesticMoth/ytl/static"
)

func testTcpDialerLoopRoutingProtection(
	t *testing.T, addr url.URL, proxy *url.URL, isYggOverYgg bool,
	){
	correct_error_text := static.UnacceptableAddressError{
		Text: "ygg over ygg routing",
	}.Error()
	dialer := TcpDialer{}
	_, err := dialer.Dial(addr, proxy)
	if isYggOverYgg {
		if err == nil {
			t.Errorf("Try ygg over ygg routing must retrun error")
		}else if err.Error() != correct_error_text {
			t.Errorf("Wrong error %s", err)
		}
	}else{
		if err != nil {
			if err.Error() == correct_error_text {
				t.Errorf("Unexcepted ygg over ygg routing error")
			}
		}
	}
}

func TestTcpDialerLoopRoutingProtectionWithDns(t *testing.T){
	srv, _ := mockdns.NewServer(map[string]mockdns.Zone{
	    "ygg.org.": {
	        AAAA: []string{"202:a029:6fa0:f079:7fc:646f:cd3b:6248"},
	    },
	    "localhost.": {
	        AAAA: []string{"::1"},
	    },
	}, false)
	defer srv.Close()
	srv.PatchNet(net.DefaultResolver)
	defer mockdns.UnpatchNet(net.DefaultResolver)
	ygg_addr, _ := url.Parse("tcp://ygg.org:1000")
	normal_addr, _ := url.Parse("tcp://localhost:1000")
	ygg_proxy, _ := url.Parse("socks://ygg.org:1001")
	normal_proxy, _ := url.Parse("socks://localhost:1001")
	testTcpDialerLoopRoutingProtection(t, *ygg_addr, nil, true)
	testTcpDialerLoopRoutingProtection(t, *ygg_addr, ygg_proxy, true)
	testTcpDialerLoopRoutingProtection(t, *normal_addr, ygg_proxy, true)
	testTcpDialerLoopRoutingProtection(t, *normal_addr, nil, false)
	testTcpDialerLoopRoutingProtection(t, *normal_addr, normal_proxy, false)
}
