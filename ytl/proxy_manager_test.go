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
