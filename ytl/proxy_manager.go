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
	"regexp"
	"net/url"
)

type ProxyMapping struct {
	HostRegexp regexp.Regexp
	Proxy *url.URL
}

type ProxyManager struct {
	defaultProxy *url.URL
	mapping []ProxyMapping
}

func NewProxyManager(defaultProxy *url.URL, mapping []ProxyMapping) ProxyManager{
	if mapping == nil {
		mapping = make([]ProxyMapping, 0)
	}
	return ProxyManager{defaultProxy, mapping}
}

func (p * ProxyManager) Get(uri url.URL) *url.URL {
	for _, mapping := range p.mapping {
		if mapping.HostRegexp.MatchString(uri.Host) {
			return mapping.Proxy
		}
	}
	return p.defaultProxy
}
