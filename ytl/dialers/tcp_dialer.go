// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package dialers

import (
	"net"
	"net/url"
	"time"
	"syscall"
	"context"
	"golang.org/x/net/proxy"
)

type TcpDialer struct {
	Timeout time.Duration `default:"2m"`
	KeepAlive time.Duration `default:"15s"`
	Control func(network, address string, c syscall.RawConn) error
}

func (d *TcpDialer) Dial(uri url.URL, proxy *url.URL) (net.Conn, error) {
	return d.DialContext(context.Background(), uri, proxy)
}

func (d *TcpDialer) DialContext(ctx context.Context, uri url.URL, proxy_uri *url.URL) (net.Conn, error) {
	use_proxy := false
	if proxy_uri != nil {
		use_proxy = proxy_uri.Scheme == "socks" || proxy_uri.Scheme == "socks5" || proxy_uri.Scheme == "socks5h"
	}
	if use_proxy {
		dialerdst, err := net.ResolveTCPAddr("tcp", proxy_uri.Host)
		if err != nil { return nil, err }
		auth := &proxy.Auth{}
		if proxy_uri.User != nil {
			auth.User = proxy_uri.User.Username()
			auth.Password, _ = proxy_uri.User.Password()
		}
		innerDialer, err := proxy.SOCKS5("tcp", dialerdst.String(), auth, proxy.Direct)
		if err != nil { return nil, err }
		ctx, cancel := context.WithTimeout(ctx, d.Timeout)
		conn, err := innerDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", uri.Host)
		cancel()
		return conn, err
	}else{
		dst, err := net.ResolveTCPAddr("tcp", uri.Host)
		if err != nil { return nil, err }
		innerDialer := net.Dialer{
			Timeout: d.Timeout,
			KeepAlive: d.KeepAlive,
			Control: d.Control,
		}
		ctx, cancel := context.WithTimeout(ctx, d.Timeout)
		conn, err := innerDialer.DialContext(ctx, "tcp", dst.String())
		cancel()
		return conn, err
	}
}
