// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package addr

import (
	"net"
	"github.com/DomesticMoth/ytl/ytl/static"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

func CheckAddr(ip net.IP) error {
	ipaddr := ip.To16()
	if ipaddr != nil {
		var addr address.Address
		var subnet address.Subnet
		copy(addr[:], ipaddr)
		copy(subnet[:], ipaddr)
		if addr.IsValid() || subnet.IsValid() {
			// Destionation addr is inside yggfrasil network
			return static.UnacceptableAddressError{"ygg voer ygg routing"}
		}
	}
	return nil
}
