// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package debugstuff

import (
	"testing"
	"bytes"
	"github.com/DomesticMoth/ytl/ytl/static"
)

func TestMockPubKeyGeneration(t *testing.T){
	key := MockPubKey()
	correct := []byte{
		194, 220, 146,  21, 237, 163, 168,  31,
		216,  91, 173,   6,  46, 225, 161, 231,
		146, 238,  83, 130, 131,  95, 151, 141,
		143,  73, 142,  61,  27, 142, 160, 212,
	}
	if bytes.Compare(key, correct) != 0 {
		t.Errorf("Wrong mock PubKey %s", static.TransportSecurityCheckError{
						Expected: correct,
						Received: key,
					})
	}
}
