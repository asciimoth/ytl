// Ytl by DomesticMoth
//
// To the extent possible under law, the person who associated CC0 with
// ytl has waived all copyright and related or neighboring rights
// to ytl.
//
// You should have received a copy of the CC0 legalcode along with this
// work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
package static

const (
	SECURE_LVL_UNSECURE uint = 0
	SECURE_LVL_ENCRYPTED = 1
	SECURE_LVL_SIGNED = 2
	SECURE_LVL_ENCRYPTED_AND_SIGNED = 3
)

// Because there are no constants structures in go
func PROTO_VERSION() ProtoVersion {
	return ProtoVersion{0,4}
}

func META_HEADER() []byte {
	return []byte{'m', 'e', 't', 'a'}
}
