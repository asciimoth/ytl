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
	"bytes"
	"testing"
	"crypto/ed25519"
)

func TestDeduplicationManager(t *testing.T){
	manager := NewDeduplicationManager(true)
	chn := make(chan ed25519.PublicKey, 1)
	// Creating a pool of open "connections"
	for i := 0; i < 10; i++ {
		for j := 0; j < 2; j++ {
			secure := false
			if j > 0 {
				secure = true
			}
			key := make(ed25519.PublicKey, i+(10*j))
			cancel := manager.Check(key, secure, func(){ chn <- key })
			if cancel == nil {
				t.Errorf("Negative response when positive was expected") // TODO Add more informative errors
			}
		}
	}
	// Insecure connection with an already existing key that is occupied by other insecure connection
	cancel := manager.Check(make(ed25519.PublicKey, 1), false, func(){})
	if cancel != nil {
		t.Errorf("Positive response when negative was expected")
	}
	// Insecure connection with an already existing key that is occupied by secure connection
	cancel = manager.Check(make(ed25519.PublicKey, 11), false, func(){})
	if cancel != nil {
		t.Errorf("Positive response when negative was expected")
	}
	// Secure connection with an already existing key that is occupied by insecure connection
	key := make(ed25519.PublicKey, 2)
	cancel = manager.Check(key, true, func(){})
	if cancel == nil {
		t.Errorf("Negative response when positive was expected")
	}
	if len(chn) > 0 {
		key2 := <- chn
		if !bytes.Equal(key, key2) {
			t.Errorf("Invalid closing function was called")
		}
	}else{
		t.Errorf("The closing function was not called")
	}
	// Secure connection with an already existing key that is occupied by other secure connection
	cancel = manager.Check(make(ed25519.PublicKey, 12), true, func(){})
	if cancel != nil {
		t.Errorf("Positive response when negative was expected")
	}	
}
