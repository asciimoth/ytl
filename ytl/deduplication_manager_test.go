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
	//"bytes"
	"testing"
	"crypto/ed25519"
)

func testCollision(
		t *testing.T, 
		n1, n2 bool, // secure params for connections
		n int, // The number of the connection to be CLOSED
	) {
	manager := NewDeduplicationManager(true)
	closeChn := make(chan int, 10)
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	cancel1 := manager.Check(key, n1, func(){ closeChn <- 1 })
	cancel2 := manager.Check(key, n2, func(){ closeChn <- 2 })
	if cancel1 == nil {
		t.Errorf("Connection 1 was closed at the start")
		return
	}
	if len(closeChn) > 1 {
		t.Errorf("Connection close callback was called more than once")
		return
	}
	if len(closeChn) == 1 {
		c := <- closeChn
		closeChn <- c
		if c == 2 {
			t.Errorf("Second conn callback was called")
			return
		}
	}
	if n == 1 {
		if len(closeChn) < 1 {
			t.Errorf("First connection was not closed")
			if cancel2 == nil {
				t.Errorf("Second connection was closed instead")
			}
		}
	}else{
		if cancel2 != nil {
			t.Errorf("Second connection was not closed")
			if len(closeChn) > 0 {
				t.Errorf("First connection was closed instead")
			}
		}
	}
}

func TestCollisionII(t *testing.T){
	testCollision(t, false, false, 2)
}

func TestCollisionIS(t *testing.T){
	testCollision(t, false, true, 1)
}

func TestCollisionSI(t *testing.T){
	testCollision(t, true, false, 2)
}

func TestCollisionSS(t *testing.T){
	testCollision(t, true, false, 2)
}

func TestNoCollision(t *testing.T){
	manager := NewDeduplicationManager(true)
	chn := make(chan ed25519.PublicKey, 1)
	for i := 0; i < 10; i++ {
		for j := 0; j < 2; j++ {
			secure := false
			if j > 0 {
				secure = true
			}
			key := make(ed25519.PublicKey, i+(10*j))
			cancel := manager.Check(key, secure, func(){ chn <- key })
			if cancel == nil {
				t.Errorf("Connection closed")
				return
			}
		}
	}
	if len(chn) > 0 {
		t.Errorf("Connection closed")
		return
	}
}
