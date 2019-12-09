package randPwGen

import (
	"os"
	"testing"
)

const passwords_to_generate = 1400000
const password_length = 12

/*
func TestBasicOutput(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	printChars()
	for i := 0; i < 1000; i++ {
		fmt.Println(genPass(6))
	}
	return
}
*/

func TestHive(t *testing.T) {
	H, e := NewHive(passwords_to_generate, password_length, os.Stdout)
	if e != nil {
		t.Fatalf("Error creating password encoder: %s", e)
		return
	}
	H.Generate()
	H.Close()
	return
}
