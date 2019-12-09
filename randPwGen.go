package randPwGen

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	prand "math/rand"

	"github.com/koepkeca/goSafeDataStruct/safeTrie"
)

//char_pool contains the pool of available characters to be selected for the passwords.
//for simplicity I use [A-Z] && [0-9] && [a-z]. It could also be prudent to use [!-)] but
//sometimes this creates more confusion for users than it's worth.
var char_pool = [...]string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
	"L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1",
	"2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g",
	"h", "i", "j", "i", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
	"w", "x", "y", "z"}

//PwHive stores the configuration for the creation as well as the
//Trie we use to determine if a password has been generated already.
type PwHive struct {
	GenLen  int
	PwLen   int
	T       *safeTrie.SafeTrie
	WriteTo io.Writer
	RandSrc *prand.Rand
}

//NewHive takes (nbr) number of passwords to generate (pw_len) the length of the password
// as well as an io.Writer to write the output to. It returns a new, functioning Hive.
//We are seeding the psuedo random number generator with cryptographically secure random data.
func NewHive(nbr, pw_len int, w io.Writer) (p PwHive, e error) {
	//Generate the random seed from crypto/rand
	var seeder [8]byte
	_, e = crand.Read(seeder[:])
	if e != nil {
		return
	}
	p.RandSrc = prand.New(prand.NewSource(int64(binary.LittleEndian.Uint64(seeder[:]))))
	p.GenLen = nbr
	p.PwLen = pw_len
	p.WriteTo = w
	p.T = safeTrie.New()
	return
}

//Close performs a cleanup of the Trie.
func (p PwHive) Close() {
	p.T.Destroy()
	return
}

//Generate is the main loop, it will generate p.GenLen random unique passwords of
//p.PwLen length. The output is written to p.WriteTo.
//This function is a prototype, a complete program would have command line paramaters
//as well as better error management. In this case, any error is logged to stdout and
//the password is regenerated.
func (p PwHive) Generate() {
	colCtr := 0
	pwGend := 0
	errCtr := 0
	mapOk := make([]interface{}, 1)
	mapOk = append(mapOk, true)
	//Primary loop, in the event you would be reading users from a database collection, this
	//main loop would be the userlist.
	for i := 0; i < p.GenLen; i++ {
		tmpPw := p.genPass()
		r, e := p.T.Get(tmpPw)
		if e != nil {
			log.Printf("%s", e)
			i--
			errCtr++
		}
		//if the returned value from the get is not nil, then we know the password
		//already exists in the hive and should not be added, we decrement the counter
		//increase the collision counter and try again.
		if r != nil {
			i--
			colCtr++
			continue
		}
		pwGend++
		p.T.Insert(tmpPw, mapOk)
		if e != nil {
			log.Printf("%s", e)
			i--
			errCtr++
		}
		_, e = io.WriteString(p.WriteTo, fmt.Sprintf("%s\n", tmpPw))
		if e != nil {
			log.Printf("%s", e)
			i--
			errCtr++

		}
		//If we were encrypting/encoding the passwords, this would occur here.
	}
	fmt.Printf("There were %d passwords generated with %d collisions and %d errors.\n", pwGend, colCtr, errCtr)
	return
}

//genPass is a utility function that creates a random list of p.PwLen characters from char_pool.
func (p PwHive) genPass() (pw string) {
	for i := 0; i < p.PwLen; i++ {
		pw = fmt.Sprintf("%s%s", pw, char_pool[p.RandSrc.Intn(len(char_pool))])
	}
	return
}

//printChars is a utility function to display the character pool as a list of characters.
func printChars() {
	for _, next := range char_pool {
		fmt.Println(next)
	}
	return
}
