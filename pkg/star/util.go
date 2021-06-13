package star

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

// NewUID fills a byte array with random data
func NewUID(id []byte) {
	rand.Read(id[:])
}

// SqrtedString turns a []byte into a hexadecimal string that is split into
// substrings demarcated by the specified separator string. The number of
// substrings is equal to the square root of the length of []byte. (Note: If
// "len([]byte)" is not a square number, not all data will be included).
func SqrtedString(b []byte, sep string) string {
	var parts []string
	n := int(math.Sqrt(float64(len(b))))
	for i := 0; i < n; i++ {
		parts = append(parts, strings.ToUpper(hex.EncodeToString(b[i*n:i*n+n])))
	}
	return strings.Join(parts, sep)
}

// GobEncode gob encodes the provided data(d)
func GobEncode(d interface{}) []byte {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(d)
	return b.Bytes()
}

// GobDecode gob decodes the provided data(d) into a type(t) pointer
func (msg *Message) GobDecodeMessage(reqMsg interface{}) (err error) {
	var b bytes.Buffer

	b.Write(msg.Data)
	err = gob.NewDecoder(&b).Decode(reqMsg)
	if err != nil {
		errMsg := NewMessageError(MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(ConnectID{})
	}
	return
}

func StringifySubarray(arr []string, starti int, endi int) (s string) {
	s = arr[starti]
	if len(arr) > endi {
		endi = len(arr)
	}
	for i := starti + 1; i < endi; i++ {
		s = s + " " + arr[i]
	}
	return s
}

func STARCoreSetup() {
	connectionTracker = make(map[ConnectID]Connection)
	connectionTrackerMutex = &sync.Mutex{}

	listenerTracker = make(map[ConnectID]Connector)
	listenerTrackerMutex = &sync.Mutex{}

	destinationTracker = make(map[NodeID]ConnectID)
	destinationTrackerMutex = &sync.Mutex{}

	messageTracker = make(map[MessageID]bool)
	messageTrackerMutex = &sync.Mutex{}

	ActiveStreams = make(map[StreamID]*StreamMeta)
	ActiveStreamsMutex = &sync.Mutex{}
}

// Allows for the creation of listeners (bind) and connections (connect) via
// command-line arguments.
func ParameterHandling() {
	for _, arg := range os.Args[1:] {
		setup := strings.Split(arg, ":")
		if setup[0] == "b" || setup[0] == "l" {
			// [b]ind/[l]istener

			if len(setup) == 2 {
				NewTCPListener(":" + setup[1])
			} else if len(setup) == 3 {
				NewTCPListener(setup[1] + ":" + setup[2])
			}
		} else if setup[0] == "r" || setup[0] == "c" {
			// [r]everse/[c]onnect

			if len(setup) == 2 {
				NewTCPConnection(":" + setup[1])
			} else if len(setup) == 3 {
				NewTCPConnection(setup[1] + ":" + setup[2])
			}
		}
	}
}

func RandDataSize() int {
	min := 23456
	max := 65432
	mrand.Seed(time.Now().UnixNano())
	return mrand.Intn(max-min+1) + min
}

func RandString(seed string, n int) string {
	b := make([]byte, n)
	mrand.Seed(time.Now().UnixNano())
	for i := range b {
		b[i] = seed[mrand.Intn(len(seed))]
	}
	return string(b)
}
