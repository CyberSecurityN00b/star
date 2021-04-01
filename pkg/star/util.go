package star

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"math"
	"os"
	"strings"
	"sync"
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

func GobEncode(d interface{}) []byte {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(d)
	return b.Bytes()
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
