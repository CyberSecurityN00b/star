package star

import (
	"sync"
	"time"
)

// MessagesTracker is used by the STAR Node to track what Messages have been
// handled, whether processed locally or passed on to adjacent Nodes
var MessagesTracker []MessageID

// MessagesTrackerMutex is used to un/lock access to MessagesTracker
var MessagesTrackerMutex sync.Mutex

// ConnectionsTracker is used by the STAR Node to track it's connections, to
// include open listeners.
var ConnectionsTracker []Node

///////////////////////////////////////////////////////////////////////////////
/****************************** MessagesTracker ******************************/
///////////////////////////////////////////////////////////////////////////////

// MessagesTrackerTrack adds a MessageID to MessagesTracker and then removes it
// after the specified duration of time. Durations should be specific to each
// connection type (i.e., a slower connection using GMail may have a longer
// duration than a network based connection).
func MessagesTrackerTrack(id MessageID, d time.Duration) {
	// Lock to make sure nothing else is accessing it
	MessagesTrackerMutex.Lock()
	MessagesTrackerMutex.Unlock()

	// Add the MessageID to the tracker
	MessagesTracker = append(MessagesTracker, id)

	time.AfterFunc(d, func() {
		// Lock to make sure only one goroutine can access at a time
		MessagesTrackerMutex.Lock()
		defer MessagesTrackerMutex.Unlock()

		// TODO: Remove ID from the tracker
	})
}
