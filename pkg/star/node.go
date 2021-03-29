package star

import (
	"os"
	"runtime"
)

// The Node type serves as the overarching data structure for tracking STAR nodes.
type Node struct {
	ID               NodeID
	Type             NodeType
	Neighbors        []NodeID
	MessageProcesser func(*Message)
}

type NodeInfo struct {
	ConnectionIDs   map[uint]ConnectID
	ConnectionInfos map[uint]string
	ListenerIDs     map[uint]ConnectID
	ListenerInfos   map[uint]string
	ShellIDs        map[uint]NodeID
	ShellInfos      map[uint]string
	StreamIDs       map[uint]StreamID
	StreamInfos     map[uint]string
	StreamTypes     map[uint]StreamType

	GOOS   string
	GOARCH string

	OS_egid       int
	OS_environ    []string
	OS_euid       int
	OS_gid        int
	OS_groups     []int
	OS_hostname   string
	OS_pagesize   int
	OS_pid        int
	OS_ppid       int
	OS_uid        int
	OS_workingdir string
}

var nodeInfoConnectionIDsCount uint
var nodeInfoListenerIDsCount uint
var nodeInfoShellIDsCount uint
var nodeInfoStreamIDsCount uint

var ThisNode Node
var ThisNodeInfo NodeInfo

///////////////////////////////////////////////////////////////////////////////
/********************************* NewNode ***********************************/
///////////////////////////////////////////////////////////////////////////////

// NewNode creates and sets up a new STAR Node
func NewNode(t NodeType) (node Node) {
	NewUID([]byte(node.ID[:]))
	node.Type = t
	return
}

///////////////////////////////////////////////////////////////////////////////
/********************************** NodeID ***********************************/
///////////////////////////////////////////////////////////////////////////////

// The NodeID type is a fixed-length byte array which should serve as a UUID
// for each Node
type NodeID [9]byte

// Is the NodeID the Broadcast NodeID?
func (id NodeID) IsBroadcastNodeID() bool {
	var tmp NodeID
	return tmp == id
}

// Formats a NodeID into a print-friendly string
func (id NodeID) String() string {
	return SqrtedString(id[:], "-")
}

///////////////////////////////////////////////////////////////////////////////
/********************************* NodeType **********************************/
///////////////////////////////////////////////////////////////////////////////

// NodeType determines what kind of STAR Node we are dealing with (e.g., a
// terminal or an agent).
type NodeType byte

const (
	// NodeTypeTerminal identifies the STAR Node as being a Terminal Node
	NodeTypeTerminal NodeType = iota + 1

	// NodeTypeAgent identifies the STAR Node as being an Agent Node
	NodeTypeAgent

	// NodeTypeShell is a psuedonode that is used when connections from
	// external shells (i.e., netcat) are detected in an listener
	NodeTypeShell
)

///////////////////////////////////////////////////////////////////////////////
/********************************* NodeInfo **********************************/
///////////////////////////////////////////////////////////////////////////////

func (ni *NodeInfo) Setup() {
	ni.ConnectionIDs = make(map[uint]ConnectID)
	ni.ConnectionInfos = make(map[uint]string)
	ni.ListenerIDs = make(map[uint]ConnectID)
	ni.ListenerInfos = make(map[uint]string)
	ni.ShellIDs = make(map[uint]NodeID)
	ni.ShellInfos = make(map[uint]string)
	ni.StreamIDs = make(map[uint]StreamID)
	ni.StreamInfos = make(map[uint]string)
	ni.StreamTypes = make(map[uint]StreamType)

	ni.GOOS = runtime.GOOS
	ni.GOARCH = runtime.GOARCH

	ni.Update()
}

func (ni *NodeInfo) Update() {
	ni.OS_egid = os.Getegid()
	ni.OS_environ = os.Environ()
	ni.OS_euid = os.Geteuid()
	ni.OS_gid = os.Getgid()
	ni.OS_groups, _ = os.Getgroups()
	ni.OS_pagesize = os.Getpagesize()
	ni.OS_pid = os.Getpid()
	ni.OS_ppid = os.Getppid()
	ni.OS_uid = os.Getuid()
	ni.OS_workingdir, _ = os.Getwd()
	ni.OS_hostname, _ = os.Hostname()
}

func (ni *NodeInfo) AddConnector(id ConnectID, info string) {
	nodeInfoConnectionIDsCount++
}

func (ni *NodeInfo) RemoveConnector(id ConnectID) {
	for i, c := range ni.ConnectionIDs {
		if c == id {
			delete(ni.ConnectionIDs, i)
			delete(ni.ConnectionInfos, i)
		}
	}
}

func (ni *NodeInfo) AddListener(id ConnectID, info string) {
	nodeInfoListenerIDsCount++
}

func (ni *NodeInfo) RemoveListener(id ConnectID) {
	for i, l := range ni.ListenerIDs {
		if l == id {
			delete(ni.ListenerIDs, i)
			delete(ni.ListenerInfos, i)
		}
	}
}

func (ni *NodeInfo) AddShell(id NodeID, info string) {
	nodeInfoShellIDsCount++
}

func (ni *NodeInfo) RemoveShell(id NodeID) {
	for i, s := range ni.ShellIDs {
		if s == id {
			delete(ni.ShellIDs, i)
			delete(ni.ShellInfos, i)
		}
	}
}

func (ni *NodeInfo) AddStream(id StreamID, info string) {
	nodeInfoStreamIDsCount++
}

func (ni *NodeInfo) RemoveStream(id StreamID) {
	for i, s := range ni.StreamIDs {
		if s == id {
			delete(ni.StreamIDs, i)
			delete(ni.StreamInfos, i)
			delete(ni.StreamTypes, i)
		}
	}
}
