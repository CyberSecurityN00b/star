package star

import (
	"crypto"
)

// The Node type serves as the overarching data structure for tracking STAR nodes.
type Node struct {
	ID               NodeID           `json:"id"`
	Type             NodeType         `json:"type"`
	Neighbors        []NodeID         `json:"neighbors"`
	PublicKey        crypto.PublicKey `json:"publickey"`
	PrivateKey       crypto.PrivateKey
	MessageProcesser func(*Message)
}

var ThisNode Node

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
