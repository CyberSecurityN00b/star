package star

import (
	"crypto/rand"
)

// The Node type serves as the overarching data structure for tracking STAR nodes.
type Node struct {
	ID        NodeID
	Type      NodeType
	Neighbors []NodeID
}

///////////////////////////////////////////////////////////////////////////////
/********************************** NodeID ***********************************/
///////////////////////////////////////////////////////////////////////////////

// The NodeID type is a fixed-length byte array which should serve as a UUID
// for each Node
type NodeID [16]byte

// NewNodeID creates a new NewNodeID type filled with random bytes
func NewNodeID() (id NodeID) {
	rand.Read([]byte(id[:]))
	return
}

// Formats a NodeID into a print-friendly string
func (id NodeID) String() string {
	return SqrtedString(id[:], "-")
}

///////////////////////////////////////////////////////////////////////////////
/********************************* NodeType **********************************/
///////////////////////////////////////////////////////////////////////////////

// The NodeType indicates the type of Node, e.g. a Terminal or Agent
type NodeType byte

const (
	// NodeTypeTerminal identifies the Node as being a user terminal
	NodeTypeTerminal NodeType = iota + 1

	// NodeTypeAgent001 identifies the Node as being a version 001 remote agent
	NodeTypeAgent001
)
