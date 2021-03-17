package star

// The Connection interface provides the standard functions for using STAR node communications.
type Connection interface {
	Close() (err error)
	Receive() (msg Message, err error)
	Send(msg Message) (err error)
	Track(msg Message) (err error)
}

// The Connector interface provides the standard functions for creating STAR node connections.
type Connector interface {
	Connect() (conn Connection, err error)
	Listen() (conn Connection, err error)
}
