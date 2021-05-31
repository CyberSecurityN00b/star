package star

import (
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// The Message type serves as the overarching data structure for STAR messages.
type Message struct {
	ID          MessageID
	Source      NodeID
	Destination NodeID
	Type        MessageType
	Data        []byte
}

var messageTracker map[MessageID]bool
var messageTrackerMutex *sync.Mutex

///////////////////////////////////////////////////////////////////////////////
/******************************** NewMessage *********************************/
///////////////////////////////////////////////////////////////////////////////

// NewMessage creates and sets up a bare-bones STAR Message
func NewMessage() (msg *Message) {
	msg = &Message{}
	NewUID([]byte(msg.ID[:]))
	msg.Source = ThisNode.ID
	return
}

//////////////////////////////////////////////////////////////////////////////
/******************************** MessageID *********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageID type is a fixed-length byte array which should serve as a UUID
// for each Message
type MessageID [16]byte

// Formats a MessageID into a print-friendly string
func (id MessageID) String() string {
	return SqrtedString(id[:], ":")
}

//////////////////////////////////////////////////////////////////////////////
/******************************* MessageType ********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageType type indicates the type of Message
type MessageType byte

const (
	// MessageTypeError identifies the Message as being in relation to an
	// error that occurred on the Agent and is being relayed to the Terminal
	// user.
	MessageTypeError MessageType = iota + 1

	// MessageTypeSyncRequest identifies the Message as being a synchronization
	// request from the Terminal to Agents. The Message will be forwarded to
	// all neighboring Agents.
	MessageTypeSyncRequest

	// MessageTypeSyncResponse identifies the Message as being a
	// synchronization response from Agents to the Terminal. The Message
	// will be forwarded to all neighboring Agents.
	MessageTypeSyncResponse

	// MessageTypeKillSwitch identifies the Message as being a self-destruct
	// request from the Terminal to Agents. The Message will *only* be
	// forwarded if the correct confirmation code is passed.
	MessageTypeKillSwitch

	// MessageTypeStream* identifies the Message as being related to
	// bi-directional interactive traffic (i.e., a command prompt)
	MessageTypeStream
	MessageTypeStreamCreate
	MessageTypeStreamAcknowledge
	MessageTypeStreamClose
	MessageTypeStreamTakeover

	// MessageTypeStreamTakenOver is not handled by the stream, but rather
	// the terminal who previously had access to the stream.
	MessageTypeStreamTakenOver

	// MessageTypeBind indentifies the Message as being related to
	// the creation of a Listener on an agent
	MessageTypeBind

	// MessageTypeConnect identifies the Message as being related to
	// the creation of a Connection on an agent
	MessageTypeConnect

	// MessageTypeHello identifies the Message as being related to a
	// new node joining the constellation
	MessageTypeHello

	// MessageTypeNewBind identifies the message as being related to
	// the successful creation of a new listener. This is separate
	// from the MessageTypeBind Response in that this is sent to the
	// broadcast NodeID, so all terminals will be aware.
	MessageTypeNewBind

	// MessageTypeNewConnection identifies the message as being related to
	// the successful creation of a new connection. This is separate from the
	// MessageTypeConnection Response in that this is sent to the broadcast
	// NodeID, so all terminals will be aware.
	MessageTypeNewConnection

	// MessageTypeTerminateAgent identifies the message as being related to
	// the termination request of an agent.
	MessageTypeTerminate

	// MessageTypeShellBind identifies the message as being related to the
	// creation of a new shell listener.
	MessageTypeShellBind

	// MessageTypeShellConnection identifies the message as being related to the
	// creation of a new shell connection.
	MessageTypeShellConnection

	// MessageTypeRemoteCD identifies the message as being related to the changing
	// of the working directory for the remote node (agent).
	MessageTypeRemoteCDRequest
	MessageTypeRemoteCDResponse

	// MessageTypeRemoteLS identifies the message as being related to the listing
	// of files and directories for the remote node (agent).
	MessageTypeRemoteLSRequest
	MessageTypeRemoteLSResponse

	// MessageTypeRemotePWD identifies the message as being related to the listing
	// of the present working directory
	MessageTypeRemotePWDRequest
	MessageTypeRemotePWDResponse
)

func (msg *Message) Process() {
	ThisNode.MessageProcessor(msg)
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageError ********************************/
///////////////////////////////////////////////////////////////////////////////

// MessageError holds values related to any error messages returned by an
// Agent Node. Termainal Nodes *should not* send error messages to Agent Nodes.
type MessageErrorResponse struct {
	Type    MessageErrorResponseType
	Context string
}

type MessageErrorResponseType byte

const (
	MessageErrorResponseTypeX509KeyPair MessageErrorResponseType = iota + 1
	MessageErrorResponseTypeConnectionLost
	MessageErrorResponseTypeBindDropped
	MessageErrorResponseTypeGobDecodeError
	MessageErrorResponseTypeAgentExitSignal
	MessageErrorResponseTypeUnsupportedConnectorType
	MessageErrorResponseTypeUnsupportedTerminationType
	MessageErrorResponseTypeInvalidTerminationIndex
	MessageErrorResponseTypeCommandEnded
	MessageErrorResponseTypeShellConnectionLost
	MessageErrorResponseTypeFileDownloadOpenFileError
	MessageErrorResponseTypeFileUploadOpenFileError
	MessageErrorResponseTypeFileDownloadCompleted
	MessageErrorResponseTypeFileUploadCompleted
)

func NewMessageError(errorType MessageErrorResponseType, context string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeError
	msg.Data = GobEncode(MessageErrorResponse{Type: errorType, Context: context})

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageKillSwitch *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageKillSwitchRequest struct {
}

func NewMessageKillSwitch() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeKillSwitch
	msg.Data = GobEncode(MessageKillSwitchRequest{})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageSync *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageSyncRequest struct {
}

type MessageSyncResponse struct {
	Node Node
	Info NodeInfo
}

func NewMessageSyncRequest() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeSyncRequest
	msg.Data = GobEncode(MessageSyncRequest{})

	return
}

func NewMessageSyncResponse() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeSyncResponse
	ThisNodeInfo.Update()
	if ThisNode.Type == NodeTypeTerminal {
		msg.Data = GobEncode(MessageSyncResponse{Node: ThisNode, Info: NodeInfo{}})
	} else {
		msg.Data = GobEncode(MessageSyncResponse{Node: ThisNode, Info: ThisNodeInfo})
	}

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageBind *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageBindRequest struct {
	Type ConnectorType
	Data []byte
}

func newMessageBind(t ConnectorType, gobEncodedData []byte) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeBind
	msg.Data = GobEncode(MessageBindRequest{Type: t, Data: gobEncodedData})

	return
}

func NewMessageBindTCP(address string) (msg *Message) {
	return newMessageBind(ConnectorTypeTCP, GobEncode(address))
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageConnect *******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageConnectRequest struct {
	Type ConnectorType
	Data []byte
}

func newMessageConnect(t ConnectorType, gobEncodedData []byte) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeConnect
	msg.Data = GobEncode(MessageConnectRequest{Type: t, Data: gobEncodedData})

	return
}

func NewMessageConnectTCP(address string) (msg *Message) {
	return newMessageConnect(ConnectorTypeTCP, GobEncode(address))
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageHello ********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageHelloResponse struct {
	Node Node
	Info NodeInfo
}

func NewMessageHello() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeHello
	msg.Data = GobEncode(MessageHelloResponse{Node: ThisNode, Info: ThisNodeInfo})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageNewBind *******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageNewBindResponse struct {
	Address string
}

func NewMessageNewBind(address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeNewBind
	msg.Data = GobEncode(MessageNewBindResponse{Address: address})

	return
}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessageNewConnection ****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageNewConnectionResponse struct {
	Address string
}

func NewConnection(address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeNewConnection
	msg.Data = GobEncode(MessageNewConnectionResponse{Address: address})

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageTerminate ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageTerminateRequest struct {
	Type  MessageTerminateType
	Index uint
}

type MessageTerminateType byte

const (
	MessageTerminateTypeAgent MessageTerminateType = iota + 1
	MessageTerminateTypeConnection
	MessageTerminateTypeListener
	MessageTerminateTypeShell
	MessageTerminateTypeStream
)

func NewMessageTerminate(t MessageTerminateType, index uint) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeTerminate
	msg.Data = GobEncode(MessageTerminateRequest{Type: t, Index: index})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageShell ********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageShellBindRequest struct {
	Address   string
	Type      ShellType
	Requester NodeID
}

type MessageShellConnectionRequest struct {
	Address   string
	Type      ShellType
	Requester NodeID
}

func NewMessageShellBindRequest(t ShellType, address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeShellBind
	msg.Data = GobEncode(MessageShellBindRequest{Type: t, Address: address, Requester: ThisNode.ID})

	return
}

func NewMessageShellConnectionRequest(t ShellType, address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeShellConnection
	msg.Data = GobEncode(MessageShellConnectionRequest{Type: t, Address: address, Requester: ThisNode.ID})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageRemoteCD ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageRemoteCDRequest struct {
	Directory string
}

type MessageRemoteCDResponse struct {
	NewDirectory string
	OldDirectory string
	Requester    NodeID
}

func NewMessageTypeRemoteCDRequest(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteCDRequest
	msg.Data = GobEncode(MessageRemoteCDRequest{Directory: Directory})

	return
}

func NewMessageTypeRemoteCDResponse(NewDirectory string, OldDirectory string, Requester NodeID) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteCDResponse
	msg.Data = GobEncode(MessageRemoteCDResponse{NewDirectory: NewDirectory, OldDirectory: OldDirectory, Requester: Requester})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageRemoteLS ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageRemoteLSRequest struct {
	Directory string
}

type MessageRemoteLSResponse struct {
	Directory string
	Files     []MessageRemoteLSFileFormat
}

type MessageRemoteLSFileFormat struct {
	Name    string
	ModTime time.Time
	Mode    fs.FileMode
	Size    int64
	IsDir   bool
}

func NewMessageTypeRemoteLSRequest(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteLSRequest
	msg.Data = GobEncode(MessageRemoteLSRequest{Directory: Directory})

	return
}

func NewMessageTypeRemoteLSResponse(Directory string, FileInfos []os.FileInfo) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteLSResponse

	Files := make([]MessageRemoteLSFileFormat, len(FileInfos))
	for i, f := range FileInfos {
		Files[i].IsDir = f.IsDir()
		Files[i].Name = f.Name()
		Files[i].ModTime = f.ModTime()
		Files[i].Mode = f.Mode()
		Files[i].Size = f.Size()
	}

	msg.Data = GobEncode(MessageRemoteLSResponse{Directory: Directory, Files: Files})
	fmt.Printf("%v+", Directory)
	fmt.Printf("%v+", FileInfos)

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageRemotePWD *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageRemotePWDRequest struct {
}

type MessageRemotePWDResponse struct {
	Directory string
}

func NewMessageTypeRemotePWDRequest() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemotePWDRequest
	msg.Data = GobEncode(MessageRemotePWDRequest{})

	return
}

func NewMessageTypeRemotePWDResponse(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemotePWDResponse
	msg.Data = GobEncode(MessageRemotePWDResponse{Directory: Directory})

	return
}

///////////////////////////////////////////////////////////////////////////////
/************************************ Send ***********************************/
///////////////////////////////////////////////////////////////////////////////

func (msg *Message) Send(src ConnectID) {
	connectionTrackerMutex.Lock()
	defer connectionTrackerMutex.Unlock()

	destinationTrackerMutex.Lock()
	dst, exists := destinationTracker[msg.Destination]
	destinationTrackerMutex.Unlock()

	if msg.Destination.IsBroadcastNodeID() || !exists {
		for conn := range connectionTracker {
			if conn != src {
				c, ok := connectionTracker[conn]
				if ok {
					c.Send(*msg)
				}
			}
		}
	} else {
		c, ok := connectionTracker[dst]
		if ok {
			c.Send(*msg)
		} else if exists {
			// Try try again
			destinationTrackerMutex.Lock()
			delete(destinationTracker, msg.Destination)
			destinationTrackerMutex.Unlock()
			msg.Send(src)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
/*********************************** Handle **********************************/
///////////////////////////////////////////////////////////////////////////////

func (msg *Message) Handle(src ConnectID) {
	ismsg := false
	// If part of a stream, offload to the functions in stream.go
	if msg.Type == MessageTypeStream || msg.Type == MessageTypeStreamCreate || msg.Type == MessageTypeStreamClose || msg.Type == MessageTypeStreamAcknowledge || msg.Type == MessageTypeStreamTakeover {
		ismsg = true
	}

	if !ismsg {
		// Have we already received this Message before?
		messageTrackerMutex.Lock()
		defer messageTrackerMutex.Unlock()
		if messageTracker[msg.ID] {
			return
		}

		// Add the MessageID to the tracker, removing after certain duration
		connectionTrackerMutex.Lock()
		messageTracker[msg.ID] = true
		time.AfterFunc(connectionTracker[src].MessageDuration(), func() {
			messageTrackerMutex.Lock()
			defer messageTrackerMutex.Unlock()
			delete(messageTracker, msg.ID)
		})
		connectionTrackerMutex.Unlock()
	}

	// Track destination
	if !src.IsNone() && !msg.Source.IsBroadcastNodeID() {
		destinationTrackerMutex.Lock()
		destinationTracker[msg.Source] = src
		destinationTrackerMutex.Unlock()
	}

	// Is the MessageType supposed to be broadcasted or sent to an individual?
	if msg.Destination.IsBroadcastNodeID() {
		// Pass it along first and then process
		msg.Send(src)
		if ismsg {
			go msg.HandleStream()
		} else {
			go msg.Process()
		}
	} else if msg.Destination == ThisNode.ID {
		if ismsg {
			go msg.HandleStream()
		} else {
			go msg.Process()
		}
	} else {
		msg.Send(src)
	}
}
