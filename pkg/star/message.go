package star

import (
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

	// MessageTypeFileServerBind identifies the message as being related to the
	// creation of a new single-use file server.
	MessageTypeFileServerBind

	// MessageTypeFileServerConnection identifies the message as being related to the
	// creation of a new file server connection.
	MessageTypeFileServerConnect

	// MessageTypeFileServerInitiateTransfer identifies the message as being related to
	// the transfer initiation of a file server file.
	MessageTypeFileServerInitiateTransfer

	// MessageTypeRemoteCD identifies the message as being related to the changing
	// of the working directory for the remote node (agent).
	MessageTypeRemoteCDRequest
	MessageTypeRemoteCDResponse

	// MessageTypeRemoteLS identifies the message as being related to the listing
	// of files and directories for the remote node (agent).
	MessageTypeRemoteLSRequest
	MessageTypeRemoteLSResponse

	// MessageTypeRemoteMkDir identifies the message as being related to the creation
	// of a directory for the remote node (agent).
	MessageTypeRemoteMkDirRequest
	MessageTypeRemoteMkDirResponse

	// MessageTypeRemotePWD identifies the message as being related to the listing
	// of the present working directory
	MessageTypeRemotePWDRequest
	MessageTypeRemotePWDResponse

	// MessageTypeRemoteTmpDir identifies the message as being related to the creation
	// of a temporary directory for the remote node (agent.)
	MessageTypeRemoteTmpDirRequest
	MessageTypeRemoteTmpDirResponse

	// MessageTypeChat identifies the message as being related to chatting
	MessageTypeChat

	// MessageTypePortForwardRequest identifies the message as being related to the
	// setting up of port forwarding
	MessageTypePortForwardRequest

	// MessageTypePortScan identifies the message as being related to a TCP port scan
	MessageTypePortScanRequest
	MessageTypePortScanResponse
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
	MessageErrorResponseTypeDirectoryCreationError
	MessageErrorResponseTypeFileServerConnectionLost
	MessageErrorResponseTypeFileServerConnectionNotFound
	MessageErrorResponseTypePortForwardingConnectionNotFound
	MessageErrorResponseTypePortForwardingSourceAddressUnavailable
	MessageErrorResponseTypePortForwardingDestinationAddressUnavailable
	MessageErrorResponseTypePortForwardingConnectionLost
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
	return newMessageBind(ConnectorType_TCPTLS, GobEncode(address))
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
	return newMessageConnect(ConnectorType_TCPTLS, GobEncode(address))
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
	Type      ConnectorType
	Requester NodeID
}

type MessageShellConnectionRequest struct {
	Address   string
	Type      ConnectorType
	Requester NodeID
}

func NewMessageShellBindRequest(t ConnectorType, address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeShellBind
	msg.Data = GobEncode(MessageShellBindRequest{Type: t, Address: address, Requester: ThisNode.ID})

	return
}

func NewMessageShellConnectionRequest(t ConnectorType, address string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeShellConnection
	msg.Data = GobEncode(MessageShellConnectionRequest{Type: t, Address: address, Requester: ThisNode.ID})

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageFileServer *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileServerBindRequest struct {
	Address    string
	Type       ConnectorType
	Requester  NodeID
	FileConnID ConnectID
}

type MessageFileServerConnectRequest struct {
	Address    string
	Type       ConnectorType
	Requester  NodeID
	FileConnID ConnectID
}

type MessageFileServerInitiateTransferRequest struct {
	FileConnID  ConnectID
	AgentConnID ConnectID
}

func NewMessageFileServerBindRequest(t ConnectorType, address string, fileconnid ConnectID) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeFileServerBind
	msg.Data = GobEncode(MessageFileServerBindRequest{Type: t, Address: address, Requester: ThisNode.ID, FileConnID: fileconnid})

	return
}

func NewMessageFileServerConnectRequest(t ConnectorType, address string, fileconnid ConnectID) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeFileServerConnect
	msg.Data = GobEncode(MessageFileServerConnectRequest{Type: t, Address: address, Requester: ThisNode.ID, FileConnID: fileconnid})

	return
}

func NewMessageFileServerInitiateTransferRequest(FileConnID ConnectID, AgentConnID ConnectID) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeFileServerInitiateTransfer
	msg.Data = GobEncode(MessageFileServerInitiateTransferRequest{FileConnID: FileConnID, AgentConnID: AgentConnID})

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

func NewMessageRemoteCDRequest(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteCDRequest
	msg.Data = GobEncode(MessageRemoteCDRequest{Directory: Directory})

	return
}

func NewMessageRemoteCDResponse(NewDirectory string, OldDirectory string, Requester NodeID) (msg *Message) {
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

func NewMessageRemoteLSRequest(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteLSRequest
	msg.Data = GobEncode(MessageRemoteLSRequest{Directory: Directory})

	return
}

func NewMessageRemoteLSResponse(Directory string, FileInfos []os.FileInfo) (msg *Message) {
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

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageRemoteMkDir ****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageRemoteMkDirRequest struct {
	Directory string
}

type MessageRemoteMkDirResponse struct {
	Directory string
}

func NewMessageRemoteMkDirRequest(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteMkDirRequest
	msg.Data = GobEncode(MessageRemoteMkDirRequest{Directory: Directory})

	return
}

func NewMessageRemoteMkDirResponse(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteMkDirResponse
	msg.Data = GobEncode(MessageRemoteMkDirResponse{Directory: Directory})

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

func NewMessageRemotePWDRequest() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemotePWDRequest
	msg.Data = GobEncode(MessageRemotePWDRequest{})

	return
}

func NewMessageRemotePWDResponse(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemotePWDResponse
	msg.Data = GobEncode(MessageRemotePWDResponse{Directory: Directory})

	return
}

///////////////////////////////////////////////////////////////////////////////
/**************************** MessageRemoteTmpDir ****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageRemoteTmpDirRequest struct {
}

type MessageRemoteTmpDirResponse struct {
	Directory string
}

func NewMessageRemoteTmpDirRequest() (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteTmpDirRequest
	msg.Data = GobEncode(MessageRemoteTmpDirRequest{})

	return
}

func NewMessageRemoteTmpDirResponse(Directory string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeRemoteTmpDirResponse
	msg.Data = GobEncode(MessageRemoteTmpDirResponse{Directory: Directory})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************** MessageChat ********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageChatRequest struct {
	Nickname string
	Content  string
}

func NewMessageChatRequest(Nickname string, Content string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypeChat
	msg.Data = GobEncode(MessageChatRequest{Nickname: Nickname, Content: Content})

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessagePortForward ****************************/
///////////////////////////////////////////////////////////////////////////////

type MessagePortForwardRequest struct {
	DstNode    NodeID
	SrcType    ConnectorType
	DstType    ConnectorType
	SrcAddress string
	DstAddress string
}

func NewMessagePortForwardRequest(SrcAddress string, SrcType ConnectorType, DstNode NodeID, DstAddress string, DstType ConnectorType) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypePortForwardRequest
	msg.Data = GobEncode(MessagePortForwardRequest{DstNode: DstNode, SrcType: SrcType, DstType: DstType, SrcAddress: SrcAddress, DstAddress: DstAddress})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessagePortScan ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessagePortScanRequest struct {
	IP    string
	Ports string
}

type MessagePortScanResponse struct {
	IP        string
	OpenPorts string
}

func NewMessagePortScanRequest(IP string, Ports string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypePortScanRequest
	msg.Data = GobEncode(MessagePortScanRequest{IP: IP, Ports: Ports})

	return
}

func NewMessagePortScanResponse(IP string, OpenPorts string) (msg *Message) {
	msg = NewMessage()
	msg.Type = MessageTypePortScanResponse
	msg.Data = GobEncode(MessagePortScanResponse{IP: IP, OpenPorts: OpenPorts})

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

	// Either global or self->self
	if msg.Destination == ThisNode.ID {
		msg.Process()
	}

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
			connectionTrackerMutex.Unlock()
			msg.Send(src)
			connectionTrackerMutex.Lock()
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
