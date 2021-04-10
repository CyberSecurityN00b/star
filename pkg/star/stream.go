package star

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const streamBufferMax int = 10000

type Stream struct {
	ID   StreamID
	Data []byte
}

type StreamMeta struct {
	ID            StreamID
	remoteNodeID  NodeID
	Type          StreamType
	Context       string
	writelock     *sync.Mutex
	stdin         io.WriteCloser
	funcwriter    func([]byte)
	funccloser    func(StreamID)
	functerminate func()
}

var ActiveStreams map[StreamID]*StreamMeta
var ActiveStreamsMutex *sync.Mutex

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// NewStreamMeta is called by the terminal to setup a stream meta
func NewStreamMeta(t StreamType, dstID NodeID, context string) (meta *StreamMeta) {
	meta = &StreamMeta{}
	NewUID([]byte(meta.ID[:]))
	meta.Type = t
	meta.remoteNodeID = dstID
	meta.Context = context
	meta.writelock = &sync.Mutex{}

	NewActiveStream(meta)

	return
}

// NewStreamMetaMirror is called by the agent to mirror/setup a stream meta
func NewStreamMetaMirror(metaOrig *StreamMeta, dstID NodeID) (metaNew *StreamMeta) {
	metaNew = &StreamMeta{}
	metaNew.ID = metaOrig.ID
	metaNew.Type = metaOrig.Type
	metaNew.remoteNodeID = dstID
	metaNew.Context = metaOrig.Context
	metaNew.writelock = &sync.Mutex{}
	metaNew.funcwriter = nil
	metaNew.funccloser = nil

	NewActiveStream(metaNew)
	NewMessageSyncResponse().Send(ConnectID{})

	return
}

func NewStreamMetaCommand(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeCommand, dstID, context)
	go meta.SendMessageCreate()
	meta.funcwriter = writer
	meta.funccloser = closer
	return
}

func NewStreamMetaShell(context string, dstID NodeID, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeShell, dstID, context)
	go meta.SendMessageCreate()
	meta.funcwriter = writer
	meta.funccloser = closer
	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (meta *StreamMeta) SendMessageCreate() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamCreate
	msg.Data = GobEncode(meta)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})

	meta.writelock.Lock()
}

func (meta *StreamMeta) SendMessageAcknowledge() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamAcknowledge
	msg.Data = GobEncode(&Stream{ID: meta.ID})
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageClose() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamClose
	msg.Data = GobEncode(meta)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageWrite(data []byte) {
	flow := &Stream{}
	flow.ID = meta.ID
	flow.Data = data

	msg := NewMessage()
	msg.Type = MessageTypeStream
	msg.Data = GobEncode(flow)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})
	meta.writelock.Lock()
}

func (meta *StreamMeta) Close() {
	if meta.functerminate != nil {
		meta.functerminate()
	}
	if meta.funccloser != nil {
		meta.funccloser(meta.ID)
	}
	meta.SendMessageClose()
	RemoveActiveStream(meta.ID)
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func NewActiveStream(tracker *StreamMeta) {
	ActiveStreamsMutex.Lock()
	defer ActiveStreamsMutex.Unlock()

	id := tracker.ID
	ActiveStreams[id] = tracker
	ThisNodeInfo.AddStream(tracker.ID, tracker.Type, tracker.Context)
}

func GetActiveStream(id StreamID) (tracker *StreamMeta, ok bool) {
	ActiveStreamsMutex.Lock()
	defer ActiveStreamsMutex.Unlock()

	tracker, ok = ActiveStreams[id]
	return
}

func RemoveActiveStream(id StreamID) {
	ActiveStreamsMutex.Lock()
	defer ActiveStreamsMutex.Unlock()

	delete(ActiveStreams, id)
	ThisNodeInfo.RemoveStream(id)
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

type StreamID [9]byte

// Is the StreamID an empty StreamID?
func (id StreamID) IsEmptyStreamID() bool {
	var tmp StreamID
	return tmp == id
}

func (id StreamID) String() string {
	return SqrtedString(id[:], "~")
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

type StreamType byte

const (
	StreamTypeCommand StreamType = iota + 1
	StreamTypeFileUpload
	StreamTypeFileDownload
	StreamTypeShell
)

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (msg *Message) HandleStream() {
	switch msg.Type {
	case MessageTypeStreamCreate:
		HandleStreamCreate(msg)
	case MessageTypeStream:
		HandleStreamFlow(msg)
	case MessageTypeStreamClose:
		HandleStreamClose(msg)
	case MessageTypeStreamAcknowledge:
		HandleStreamAcknowledge(msg)
	}
}

func HandleStreamAcknowledge(msg *Message) {
	var streamMsg Stream
	defer func() { recover() }()

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		meta, ok := GetActiveStream(streamMsg.ID)
		if ok {
			meta.writelock.Unlock()
		}
	}
}

func HandleStreamCreate(msg *Message) {
	// Create new meta if none exists
	var streamMsg StreamMeta

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		meta := NewStreamMetaMirror(&streamMsg, msg.Source)
		meta.SendMessageAcknowledge()
		switch meta.Type {
		case StreamTypeCommand:
			// Agent will handle this one
			args := strings.Split(meta.Context, " ")
			var c *exec.Cmd
			if len(args) == 0 {
				meta.Close()
			} else if len(args) == 1 {
				c = exec.Command(args[0])
			} else {
				c = exec.Command(args[0], args[1:]...)
			}
			c.Stdout = meta
			c.Stderr = meta
			c.Env = os.Environ()
			meta.stdin, err = c.StdinPipe()
			if err != nil {
				defer meta.Close()
			}
			meta.funcwriter = func(data []byte) {
				_, err = meta.stdin.Write(data)
				if err != nil {
					meta.Close()
				}
			}

			meta.functerminate = func() {
				if c.Process != nil {
					c.Process.Kill()
				}
			}

			err = c.Start()
			if err == nil {
				go func() {
					err = c.Wait()
					NewMessageError(MessageErrorResponseTypeCommandEnded, fmt.Sprintf("%v(%v)", c.Args, err)).Send(ConnectID{})
					meta.Close()
				}()
			} else {
				meta.Close()
			}
		case StreamTypeShell:
			// Terminal will handle this one
			meta.funcwriter = func(data []byte) {
				fmt.Printf("%s", data)
			}
			meta.functerminate = func() {

			}
		default:
			meta.Close()
		}
	} else {
		NewMessageError(MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%s.c", msg.ID))
	}
}

func HandleStreamFlow(msg *Message) {
	// Write to meta.ReadChannel
	var streamMsg Stream

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		stream, ok := GetActiveStream(streamMsg.ID)
		if ok {
			stream.funcwriter(streamMsg.Data)
			stream.SendMessageAcknowledge()
		} else {
			fmt.Println("DEBUG: Error with GetActiveStream in HandleStreamFlow")
		}
	}
}

func HandleStreamClose(msg *Message) {
	var streamMsg StreamMeta

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		stream, ok := GetActiveStream(streamMsg.ID)
		if ok {
			if stream.functerminate != nil {
				stream.functerminate()
			}
			if stream.funccloser != nil {
				stream.funccloser(stream.ID)
			}
			RemoveActiveStream(stream.ID)
		} else {
			fmt.Println("DEBUG: Error with GetActiveStream in HandleStreamClose")
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (stream *StreamMeta) Write(p []byte) (n int, err error) {
	for i := 0; i < len(p); i += streamBufferMax {
		n = i + streamBufferMax
		if n > len(p) {
			n = len(p)
		}
		stream.SendMessageWrite(p[i:n])
	}
	return n, nil
}
