package star

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os/exec"
	"sync"
)

const streamBufferMax int = 10000

type Stream struct {
	ID   StreamID
	Data []byte
}

type StreamMeta struct {
	ID           StreamID
	remoteNodeID NodeID
	Type         StreamType
	Context      string
	buffer       *bytes.Buffer
	writelock    *sync.Mutex
	endwriter    func([]byte)
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
	meta.buffer = &bytes.Buffer{}
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
	metaNew.buffer = &bytes.Buffer{}
	metaNew.writelock = &sync.Mutex{}
	metaNew.endwriter = func(data []byte) {
		fmt.Printf("~~~> %s\n", data)
		metaNew.buffer.Write(data)
	}

	NewActiveStream(metaNew)
	NewMessageSyncResponse().Send(ConnectID{})

	return
}

func NewStreamMetaCommand(dstID NodeID, context string, writer func(data []byte)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeCommand, dstID, context)
	go meta.SendMessageCreate()
	meta.endwriter = writer
	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (meta *StreamMeta) SendMessageCreate() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamCreate
	msg.Data = GobEncode(meta)

	msg.Source = meta.remoteNodeID
	msg.Send(ConnectID{})

	meta.writelock.Lock()
}

func (meta *StreamMeta) SendMessageAcknowledge() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamAcknowledge
	msg.Data = GobEncode(&Stream{ID: meta.ID})

	msg.Source = meta.remoteNodeID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageClose() {
	fmt.Println("DEBUG: meta.SendMessageClose()")
	msg := NewMessage()
	msg.Type = MessageTypeStreamClose
	msg.Data = GobEncode(meta)

	msg.Source = meta.remoteNodeID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageWrite(data []byte) {
	flow := &Stream{}
	flow.ID = meta.ID
	flow.Data = data

	msg := NewMessage()
	msg.Type = MessageTypeStream
	msg.Data = GobEncode(flow)

	msg.Source = meta.remoteNodeID
	msg.Send(ConnectID{})
	meta.writelock.Lock()
}

func (meta *StreamMeta) Close() {
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

type StreamID [16]byte

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
)

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (stream *Stream) Process() {
	fmt.Println("DEBUG: stream.Process()")
	ThisNode.StreamProcessor(stream)
}

func (msg *Message) HandleStream() {
	fmt.Println("DEBUG: HandleStream()")
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
	var b bytes.Buffer
	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&streamMsg)
	if err == nil {
		meta, ok := GetActiveStream(streamMsg.ID)
		if ok {
			meta.writelock.Unlock()
		} else {
			fmt.Println("DEBUG: Error with GetActiveStream in HandleStreamAcknowledge")
		}
	} else {
		fmt.Println("DEBUG: Error with gob encoding in HandleStreamAcknowledge")
	}
}

func HandleStreamCreate(msg *Message) {
	fmt.Println("DEBUG: HandleStreamCreate()")
	// Create new meta if none exists
	var streamMsg StreamMeta
	var b bytes.Buffer
	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&streamMsg)
	if err == nil {
		meta := NewStreamMetaMirror(&streamMsg, msg.Source)
		meta.SendMessageAcknowledge()
		switch meta.Type {
		case StreamTypeCommand:
			c := exec.Command(meta.Context)
			c.Stdin = meta.buffer
			c.Stdout = meta
			c.Stderr = meta
			go c.Run()
		default:
			meta.Close()
		}
	} else {
		fmt.Println("DEBUG: Error with gob decoding in HandleStreamCreate")
	}
}

func HandleStreamFlow(msg *Message) {
	fmt.Println("DEBUG: HandleStreamFlow()")
	// Write to meta.ReadChannel
	var streamMsg Stream
	var b bytes.Buffer
	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&streamMsg)
	if err == nil {
		stream, ok := GetActiveStream(streamMsg.ID)
		if ok {
			stream.endwriter(streamMsg.Data)
			stream.SendMessageAcknowledge()
		} else {
			fmt.Println("DEBUG: Error with GetActiveStream in HandleStreamFlow")
		}
	} else {
		fmt.Println("DEBUG: Error with gob decoding in HandleStreamFlow")
	}
	fmt.Println("DEBUG: HandleStreamFlow() Done")
}

func HandleStreamClose(msg *Message) {
	fmt.Println("DEBUG: HandleStreamClose()")
	var streamMsg StreamMeta
	var b bytes.Buffer
	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&streamMsg)
	if err == nil {
		stream, ok := GetActiveStream(streamMsg.ID)
		if ok {
			RemoveActiveStream(stream.ID)
		} else {
			fmt.Println("DEBUG: Error with GetActiveStream in HandleStreamClose")
		}
	} else {
		fmt.Println("DEBUG: Error with gob decoding in HandleStreamClose")
	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (stream *StreamMeta) Write(p []byte) (n int, err error) {
	for i := 0; i < len(p); i += streamBufferMax {
		n := i + streamBufferMax
		if n > len(p) {
			n = len(p)
		}

		fmt.Printf("---> %s\n", p[i:n])
		stream.SendMessageWrite(p[i:n])
	}
	return n, nil
}
