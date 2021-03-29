package main

import (
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS

func main() {
	initAgent()
	parameterHandlingAgent()

	// SECURITY RESEARCHER TODO: Configure default connections here
	star.NewTCPListener(":42069")

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	es := <-exitSignal

	//Let the terminal know we closed due to a signal
	errMsg := star.NewMessageError(star.MessageErrorResponseTypeAgentExitSignal, fmt.Sprintf("%b", es))
	errMsg.Send(star.ConnectID{})

	//Handle termination
	// TODO: change false to true when "done" with development
	cleanMsg := star.NewMessageTerminateAgent(false)
	star.ThisNode.MessageProcesser(&cleanMsg)
}

///////////////////////////////////////////////////////////////////////////////

func initAgent() {
	star.STARCoreSetup()
	star.ThisNode = star.NewNode(star.NodeTypeAgent)
	star.ThisNode.MessageProcesser = AgentProcessMessage

	star.ThisNodeInfo.Setup()

	// Setup connection cert
	conncrt, err := fs.ReadFile("connection.crt")
	if err != nil {
		print(err)
		os.Exit(1)
	}
	connkey, err := fs.ReadFile("connection.key")
	if err != nil {
		print(err)
		os.Exit(1)
	}
	err = star.SetupConnectionCertificate(conncrt, connkey)
	if err != nil {
		print(err)
		os.Exit(1)
	}
}

// Allows for the creation of listeners (bind) and connections (connect) via
// command-line arguments.
func parameterHandlingAgent() {
	for _, arg := range os.Args[1:] {
		setup := strings.Split(arg, ":")
		if setup[0] == "b" || setup[0] == "l" {
			// [b]ind/[l]istener

			if len(setup) == 2 {
				star.NewTCPListener(":" + setup[1])
			} else if len(setup) == 3 {
				star.NewTCPListener(setup[1] + ":" + setup[2])
			}
		} else if setup[0] == "r" || setup[0] == "c" {
			// [r]everse/[c]onnect

			if len(setup) == 2 {
				star.NewTCPConnection(":" + setup[1])
			} else if len(setup) == 3 {
				star.NewTCPConnection(setup[1] + ":" + setup[2])
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

func AgentProcessMessage(msg *star.Message) {
	switch msg.Type {
	case star.MessageTypeBind:
		AgentProcessBind(msg)
	case star.MessageTypeCommandRequest:
		AgentProcessCommandRequest(msg)
	case star.MessageTypeConnect:
		AgentProcessConnect(msg)
	case star.MessageTypeFileDownload:
		AgentProcessFileDownload(msg)
	case star.MessageTypeFileUpload:
		AgentProcessFileUpload(msg)
	case star.MessageTypeKillSwitch:
		AgentProcessKillSwitch(msg)
	case star.MessageTypeSyncRequest:
		AgentProcessSyncRequest(msg)
	}
}

func AgentProcessBind(msg *star.Message) {
	var reqmsg star.MessageBindRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessCommandRequest(msg *star.Message) {
	var reqmsg star.MessageCommandRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessConnect(msg *star.Message) {
	var reqmsg star.MessageConnectRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessFileDownload(msg *star.Message) {
	var reqmsg star.MessageFileDownload
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessFileUpload(msg *star.Message) {
	var reqmsg star.MessageFileUpload
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessKillSwitch(msg *star.Message) {
	var reqmsg star.MessageKillSwitchRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessSyncRequest(msg *star.Message) {
	var reqmsg star.MessageSyncRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqmsg)
	if err == nil {
		// TODO: Handle
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%b", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}
