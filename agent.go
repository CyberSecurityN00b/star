package main

import (
	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	star.ThisNode = star.NewNode(star.NodeTypeAgent)
	star.ThisNode.MessageProcesser = AgentProcessMessage
}

///////////////////////////////////////////////////////////////////////////////

func AgentProcessMessage(msg *star.Message) {
	msg.Decrypt()
	switch msg.Type {
	case star.MessageTypeBind:
	case star.MessageTypeCommand:
	case star.MessageTypeConnect:
	case star.MessageTypeError:
	case star.MessageTypeFileDownload:
	case star.MessageTypeFileUpload:
	case star.MessageTypeKillSwitch:
	case star.MessageTypeSync:
	}
}
