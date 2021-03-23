package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

var terminalNode star.Node

func main() {
	in := bufio.NewReader(os.Stdin)
	terminalNode = star.NewNode(star.NodeTypeTerminal)

	for {
		fmt.Print("")
		text, _ := in.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)
		handleTerminalInput(text)
	}
}

///////////////////////////////////////////////////////////////////////////////

func handleTerminalInput(input string) {
	if len(input) == 0 {
		return
	}
	inputs := strings.Split(input, " ")
	switch inputs[0] {
	case ":?", ":help":
		terminalCommandHelp()
	case ":b", ":bind":
		terminalCommandBind()
	case ":c", ":connect":
		terminalCommandConnect()
	case ":d", ":down", ":download":
		terminalCommandDownload()
	case ":h", ":history":
		terminalCommandHistory()
	case ":i", ":info", ":information":
		terminalCommandInformation()
	case ":j", ":jump":
		terminalCommandJump()
	case ":k", ":kill", ":killswitch":
		terminalCommandKillSwitch()
	case ":l", ":list":
		terminalCommandList()
	case ":r", ":run", ":runfile":
		terminalCommandRunFile()
	case ":t", ":terminate":
		terminalCommandTerminate()
	case ":u", ":up", ":upload":
		terminalCommandUpload()
	case ":q", ":quit":
		terminalCommandQuit()
	case "::":
		if len(input) > 3 {
			terminalCommandSendCommand(input[3:])
		} else {
			terminalCommandSendCommand("")
		}
	default:
		if inputs[0][0] == ':' {
			printError("It looks like you were attempting to enter in a command?")
		} else {
			terminalCommandSendCommand(input)
		}
	}
	return
}

///////////////////////////////////////////////////////////////////////////////

func printError(text string) {
	fmt.Println("[ STAR | error ]> " + text)
}

func printInfo(text string) {
	fmt.Println("[ STAR | info  ]> " + text)
}

///////////////////////////////////////////////////////////////////////////////

func terminalCommandHelp() {
	printError("Help is not yet implemented!")
}

func terminalCommandBind() {
	printError("Bind is not yet implemented!")
}

func terminalCommandConnect() {
	printError("Connect is not yet implemented!")
}

func terminalCommandDownload() {
	printError("Download is not yet implemented!")
}

func terminalCommandHistory() {
	printError("History is not yet implemented!")
}

func terminalCommandInformation() {
	fmt.Print("Terminal ID: ")
	fmt.Println(terminalNode.ID)
}

func terminalCommandJump() {
	printError("Jump is not yet implemented!")
}

func terminalCommandKillSwitch() {
	printError("Killswitch is not yet implemented!")
}

func terminalCommandList() {
	printError("List is not yet implemented!")
}

func terminalCommandRunFile() {
	printError("Runscripts are not yet implemented!")
}

func terminalCommandTerminate() {
	printError("Terminate is not yet implemented!")
}

func terminalCommandUpload() {
	printError("Upload is not yet implemented!")
}

func terminalCommandQuit() {
	printInfo("Goodbye!")
	os.Exit(0)
}

func terminalCommandSendCommand(cmd string) {
	printInfo("You attempted to send: " + cmd)
	printError("Sending commands is not yet implemented.")
}
