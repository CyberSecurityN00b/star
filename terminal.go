package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	in := bufio.NewReader(os.Stdin)

	star.ThisNode = star.NewNode(star.NodeTypeTerminal)
	star.ThisNode.MessageProcesser = TerminalProcessMessage

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
		topic := ""
		if len(inputs) >= 2 {
			topic = inputs[1]
		}
		terminalCommandHelp(topic)
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
/****************************** Terminal Output ******************************/
///////////////////////////////////////////////////////////////////////////////

func printError(text string) {
	fmt.Println("[ STAR | error ]> " + text)
}

func printInfo(text string) {
	fmt.Println("[ STAR | info  ]> " + text)
}

///////////////////////////////////////////////////////////////////////////////
/************************* Terminal Command Handling *************************/
///////////////////////////////////////////////////////////////////////////////

func terminalCommandHelp(topic string) {
	fmt.Println("********************************************************************************")
	switch strings.ToLower(topic) {
	case ":?", ":help":
		fmt.Println("--> COMMAND HELP FOR: :?, :help")
		fmt.Println()
		fmt.Println("USAGE: :?, :? <cmd>, :? <topic>")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t:? :bind")
		fmt.Println("\t:? library")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUsing `:?` by itself prints a list of STAR commands and topics. Specifying a command or topic provides more detailed help specific to that command or topic.")
	case ":b", ":bind":
		fmt.Println("--> COMMAND HELP FOR: :b, :bind")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":c", ":connect":
		fmt.Println("--> COMMAND HELP FOR: :c, :connect")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":d", ":down", ":download":
		fmt.Println("--> COMMAND HELP FOR: :d, :down, :download")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":h", ":history":
		fmt.Println("--> COMMAND HELP FOR: :h, :history")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
	case ":i", ":info", ":information":
		fmt.Println("--> COMMAND HELP FOR: :i, :info, :information")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":j", ":jump":
		fmt.Println("--> COMMAND HELP FOR: :j, :jump")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":k", ":kill", ":killswitch":
		fmt.Println("--> COMMAND HELP FOR: :k, :kill, :killswitch")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":l", ":list":
		fmt.Println("--> COMMAND HELP FOR: :l, :list")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":r", ":run", ":runfile":
		fmt.Println("--> COMMAND HELP FOR: :r, :run, :runfile")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":t", ":terminate":
		fmt.Println("--> COMMAND HELP FOR: :t, :terminate")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":u", ":up", ":upload":
		fmt.Println("--> COMMAND HELP FOR: :u, :up, :upload")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":q", ":quit":
		fmt.Println("--> COMMAND HELP FOR: :q, :quit")
		fmt.Println()
		fmt.Println()
		fmt.Println("USAGE: :q")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tQuits the terminal. Does *NOT* quit any agents.")
	case "::":
		fmt.Println("--> COMMAND HELP FOR: ::")
		fmt.Println()
		fmt.Println("USAGE: :: <command to pass to agent>")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t:: :i")
		fmt.Println("\t:: /bin/bash")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:: <cmd>` to pass a command to an agent and not have it interpreted by the terminal. This is useful for scenarios where you have 'nested terminals' or are interacting with another tool which requires starting a command string with the ':' character. You do *NOT* need to use :: to pass a command to the terminal if it doesn't start with the ':' character.")
	case "agent", "agents":
		fmt.Println("--> ABOUT AGENTS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "connection", "connections":
		fmt.Println("--> ABOUT CONNECTIONS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "constellation", "constellations":
		fmt.Println("--> ABOUT CONSTELLATIONS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "library", "libraries":
		fmt.Println("--> ABOUT LIBRARIES")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "terminal", "terminals":
		fmt.Println("--> ABOUT TERMINALS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	default:
		fmt.Println("------------------------------ STAR Help Overview ------------------------------")
		fmt.Println("********************************************************************************")

		if topic != "" {
			fmt.Println()
			fmt.Println("There is no help for `%s`!", topic)
			fmt.Println()
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, ":? :help \t Displays this help screen.")
		fmt.Fprintln(w, ":: \t Used to pass commands starting with : to an agent.")
		fmt.Fprintln(w, ":b :bind \t Creates a STAR listener and binds it.")
		fmt.Fprintln(w, ":c :connect \t Connects to a STAR listener.")
		fmt.Fprintln(w, ":d :down :download \t Downloads a file from the terminal to the agent.")
		fmt.Fprintln(w, ":h :history \t Displays the command history for an agent.")
		fmt.Fprintln(w, ":i :info :information \t Shows information for a specific agent.")
		fmt.Fprintln(w, ":j :jump \t Jump to another agent (i.e., change focus to another agent).")
		fmt.Fprintln(w, ":k :kill :killswitch \t Panic button! Destroy and cleanup STAR constellation.")
		fmt.Fprintln(w, ":l :list \t Lists the agents in the constellation.")
		fmt.Fprintln(w, ":r :run :runfile \t Runs a prepared file of commands.")
		fmt.Fprintln(w, ":t :terminate \t Terminates a particular agent.")
		fmt.Fprintln(w, ":u :up :upload \t Uploads a file from the agent to the terminal.")
		fmt.Fprintln(w, ":q :quit \t Quits the current terminal.")
		w.Flush()

		fmt.Println()
		fmt.Println("Use `:? <cmd>` for more details on the above commands (i.e., `:? :bind`).")
		fmt.Println()
		fmt.Println("Use `:? <topic>` for more information on the following topics:")
		fmt.Println("\tagent")
		fmt.Println("\tconnections")
		fmt.Println("\tconstellation")
		fmt.Println("\tlibrary")
		fmt.Println("\tterminal")
		w.Flush()
	}
	fmt.Println("********************************************************************************")
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
	fmt.Printf("Terminal ID: %v\n", star.ThisNode.ID)
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

///////////////////////////////////////////////////////////////////////////////

func TerminalProcessMessage(msg *star.Message) {
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
