package main

import (
	"bufio"
	"embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS

var activeNode star.NodeID
var activeStream star.StreamID
var tickerSynchronization *time.Ticker

func main() {
	defer CloseRecordLog()

	showWelcomeText()
	initTerminal()
	star.ParameterHandling()

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	runTerminal()
}

///////////////////////////////////////////////////////////////////////////////

func showWelcomeText() {

	fmt.Println("/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\\")
	fmt.Println("*             _____        _____           ___        ______                  |")
	fmt.Println("|            /  ___|      |_   _|         / _ \\       | ___ \\                 *")
	fmt.Println("*            \\  --.         | |          / /_\\ \\      | |_/ /                 |")
	fmt.Println("|             `--. \\        | |          |  _  |      |    /                  *")
	fmt.Println("*            /\\__/ /        | |          | | | |      | |\\ \\                  |")
	fmt.Println("|            \\____/ imple   \\_/ actical  \\_| |_/ gent \\_| \\_| elay            *")
	fmt.Println("*                                                                             |")
	fmt.Println("\\*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/")
	fmt.Println("")
}

func initTerminal() {
	star.STARCoreSetup()
	star.ThisNode = star.NewNode(star.NodeTypeTerminal)
	star.ThisNode.MessageProcessor = TerminalProcessMessage

	star.ThisNodeInfo.Setup()

	// Setup connection cert
	conncrt, err := fs.ReadFile("connection.crt")
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to read \"connection.crt\" from the embedded file system.")
	}
	connkey, err := fs.ReadFile("connection.key")
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to read \"connection.key\" from the embedded file system.")
	}
	err = star.SetupConnectionCertificate(conncrt, connkey)
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to create the connection's X509KeyPair.")
	}

	// Setup settings
	terminalSettings = make(map[string]terminalSetting)
	terminalSettings["history.tracklength"] = terminalSetting{int64(100), "The number of commands to track in the history."}
	terminalSettings["history.displaylength"] = terminalSetting{int64(10), "The number of commands to show when displaying history (doesn't include `:h all`)."}
	terminalSettings["display.ansicolor"] = terminalSetting{true, "Use ANSI color codes in STAR output."}
	terminalSettings["display.timestamp"] = terminalSetting{"2006.01.02-15:04:05", "GoLang timestamp format for logs/notices."}
	terminalSettings["sync.minutes"] = terminalSetting{int64(5), "Send a Synchronization Request to all agents every N minutes. (Changes take effect at the next ticker synchronization; values less than 1 are ignored.)"}
	terminalSettings["sync.mute"] = terminalSetting{true, "Mutes Synchronization Responses from agents. (Not applicable to errors.)"}
	terminalSettings["info.showenv"] = terminalSetting{false, "Shows environment variables in agent information."}
	terminalSettings["info.showos"] = terminalSetting{true, "Shows OS information in agent information."}
	terminalSettings["info.showinterfaces"] = terminalSetting{true, "Shows network interfaces in agent information."}
	terminalSettings["chat.nickname"] = terminalSetting{fmt.Sprintf("researcher_%s", star.RandString("abcdefghijklmnopqrstuvwxyz0123456789", 8)), "Nickname to use in S.T.A.R. chat messages."}
	terminalSettings["chat.tracklength"] = terminalSetting{int64(100), "The number of chat messages to track in the history."}
	terminalSettings["log.enabled"] = terminalSetting{true, "Whether or not logging is actually enabled."}
	terminalSettings["log.chat"] = terminalSetting{true, "Determines if chat messages are logged."}
	terminalSettings["log.commands"] = terminalSetting{true, "Determines if commands are logged."}
	terminalSettings["log.errors"] = terminalSetting{true, "Determines if agent errors are logged."}
	terminalSettings["log.notices"] = terminalSetting{true, "Determines if agent notices are logged."}
	terminalSettings["log.output"] = terminalSetting{true, "Determines if terminal output is logged. Does not apply to command output."}
	terminalSettings["log.sync"] = terminalSetting{true, "Determines if synchronization activity is logged."}

	// Setup history
	SetupRecordLog()
	historyItems = make(map[uint]historyItem)
	historyItemsMutex = &sync.Mutex{}

	// Setup chat history
	historyChatItems = make(map[uint]historyChatItem)
	historyChatItemsMutex = &sync.Mutex{}

	// Setup agent tracker
	agentFriendlyTracker = make(map[string]*agentInfo)
	agentNodeIDTracker = make(map[star.NodeID]*agentInfo)
	agentTrackerMutex = &sync.Mutex{}
	AgentTrackerUpdateInfo(&star.ThisNode, &star.ThisNodeInfo)

	// Setup file tracker
	fileServerTracker = make(map[star.ConnectID]string)

	// Synchronization ticker
	tickerSynchronization = time.NewTicker(time.Duration(terminalSettings["sync.minutes"].Data.(int64)) * time.Minute)
	go func() {
		for {
			select {
			case <-tickerSynchronization.C:
				TerminalSynchronize(false)

				next := terminalSettings["sync.minutes"].Data.(int64)
				if next >= 1 {
					tickerSynchronization.Reset(time.Duration(next) * time.Minute)
				}
			}
		}
	}()

	printInfo(fmt.Sprintf("Terminal Initiated! Terminal ID is %s.", star.ThisNode.ID))
	printInfo("Good luck and have fun!")
}

func runTerminal() {
	in := bufio.NewReader(os.Stdin)
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

	// Add to history
	n := activeNode
	s := activeStream
	if len(input) >= 2 {
		if input[0] == ':' && input[1] != ':' {
			n = star.ThisNode.ID
		}
	}
	HistoryPush(historyItem{time.Now(), input, n, s})

	// ### Handle ###
	// Old way of handling below, did not respect spaces in quotes
	//inputs := strings.Split(input, " ")
	// New way:
	r := csv.NewReader(strings.NewReader(input))
	r.Comma = ' '
	inputs, _ := r.Read()

	// Used by commands run on remote agent (such as :rls). Declared after variables above.
	remoteAgentCheck := func() (node *agentInfo, argoffset int, ok bool) {
		// argoffset tracks if the agent was specified, use in inputs[] index offset
		argoffset = 1
		ok = false

		if len(inputs) > 1 {
			node, ok = AgentTrackerGetInfoByFriendly(inputs[1])
		}
		if !ok {
			node, ok = AgentTrackerGetInfoByNodeID(activeNode)
			argoffset = 0
		}

		return
	}

	if input[0] == ':' && inputs[0] != "::" && inputs[0] != ":q" {
		fmt.Println("/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\\")
	}

	switch inputs[0] {
	case ":?", ":help":
		topic := ""
		if len(inputs) >= 2 {
			topic = inputs[1]
		}
		terminalCommandHelp(topic)
	case ":b", ":bind":
		if len(inputs) == 2 {
			// Single address string, default to terminal
			terminalCommandBind(star.ThisNode.ID, inputs[1:]...)
		} else if len(inputs) > 2 {
			if inputs[1] == "all" {
				// Use broadcast NodeID to send address string to all Nodes
				terminalCommandBind(star.NodeID{}, inputs[2:]...)
			} else if strings.HasPrefix(inputs[1], "agent") {
				node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
				if !ok {
					// Invalid agentID
					printError("No such agent as " + inputs[1] + "!")
				} else {
					// Send address string(s) to Node
					terminalCommandBind(node.Node.ID, inputs[2:]...)
				}
			} else {
				// No agent, multiple address strings, send to terminal
				terminalCommandBind(star.ThisNode.ID, inputs[1:]...)
			}
		} else {
			terminalCommandHelp(":b")
		}
	case ":c", ":connect":
		if len(inputs) == 2 {
			// Single address string, default to terminal
			terminalCommandConnect(star.ThisNode.ID, inputs[1:]...)
		} else if len(inputs) > 2 {
			if inputs[1] == "all" {
				// Use broadcast NodeID to send address string to all Nodes
				terminalCommandConnect(star.NodeID{}, inputs[2:]...)
			} else if strings.HasPrefix(inputs[1], "agent") {
				node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
				if !ok {
					// Invalid agentID
					printError("No such agent as " + inputs[1] + "!")
				} else {
					// Send address string(s) to Node
					terminalCommandConnect(node.Node.ID, inputs[2:]...)
				}
			} else {
				// No agent, multiple address strings, send to terminal
				terminalCommandConnect(star.ThisNode.ID, inputs[1:]...)
			}
		} else {
			terminalCommandHelp(":c")
		}
	case ":chat":
		// Note: Keep the chat command exactly the five characters
		if len(input) > 6 {
			terminalCommandChat(input[6:])
		} else {
			printError("Empty chat message, not sending to constellation.")
		}
	case ":clear":
		terminalCommandClear()
	case ":d", ":down", ":download":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":d")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 2 {
				// No dst filename provided, use same as src
				terminalCommandDownload(node.Node.ID, inputs[1+argoffset], TerminalSanitizeFilepath(inputs[1+argoffset]))
			} else if (len(inputs) - argoffset) == 3 {
				terminalCommandDownload(node.Node.ID, inputs[1+argoffset], inputs[2+argoffset])
			} else {
				terminalCommandHelp(":d")
			}
		}
	case ":h", ":history":
		if len(inputs) == 2 {
			if inputs[1] == "all" {
				terminalCommandHistory(true, activeNode, activeStream)
			} else if inputs[1] == "chat" {
				terminalCommandChatHistory()
			} else {
				node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
				if !ok {
					terminalCommandList("all")
					printError(fmt.Sprintf("%s is not a valid identifier, use one of the above!", inputs[1]))
				} else {
					terminalCommandHistory(false, node.Node.ID, activeStream)
				}
			}
		} else {
			terminalCommandHistory(false, activeNode, activeStream)
		}
	case ":i", ":info", ":information":
		if len(inputs) == 2 {
			terminalCommandInformation(inputs[1])
		} else if len(inputs) == 1 {
			terminalCommandInformation("")
		} else {
			terminalCommandHelp(":i")
		}
	case ":j", ":jump":
		if len(inputs) == 2 {
			terminalCommandJump(inputs[1])
		} else {
			terminalCommandHelp(":j")
		}
	case ":k", ":kill", ":killswitch":
		if len(inputs) == 1 {
			terminalCommandKillSwitch("")
		} else if len(inputs) == 2 {
			terminalCommandKillSwitch(inputs[1])
		} else {
			terminalCommandHelp(":k")
		}
	case ":l", ":list":
		if len(inputs) >= 2 {
			terminalCommandList(inputs[1])
		} else {
			terminalCommandList("all")
		}
	case ":lcat":
		if len(inputs) == 1 {
			printError("No file specified to cat locally.")
		} else if len(inputs) == 2 {
			terminalCommandLocalCat(inputs[1])
		} else {
			terminalCommandHelp(":lcat")
		}
	case ":lcd":
		if len(inputs) == 1 {
			terminalCommandLocalPresentWorkingDirectory()
		} else if len(inputs) == 2 {
			terminalCommandLocalChangeDirectory(inputs[1])
		} else {
			terminalCommandHelp(":lcd")
		}
	case ":lls", ":ldir":
		if len(inputs) == 1 {
			terminalCommandLocalListFiles(".")
		} else if len(inputs) == 2 {
			terminalCommandLocalListFiles(inputs[1])
		} else {
			terminalCommandHelp(":lls")
		}
	case ":lmkdir":
		if len(inputs) == 1 {
			terminalCommandLocalMakeTemporaryDirectory()
		} else if len(inputs) == 2 {
			terminalCommandLocalMakeDirectory(inputs[1])
		} else {
			terminalCommandHelp(":lmkdir")
		}
	case ":lpwd":
		if len(inputs) == 1 {
			terminalCommandLocalPresentWorkingDirectory()
		} else {
			terminalCommandHelp(":lpwd")
		}
	case ":ltmpdir":
		if len(inputs) == 1 {
			terminalCommandLocalMakeTemporaryDirectory()
		} else {
			terminalCommandHelp(":ltmpdir")
		}
	case ":rcat":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rcat")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				printError("No file specified to cat remotely.")
			} else if (len(inputs) - argoffset) == 2 {
				terminalCommandRemoteCat(node.Node.ID, inputs[1+argoffset])
			} else {
				terminalCommandHelp("rcat")
			}
		}
	case ":rcd":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rcd")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				terminalCommandRemotePresentWorkingDirectory(node.Node.ID)
			} else if (len(inputs) - argoffset) == 2 {
				terminalCommandRemoteChangeDirectory(node.Node.ID, inputs[1+argoffset])
			} else {
				terminalCommandHelp(":rcd")
			}
		}
	case ":rls", ":rdir":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rls")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				terminalCommandRemoteListFiles(node.Node.ID, ".")
			} else if (len(inputs) - argoffset) == 2 {
				terminalCommandRemoteListFiles(node.Node.ID, inputs[1+argoffset])
			} else {
				terminalCommandHelp(":rls")
			}
		}
	case ":rmkdir":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rmkdir")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				terminalCommandRemoteTmpDir(node.Node.ID)
			} else if (len(inputs) - argoffset) == 2 {
				terminalCommandRemoteMkDir(node.Node.ID, inputs[1+argoffset])
			} else {
				terminalCommandHelp(":rmkdir")
			}
		}
	case ":rpwd":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rcd")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				terminalCommandRemotePresentWorkingDirectory(node.Node.ID)
			} else {
				terminalCommandHelp(":rpwd")
			}
		}
	case ":rtmpdir":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":rtmpdir")
			printError("No active agent and no agent spcified in command.")
		} else {
			if (len(inputs) - argoffset) == 1 {
				terminalCommandRemoteTmpDir(node.Node.ID)
			} else {
				terminalCommandHelp(":rtmpdir")
			}
		}
	case ":s", ":set", ":setting", ":settings":
		if len(inputs) == 1 {
			terminalCommandSet("", "")
		} else if len(inputs) == 2 {
			terminalCommandSet(inputs[1], "")
		} else {
			terminalCommandSet(inputs[1], star.StringifySubarray(inputs, 2, len(inputs)))
		}
	case ":sync":
		TerminalSynchronize(true)
	case ":t", ":terminate":
		if len(inputs) == 1 {
			terminalCommandTerminate("")
		} else if len(inputs) == 2 {
			terminalCommandTerminate(inputs[1])
		} else {
			terminalCommandHelp(":t")
		}
	case ":u", ":up", ":upload":
		node, argoffset, ok := remoteAgentCheck()
		if !ok {
			terminalCommandHelp(":u")
			printError("No active agent and no agent specified in command.")
		} else {
			if (len(inputs) - argoffset) == 2 {
				// No dst filename provided, use same as src
				terminalCommandUpload(node.Node.ID, inputs[1+argoffset], TerminalSanitizeFilepath(inputs[1+argoffset]))
			} else if (len(inputs) - argoffset) == 3 {
				terminalCommandUpload(node.Node.ID, inputs[1+argoffset], inputs[2+argoffset])
			} else {
				terminalCommandHelp(":u")
			}
		}
	case ":q", ":quit":
		terminalCommandQuit(nil, "")
	case "::":
		if len(input) > 3 {
			terminalCommandSendCommand(input[3:])
		} else {
			terminalCommandSendCommand("")
		}
	default:
		if inputs[0][0] == ':' {
			terminalCommandHelp("")
			fmt.Println()
			printError("It looks like you were attempting to enter in a command? If so, commands are case sensitive. If not, run `:? ::`.")
		} else {
			terminalCommandSendCommand(input)
		}
	}

	if input[0] == ':' && inputs[0] != "::" && inputs[0] != ":q" && inputs[0] != ":clear" {
		fmt.Println("\\*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/")
	}

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Terminal Output ******************************/
///////////////////////////////////////////////////////////////////////////////

type ANSIColor string

const (
	ANSIColor_Chat      ANSIColor = "\033[0;35;51m%s\033[0m"
	ANSIColor_Error     ANSIColor = "\033[0;31m%s\033[0m"
	ANSIColor_Info      ANSIColor = "\033[0;36m%s\033[0m"
	ANSIColor_Debug     ANSIColor = "\033[1;31m%s\033[0m"
	ANSIColor_Time      ANSIColor = "\033[7m%s\033[0m"
	ANSIColor_Focus     ANSIColor = "\033[7m%s\033[0m"
	ANSIColor_Notice    ANSIColor = "\033[33m%s\033[0m"
	ANSIColor_DeadAgent ANSIColor = "\033[101m%s\033[0m"
)

func ANSIColorize(text string, color ANSIColor) string {
	c, ok := terminalSettings["display.ansicolor"].Data.(bool)
	if !ok {
		c = false
	}
	if c {
		return fmt.Sprintf(string(color), text)
	} else {
		return text
	}
}

func printChat(text string) {
	t := time.Now().Format(terminalSettings["display.timestamp"].Data.(string))
	fmt.Println(ANSIColorize(t, ANSIColor_Time), ANSIColorize("[ STAR | chat ]> "+text, ANSIColor_Chat))
	// Chat history is already recorded to file elsewhere
}

func printError(text string) {
	t := time.Now().Format(terminalSettings["display.timestamp"].Data.(string))
	fmt.Println(ANSIColorize(t, ANSIColor_Time), ANSIColorize("[ STAR | err! ]> "+text, ANSIColor_Error))
	RecordLog(time.Now(), star.ThisNode.ID, "output", "error", text)
}

func printInfo(text string) {
	t := time.Now().Format(terminalSettings["display.timestamp"].Data.(string))
	fmt.Println(ANSIColorize(t, ANSIColor_Time), ANSIColorize("[ STAR | info ]> "+text, ANSIColor_Info))
	RecordLog(time.Now(), star.ThisNode.ID, "output", "info", text)
}

func printDebug(text string) {
	t := time.Now().Format(terminalSettings["display.timestamp"].Data.(string))
	fmt.Println(ANSIColorize(t, ANSIColor_Time), ANSIColorize("[ STAR | dbg! ]> "+text, ANSIColor_Debug))
	RecordLog(time.Now(), star.ThisNode.ID, "output", "debug", text)
}

func printNotice(text string) {
	t := time.Now().Format(terminalSettings["display.timestamp"].Data.(string))
	fmt.Println(ANSIColorize(t, ANSIColor_Time), ANSIColorize("[ STAR | !!!! ]> "+text, ANSIColor_Notice))
	RecordLog(time.Now(), star.ThisNode.ID, "output", "notice", text)
}

///////////////////////////////////////////////////////////////////////////////
/************************* Terminal Command Handling *************************/
///////////////////////////////////////////////////////////////////////////////

func terminalCommandHelp(topic string) {
	switch strings.ToLower(topic) {
	case ":?", ":help":
		fmt.Println("--> COMMAND HELP FOR: :?, :help")
		fmt.Println()
		fmt.Println("USAGE:")
		fmt.Println("\t:?          -  Shows help overview.")
		fmt.Println("\t:? <cmd>    -  Shows help for a specific command.")
		fmt.Println("\t:? <topic>  -  Shows help for a topic (see `:?`).")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUsing `:?` by itself prints a list of STAR commands and topics. Specifying a command or topic provides more detailed help specific to that command or topic.")
	case ":b", ":bind":
		fmt.Println("--> COMMAND HELP FOR: :b, :bind")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t==================== S.T.A.R. Connections ====================")
		fmt.Println("\t:b <addr>                    -  Creates a listener on the local terminal at <addr>.")
		fmt.Println("\t:b :4444                     -  Creates a listener on the local terminal on port 4444.")
		fmt.Println("\t:b <agent> <addr>            -  Creates a listener on <agent> at <addr>.")
		fmt.Println("\t:b agent001 :4444")
		fmt.Println("\t:b agent001 10.10.10.10:4444")
		fmt.Println("\t===================== Shell Connections =====================")
		fmt.Println("\t:b <agent> shell:<addr>      -  Creates a listener to interact with reverse shells over tcp.")
		fmt.Println("\t:b <agent> shell.tcp:<addr>  -  Creates a listener to interact with reverse shells over tcp.")
		fmt.Println("\t:b <agent> shell.tls:<addr>  -  Creates a listener to interact with reverse shells over tcp/tls.")
		fmt.Println("\t:b <agent> shell.udp:<addr>  -  Creates a listener to interact with reverse shells over udp.")
		fmt.Println("\t:b <agent> shell.wtf:<addr>  -  Creates a listener to interact with reverse shells over udp/tls (why would you do this!?).")
		fmt.Println("\t=================== FileServer Connections ===================")
		fmt.Println("\t:b <agent> file:<addr>:<file>      -  Creates a single-file file server over tcp.")
		fmt.Println("\t:b <agent> file:12345:agent.exe    -  Creates a file server on port 12345, serving up agent.exe.")
		fmt.Println("\t:b <agent> file.tcp:<addr>:<file>  -  Creates a single-file file server over tcp.")
		fmt.Println("\t:b <agent> file.tls:<addr>:<file>  -  Creates a single-file file server over tcp/tls.")
		fmt.Println("\t:b <agent> file.udp:<addr>:<file>  -  Creates a single-file file server over udp.")
		fmt.Println("\t:b <agent> file.wtf:<addr>:<file>  -  Creates a single-file file server over udp/tls (why would you do this!?).")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:b` to create a TCP TLS listener for other STAR node to connect to. <addr> uses the Golang network address format.")
		fmt.Println()
		fmt.Println("Note: <addr> can be in port or ip:port format. If just a format, it must be preceded by a ':', such as 'shell.tcp:4444' or ':4444'")
	case ":c", ":connect":
		fmt.Println("--> COMMAND HELP FOR: :c, :connect")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t==================== S.T.A.R. Connections ====================")
		fmt.Println("\t:c <addr>                    -  Connects the terminal to a STAR node at <addr>.")
		fmt.Println("\t:c 10.10.10.10:4444          -  Connects the terminal to a STAR node at 10.10.10.10:4444")
		fmt.Println("\t:c <agent> <addr>            -  Connects <agent> to a STAR node at <addr>.")
		fmt.Println("\t:c agent002 10.10.10.10:4444")
		fmt.Println("\t===================== Shell Connections =====================")
		fmt.Println("\t:c <agent> shell:<addr>      -  Connects to a listening shell to interact with it over tcp.")
		fmt.Println("\t:c <agent> shell.tcp:<addr>  -  Connects to a listening shell to interact with it over tcp.")
		fmt.Println("\t:c <agent> shell.tls:<addr>  -  Connects to a listening shell to interact with it over tcp/tls.")
		fmt.Println("\t:c <agent> shell.udp:<addr>  -  Connects to a listening shell to interact with it over udp.")
		fmt.Println("\t:c <agent> shell.wtf:<addr>  -  Connects to a listening shell to interact with it over udp/tls (why would you do this!?).")
		fmt.Println("\t=================== FileServer Connections ===================")
		fmt.Println("\t:c <agent> file:<addr>:<file>               -  Connects to a over tcp.")
		fmt.Println("\t:c <agent> file:10.10.10.1:12345:agent.exe  -  Connects to 10.10.10.1:12345 over tcp and sends agent.exe.")
		fmt.Println("\t:c <agent> file.tcp:<addr>:<file>           -  Connects to a listening port to send a file over tcp.")
		fmt.Println("\t:c <agent> file.tls:<addr>:<file>           -  Connects to a listening port to send a file over tcp/tls.")
		fmt.Println("\t:c <agent> file.udp:<addr>:<file>           -  Connects to a listening port to send a file over udp.")
		fmt.Println("\t:c <agent> file.wtf:<addr>:<file>           -  Connects to a listening port to send a file over udp/tls (why would you do this!?).")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:c` to connect to a TCP TLS listener of another STAR node. <addr> uses the Golang network address format.")
		fmt.Println()
		fmt.Println("Note: <addr> can be in port or ip:port format. If just a format, it must be preceded by a ':', such as 'shell.tcp:4444' or ':4444'")
	case ":chat":
		fmt.Println("--> COMMAND HELP FOR: :chat")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:chat <message>                          -  Sends a message.")
		fmt.Println("\t:chat Check out what I did on agent002!  -  Sends a message.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tCommunicate with other security researchers in the constellation. Note that agent/term identifiers, such as agent002, are automatically converted to their unique identifier when sent, and then converted back into the receiving terminal's identifiers.")
	case ":clear":
		fmt.Println("--> COMMAND HELP FOR: :clear")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:clear")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tClears the terminal screen, 'cause apparently some people are into that.")
	case ":d", ":down", ":download":
		fmt.Println("--> COMMAND HELP FOR: :d, :down, :download")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:d <remote_src_file>                           -  Downloads the remote source file from the active agent to the local directory.")
		fmt.Println("\t:d /etc/shadow                                 -  Downloads '/etc/shadow' from the active agent to './-etc-shadow' locally.")
		fmt.Println("\t:d <remote_src_file> <local_dst_file>          -  Downloads the remote source file from the active agent to the specific local location.")
		fmt.Println("\t:d /etc/shadow /tmp/victim.shadow              -  Downloads '/etc/shadow' from the active agent to '/tmp/victim.shadow' locally.")
		fmt.Println("\t:d <agent> <remote_src_file>                   -  Downloads the remote source file from the specified agent to the local directory.")
		fmt.Println("\t:d agent002 /etc/shadow                        -  Downloads '/etc/shadow' from agent002 to './-etc-shadow' locally.")
		fmt.Println("\t:d <agent> <remote_src_file> <local_dst_file>  -  Downloads the remote source file from the specified agent to the specified local location.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:d` to download files from an agent node to the local terminal node.")
		fmt.Println()
		fmt.Println(ANSIColorize("NOTE: If multiple security researchers are using the constellation, best practice is to explicitly specify the full file path for the remote file.", ANSIColor_Error))
	case ":h", ":history":
		fmt.Println("--> COMMAND HELP FOR: :h, :history")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:h       -  Shows history for active STAR node.")
		fmt.Println("\t:h all   -  Shows history for all nodes.")
		fmt.Println("\t:h chat  -  Shows chat history.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:h` to view the timestamped command or chat history.")
	case ":i", ":info", ":information":
		fmt.Println("--> COMMAND HELP FOR: :i, :info, :information")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:i          -  Shows STAR nodes connected to constellation.")
		fmt.Println("\t:i <agent>  -  Shows information specific to <agent.")
		fmt.Println("\t:i agent001")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:i` to view information pertaining to a STAR node, to include network interfaces, environment variables, etc.")
	case ":j", ":jump":
		fmt.Println("--> COMMAND HELP FOR: :j, :jump")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:j <agent>           -  Change the active/focused STAR node to <agent>.")
		fmt.Println("\t:j <agent>:<stream>  -  Change the active/focused STAR node to specific stream.")
		fmt.Println("\t:j agent001")
		fmt.Println("\t:j agent003:stream001")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:j` to jump to another agent or stream. When jumping to another agent, any commands passed to the node will create a new stream and that stream will receive the focus. When jumping to an <agent>:<stream>, such as going to a shell or a previous, still-running command, that stream will receive the input/commands passed.")
	case ":k", ":kill", ":killswitch":
		fmt.Println("--> COMMAND HELP FOR: :k, :kill, :killswitch")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:k  - Terminates constellation and attempts cleanup (cleanup not yet implemented).")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:k` as a panic button or when you're done for the night. Terminates all agents, commands, and shells.")
	case ":l", ":list":
		fmt.Println("--> COMMAND HELP FOR: :l, :list")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:l          -  Lists the agents and terminals in the constellation.")
		fmt.Println("\t:l <agent>  -  Lists the connections, listeners, and streams for an agent.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:l` to list agents, connections, listeners, shells, streams, etc. Also shows how long it has been since an agent has synced.")
	case ":lcat":
		fmt.Println("--> COMMAND HELP FOR: :lcat")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:lcat <file>                -  Outputs the contents of a local file.")
		fmt.Println("\t:lcat notes                 -  Outputs the contents of the local file './notes'.")
		fmt.Println("\t:lcat /etc/passwd           -  Outputs the contents of the local file '/etc/passwd'.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tOutputs the contents of a local file.")
		fmt.Println()
	case ":lcd":
		fmt.Println("--> COMMAND HELP FOR: :lcd")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:lcd             -  Same as running :lpwd, shows the current working directory.")
		fmt.Println("\t:lcd <path>      -  Changes the working directory of the terminal to <path>.")
		fmt.Println("\t:lcd ../../.git  -  Changes the working directory of the terminal to '.git' two folders up.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tChanges the local terminal's working directory.")
		fmt.Println()
	case ":lls", ":ldir":
		fmt.Println("--> COMMAND HELP FOR: :lls, :ldir")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:lls         -  Lists the contents of the current working directory.")
		fmt.Println("\t:lls <path>  -  Lists the contents of the files in the directory specified by <path>.")
		fmt.Println("\t:lls /etc    -  Lists the contents of the files in the '/etc' directory.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tLists the contents of a directory on the local terminal.")
		fmt.Println()
	case ":lmkdir":
		fmt.Println("--> COMMAND HELP FOR: :lmkdir")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:lmkdir             -  With no arguments, same as running `:ltmpdir`.")
		fmt.Println("\t:lmkdir <path>      -  Creates a local directory as specified by <path> and makes it the working directory.")
		fmt.Println("\t:lmkdir /a/new/dir  -  Creates '/a/new/dir' locally and makes it the working directory.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tCreates a directory on the local terminal's machine and changes the working directory to it. If any parent directories do not exist, they will be created.")
		fmt.Println()
	case ":lpwd":
		fmt.Println("--> COMMAND HELP FOR: :lpwd")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:lpwd  -  Prints the terminal's current working directory.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tDisplays the local terminal's current working directory.")
		fmt.Println()
	case ":ltmpdir":
		fmt.Println("--> COMMAND HELP FOR: :ltmpdir")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:ltmpdir  -  Create a temporary directory and make it the working directory.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tCreates a temporary directory on the local temrinal's machine and changes the working directory to it.")
		fmt.Println()
	case ":rcat":
		fmt.Println("--> COMMAND HELP FOR: :rcat")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:rcat <file>                -  Outputs the contents of the remote file on the currently focused agent.")
		fmt.Println("\t:rcat /etc/passwd           -  Outputs the contents of `/etc/passwd` on the currently focused agent.")
		fmt.Println("\t:rcat <agent> <file>        -  Outputs the contents of the remote file of the specified agent.")
		fmt.Println("\t:rcat agent002 /etc/shadow  -  Outputs the contents of `/etc/shadow` on agent002.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tOutputs the contents of a remote file.")
		fmt.Println()
	case ":rcd":
		fmt.Println("--> COMMAND HELP FOR: :rcd")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:rcd                              -  Same as running :rpwd, show the currently focused remote agent's working directory.")
		fmt.Println("\t:rcd <path>                       -  Changes the currently focused remote agent's working directory to <path>.")
		fmt.Println("\t:rcd <agent> <path>               -  Changes the specified remote agent's working directory to <path>.")
		fmt.Println("\t:rcd agent001 \"C:\\Program Files\"  -  Changes agent001's working directory to \"C:\\Program Files\".")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
	case ":rls", ":rdir":
		fmt.Println("--> COMMAND HELP FOR: :rls, :rdir")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
	case ":rmkdir":
		fmt.Println("--> COMMAND HELP FOR: :rmkdir")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println(":rmkdir  -  With no arguments, same as running `:rtmpdir`.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
	case ":rpwd":
		fmt.Println("--> COMMAND HELP FOR: :rpwd")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
	case ":rtmpdir":
		fmt.Println("--> COMMAND HELP FOR: :lmkdir")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
	case ":s", ":set", ":setting", ":settings":
		fmt.Println("--> COMMAND HELP FOR: :s, :set, :setting, :settings")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:s                    -  Lists all the settings available to modify.")
		fmt.Println("\t:s <setting>          -  Shows the value of the setting, and its description.")
		fmt.Println("\t:s <setting> <value>  -  Changes the value of the setting.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:s` to modify properties of the STAR terminal and constellation.")
	case ":sync":
		fmt.Println("--> COMMAND HELP FOR: :sync")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:sync  -  Forces synchronization of agents.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:sync` to force a synchronization of agents. This is beneficial to update information/lists, and share with agents any terminal changes (files, passwords, etc.).")
	case ":t", ":terminate":
		fmt.Println("--> COMMAND HELP FOR: :t, :terminate")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:t <agent>               -  Terminates an agent.")
		fmt.Println("\t:t <agent>:<connection>  -  Terminates an existing connection on an agent (careful!).")
		fmt.Println("\t:t <agent>:<listener>    -  Terminates a listener on an agent.")
		fmt.Println("\t:t <agent>:<stream>       -  Terminates a stream on an agent.")
		fmt.Println("\t:t agent001:listener002")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:t` to terminate agents, connctions, listeners, and streams. Use `:l <agent>` for a listing of identifiers that can be used for that agent.")
	case ":u", ":up", ":upload":
		fmt.Println("--> COMMAND HELP FOR: :u, :up, :upload")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:u <local_src_file>                            -  Uploads the local source file to the active agent's current directory.")
		fmt.Println("\t:u webshell.php                                -  Uploads './webshell.php' to the active agent's current directory.")
		fmt.Println("\t:u <local_src_file> <remote_dst_file>          -  Uploads the local source file to the active agent's specified local location.")
		fmt.Println("\t:u webshell.php /var/www/html/webshell.php     -  Uploads './webshell.php' to '/var/www/html/webshell.php' on the active agent.")
		fmt.Println("\t:u <agent> <local_src_file>                    -  Uploads the local source file to the specified agent's current directory.")
		fmt.Println("\t:u agent002 webshell.php                       -  Uploads './webshell.php' to agent002's current directory.")
		fmt.Println("\t:u <agent> <local_src_file> <remote_dst_file>  -  Uploads the local source file to the specified file location on the specified agent.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println(ANSIColorize("NOTE: If multiple security researchers are using the constellation, best practice is to explicitly specify the full file path for the remote file.", ANSIColor_Error))
	case ":q", ":quit":
		fmt.Println("--> COMMAND HELP FOR: :q, :quit")
		fmt.Println()
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("\t:q  - Quits the terminal.")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tQuits the terminal. Does *NOT* quit any agents.")
	case "::":
		fmt.Println("--> COMMAND HELP FOR: ::")
		fmt.Println()
		fmt.Println("USAGE:")
		fmt.Println("\t:: :i")
		fmt.Println("\t:: /bin/bash")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:: <cmd>` to pass a command to an agent and not have it interpreted by the terminal. This is useful for scenarios where you have 'nested terminals' or are interacting with another tool which requires starting a command string with the ':' character. You do *NOT* need to use :: to pass a command to the terminal if it doesn't start with the ':' character. Only works for the active agent/stream.")
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
	case "shell", "shells":
		fmt.Println("--> ABOUT SHELLS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "terminal", "terminals":
		fmt.Println("--> ABOUT TERMINALS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	default:
		fmt.Println("------------------------------ STAR Help Overview -----------------------------")
		fmt.Println("=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=")

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
		fmt.Fprintln(w, ":chat \t Chat with other security researchers in the constellation.")
		fmt.Fprintln(w, ":clear \t Clears the terminal screen.")
		fmt.Fprintln(w, ":d :down :download \t Downloads a file from the terminal to the agent.")
		fmt.Fprintln(w, ":h :history \t Displays the command history for an agent.")
		fmt.Fprintln(w, ":i :info :information \t Shows information for a specific agent.")
		fmt.Fprintln(w, ":j :jump \t Jump (change focus) to another agent.")
		fmt.Fprintln(w, ":k :kill :killswitch \t Panic button! Destroy and cleanup constellation.")
		fmt.Fprintln(w, ":l :list \t Lists agents, connections, and commands.")
		fmt.Fprintln(w, ":p :proxy \t Creates a SOCKS5 server tunnel.")
		fmt.Fprintln(w, ":pf :portforward \t Creates a port-forwarding tunnel.")
		fmt.Fprintln(w, ":s :set :setting :settings \t View/set configuration settings.")
		fmt.Fprintln(w, ":sync \t Force constellation synchronization.")
		fmt.Fprintln(w, ":t :terminate \t Terminates an agent, connection, or command.")
		fmt.Fprintln(w, ":u :up :upload \t Uploads a file from the terminal to the agent.")
		fmt.Fprintln(w, ":q :quit \t Quits the current terminal.")
		w.Flush()

		fmt.Println()
		fmt.Println("=============== Built-In Local Commands  ===============")
		fmt.Fprintln(w, ":lcat \t Outputs the contents of a local file.")
		fmt.Fprintln(w, ":lcd \t Changes the directory for the local node.")
		fmt.Fprintln(w, ":lls :ldir \t Lists files for the local node.")
		fmt.Fprintln(w, ":lmkdir \t Creates a directory in the local node.")
		fmt.Fprintln(w, ":lpwd \t Prints the working directory for the local node.")
		fmt.Fprintln(w, ":ltmpdir \t Creates a temporary directory in the local node.")
		w.Flush()

		fmt.Println()
		fmt.Println("=============== Built-In Remote Commands ===============")
		fmt.Fprintln(w, ":rcat \t Outputs the contents of a remote file.")
		fmt.Fprintln(w, ":rcd \t Changes the directory for the remote node.")
		fmt.Fprintln(w, ":rls :rdir \t Lists files for the remote node.")
		fmt.Fprintln(w, ":rmkdir \t Creates a directory on the remote node.")
		fmt.Fprintln(w, ":rpwd \t Prints the working directory for the remote node.")
		fmt.Fprintln(w, ":rtmpdir \t Creates a temporary directory on the remote node.")
		w.Flush()

		fmt.Println()
		fmt.Println("Use `:? <cmd>` for more details on the above commands (i.e., `:? :bind`).")
		fmt.Println()
		fmt.Println("Use `:? <topic>` for more information on the following topics:")
		fmt.Println("\tagent")
		fmt.Println("\tconnections")
		fmt.Println("\tconstellation")
		fmt.Println("\tshells")
		fmt.Println("\tterminal")
		w.Flush()
	}
}

func terminalCommandBind(node star.NodeID, addresses ...string) {
	for _, address := range addresses {
		switch strings.ToLower(strings.Split(address, ":")[0]) {
		case "tcp":
			terminalCommandTCPBind(node, address)
		case "shell", "shell.tcp", "shell.tls", "shell.udp", "shell.wtf":
			terminalCommandShellBind(node, address)
		case "file", "file.tcp", "file.tls", "file.udp", "file.wtf":
			terminalCommandFileServerBind(node, address)
		default:
			terminalCommandTCPBind(node, "tcp:"+address)
		}
	}
}

func terminalCommandTCPBind(node star.NodeID, address string) {
	var a string

	parts := strings.Split(address, ":")
	if len(parts) == 2 {
		a = ":" + parts[1]
	} else if len(parts) == 3 {
		a = parts[1] + ":" + parts[2]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for TCP listener: %s", a))
		return
	}

	if node.IsBroadcastNodeID() || node == star.ThisNode.ID {
		printInfo("Setting up listener on " + a)
		star.NewTCPListener(a)
	}

	if node != star.ThisNode.ID {
		bindMsg := star.NewMessageBindTCP(a)
		bindMsg.Destination = node
		bindMsg.Send(star.ConnectID{})
	}
	return
}

func terminalCommandShellBind(node star.NodeID, address string) {
	var a string // Address
	var t star.ConnectorType

	parts := strings.Split(address, ":")
	if len(parts) == 2 { // shell:<port>
		a = ":" + parts[1]
	} else if len(parts) == 3 { // shell:<ip>:<port>
		a = parts[1] + ":" + parts[2]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for shell listener: %s", address))
		return
	}

	switch parts[0] {
	case "shell", "shell.tcp":
		t = star.ConnectorType_ShellTCP
	case "shell.tls":
		t = star.ConnectorType_ShellTCPTLS
	case "shell.udp":
		t = star.ConnectorType_ShellUDP
	case "shell.wtf":
		t = star.ConnectorType_ShellUDPTLS
	default:
		printError(fmt.Sprintf("Invalid shell type specifier given: %s", parts[0]))
		return
	}

	if node != star.ThisNode.ID {
		bindMsg := star.NewMessageShellBindRequest(t, a)
		bindMsg.Destination = node
		bindMsg.Send(star.ConnectID{})
	} else {
		printError(fmt.Sprintf("Cannot create shell listeners on terminal nodes!"))
		return
	}
}

func terminalCommandFileServerBind(node star.NodeID, address string) {
	var a string // Address
	var f string // file
	var t star.ConnectorType

	parts := strings.Split(address, ":")
	if len(parts) == 3 { // file:<port>:<file>
		a = ":" + parts[1]
		f = parts[2]
	} else if len(parts) == 4 { // file:<ip>:<port>:<file>
		a = parts[1] + ":" + parts[2]
		f = parts[3]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for fileserver listener: %s", address))
		return
	}

	switch parts[0] {
	case "file", "file.tcp":
		t = star.ConnectorType_FileServerTCP
	case "file.tls":
		t = star.ConnectorType_FileServerTCPTLS
	case "file.udp":
		t = star.ConnectorType_FileServerUDP
	case "file.wtf":
		t = star.ConnectorType_FileServerUDPTLS
	default:
		printError(fmt.Sprintf("Invalid fileserver type specifier given: %s", parts[0]))
		return
	}

	if node != star.ThisNode.ID {
		id, err := FileServerTrackerGetID(f)
		if err != nil {
			printError(fmt.Sprintf("Error while trying to create fileserver: %v", err.Error()))
			return
		}
		bindMsg := star.NewMessageFileServerBindRequest(t, a, id)
		bindMsg.Destination = node
		bindMsg.Send(star.ConnectID{})
	} else {
		printError(fmt.Sprintf("Cannot create shell listeners on terminal nodes!"))
		return
	}
}

func terminalCommandConnect(node star.NodeID, addresses ...string) (err error) {
	for _, address := range addresses {
		switch strings.ToLower(strings.Split(address, ":")[0]) {
		case "tcp":
			terminalCommandTCPConnect(node, address)
		case "shell", "shell.tcp", "shell.tls", "shell.udp", "shell.wtf":
			terminalCommandShellConnect(node, address)
		case "file", "file.tcp", "file.tls", "file.udp", "file.wtf":
			terminalCommandFileServerConnect(node, address)
		default:
			terminalCommandTCPConnect(node, "tcp:"+address)
		}
	}
	return
}

func terminalCommandTCPConnect(node star.NodeID, address string) {
	var a string

	parts := strings.Split(address, ":")
	if len(parts) == 2 {
		a = ":" + parts[1]
	} else if len(parts) == 3 {
		a = parts[1] + ":" + parts[2]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for TCP connector: %s", a))
		return
	}

	if node.IsBroadcastNodeID() || node == star.ThisNode.ID {
		printInfo("Connecting to " + a)
		star.NewTCPConnection(a)
	}

	if node != star.ThisNode.ID {
		conMsg := star.NewMessageConnectTCP(a)
		conMsg.Destination = node
		conMsg.Send(star.ConnectID{})
	}
	return
}

func terminalCommandShellConnect(node star.NodeID, address string) {
	var a string // Address
	var s star.ConnectorType

	parts := strings.Split(address, ":")
	if len(parts) == 2 { // shell:<port>
		a = ":" + parts[1]
	} else if len(parts) == 3 { // shell:<ip>:<port>
		a = parts[1] + ":" + parts[2]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for shell connection: %s", address))
		return
	}

	switch parts[0] {
	case "shell", "shell.tcp":
		s = star.ConnectorType_ShellTCP
	case "shell.tls":
		s = star.ConnectorType_ShellTCPTLS
	case "shell.udp":
		s = star.ConnectorType_ShellUDP
	case "shell.wtf":
		s = star.ConnectorType_ShellUDPTLS
	default:
		printError(fmt.Sprintf("Invalid shell type specifier given: %s", parts[0]))
		return
	}

	if node != star.ThisNode.ID {
		conMsg := star.NewMessageShellConnectionRequest(s, a)
		conMsg.Destination = node
		conMsg.Send(star.ConnectID{})
	} else {
		printError(fmt.Sprintf("Cannot create shell connections on terminal nodes!"))
		return
	}
}

func terminalCommandFileServerConnect(node star.NodeID, address string) {
	var a string // Address
	var f string // file
	var t star.ConnectorType

	parts := strings.Split(address, ":")
	if len(parts) == 3 { // file:<port>:<file>
		a = ":" + parts[1]
		f = parts[2]
	} else if len(parts) == 4 { // file:<ip>:<port>:<file>
		a = parts[1] + ":" + parts[2]
		f = parts[3]
	} else {
		// Invalid address format
		printError(fmt.Sprintf("Invalid address format given for fileserver listener: %s", address))
		return
	}

	switch parts[0] {
	case "file", "file.tcp":
		t = star.ConnectorType_FileServerTCP
	case "file.tls":
		t = star.ConnectorType_FileServerTCPTLS
	case "file.udp":
		t = star.ConnectorType_FileServerUDP
	case "file.wtf":
		t = star.ConnectorType_FileServerUDPTLS
	default:
		printError(fmt.Sprintf("Invalid fileserver type specifier given: %s", parts[0]))
		return
	}

	if node != star.ThisNode.ID {
		id, err := FileServerTrackerGetID(f)
		if err != nil {
			printError(fmt.Sprintf("Error while trying to create fileserver: %v", err.Error()))
			return
		}
		bindMsg := star.NewMessageFileServerConnectRequest(t, a, id)
		bindMsg.Destination = node
		bindMsg.Send(star.ConnectID{})
	} else {
		printError(fmt.Sprintf("Cannot create shell listeners on terminal nodes!"))
		return
	}
}

func terminalCommandClear() (err error) {
	// Per https://stackoverflow.com/a/22892171
	//  - also
	fmt.Print("\033[H\033[2J")
	return
}

func terminalCommandHistory(all bool, node star.NodeID, stream star.StreamID) (err error) {
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	// "Filter" the history items
	selectHistoryItems := make(map[uint]historyItem)
	if all {
		for i, h := range historyItems {
			selectHistoryItems[i] = h
		}
	} else {
		for i, h := range historyItems {
			if (h.Node == node || h.Node == star.ThisNode.ID) && (h.Stream.IsEmptyStreamID() || h.Stream == stream) {
				selectHistoryItems[i] = h
			}
		}
	}

	// Sort the keys
	keys := make([]uint, len(selectHistoryItems))
	i := 0
	for k := range selectHistoryItems {
		keys[i] = k
		i++
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	max := int(terminalSettings["history.displaylength"].Data.(int64))
	if !all && len(keys) > max {
		keys = keys[len(keys)-max : len(keys)]
	}

	for _, k := range keys {
		fmt.Fprintln(w, selectHistoryItems[k].Timestamp.Format(terminalSettings["display.timestamp"].Data.(string)), "\t", k, "\t", FriendlyAgentName(selectHistoryItems[k].Node, selectHistoryItems[k].Stream), "\t", selectHistoryItems[k].String)
	}
	w.Flush()
	return
}

func terminalCommandInformation(context string) (err error) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	agent, ok := AgentTrackerGetInfoByFriendly(context)

	if !ok || context == "" {
		terminalCommandList("all")
	} else {
		fmt.Fprintln(w, "NODE.ID: ", "\t", agent.Node.ID)
		if terminalSettings["info.showos"].Data.(bool) {
			fmt.Fprintln(w, "OS.EGID: ", "\t", agent.Info.OS_egid)
			fmt.Fprintln(w, "OS.EUID: ", "\t", agent.Info.OS_euid)
			fmt.Fprintln(w, "OS.GID: ", "\t", agent.Info.OS_gid)
			fmt.Fprintln(w, "OS.GROUPS: ", "\t", agent.Info.OS_groups)
			fmt.Fprintln(w, "OS.PAGESIZE: ", "\t", agent.Info.OS_pagesize)
			fmt.Fprintln(w, "OS.PID: ", "\t", agent.Info.OS_pid)
			fmt.Fprintln(w, "OS.PPID: ", "\t", agent.Info.OS_ppid)
			fmt.Fprintln(w, "OS.UID: ", "\t", agent.Info.OS_uid)
			fmt.Fprintln(w, "OS.DIR: ", "\t", agent.Info.OS_workingdir)
			fmt.Fprintln(w, "OS.HOSTNAME: ", "\t", agent.Info.OS_hostname)
		}
		w.Flush()

		if terminalSettings["info.showenv"].Data.(bool) {
			fmt.Println()
			fmt.Println("ENVIRONMENT VARIABLES:")
			for _, e := range agent.Info.OS_environ {
				fmt.Println("\t", e)
			}
		}

		if terminalSettings["info.showinterfaces"].Data.(bool) {
			fmt.Println()
			fmt.Println("NETWORK INTERFACES WITH ADDRESSES:")
			fmt.Println("    ----------------------------------------")
			for _, e := range agent.Info.Interfaces {
				addrs, err := e.Addrs()
				if err == nil && len(addrs) > 0 {
					fmt.Printf("    NAME: %s\n", e.Name)
					fmt.Printf("    MAC:  %s\n", e.HardwareAddr.String())

					fmt.Printf("    ADDRESSES:\n")
					for _, a := range addrs {
						fmt.Printf("        %s\n", a.String())
					}
					fmt.Println("    ----------------------------------------")
				}
			}
		}
	}
	return
}

func terminalCommandJump(context string) (err error) {
	identifiers := strings.Split(context, ":")
	agent, ok := AgentTrackerGetInfoByFriendly(identifiers[0])
	if !ok {
		terminalCommandList("all")
		printError(fmt.Sprintf("%s is not a valid identifier! Use one of the above agents!", identifiers[0]))
	} else if context == "" {
		terminalCommandHelp(":j")
		printError("Must specify agent or agent:stream to jump to!")
	} else if !strings.HasPrefix(context, "agent") {
		printError(fmt.Sprintf("%s is not an agent! Only agents can be jumped to!", context))
	} else {
		activeNode = agent.Node.ID
		activeStream = star.StreamID{}
		printInfo(fmt.Sprintf("Changing agent focus to %s(%s)", agent.FriendlyName, agent.Node.ID))
		if len(identifiers) > 1 {
			for i, id := range agent.Info.StreamIDs {
				streamname := fmt.Sprintf("stream%03d", i)
				if streamname == identifiers[1] {
					if agent.Info.StreamTypes[i] == star.StreamTypeCommand || agent.Info.StreamTypes[i] == star.StreamTypeShell {
						activeStream = id
						printInfo(fmt.Sprintf("Changing stream focus to %s(%s)", streamname, id))
					} else {
						printError(fmt.Sprintf("%s for %s is not a Command/Shell type stream; only Command/Shell type streams can have focus. No stream focus set.", streamname, agent.FriendlyName))
					}
				}
			}
		}
	}
	return
}

func terminalCommandKillSwitch(confirm string) (err error) {
	if confirm == "confirm" {
		killMsg := star.NewMessageKillSwitch()
		killMsg.Send(star.ConnectID{})
	} else {
		printNotice("Killswitch will terminate the constellation and perform cleanup! This is irreversable! Type `:k confirm` to confirm this is what you want!")
	}
	return
}

func terminalCommandList(context string) (err error) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	if context == "all" {
		fmt.Println("Agents:")
		//Sort then print
		keys := make([]string, len(agentFriendlyTracker))
		ki := 0
		for k := range agentFriendlyTracker {
			keys[ki] = k
			ki++
		}
		sort.Strings(keys)
		for _, k := range keys {
			focus := ""
			a := agentFriendlyTracker[k]

			// Current focus check
			if a.Node.ID == activeNode {
				if activeStream.IsEmptyStreamID() {
					focus = ANSIColorize("CURRENT FOCUS", ANSIColor_Focus)
				} else {
					focus = ANSIColorize("CURRENT FOCUS (STREAM)", ANSIColor_Focus)
				}
			}

			// Is alive check
			dead := false
			sync_minutes := terminalSettings["sync.minutes"].Data.(int64)
			if sync_minutes > 0 {
				if a.LastSynced.Add(time.Minute * time.Duration(sync_minutes)).Before(time.Now()) {
					dead = true
				}
			}

			row := fmt.Sprintf("    %s \t %s \t %s \t %s \t %s", a.FriendlyName, a.Node.ID, a.Info.OS_hostname, fmt.Sprintf("%0.1f minutes ago", time.Since(a.LastSynced).Minutes()), focus)
			if dead {
				row = ANSIColorize(row, ANSIColor_DeadAgent)
			}
			fmt.Fprintln(w, row)
		}
		w.Flush()
	} else {
		agent, ok := agentFriendlyTracker[context]
		if ok {
			fmt.Println(fmt.Sprintf("%s (%s)", agent.FriendlyName, agent.Node.ID))
			fmt.Println()
			fmt.Fprintln(w, "Connections: \t ")
			//Sort then print
			keys := make([]uint, len(agent.Info.ConnectionIDs))
			ki := 0
			for k := range agent.Info.ConnectionIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:conn%03d", agent.FriendlyName, i), "\t", agent.Info.ConnectionIDs[i], "\t", TerminalConnectorTypeToString(agent.Info.ConnectionTypes[i])+agent.Info.ConnectionInfos[i])
			}
			fmt.Fprintln(w, " \t ")

			fmt.Fprintln(w, "Listeners: \t ")
			//Sort then print
			keys = make([]uint, len(agent.Info.ListenerIDs))
			ki = 0
			for k := range agent.Info.ListenerIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:listener%03d", agent.FriendlyName, i), "\t", agent.Info.ListenerIDs[i], "\t", TerminalConnectorTypeToString(agent.Info.ListenerTypes[i])+agent.Info.ListenerInfos[i])
			}
			fmt.Fprintln(w, " \t ")

			fmt.Fprintln(w, "Streams: \t ")
			keys = make([]uint, len(agent.Info.StreamIDs))
			ki = 0
			for k := range agent.Info.StreamIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				focus := ""
				if agent.Info.StreamIDs[i] == activeStream {
					focus = ANSIColorize("CURRENT FOCUS", ANSIColor_Focus)
				}

				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:stream%03d\t%s\t%s(%s)\t%s\t%s", agent.FriendlyName, i, agent.Info.StreamIDs[i], TerminalStreamTypeToString(agent.Info.StreamTypes[i]), FriendlyAgentName(agent.Info.StreamOwners[i], star.StreamID{}), agent.Info.StreamInfos[i], focus))
			}
			fmt.Fprintln(w, " \t ")
			w.Flush()
		} else {
			printError(fmt.Sprintf("%s is not a valid identifier! Use one of the following!", context))
			terminalCommandList("all")
		}
	}

	return
}

func terminalCommandLocalCat(src string) (err error) {
	// Kinda like "terminalCommandUpload", except we just print instead of use messages
	f, err := os.Open(src)
	if err != nil {
		printError(fmt.Sprintf("Error attempting to open local file [ %s ] for output: %v", src, err))
		return
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		buff := make([]byte, star.RandDataSize())
		n, err := r.Read(buff)
		if err == nil && n > 0 {
			fmt.Printf("%s", buff[:n])
		} else {
			break
		}
	}

	return
}

func terminalCommandLocalChangeDirectory(directory string) (err error) {
	olddirectory, _ := os.Getwd()
	os.Chdir(directory)
	newdirectory, _ := os.Getwd()

	fmt.Println("Changed terminal working directory from [", olddirectory, "] to [", newdirectory, "]")

	return
}

func terminalCommandLocalListFiles(directory string) (err error) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	files, _ := ioutil.ReadDir(directory)

	// Directories first
	for _, f := range files {
		if f.IsDir() {
			fmt.Fprintln(w, "["+f.Name()+"]", "\t", f.ModTime().Format(terminalSettings["display.timestamp"].Data.(string)), "\t", f.Mode(), "\t", f.Size())
		}
	}

	// Files second
	for _, f := range files {
		if !f.IsDir() {
			fmt.Fprintln(w, f.Name(), "\t", f.ModTime().Format(terminalSettings["display.timestamp"].Data.(string)), "\t", f.Mode(), "\t", f.Size())
		}
	}

	w.Flush()

	return
}

func terminalCommandLocalMakeDirectory(directory string) (err error) {
	if len(directory) == 0 {
		printInfo("Empty string passed as directory name, creating temporary directory instead.")
		return terminalCommandLocalMakeTemporaryDirectory()
	}

	err = os.MkdirAll(directory, 0700)
	if err != nil {
		printError(fmt.Sprintf("Unable to create local directory: [ %s ].", err.Error()))
		return
	}

	err = os.Chdir(directory)
	if err == nil {
		dir, err := os.Getwd()
		if err == nil {
			printInfo(fmt.Sprintf("Changed working directory to [ %s ].", dir))
		}
	}

	return
}

func terminalCommandLocalPresentWorkingDirectory() (err error) {
	path, _ := os.Getwd()
	fmt.Println(path)

	return
}

func terminalCommandLocalMakeTemporaryDirectory() (err error) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		printError(fmt.Sprintf("Unable to create temporary directory."))
		return
	}

	err = os.Chdir(dir)
	if err == nil {
		printInfo(fmt.Sprintf("Changed working directory to [ %s ].", dir))
	}

	return
}

func terminalCommandRemoteCat(node star.NodeID, src string) (err error) {
	// Same as "terminalCommandDownload", just print instead of save
	star.NewStreamMetaDownload(node, src, func(data []byte) {
		fmt.Printf("%s", data)
	}, func(s star.StreamID) {})

	return
}

func terminalCommandRemoteChangeDirectory(node star.NodeID, directory string) (err error) {
	msg := star.NewMessageRemoteCDRequest(directory)
	msg.Destination = node
	msg.Send(star.ConnectID{})

	return
}

func terminalCommandRemoteListFiles(node star.NodeID, directory string) (err error) {
	msg := star.NewMessageRemoteLSRequest(directory)
	msg.Destination = node
	msg.Send(star.ConnectID{})

	return
}

func terminalCommandRemoteMkDir(node star.NodeID, directory string) (err error) {
	if len(directory) == 0 {
		printInfo("Empty string passed as directory name, creating temporary directory isntead.")
		return terminalCommandRemoteTmpDir(node)
	}

	msg := star.NewMessageRemoteMkDirRequest(directory)
	msg.Destination = node
	msg.Send(star.ConnectID{})

	return
}

func terminalCommandRemotePresentWorkingDirectory(node star.NodeID) (err error) {
	msg := star.NewMessageRemotePWDRequest()
	msg.Destination = node
	msg.Send(star.ConnectID{})

	return
}

func terminalCommandRemoteTmpDir(node star.NodeID) (err error) {
	msg := star.NewMessageRemoteTmpDirRequest()
	msg.Destination = node
	msg.Send(star.ConnectID{})

	return
}

func terminalCommandSet(setting string, value string) (err error) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	if setting == "" {
		// Sort keys
		keys := make([]string, len(terminalSettings))
		i := 0
		for key := range terminalSettings {
			keys[i] = key
			i++
		}
		sort.Strings(keys)

		// Print settings
		for i := range keys {
			fmt.Fprintln(w, fmt.Sprintf("%s\t%v\t%T", keys[i], terminalSettings[keys[i]].Data, terminalSettings[keys[i]].Data))
		}
	} else if value == "" {
		if _, ok := terminalSettings[setting]; ok {
			fmt.Fprintln(w, fmt.Sprintf("NAME: \t %s", setting))
			fmt.Fprintln(w, fmt.Sprintf("TYPE: \t %T", terminalSettings[setting].Data))
			fmt.Fprintln(w, fmt.Sprintf("VALUE: \t %v", terminalSettings[setting].Data))
			fmt.Fprintln(w, fmt.Sprintf("DESCRIPTION: \t %s", terminalSettings[setting].Description))
		} else {
			printError(fmt.Sprintf("No such setting as %s! Run `:settings` for a full list of settings!", value))
		}
	} else {
		if s, ok := terminalSettings[setting]; ok {
			switch s.Data.(type) {
			case bool:
				s.Data, _ = strconv.ParseBool(value)
			case float32, float64:
				s.Data, _ = strconv.ParseFloat(value, 64)
			case int, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
				s.Data, _ = strconv.ParseInt(value, 10, 64)
			case string:
				s.Data = value
			default:
				printDebug("Error when attempt to change setting, unexpected setting value?")
			}
			terminalSettings[setting] = s
			fmt.Fprintln(w, fmt.Sprintf("%s\t|\t%v\t|\t%T\t|\t%s", setting, terminalSettings[setting].Data, terminalSettings[setting].Data, terminalSettings[setting].Description))
		} else {
			printError(fmt.Sprintf("No such setting as %s! Run `:settings` for a full list of settings!", setting))
		}
	}
	w.Flush()
	return
}

func terminalCommandTerminate(context string) (err error) {
	identifiers := strings.Split(context, ":")
	agent, ok := AgentTrackerGetInfoByFriendly(identifiers[0])
	if !ok {
		terminalCommandList("all")
		printError(fmt.Sprintf("%s is not a valid identifier! Use one of the above agents!", identifiers[0]))
	} else if context == "" {
		terminalCommandHelp(":t")
		printError("Must explicitly specify agent, agent:connection, agent:listener, agent:shell, or agent:stream!")
	} else if !strings.HasPrefix(context, "agent") {
		printError(fmt.Sprintf("%s is not an agent! Terminating termination attempt.", identifiers[0]))
	} else {
		if len(identifiers) == 1 {
			termMsg := star.NewMessageTerminate(star.MessageTerminateTypeAgent, 0)
			termMsg.Destination = agent.Node.ID
			termMsg.Send(star.ConnectID{})
			AgentTrackerRemoveInfo(agent.Node.ID)
		} else if len(identifiers) == 2 {
			match := regexp.MustCompile(`^(conn|listener|stream)(\d+)$`).FindStringSubmatch(identifiers[1])
			if len(match) == 3 {
				var termMsg *star.Message
				index, _ := strconv.ParseUint(match[2], 10, 64)
				switch match[1] {
				case "conn":
					termMsg = star.NewMessageTerminate(star.MessageTerminateTypeConnection, uint(index))
				case "listener":
					termMsg = star.NewMessageTerminate(star.MessageTerminateTypeListener, uint(index))
				case "stream":
					termMsg = star.NewMessageTerminate(star.MessageTerminateTypeStream, uint(index))
				default:
					// Shouldn't ever reach here, but, uh, oh well.
					terminalCommandList(identifiers[0])
					printError(fmt.Sprintf("%s has an invalid sub-identifier! Must be one of the ones listed above!", context))
					return
				}
				termMsg.Destination = agent.Node.ID
				termMsg.Send(star.ConnectID{})
			} else {
				terminalCommandList(identifiers[0])
				printError(fmt.Sprintf("%s has an invalid sub-identifier! Must be one of the ones listed above!", context))
				return
			}
		} else {
			terminalCommandHelp(":t")
			printError("Invalid number of separators!")
			return
		}
	}
	return
}

func terminalCommandDownload(node star.NodeID, src string, dst string) (err error) {
	// Open the file
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		printError(fmt.Sprintf("Error attempting to open local file %s to download: %v", src, err))
		return
	}

	// Download stream!
	star.NewStreamMetaDownload(node, src, func(data []byte) {
		f.Write(data)
	}, func(s star.StreamID) {
		f.Close()
	})
	return
}

func terminalCommandUpload(node star.NodeID, src string, dst string) (err error) {
	go func() {
		// Open the file
		f, err := os.Open(src)
		if err != nil {
			printError(fmt.Sprintf("Error attempting to open local file [ %s ] to upload: %v", src, err))
			return
		}
		defer f.Close()

		// Upload stream!
		meta := star.NewStreamMetaUpload(node, dst, func(data []byte) {}, func(s star.StreamID) {})
		r := bufio.NewReader(f)
		for {
			buff := make([]byte, star.RandDataSize())
			n, err := r.Read(buff)
			if err == nil && n > 0 {
				meta.Write(buff[:n])
			} else {
				break
			}
		}

		meta.Close()
	}()

	return
}

func terminalCommandQuit(err error, errmsg string) {
	if err != nil {
		fmt.Println(err)
		printError(errmsg)
		printInfo("Quitting due to error!")
	} else {
		printInfo("Goodbye!")
	}
	os.Exit(0)
}

func terminalCommandSendCommand(cmd string) (err error) {
	if activeNode.IsBroadcastNodeID() {
		if len(agentFriendlyTracker) > 1 {
			terminalCommandList("all")
			printError("Must have an active/focused node to send commands! Change focus to one of the above with `:j`")
		} else {
			printError("Must have an active/focused node to send commands! Connect the terminal to an agent first!")
		}
	} else if activeNode == star.ThisNode.ID {
		if len(agentFriendlyTracker) > 1 {
			terminalCommandList("all")
			printError("Cannot send commands to the terminal! Change focus to one of the above with `:j`")
		} else {
			printError("Cannot send commands to the terminal! Connect the terminal to an agent first!")
		}
	} else {
		if activeStream.IsEmptyStreamID() {
			// New stream!
			meta := star.NewStreamMetaCommand(activeNode, cmd, func(data []byte) {
				fmt.Printf("%s", data)
			}, func(s star.StreamID) {
				if activeStream == s {
					activeStream = star.StreamID{}
				}
			})
			activeStream = meta.ID
		} else {
			meta, ok := star.GetActiveStream(activeStream)
			if ok {
				meta.Write([]byte(cmd + "\n"))
			} else {
				activeStream = star.StreamID{}
				printError(fmt.Sprintf("Invalid command stream, resetting active stream."))
				printError(fmt.Sprintf("`%s` not sent to %s as a precaution. Resend if appropriate.", cmd, FriendlyAgentName(activeNode, star.StreamID{})))
			}
		}
	}
	return
}

func terminalCommandChat(msg string) (err error) {
	// Expand/replace agent/term names if appropriate
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()

	for _, a := range agentFriendlyTracker {
		msg = strings.ReplaceAll(msg, a.FriendlyName, a.Node.ID.String())
	}

	// Print chat message
	printChat(fmt.Sprintf("You say: %s", msg))

	// Send chat message
	star.NewMessageChatRequest(terminalSettings["chat.nickname"].Data.(string), msg).Send(star.ConnectID{})

	// Add to history
	HistoryChatPush(historyChatItem{Timestamp: time.Now(), Node: star.ThisNode.ID, Nickname: ">you<", Content: msg})

	return
}

func terminalCommandChatHistory() (err error) {
	historyChatItemsMutex.Lock()
	defer historyChatItemsMutex.Unlock()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	for _, i := range historyChatItems {
		fmt.Fprintln(w, i.Timestamp.Format(terminalSettings["display.timestamp"].Data.(string)), "\t", FriendlyAgentName(i.Node, star.StreamID{}), "\t", i.Nickname, "\t", i.Content)
	}

	w.Flush()

	return
}

///////////////////////////////////////////////////////////////////////////////

func TerminalProcessMessage(msg *star.Message) {
	switch msg.Type {
	case star.MessageTypeError:
		TerminalProcessMessageError(msg)
	case star.MessageTypeSyncRequest:
		TerminalProcessSyncRequest(msg)
	case star.MessageTypeSyncResponse:
		TerminalProcessSyncResponse(msg)
	case star.MessageTypeNewBind:
		TerminalProcessMessageNewBind(msg)
	case star.MessageTypeNewConnection:
		TerminalProcessMessageNewConnection(msg)
	case star.MessageTypeHello:
		TerminalProcessMessageHello(msg)
	case star.MessageTypeRemoteCDResponse:
		TerminalProcessMessageRemoteCDResponse(msg)
	case star.MessageTypeRemoteLSResponse:
		TerminalProcessMessageRemoteLSResponse(msg)
	case star.MessageTypeRemoteMkDirResponse:
		TerminalProcessMessageRemoteMkDirResponse(msg)
	case star.MessageTypeRemotePWDResponse:
		TerminalProcessMessageRemotePWDResponse(msg)
	case star.MessageTypeRemoteTmpDirResponse:
		TerminalProcessMessageRemoteTmpDirResponse(msg)
	case star.MessageTypeChat:
		TerminalProcessMessageChat(msg)
	case star.MessageTypeFileServerInitiateTransfer:
		TerminalProcessMessageFileServerInitiateTransfer(msg)
	}
}

func TerminalProcessMessageError(msg *star.Message) {
	var errMsg star.MessageErrorResponse
	var histContext string    // Provide context for history file
	var histSubcontext string // Provide subcontext for history file

	histContext = "error" // "Default" value

	err := msg.GobDecodeMessage(&errMsg)
	if err == nil {
		switch errMsg.Type {
		case star.MessageErrorResponseTypeX509KeyPair:
			histSubcontext = "Error with creation of X509 key pair."
			printError(fmt.Sprintf("%s has reported an error with the creation of the X509 Key pair. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeConnectionLost:
			histContext = "notice"
			histSubcontext = "Connection lost or dropped."
			printNotice(fmt.Sprintf("%s has reported that it has lost/dropped the connection with %s.", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeBindDropped:
			histContext = "notice"
			histSubcontext = "Listener lost or dropped."
			printNotice(fmt.Sprintf("%s has reported that it has lost/dropped the listening bind on %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeGobDecodeError:
			histSubcontext = "Gob decoding error."
			printError(fmt.Sprintf("%s has reported an error with attempting to gob decode a message of type %s.", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeAgentExitSignal:
			histContext = "notice"
			histSubcontext = "Agent signal interrupt."
			printNotice(fmt.Sprintf("%s has reported that it was terminated with the signal interrupt %s.", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
			AgentTrackerRemoveInfo(msg.Source)
		case star.MessageErrorResponseTypeUnsupportedConnectorType:
			histSubcontext = "Unsupported connector type."
			printError(fmt.Sprintf("%s has reported that an unsupported connector type was specified. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeInvalidTerminationIndex:
			histSubcontext = "Invalid termination index."
			printError(fmt.Sprintf("%s has reported that an invalid termination index was specified. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeCommandEnded:
			histContext = "notice"
			histSubcontext = "Command terminated."
			printNotice(fmt.Sprintf("%s has reported that a command has terminated. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeShellConnectionLost:
			histContext = "notice"
			histSubcontext = "Shell connection dropped."
			printNotice(fmt.Sprintf("%s has reported that a shell connection was dropped. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeFileDownloadOpenFileError:
			histSubcontext = "Failed to open file for download."
			printError(fmt.Sprintf("%s has reported an error when attempting to open a file for downloading to the terminal. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeFileUploadOpenFileError:
			histSubcontext = "Failed to open/create file for upload."
			printError(fmt.Sprintf("%s has reported an error when attempting to open/create a file for uploading from the terminal. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeFileDownloadCompleted:
			histContext = "notice"
			histSubcontext = "Download completed."
			printNotice(fmt.Sprintf("%s has reported that %s has completed downloading.", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeFileUploadCompleted:
			histContext = "notice"
			histSubcontext = "Upload completed."
			printNotice(fmt.Sprintf("%s has reported that %s has completed uploading.", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		case star.MessageErrorResponseTypeDirectoryCreationError:
			histSubcontext = "Failed to create directory."
			printError(fmt.Sprintf("%s has reported an error when attempting to create a directory. Context: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		default:
			histSubcontext = "Unspecified error."
			printError(fmt.Sprintf("%s has reported: %s", FriendlyAgentName(msg.Source, star.StreamID{}), errMsg.Context))
		}

		// Record to file
		RecordLog(time.Now(), msg.Source, histContext, histSubcontext, errMsg.Context)
	}
}

func TerminalProcessSyncRequest(msg *star.Message) {
	var reqMsg star.MessageSyncRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		syncMsg := star.NewMessageSyncResponse()
		syncMsg.Destination = msg.Source
		syncMsg.Send(star.ConnectID{})
	}

	RecordLog(time.Now(), msg.Source, "sync", "request", "")
}

func TerminalProcessSyncResponse(msg *star.Message) {
	var resMsg star.MessageSyncResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		AgentTrackerUpdateInfo(&resMsg.Node, &resMsg.Info)

		if !terminalSettings["sync.mute"].Data.(bool) {
			printInfo(fmt.Sprintf("%s has synchronized.", FriendlyAgentName(msg.Source, star.StreamID{})))
		}
	}

	RecordLog(time.Now(), msg.Source, "sync", "response", "")
}

func TerminalProcessMessageNewBind(msg *star.Message) {
	var resMsg star.MessageNewBindResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new bind/listener on %s.", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Address))
	}

	RecordLog(time.Now(), msg.Source, "constellation", "bind", resMsg.Address)

	// Resynchronize
	TerminalSynchronize(false)
}

func TerminalProcessMessageNewConnection(msg *star.Message) {
	var resMsg star.MessageNewConnectionResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new connection with %s.", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Address))
	}

	RecordLog(time.Now(), msg.Source, "constellation", "conn", resMsg.Address)

	// Resynchronize
	TerminalSynchronize(false)
}

func TerminalProcessMessageHello(msg *star.Message) {
	var resMsg star.MessageHelloResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		AgentTrackerUpdateInfo(&resMsg.Node, &resMsg.Info)
	}
}

func TerminalProcessMessageRemoteCDResponse(msg *star.Message) {
	var resMsg star.MessageRemoteCDResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s reports that it has changed its working directory from [%s] to [%s], per %s.", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.OldDirectory, resMsg.NewDirectory, FriendlyAgentName(resMsg.Requester, star.StreamID{})))
	}

	RecordLog(time.Now(), msg.Source, "remote cmd", "cd", fmt.Sprintf("From [ %s ] to [ %s ].", resMsg.OldDirectory, resMsg.NewDirectory))
}

func TerminalProcessMessageRemoteLSResponse(msg *star.Message) {
	var resMsg star.MessageRemoteLSResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s reports the following file/directory information for [%s]:", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Directory))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

		// Directories first
		for _, f := range resMsg.Files {
			if f.IsDir {
				fmt.Fprintln(w, "["+f.Name+"]", "\t", f.ModTime.Format(terminalSettings["display.timestamp"].Data.(string)), "\t", f.Mode, "\t", f.Size)
			}
		}

		// Files second
		for _, f := range resMsg.Files {
			if !f.IsDir {
				fmt.Fprintln(w, f.Name, "\t", f.ModTime.Format(terminalSettings["display.timestamp"].Data.(string)), "\t", f.Mode, "\t", f.Size)
			}
		}

		w.Flush()
	} else {
		fmt.Printf("%v+", err)
	}

	RecordLog(time.Now(), msg.Source, "remote cmd", "ls", resMsg.Directory)
}

func TerminalProcessMessageRemoteMkDirResponse(msg *star.Message) {
	var resMsg star.MessageRemoteMkDirResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s reports that its PWD has been changed to a newly created directory: [ %s ]", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Directory))
	}

	RecordLog(time.Now(), msg.Source, "remote cmd", "mkdir", resMsg.Directory)
}

func TerminalProcessMessageRemotePWDResponse(msg *star.Message) {
	var resMsg star.MessageRemotePWDResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s reports that its PWD=[ %s ]", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Directory))
	}

	RecordLog(time.Now(), msg.Source, "remote cmd", "pwd", resMsg.Directory)
}

func TerminalProcessMessageRemoteTmpDirResponse(msg *star.Message) {
	var resMsg star.MessageRemoteTmpDirResponse

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s reports that its PWD has been changed to a new temporary directory: [ %s ]", FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Directory))
	}

	RecordLog(time.Now(), msg.Source, "remote cmd", "tmpdir", resMsg.Directory)
}

func TerminalProcessMessageChat(msg *star.Message) {
	var resMsg star.MessageChatRequest

	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		// Expand/replace agent/term names if appropriate
		agentTrackerMutex.Lock()
		defer agentTrackerMutex.Unlock()

		for _, a := range agentFriendlyTracker {
			resMsg.Content = strings.ReplaceAll(resMsg.Content, a.Node.ID.String(), a.FriendlyName)
		}

		// Display
		printChat(fmt.Sprintf("%s@%s says: %s", resMsg.Nickname, FriendlyAgentName(msg.Source, star.StreamID{}), resMsg.Content))

		// Add to history (takes care of record history as well)
		HistoryChatPush(historyChatItem{Timestamp: time.Now(), Node: msg.Source, Nickname: resMsg.Nickname, Content: resMsg.Content})
	}
}

func TerminalProcessMessageFileServerInitiateTransfer(msg *star.Message) {
	var resMsg star.MessageFileServerInitiateTransferRequest
	err := msg.GobDecodeMessage(&resMsg)
	if err == nil {
		src, err := FileServerTrackerGetFilename(resMsg.FileConnID)
		if err == nil {
			go func() {
				printInfo(fmt.Sprintf("Request to download [ %s ] from %s has been initiated.", src, FriendlyAgentName(msg.Source, star.StreamID{})))
				// Open the file
				f, err := os.Open(src)
				if err != nil {
					printError(fmt.Sprintf("Error attempting to open local file [ %s ] for file-server: %v", src, err))
					return
				}
				defer f.Close()

				// File server stream!
				meta := star.NewStreamMetaFileServer(msg.Source, resMsg.AgentConnID.String(), func(data []byte) {}, func(s star.StreamID) {})
				r := bufio.NewReader(f)
				for {
					buff := make([]byte, star.RandDataSize())
					n, err := r.Read(buff)
					if err == nil && n > 0 {
						meta.Write(buff[:n])
					} else {
						break
					}
				}

				printInfo(fmt.Sprintf("Request to download [ %s ] from %s has completed.", src, FriendlyAgentName(msg.Source, star.StreamID{})))

				meta.Close()
			}()
		}

		RecordLog(time.Now(), msg.Source, "fileserver", "transfer initated", src)
	}

	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func FriendlyAgentName(id star.NodeID, stream star.StreamID) string {
	if stream.IsEmptyStreamID() {
		if id.IsBroadcastNodeID() {
			return "?????"
		} else if id == star.ThisNode.ID {
			return "This Terminal"
		} else {
			n, ok := agentNodeIDTracker[id]
			if ok {
				return fmt.Sprintf("%s", n.FriendlyName)
			} else {
				return fmt.Sprintf("%s", id)
			}
		}
	} else {
		if id.IsBroadcastNodeID() {
			return "?????"
		} else if id == star.ThisNode.ID {
			return "This Terminal"
		} else {
			n, ok := agentNodeIDTracker[id]
			if ok {
				// Find stream id
				for i, _ := range n.Info.StreamIDs {
					if n.Info.StreamIDs[i] == stream {
						return fmt.Sprintf("%s:stream%03d[%s]", n.FriendlyName, i, n.Info.StreamInfos[i])
					}
				}
				return fmt.Sprintf("%s:%s", n.FriendlyName, stream)
			} else {
				return fmt.Sprintf("%s:%s", id, stream)
			}
		}
	}
}

func TerminalSynchronize(showmsg bool) {
	if !terminalSettings["sync.mute"].Data.(bool) || showmsg {
		printInfo("Synchronizing with agents...")
	}
	syncMsg := star.NewMessageSyncRequest()
	syncMsg.Send(star.ConnectID{})
	AgentTrackerUpdateInfo(&star.ThisNode, &star.ThisNodeInfo)
}

///////////////////////////////////////////////////////////////////////////////
/********************************** History **********************************/
///////////////////////////////////////////////////////////////////////////////
type historyItem struct {
	Timestamp time.Time
	String    string
	Node      star.NodeID
	Stream    star.StreamID
}

var historyItems map[uint]historyItem
var historyItemsMutex *sync.Mutex
var historyIndex uint

func HistoryPush(item historyItem) {
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

	historyIndex++
	historyItems[historyIndex] = item

	// Enforce history.length
	l, ok := terminalSettings["history.tracklength"].Data.(int64)
	if ok {
		l := uint(l)
		if historyIndex > l && historyIndex > 0 {
			oldestAllowed := historyIndex - l
			for i := range historyItems {
				if i <= oldestAllowed {
					delete(historyItems, i)
				}
			}
		}
	}

	// Record to file
	RecordLog(item.Timestamp, item.Node, "commands", FriendlyAgentName(item.Node, item.Stream), item.String)
}

func HistoryPop() {
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

	delete(historyItems, historyIndex)
	historyIndex--
}

///////////////////////////////////////////////////////////////////////////////
/******************************** Chat History *******************************/
///////////////////////////////////////////////////////////////////////////////
type historyChatItem struct {
	Timestamp time.Time
	Node      star.NodeID
	Content   string
	Nickname  string
}

var historyChatItems map[uint]historyChatItem
var historyChatItemsMutex *sync.Mutex
var historyChatIndex uint

func HistoryChatPush(item historyChatItem) {
	historyChatItemsMutex.Lock()
	defer historyChatItemsMutex.Unlock()

	historyChatIndex++
	historyChatItems[historyChatIndex] = item

	// Enforce chat.tracklength
	l, ok := terminalSettings["chat.tracklength"].Data.(int64)
	if ok {
		l := uint(l)
		if historyChatIndex > l && historyChatIndex > 0 {
			oldestAllowed := historyChatIndex - l
			for i := range historyChatItems {
				if i <= oldestAllowed {
					delete(historyChatItems, i)
				}
			}
		}
	}

	// Record to file
	RecordLog(item.Timestamp, item.Node, "chat", item.Nickname, item.Content)
}

func HistoryChatPop() {
	historyChatItemsMutex.Lock()
	defer historyChatItemsMutex.Unlock()

	delete(historyChatItems, historyChatIndex)
	historyChatIndex--
}

///////////////////////////////////////////////////////////////////////////////
/**************************** Save History To File ***************************/
///////////////////////////////////////////////////////////////////////////////
var logFile *os.File
var logCSV *csv.Writer

func SetupRecordLog() {
	var err error
	logFile, err = os.OpenFile(fmt.Sprintf("%s.log.csv", star.ThisNode.ID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		// Fail quietly
		return
	}

	logCSV = csv.NewWriter(logFile)
	logCSV.Write([]string{"Timestamp", "Node", "Context", "SubContext", "Content"})
	logCSV.Flush()
}

func RecordLog(timestamp time.Time, node star.NodeID, context string, subcontext string, content string) {
	if logFile != nil && logCSV != nil && terminalSettings["log.enabled"].Data.(bool) {
		// Filter based on settings
		switch context {
		case "chat":
			if !terminalSettings["log.chat"].Data.(bool) {
				return
			}
		case "commands":
			if !terminalSettings["log.commands"].Data.(bool) {
				return
			}
		case "error":
			if !terminalSettings["log.errors"].Data.(bool) {
				return
			}
		case "notice":
			if !terminalSettings["log.notices"].Data.(bool) {
				return
			}
		case "output":
			if !terminalSettings["log.output"].Data.(bool) {
				return
			}
		case "sync":
			if !terminalSettings["log.sync"].Data.(bool) {
				return
			}
		}

		// If we've gotten here, log away!
		print(content)
		logCSV.Write([]string{timestamp.Format(terminalSettings["display.timestamp"].Data.(string)), node.String(), context, subcontext, content})
		logCSV.Flush()
	}
}

func CloseRecordLog() {
	if logFile != nil {
		logFile.Close()
	}
}

///////////////////////////////////////////////////////////////////////////////
/********************************* Settings **********************************/
///////////////////////////////////////////////////////////////////////////////

type terminalSetting struct {
	Data        interface{}
	Description string
}

var terminalSettings map[string]terminalSetting

///////////////////////////////////////////////////////////////////////////////
/********************************** Agents ***********************************/
///////////////////////////////////////////////////////////////////////////////

type agentInfo struct {
	Node         *star.Node
	Info         *star.NodeInfo
	FriendlyName string
	LastSynced   time.Time
}

var agentFriendlyTracker map[string]*agentInfo
var agentNodeIDTracker map[star.NodeID]*agentInfo
var agentTrackerMutex *sync.Mutex

var agentFriendlyNameTracker int
var shellFriendlyNameTracker int
var terminalFriendlyNameCounter int
var unknownFriendlyNameCounter int

func AgentTrackerUpdateInfo(node *star.Node, info *star.NodeInfo) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()

	var i *agentInfo
	i, ok := agentNodeIDTracker[node.ID]
	if !ok {
		var name string
		switch node.Type {
		case star.NodeTypeAgent:
			agentFriendlyNameTracker++
			name = fmt.Sprintf("agent%03d", agentFriendlyNameTracker)
		case star.NodeTypeTerminal:
			terminalFriendlyNameCounter++
			name = fmt.Sprintf("term%03d", terminalFriendlyNameCounter)
		default:
			unknownFriendlyNameCounter++
			name = fmt.Sprintf("unk%03d", unknownFriendlyNameCounter)
		}

		i = &agentInfo{Node: node, Info: info, FriendlyName: name}
		agentNodeIDTracker[node.ID] = i
		agentFriendlyTracker[name] = i
	}

	i.Node = node
	i.Info = info
	i.LastSynced = time.Now()

	agentNodeIDTracker[node.ID] = i
	agentFriendlyTracker[i.FriendlyName] = i

	// Check if active agent:stream still exists
	if i.Node.ID == activeNode {
		for _, s := range i.Info.StreamIDs {
			if s == activeStream {
				return
			}
		}
		activeStream = star.StreamID{}
	}
}

func AgentTrackerRemoveInfo(id star.NodeID) {
	n, ok := AgentTrackerGetInfoByNodeID(id)
	if ok {
		agentTrackerMutex.Lock()
		defer agentTrackerMutex.Unlock()

		delete(agentFriendlyTracker, n.FriendlyName)
		delete(agentNodeIDTracker, id)
	}
}

func AgentTrackerGetInfoByFriendly(name string) (ai *agentInfo, ok bool) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()
	ai, ok = agentFriendlyTracker[name]
	return
}

func AgentTrackerGetInfoByNodeID(id star.NodeID) (ai *agentInfo, ok bool) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()
	ai, ok = agentNodeIDTracker[id]
	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

var fileServerTracker map[star.ConnectID]string
var fileServerMutex sync.Mutex

func FileServerTrackerGetID(f string) (id star.ConnectID, err error) {
	fileServerMutex.Lock()
	defer fileServerMutex.Unlock()

	fp, err := filepath.Abs(f)
	if err != nil {
		return
	}

	// Check for file's existence
	_, err = os.Stat(fp)
	if err != nil {
		return
	}

	for i, s := range fileServerTracker {
		if s == fp {
			// fp found, return id
			id = i
			return
		}
	}

	// fp not found, new id
	id = star.NewConnectID()
	fileServerTracker[id] = fp

	return
}

func FileServerTrackerGetFilename(id star.ConnectID) (f string, err error) {
	fileServerMutex.Lock()
	defer fileServerMutex.Unlock()

	for i, s := range fileServerTracker {
		if i.String() == id.String() {
			f = s
			return
		}
	}

	err = errors.New("Fileserver id not found.")
	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func TerminalSanitizeFilepath(fp string) (res string) {
	res = fp
	for _, s := range []string{"/", "\\"} {
		res = strings.Replace(res, s, "-", -1)
	}
	return
}

// TerminalConnectorTypeToString coverts the star.ConnectorType byte to a human-readable format.
// Used in terminal.go to avoid string IOCs in the agent
func TerminalConnectorTypeToString(t star.ConnectorType) (res string) {
	switch t {
	case star.ConnectorType_FileServerTCP:
		res = "[file][tcp]"
	case star.ConnectorType_FileServerTCPTLS:
		res = "[file][tcp.tls]"
	case star.ConnectorType_FileServerUDP:
		res = "[file][udp]"
	case star.ConnectorType_FileServerUDPTLS:
		res = "[file][udp.tls]"
	case star.ConnectorType_ShellTCP:
		res = "[shell][tcp]"
	case star.ConnectorType_ShellTCPTLS:
		res = "[shell][tcp.tls]"
	case star.ConnectorType_ShellUDP:
		res = "[shell][udp]"
	case star.ConnectorType_ShellUDPTLS:
		res = "[shell][udp.tls]"
	case star.ConnectorType_TCPTLS:
		res = "[tcp.tls]"
	default:
		res = "[unk]"
	}

	return
}

// TerminalStreamTypeToString converts the star.StreamType byte to a human-readable format.
// Used in terminal.go to avoid string IOCs in the agent
func TerminalStreamTypeToString(t star.StreamType) (res string) {
	switch t {
	case star.StreamTypeCommand:
		res = "Command"
	case star.StreamTypeFileDownload:
		res = "Download"
	case star.StreamTypeFileServer:
		res = "FileServer"
	case star.StreamTypeFileUpload:
		res = "Upload"
	case star.StreamTypeShell:
		res = "Shell"
	default:
		res = "Unknown"
	}

	return
}
