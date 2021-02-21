# **S**imple **T**actical **A**gent **R**elay (STAR) - Design Document

## Overview
**S**imple **T**actical **A**gent **R**elay (**STAR**) will serve as a basic framework for running commands and sharing files between multiple computers. It is designed for conducting penetration tests in an environment which requires pivoting from a foothold computer to other computers which are not facing the external network.

**STAR** is not intended to be any of the following:
 - Used for Command and Control (C2)
    - _C2 agents generally beacon out to an external server to check for automated/scheduled commands. **STAR** is intended to be usable without an external internet connection and to be used manually by a security researcher or penetration tester._
 - A replacement for scanners, exploitation frameworks, or privilege escalation enumeration.
    - _There are several such tools already which are mature and consistently updated to properly do their job. **STAR**'s single focus is to make it easier to run commands and transfer files in a cross-network environment._
 - Modular.
    - _**STAR**'s purpose is specific and not intended to be extended with modular features. The closest to modular that **STAR** will get is through the use of runfiles (see supported terminal commands in the "**STAR** Terminal Design" section)._

## Terms

* **Agent** - _An agent is basically a glorified shell that allows for remote commands and file operations._
* **Constellation** - _A collection of a terminal and one or more agents. Once established, moving from one agent to the other is as simple as running **:j \<agent\>** in the terminal._
    - _Note: A terminal can only ever be a part of one constellation. An agent may be a part of multiple constellations. In most cases, these constellations will be comprised of the same agents, but agents will not relay responses to Terminal B that originate from Terminal A. Files downloaded to agents via the "Save A File" command from Terminal A may not be readily usable by Terminal B._
    - _Reminder: Even though an agent can be a part of multiple constellations, the constellation's terminal must be from the same build as the agents and therefore the other constellation's terminals. An agent can only communicate with agents/terminals from the same build/compile._
* **Terminal** - _A terminal is the manner in which the security researcher or penetration tester interacts with a constellation._

## Flow Of Use

1. Make any desired configuration changes in `agentconfig.go` and `termconfig.go`.
1. Run `make build` on the project on a Linux machine.
    - Each build will regenerate security-related data, such as SSL keys, "passwords", kill switch confirmation codes, etc.
        - _Note: This will help ensure security, but also means that **STAR** agent binaries from other builds will **not** work with this **STAR** constellation. It is an intended feature that only agents/terminals from the same `make build` will be able to join a **STAR** constellation._
    - Terminals for other platforms will be generated.
        - _The build process will be dependent on toolsets on Linux. Future versions may allow for a Windows build process. It is possible/likely that **STAR** can be built on non-Linux Unix machines, but it is not explicitly supported._
1. Run a terminal instance.
1. Copy agents to other machines and execute them to connect to the terminal or interim agents.
1. Use the terminal instance to run commands/shells on machines with agents running.

It should be noted that communications between agents and terminals will be encrypted using the following "flow":

1. At build time, public/privates key will be generated, with the public key embedded in the agent binaries. These will be referred to as the Initial Keys.
1. When a connection is initiated between a terminal and an agent, the agent will generate public/private keys specific to that agent<->terminal relationship. These will be referred to as the Communication Keys.
1. Further communications between agents and terminals will use the following:
    - **WRAPPED IN INITIAL KEYS**:
        - Destination (agent|terminal)
        - **WRAPPED IN COMMUNICATION KEYS**:
            - Command/Response Payload

Golang's gob will be used to encode/decode both the payload and the message in its entirety based on custom data types. This precludes the need to design a message structure.

## STAR Agent Design

Agents will heed the following:
- Agents will **only** use the core golang library.
- Agents will be compiled to be as small as possible, to include running the binaries through `upx`.
- Where possible, hardcoded strings should be avoided in agents.
    - A sort of "bytecode" will be used in communicating between agents and the terminal. These "bytecode" commands are not mapped to a specific value, but instead will be set at compile-time using golang's enum/iota features. These "bytecode" communications include both commands and non-output responses.
- At build time, an agent will be generated for each GOOS/GOARCH. Binaries will be saved to `./agents` and have the naming convention of `staragent_<GOOS>_<GOARCH>[.ext]`
- The terminal's public certificate will be embedded in the agent.
- Hardcoded configuration options will be kept in the `agentconfig.go` file for ease of use, but will be overridden as appropriate by execution arguments.

Agent execution flow should be similar to:

1. On execution, agents will attempt to connect to the terminal and/or other agents based on the following:
    - Command Line Input
    - Hardcoded IP/Ports
1. Regardless of successful connections, agents will enter into a "binding" listening state based on the following:
    - Command Line Input
    - Hardcoded IP/Ports
1. **IF** an agent is unable to connect or listen, whether by not being configured to perform either or failing to successfully do so, it will terminate without a message.
1. The agent will be in a standby "listening" mode to perform the following (each will be run in its own goroutine):
    - Listen for connections from other agents/terminals, and relay those.
        - When a new terminal is connected (_to include any initial connections_), the agent will generate a public/private key specific to that agent<->terminal relationship. This public key will be encrypted with the terminal's public key and passed to the terminal.
    - Listen for terminations from other agents/terminals, and relay those.
        - In the case of an agent no longer being able to communicate with any terminal, and the agent is not listening for any connections (e.g., it is not bound to a port), the agent will act as though it received the "Terminate" command.
    - Relay commands to destination agents and responses to the terminal.
    - Perform self-cleanup on abrupt termination of the process, as able (CTRL+C or the `kill` command). Self-cleanup entails, in order of priority:
        - Relaying to the terminal that the agent has been killed.
        - Attempting to securely delete the binary from the machine.
        - Attempting to delete all files saved through the "Save A File" command.
    - Perform the following commands as directed by the terminal:
        - Execute A Command
        - Save A File
            - Saved files will be to a temporary or otherwise non-standard location. The destination should not matter to the terminal user.
        - Read A File
            - Read any file that the agent has permission to read on the system, relaying its contents to the terminal.
        - Information
            - Returns basic information about the host environment. Not intended to serve as enumeration, but instead situational awareness.
        - Kill Switch
            - Instructs the agent to relay the command to other agents, perform a self-cleanup, and self-terminate.
            - The agent will not relay success/failure.
        - Synchronize
            - Relays what other agents are connected to it to the terminal.
            - Relays agent specific information (to include the public key for the agent<->terminal relationship.)
            - Passes the command on to other agents.
        - Terminate
            - Deletes files downloaded through "Save A File".
            - Informs other agents and the terminal that it terminated.
            - Does **NOT** delete the agent binary.

## STAR Terminal Design

Terminals will heed the following:

- There will only ever be a single terminal in a constellation.
- When built, terminals for supported GOOS/GOARCH will be generated in `./bin/external` and follow the naming convention of `starterminal_<GOOS>_<GOARCH>`. An additional binary of `starterminal` will be generated in `./bin/` for the local environment.

Terminal execution/use flow should be similar to:

1. On execution, terminals will attempt to connect to agents based on the following:
    - Command Line Input
    - Hardcoded IP/Ports
1. Regardless of successful connections, terminals will enter into a "binding" listening state based on the following:
    - Command Line Input
    - Hardcoded IP/Ports
1. The terminal will enter into a user interaction state, taking commands, passing them to agents, etc.
    - Commands starting with a colon are terminal-specific commands and detailed further down. All other commands are passed to the currently active agent.
    - Periodically, a "synchronize" command will be sent to agents to ensure information is up to date.

Terminal supported commands:

 - **:?** - _Provide help and list command options._
 - **:b\[ind\] \[\<ip\>\]:\<port\>** - _Binds to the specified port as a listener. If the IP is not provided, defaults to all interfaces._
 - **:c\[onnect\] \<ip\>:\<port\>** - _Connect to an agent/terminal. Synchronizes with all agents._
 - **:d\[ownload\] \<tool\>** - _Downloads a file from the constellation tool library to the active agent. Location of the constellation tool library's directory on the terminal host computer is specified in `termconfig.go`._
 - **:h\[istory\] \[\<agent\>\]** - _Displays the time-stamped history of commands sent to the agent. If no agent is specified, uses the currently active agent._
 - **:i\[nfo\]** - _Provides situational information for the active agent (i.e., OS, id, etc.)_
 - **:j\[ump\] \<agent\>\[:\<command\>\]** - _Switches focus to the specified agent. If \<command\> is not provided, is 0, or is not valid, defaults to the initial "command input". Otherwise, switches focus to the specific command still running (likely a shell)._
 - **:k\[illswitch\] \[\<confirmation-code\>\]** - _Sends the "kill switch" command to the constellation. If the confirmation code is not provided, the terminal will display it. The value of the confirmation code is set at build time._
 - **:l\[ist\]** - _List the agents/terminals in the constellation, along with any running commands._
 - **:r\[un\] \<runfile\>** - _Executes a runfile. Location of the runfile folder on the terminal host computer is specified in `termconfig.go`._
    - Runfiles are for automating actions in **STAR** and consist of terminal supported commands (this listing) and commands that are passed to the agent. They are handled/passed line-by-line, so best practice is to ensure that each line can stand by itself.
- **:t\[erminate\] \[\<agent\>\]** - _Terminates an agent._
 - **:u\[pload\] \<file\>** - _Uploads a file from the active agent to the constellation loot library. Location of the loot folder on the terminal host computer is specified in `termconfig.go`._
 - **:q\[uit\]** - _Quits the terminal._
