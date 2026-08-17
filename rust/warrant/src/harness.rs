//! The harnesses: which agents can be pointed at a warranted session, how, and how much of what
//! they do actually passes through it.
//!
//! # Why the second column is the important one
//!
//! There was already an "integration" surface in this repository before this file: a Python
//! command that wrote `CLAUDE.md`, `AGENTS.md` or `.cursorrules` containing sentences like *"Every
//! action is tracked and recorded"* and *"Secret exposure triggers kill-switch"*. Nothing in the
//! system made those sentences true. They were **instructions to a model**, and a security
//! boundary that lives in the prompt is the precise failure this product was founded on — the five
//! frontier-lab intrusions in the README all failed that way, with the boundary written in the
//! context window while the substrate silently permitted the act.
//!
//! So this registry does two things and refuses to do a third. It writes the **MCP client
//! configuration** that routes a harness's tool calls through `warrantor mcp --agent <id>`, which
//! is a real boundary because the calls traverse a process that can refuse them. And it states,
//! per harness, **what does not go through it** — because for every coding agent in this list the
//! honest answer is "not everything", and an integration page that omitted that would be the
//! `CLAUDE.md` mistake wearing better clothes.
//!
//! # The coverage classes, and what each one is worth
//!
//! - [`Coverage::McpOnly`] — every tool the model can call is an MCP tool. This is the strong
//!   case: the warrant's allowlist is the model's whole reachable surface, and the proxy sees
//!   every call. It applies to SDK-built agents whose tools are all MCP servers.
//! - [`Coverage::McpAndBuiltins`] — the harness ships its own file, shell and search tools which
//!   do **not** speak MCP and therefore never reach the proxy. Every terminal coding agent is in
//!   this class. What the warrant still buys is real but bounded: the deadline, the worktree, the
//!   staged effects, the evidence, the OS lifetime link, and mediation of every *MCP* tool the
//!   agent uses. What it does not buy is mediation of `bash`.
//! - [`Coverage::ProcessOnly`] — the harness speaks no MCP at all. It can still be run under a
//!   warrant, and everything in the previous sentence except MCP mediation still holds, but no
//!   individual tool call is refusable.
//!
//! Naming the escapes per harness is the point. An operator who knows the agent's own `bash` tool
//! bypasses the proxy composes a sandbox; one who has been told "every action is tracked" does not.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// What kind of thing this harness is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A terminal or editor agent that writes code.
    CodingAgent,
    /// A general-purpose assistant or desktop client.
    GeneralAgent,
    /// A library an application builds its own agent with.
    Sdk,
}

impl Kind {
    /// The heading this kind is listed under.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CodingAgent => "coding agent",
            Self::GeneralAgent => "general-purpose agent",
            Self::Sdk => "agent SDK",
        }
    }
}

/// How much of what this harness does passes through the warrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Every tool the model can reach is an MCP tool, so every call is mediated.
    McpOnly,
    /// MCP calls are mediated; the harness's own built-in tools are not. The string names them.
    McpAndBuiltins(&'static str),
    /// No MCP. Only the process-level bounds apply.
    ProcessOnly,
}

impl Coverage {
    /// One sentence stating what is and is not mediated, for the operator.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::McpOnly => {
                "Every tool this agent can call is an MCP tool, so every call is decided by the \
                 warrant."
            }
            Self::McpAndBuiltins(_) => {
                "MCP tool calls are decided by the warrant. This harness's OWN built-in tools do \
                 not speak MCP and never reach the proxy -- compose a sandbox if you need those \
                 stopped as they happen."
            }
            Self::ProcessOnly => {
                "This harness speaks no MCP, so no individual tool call is refusable. The \
                 deadline, the worktree, the evidence and the OS lifetime link still apply."
            }
        }
    }

    /// The built-in tools that escape the proxy, if any are known.
    #[must_use]
    pub const fn escapes(self) -> Option<&'static str> {
        match self {
            Self::McpAndBuiltins(names) => Some(names),
            Self::McpOnly | Self::ProcessOnly => None,
        }
    }
}

/// Where a configuration file lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Relative to the repository the warrant was granted against.
    Project,
    /// Relative to the user's home directory.
    Home,
}

/// How this harness is pointed at the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wiring {
    /// A JSON file with a top-level object of MCP servers under `key`.
    ///
    /// The only shape this build writes automatically, because it is the only one it can
    /// round-trip without guessing: `serde_json` parses the whole file, the entry is inserted, and
    /// everything else is written back as it was read.
    Json {
        /// Where the file lives.
        scope: Scope,
        /// Its path within that scope.
        path: &'static str,
        /// The object the server entry goes into, e.g. `mcpServers`.
        key: &'static str,
    },
    /// A TOML file with an `[<table>.<name>]` section per server.
    Toml {
        /// Where the file lives.
        scope: Scope,
        /// Its path within that scope.
        path: &'static str,
        /// The parent table, e.g. `mcp_servers`.
        table: &'static str,
    },
    /// A format this build will not edit. The block is printed and the path is named.
    ///
    /// Used for YAML and for editor settings whose location varies by installation. Writing a
    /// YAML file by string-splicing loses comments and anchors, and rewriting a user's editor
    /// settings from a path this program guessed is a bad trade for saving one paste.
    Manual {
        /// Where to put it, described for a human.
        where_to: &'static str,
        /// The format the printed block is in.
        format: Format,
    },
    /// No configuration exists, because the harness has no MCP client.
    None,
}

/// The format a printed block is rendered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A JSON object.
    Json,
    /// A TOML table.
    Toml,
    /// A YAML mapping.
    Yaml,
    /// Source code for an SDK.
    Code,
}

/// One integration.
#[derive(Debug, Clone)]
pub struct Harness {
    /// The id typed on the command line.
    pub id: &'static str,
    /// The name a human uses.
    pub display: &'static str,
    /// What kind of thing it is.
    pub kind: Kind,
    /// The executable to look for on `PATH`, if it is a command-line tool.
    pub command: Option<&'static str>,
    /// How it is pointed at the proxy.
    pub wiring: Wiring,
    /// How much of what it does the warrant decides.
    pub coverage: Coverage,
    /// Anything an operator needs to know that the fields above do not carry.
    pub note: &'static str,
}

/// Every harness this build knows how to wire, or knows it cannot.
///
/// The list is deliberately explicit rather than discovered. A registry that guessed — "if
/// `~/.foo/` exists, write `~/.foo/mcp.json`" — would write files into tools it had never been
/// tested against, and the failure mode of a wrong MCP config is an agent that starts and then
/// cannot call anything, which reads to the user as Warrantor being broken.
///
/// Where a path or a key is version-dependent, the entry is [`Wiring::Manual`] and prints the
/// block instead of writing it. That is not a placeholder to be filled in later: it is the honest
/// answer for a configuration location this program cannot verify from here.
#[must_use]
pub fn registry() -> Vec<Harness> {
    vec![
        // ── terminal coding agents ────────────────────────────────────────────────────
        Harness {
            id: "claude-code",
            display: "Claude Code",
            kind: Kind::CodingAgent,
            command: Some("claude"),
            wiring: Wiring::Json {
                scope: Scope::Project,
                path: ".mcp.json",
                key: "mcpServers",
            },
            coverage: Coverage::McpAndBuiltins(
                "Bash, Read, Write, Edit, Glob, Grep and WebFetch are built in and do not \
                 traverse MCP",
            ),
            note: "Project-scoped `.mcp.json` is read from the directory the agent is started in, \
                   which is the worktree the warrant created -- so the wiring travels with the \
                   warrant rather than being installed on the machine. Run it headless under the \
                   warrant with `claude -p`; an interactive session is not supervised by the \
                   daemon's deadline in the way a `warrantor run` child is.",
        },
        Harness {
            id: "codex",
            display: "OpenAI Codex CLI",
            kind: Kind::CodingAgent,
            command: Some("codex"),
            wiring: Wiring::Toml {
                scope: Scope::Home,
                path: ".codex/config.toml",
                table: "mcp_servers",
            },
            coverage: Coverage::McpAndBuiltins(
                "its shell and apply_patch tools are built in and do not traverse MCP",
            ),
            note: "The config is per-user rather than per-project, so an entry written here \
                   applies to every repository until it is removed -- and it names ONE warrant id. \
                   Re-wire when you grant a new warrant; a stale entry points at a settled warrant \
                   and the endpoint refuses to start, which is the fail-closed direction.",
        },
        Harness {
            id: "cursor",
            display: "Cursor",
            kind: Kind::CodingAgent,
            command: Some("cursor-agent"),
            wiring: Wiring::Json {
                scope: Scope::Project,
                path: ".cursor/mcp.json",
                key: "mcpServers",
            },
            coverage: Coverage::McpAndBuiltins(
                "the editor's own file edits, terminal and codebase search do not traverse MCP",
            ),
            note: "Cursor is an editor first. Most of what its agent does is editor-native and \
                   invisible to any MCP proxy; wiring it buys mediation of the MCP servers it \
                   uses and nothing more. Read that sentence before quoting a coverage number.",
        },
        Harness {
            id: "gemini-cli",
            display: "Gemini CLI",
            kind: Kind::CodingAgent,
            command: Some("gemini"),
            wiring: Wiring::Json {
                scope: Scope::Project,
                path: ".gemini/settings.json",
                key: "mcpServers",
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in file, shell and web tools do not traverse MCP",
            ),
            note: "The project file is merged over the user file at `~/.gemini/settings.json`; \
                   writing the project one keeps the warrant's wiring inside the worktree.",
        },
        Harness {
            id: "opencode",
            display: "OpenCode",
            kind: Kind::CodingAgent,
            command: Some("opencode"),
            wiring: Wiring::Json {
                scope: Scope::Project,
                path: "opencode.json",
                key: "mcp",
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in edit, read and bash tools do not traverse MCP",
            ),
            note: "OpenCode's server entries carry a `type` discriminator; the entry written here \
                   sets it to `local`, which is what a stdio server is.",
        },
        Harness {
            id: "aider",
            display: "Aider",
            kind: Kind::CodingAgent,
            command: Some("aider"),
            wiring: Wiring::None,
            coverage: Coverage::ProcessOnly,
            note: "Aider edits files and runs git directly and has no MCP client, so there is \
                   nothing to point at the proxy. Running it under `warrantor run` still gives it \
                   a worktree, a deadline, an OS lifetime link and a signed report -- which is \
                   worth having and is not tool mediation. Said plainly rather than papered over \
                   with a config file that would do nothing.",
        },
        Harness {
            id: "copilot-cli",
            display: "GitHub Copilot CLI",
            kind: Kind::CodingAgent,
            command: Some("copilot"),
            wiring: Wiring::Manual {
                where_to: "the MCP configuration the installed version reads -- `copilot mcp add` \
                           is the supported way to register a stdio server",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in shell and file tools do not traverse MCP",
            ),
            note: "The config path has moved between releases, so this build prints the entry \
                   rather than writing to a path it cannot verify from here. Registering a server \
                   at a guessed path produces an agent that starts and can call nothing, which \
                   reads to a user as Warrantor being broken.",
        },
        Harness {
            id: "cline",
            display: "Cline (VS Code)",
            kind: Kind::CodingAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "Cline's MCP settings, reachable from its own MCP Servers panel",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its file and terminal tools are extension-native and do not traverse MCP",
            ),
            note: "The settings file lives under the editor's per-user extension storage, whose \
                   path differs by platform, by editor build and by portable-mode installs. \
                   Printed, not written.",
        },
        Harness {
            id: "continue",
            display: "Continue",
            kind: Kind::CodingAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`~/.continue/config.yaml`, under `mcpServers`",
                format: Format::Yaml,
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in edit and terminal tools do not traverse MCP",
            ),
            note: "YAML, and this build will not rewrite YAML: a string-spliced edit loses \
                   comments and anchors, and a parse-and-reserialise loses them too. One paste is \
                   cheaper than a mangled config.",
        },
        Harness {
            id: "zed",
            display: "Zed",
            kind: Kind::CodingAgent,
            command: Some("zed"),
            wiring: Wiring::Manual {
                where_to: "Zed's `settings.json`, under `context_servers`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "the editor's own edit and terminal tools do not traverse MCP",
            ),
            note: "Zed calls them context servers rather than MCP servers; the entry shape is the \
                   same. Its settings file is the editor's, not the project's, so it is printed.",
        },
        // ── general-purpose agents ────────────────────────────────────────────────────
        Harness {
            id: "claude-desktop",
            display: "Claude Desktop",
            kind: Kind::GeneralAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`claude_desktop_config.json` -- Settings, Developer, Edit Config opens \
                           it in place",
                format: Format::Json,
            },
            coverage: Coverage::McpOnly,
            note: "A general assistant's only tools are the MCP servers it is given, so coverage \
                   here is total in a way it never is for a coding agent. The trade is that it has \
                   no worktree and no repository: the warrant's write_paths bound has nothing to \
                   describe.",
        },
        Harness {
            id: "goose",
            display: "Goose",
            kind: Kind::GeneralAgent,
            command: Some("goose"),
            wiring: Wiring::Manual {
                where_to: "`~/.config/goose/config.yaml`, as an extension of type `stdio`",
                format: Format::Yaml,
            },
            coverage: Coverage::McpAndBuiltins(
                "its developer extension provides shell and file tools of its own",
            ),
            note: "Goose models everything as extensions, and its built-in developer extension is \
                   one -- disable it if you want the warrant to be the only route to a shell.",
        },
        // ── SDKs ──────────────────────────────────────────────────────────────────────
        Harness {
            id: "claude-agent-sdk",
            display: "Claude Agent SDK",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "the `mcp_servers` option passed when the client is constructed",
                format: Format::Code,
            },
            coverage: Coverage::McpAndBuiltins(
                "the SDK's own file and bash tools, unless you disable them",
            ),
            note: "This is the one harness where full mediation is reachable: restrict the \
                   allowed tools to the MCP server alone and every call the model makes is \
                   decided by the warrant. That is a decision made in your code, so this registry \
                   reports what is possible rather than claiming it.",
        },
        Harness {
            id: "openai-agents-sdk",
            display: "OpenAI Agents SDK",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an `MCPServerStdio` handed to the Agent's `mcp_servers`",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Tools are whatever you attach. Attach only this server and the warrant is the \
                   agent's whole reachable surface; attach function tools alongside it and they \
                   are not mediated, because they never leave your process.",
        },
        Harness {
            id: "langchain",
            display: "LangChain / LangGraph",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`langchain-mcp-adapters`, as a stdio server in the client's connection \
                           map",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Same caveat as the OpenAI SDK: mediation covers the tools loaded from this \
                   server, not native LangChain tools bound in the same graph.",
        },
        Harness {
            id: "pydantic-ai",
            display: "Pydantic AI",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an `MCPServerStdio` in the Agent's toolsets",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Tools are whatever the agent's toolsets contain.",
        },
        // ── terminal coding agents added 2026-08-17 ──────────────────────────────────
        //
        // Every entry below whose configuration path this build cannot verify is
        // `Wiring::Manual`. That is not a placeholder: a registry that guessed a path would write
        // a file into a tool it has never been tested against, and the failure mode of a wrong MCP
        // config is an agent that starts and then cannot call anything -- which reads to the user
        // as Warrantor being broken. A printed block that a person pastes is strictly better than
        // a written file that is wrong.
        Harness {
            id: "windsurf",
            display: "Windsurf (Codeium)",
            kind: Kind::CodingAgent,
            command: Some("windsurf"),
            wiring: Wiring::Json {
                scope: Scope::Home,
                path: ".codeium/windsurf/mcp_config.json",
                key: "mcpServers",
            },
            coverage: Coverage::McpAndBuiltins(
                "Cascade's own file, terminal and search tools do not traverse MCP",
            ),
            note:
                "Per-user like Codex, so an entry written here applies to every repository until \
                   it is removed, and it names ONE warrant id. Re-wire when you grant a new \
                   warrant. Windsurf reloads MCP servers from its settings pane rather than \
                   watching the file, so restart or press refresh after wiring.",
        },
        Harness {
            id: "roo-code",
            display: "Roo Code",
            kind: Kind::CodingAgent,
            command: None,
            wiring: Wiring::Json {
                scope: Scope::Project,
                path: ".roo/mcp.json",
                key: "mcpServers",
            },
            coverage: Coverage::McpAndBuiltins(
                "its read_file, write_to_file, apply_diff, execute_command and browser tools are \
                 built in and do not traverse MCP",
            ),
            note:
                "A Cline fork, and it keeps Cline's project-scoped MCP file at a different path. \
                   There is no command to detect: it is a VS Code extension, so `warrantor agents \
                   detect` cannot see it and reports nothing rather than guessing.",
        },
        Harness {
            id: "amp",
            display: "Amp (Sourcegraph)",
            kind: Kind::CodingAgent,
            command: Some("amp"),
            wiring: Wiring::Manual {
                where_to: "Amp's settings under `amp.mcpServers` -- in VS Code settings.json for \
                           the extension, or the CLI's own settings file",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in edit, read and Bash tools do not traverse MCP",
            ),
            note: "Manual because the settings location differs between the CLI and the editor \
                   extension, and this build cannot tell which one you are wiring from here.",
        },
        Harness {
            id: "qwen-code",
            display: "Qwen Code",
            kind: Kind::CodingAgent,
            command: Some("qwen"),
            wiring: Wiring::Manual {
                where_to: "`.qwen/settings.json` under `mcpServers`, project or home scope",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "it is a Gemini CLI fork and carries the same built-in shell, read and edit tools",
            ),
            note: "Manual rather than written: this build has not been tested against Qwen Code's \
                   settings file, and the two scopes it accepts mean a wrong guess writes a file \
                   that silently does nothing.",
        },
        Harness {
            id: "crush",
            display: "Crush (Charm)",
            kind: Kind::CodingAgent,
            command: Some("crush"),
            wiring: Wiring::Manual {
                where_to: "`crush.json` in the project, under `mcp`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins("its own file and shell tools do not traverse MCP"),
            note: "Crush's server entries carry a `type` discriminator like OpenCode's; the block \
                   printed here sets it to `stdio`. Manual because the key name has moved between \
                   releases and a wrong key is a config that parses and does nothing.",
        },
        // ── the fleet this operator actually runs ────────────────────────────────────
        //
        // Named because they are in use, not because they are wired. Four of the six speak no MCP
        // this build can verify, and saying so is the entry's whole value: an operator who assumed
        // otherwise would believe a warrant was mediating calls it has never seen.
        Harness {
            id: "factory-droid",
            display: "Factory Droid",
            kind: Kind::CodingAgent,
            command: Some("droid"),
            wiring: Wiring::Manual {
                where_to: "Factory's MCP configuration, under `mcpServers`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its own file, shell and PR tools do not traverse MCP",
            ),
            note: "Manual: this build has not been tested against Factory's config location, and \
                   Droid is normally driven from Factory's own session rather than from a \
                   worktree, so the deadline and evidence bounds are the ones that apply.",
        },
        Harness {
            id: "warp",
            display: "Warp",
            kind: Kind::CodingAgent,
            command: Some("warp"),
            wiring: Wiring::Manual {
                where_to: "Warp's Settings -> AI -> MCP Servers, which takes a JSON object per \
                           server and has no file this build can safely edit",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "Warp's agent runs commands in your real terminal, and none of those traverse MCP",
            ),
            note: "The most important entry in this list to read carefully. Warp's agent acts in \
                   YOUR shell, in whatever directory that shell is in -- not in the worktree the \
                   warrant created. Wiring the MCP server gives the warrant a view of MCP calls \
                   and NOTHING else: the containment a `warrantor run` child gets does not apply.",
        },
        Harness {
            id: "grok-cli",
            display: "Grok CLI",
            kind: Kind::CodingAgent,
            command: Some("grok"),
            wiring: Wiring::Manual {
                where_to: "the CLI's MCP settings, under `mcpServers`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in file and shell tools do not traverse MCP",
            ),
            note: "Manual: this build has not been tested against it. New and fast-moving, so \
                   verify the printed block is accepted before relying on a run.",
        },
        Harness {
            id: "glm-coding",
            display: "GLM (z.ai coding plan)",
            kind: Kind::CodingAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "whichever harness you point at the z.ai endpoint -- GLM is a MODEL, so \
                           wire the harness (`claude-code`, `opencode`, ...) and not this entry",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "whatever the harness you run it through has built in",
            ),
            note: "Listed to prevent a category error, not because it is wired. GLM is a model \
                   served over an API; the thing that calls tools is the harness in front of it. \
                   Wire that harness, and this warrant then covers exactly what that harness \
                   routes through MCP -- no more and no less, whichever model is behind it.",
        },
        Harness {
            id: "minimax",
            display: "MiniMax Agent",
            kind: Kind::GeneralAgent,
            command: None,
            wiring: Wiring::None,
            coverage: Coverage::ProcessOnly,
            note: "A hosted agent product driven from its own desktop and web surfaces. There is \
                   no local stdio MCP client this build can point at a warrant, so nothing it does \
                   passes through the proxy. Treat its output as unwarranted work and review it as \
                   such -- or have it produce a patch and settle that under a warrant of your own.",
        },
        Harness {
            id: "kimi-cli",
            display: "Kimi CLI (Moonshot)",
            kind: Kind::CodingAgent,
            command: Some("kimi"),
            wiring: Wiring::Manual {
                where_to: "the CLI's MCP configuration, under `mcpServers`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its built-in file and shell tools do not traverse MCP",
            ),
            note: "Manual: untested from here. As with every per-user config, the entry names ONE \
                   warrant id and a stale entry fails closed rather than running unwarranted.",
        },
        // ── general-purpose agents ───────────────────────────────────────────────────
        Harness {
            id: "chatgpt-desktop",
            display: "ChatGPT desktop",
            kind: Kind::GeneralAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "Settings -> Connectors, which takes a server definition through the \
                           app's own UI and has no file this build may edit",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "its own browsing, code interpreter and file tools do not traverse MCP",
            ),
            note: "A general assistant rather than a coding agent: it has no worktree and no \
                   process this warrant supervises, so the deadline and the OS lifetime link do \
                   NOT apply. What a warrant covers here is the MCP calls alone.",
        },
        Harness {
            id: "librechat",
            display: "LibreChat",
            kind: Kind::GeneralAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`librechat.yaml`, under `mcpServers`",
                format: Format::Yaml,
            },
            coverage: Coverage::McpAndBuiltins(
                "its own file upload and code interpreter tools do not traverse MCP",
            ),
            note: "YAML is never written by this build: splicing it by string loses comments and \
                   anchors, and a config file an operator hand-maintains is one they must be able \
                   to keep reading. The block is printed to paste.",
        },
        Harness {
            id: "open-webui",
            display: "Open WebUI",
            kind: Kind::GeneralAgent,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an MCP-to-OpenAPI bridge such as `mcpo` in front of this server, whose \
                           resulting URL goes in Open WebUI's `Settings -> Tools`",
                format: Format::Json,
            },
            coverage: Coverage::McpAndBuiltins(
                "anything the bridge does not forward, and Open WebUI's own tools",
            ),
            note:
                "The only entry here that needs a translator rather than a config line. A bridge \
                   is another process between the agent and the warrant, so what the warrant sees \
                   is what the bridge chose to forward -- verify that before trusting the coverage.",
        },
        // ── agent SDKs and frameworks ────────────────────────────────────────────────
        Harness {
            id: "crewai",
            display: "CrewAI",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an `MCPServerAdapter` from `crewai-tools`, whose tools are handed to \
                           the Agent",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Full mediation is reachable: give the agent the adapter's tools and nothing \
                   else, and every call it makes is decided by the warrant. Adding one Python \
                   function as a tool alongside them ends that, silently.",
        },
        Harness {
            id: "autogen",
            display: "AutoGen / AG2",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an `StdioServerParams` passed to `mcp_server_tools`, whose result is \
                           the agent's tool list",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Same rule as CrewAI, with one extra hazard: a multi-agent conversation can \
                   route a task to an agent wired to a DIFFERENT tool list. The warrant covers the \
                   agent you wired, not the group.",
        },
        Harness {
            id: "llamaindex",
            display: "LlamaIndex",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`BasicMCPClient` plus `McpToolSpec` from `llama-index-tools-mcp`",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "Retrieval is not a tool call: an index built before the run is read without \
                   passing through the warrant, and nothing here refuses that. What the warrant \
                   decides is the tools, not the context.",
        },
        Harness {
            id: "semantic-kernel",
            display: "Semantic Kernel",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "a plugin built with `MCPStdioPlugin` (Python) or \
                           `McpClientFactory.CreateAsync` (.NET) and added via `Kernel.Plugins`",
                format: Format::Code,
            },
            coverage: Coverage::McpAndBuiltins("every other plugin registered on the same Kernel"),
            note: "A Kernel usually carries several plugins, and only the MCP one traverses the \
                   warrant. That is why this is not McpOnly: the default shape of a Semantic \
                   Kernel application has native functions beside the MCP tools.",
        },
        Harness {
            id: "mastra",
            display: "Mastra",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "an `MCPClient` whose `getTools()` result is the Agent's `tools`",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "TypeScript. Full mediation is reachable and, as everywhere in this list, ends \
                   the moment a locally-defined tool is added beside the MCP ones.",
        },
        Harness {
            id: "vercel-ai-sdk",
            display: "Vercel AI SDK",
            kind: Kind::Sdk,
            command: None,
            wiring: Wiring::Manual {
                where_to: "`experimental_createMCPClient` with a stdio transport, whose tools are \
                           spread into `generateText`/`streamText`",
                format: Format::Code,
            },
            coverage: Coverage::McpOnly,
            note: "The MCP client here is marked experimental upstream, so the function name may \
                   move. Verify the printed block compiles against the version you have rather \
                   than trusting this entry's spelling of it.",
        },
    ]
}

/// Look one up by id.
#[must_use]
pub fn find(id: &str) -> Option<Harness> {
    registry().into_iter().find(|h| h.id == id)
}

/// Everything a generated configuration needs to name, so no field is passed positionally by
/// accident and every renderer sees the same session.
#[derive(Debug, Clone)]
pub struct Session<'a> {
    /// Absolute path to the `warrantor` executable.
    pub exe: &'a str,
    /// The warrant the harness will run under.
    pub warrant_id: &'a str,
    /// The store root, written explicitly into every generated config.
    ///
    /// Always written, even when it is the default. A harness is started by an editor, a service
    /// manager or a container with an environment this process never sees, and `--root` resolves
    /// from `HOME`/`USERPROFILE` when it is absent — so a config that omitted it would silently
    /// address a *different store* under any of them, and the failure would be "the warrant does
    /// not exist" at the agent's first tool call. Naming it costs one line and removes the class.
    pub root: &'a str,
    /// `--upstream` values to carry into the generated command.
    pub upstreams: &'a [String],
}

/// The command and arguments that start a policed session for one warrant.
///
/// The warrant id is baked into the arguments, which is the design and not an oversight. A config
/// naming no warrant would be a config that survives every warrant, and the endpoint would then be
/// whatever warrant happened to be open — authority by ambient state. Naming one means a config
/// that outlives its warrant points at a settled warrant, and `warrantor mcp --agent` refuses to
/// start on one. Stale wiring fails closed.
#[must_use]
pub fn server_command(session: &Session<'_>) -> (String, Vec<String>) {
    let mut args = vec![
        "mcp".to_string(),
        "--agent".to_string(),
        session.warrant_id.to_string(),
        "--root".to_string(),
        session.root.to_string(),
    ];
    for spec in session.upstreams {
        args.push("--upstream".to_string());
        args.push(spec.clone());
    }
    (session.exe.to_string(), args)
}

/// The MCP server entry, in the shape every JSON-configured client reads.
#[must_use]
pub fn server_entry(session: &Session<'_>, typed: bool) -> Value {
    let (command, args) = server_command(session);
    let mut entry = Map::new();
    if typed {
        // OpenCode and a few others discriminate stdio servers from remote ones by a `type` field,
        // and default to remote when it is absent -- which fails as a connection error rather than
        // as a configuration error, so it is worth the one extra key.
        entry.insert("type".to_string(), json!("local"));
    }
    entry.insert("command".to_string(), json!(command));
    entry.insert("args".to_string(), json!(args));
    Value::Object(entry)
}

/// What went wrong writing a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The existing file is not valid JSON.
    NotJson(String),
    /// The existing file is JSON but not an object, so there is nowhere to put the entry.
    NotAnObject,
    /// The key exists and is not an object.
    KeyNotAnObject(String),
    /// A Warrantor entry is already there, pointing somewhere else.
    AlreadyWired {
        /// What is there now, rendered.
        existing: String,
    },
    /// The TOML file contains something the section splicer will not risk editing.
    TomlTooRich(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(detail) => write!(
                f,
                "that file is not valid JSON ({detail}), and this will not overwrite a file it \
                 could not read -- the contents might be a configuration somebody needs"
            ),
            Self::NotAnObject => write!(
                f,
                "that file's top level is not a JSON object, so there is nowhere to add a server"
            ),
            Self::KeyNotAnObject(key) => {
                write!(f, "that file has a {key:?} that is not an object")
            }
            Self::AlreadyWired { existing } => write!(
                f,
                "a Warrantor server is already configured there, pointing at {existing}. Pass \
                 --replace to change it -- and note that the warrant id in the existing entry is \
                 the one the agent has been talking to."
            ),
            Self::TomlTooRich(detail) => write!(
                f,
                "this build edits TOML by splicing whole sections, and that file contains {detail}, \
                 where a line beginning with `[` may not be a section header. Add the block by \
                 hand rather than have it written wrongly."
            ),
        }
    }
}

impl std::error::Error for WireError {}

/// The name every generated entry is filed under.
pub const ENTRY_NAME: &str = "warrantor";

/// Insert the server entry into a JSON configuration, preserving everything else.
///
/// `existing` is the file's current contents, or `None` when it does not exist yet.
///
/// # Errors
/// [`WireError`] when the file cannot be read as an object, or when an entry is already there and
/// `replace` is false.
pub fn splice_json(
    existing: Option<&str>,
    key: &str,
    entry: &Value,
    replace: bool,
) -> Result<String, WireError> {
    let mut root: Value = match existing.map(str::trim) {
        None | Some("") => json!({}),
        Some(text) => serde_json::from_str(text).map_err(|e| WireError::NotJson(e.to_string()))?,
    };
    let Some(object) = root.as_object_mut() else {
        return Err(WireError::NotAnObject);
    };
    let servers = object.entry(key.to_string()).or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        return Err(WireError::KeyNotAnObject(key.to_string()));
    };
    if let Some(current) = servers.get(ENTRY_NAME) {
        if !replace {
            return Err(WireError::AlreadyWired {
                existing: describe_entry(current),
            });
        }
    }
    servers.insert(ENTRY_NAME.to_string(), entry.clone());
    // Two-space indent and a trailing newline: these files are read and edited by people, and a
    // one-line reserialisation of somebody's config is a diff nobody can review.
    let mut rendered =
        serde_json::to_string_pretty(&root).map_err(|e| WireError::NotJson(e.to_string()))?;
    rendered.push('\n');
    Ok(rendered)
}

/// A short account of an existing entry, for the refusal that names it.
fn describe_entry(entry: &Value) -> String {
    let args = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("an unnamed command");
    format!("`{command} {args}`").trim_end().to_string()
}

/// Insert an `[<table>.warrantor]` section into a TOML configuration.
///
/// This is a **section splicer**, not a TOML parser. It finds the section by its header line,
/// replaces everything up to the next header, and never looks inside a value. That is safe for the
/// one thing it does and is not safe in general, so it refuses outright on a file containing a
/// multi-line string delimiter — the one construct in which a line beginning with `[` may not be a
/// section header. Refusing a file it cannot read correctly is the same rule
/// [`splice_json`] follows for invalid JSON: this program does not overwrite what it did not
/// understand.
///
/// # Errors
/// [`WireError::TomlTooRich`] for a file it will not risk editing, or
/// [`WireError::AlreadyWired`] when a section is already there and `replace` is false.
pub fn splice_toml(
    existing: Option<&str>,
    table: &str,
    command: &str,
    args: &[String],
    replace: bool,
) -> Result<String, WireError> {
    let text = existing.unwrap_or("");
    if text.contains("\"\"\"") || text.contains("'''") {
        return Err(WireError::TomlTooRich(
            "a multi-line string delimiter".to_string(),
        ));
    }
    let header = format!("[{table}.{ENTRY_NAME}]");
    let mut out: Vec<String> = Vec::new();
    let mut skipping = false;
    let mut found = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == header {
            found = true;
            if !replace {
                return Err(WireError::AlreadyWired {
                    existing: format!("the {header} section of that file"),
                });
            }
            skipping = true;
            continue;
        }
        if skipping {
            // Any header ends the section being replaced, at any nesting depth.
            if trimmed.starts_with('[') {
                skipping = false;
            } else {
                continue;
            }
        }
        out.push(line.to_string());
    }
    let _ = found;
    // A blank line before the new section, unless the file is empty or already ends in one. TOML
    // does not care; a person reading the file does.
    while out.last().map(|l| l.trim().is_empty()) == Some(true) {
        out.pop();
    }
    if !out.is_empty() {
        out.push(String::new());
    }
    out.push(header);
    out.push(format!("command = {}", toml_string(command)));
    let rendered_args: Vec<String> = args.iter().map(|a| toml_string(a)).collect();
    out.push(format!("args = [{}]", rendered_args.join(", ")));
    let mut result = out.join("\n");
    result.push('\n');
    Ok(result)
}

/// Render a TOML basic string.
///
/// Backslashes first: escaping the quote before the backslash would double-escape the backslash
/// this function had just inserted, which on Windows is every path in the file.
fn toml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Render the block to paste, for the harnesses this build will not write to.
#[must_use]
pub fn render_manual(harness: &Harness, format: Format, session: &Session<'_>) -> String {
    let (command, args) = server_command(session);
    match format {
        Format::Json => {
            let entry = server_entry(session, false);
            serde_json::to_string_pretty(&json!({ "mcpServers": { ENTRY_NAME: entry } }))
                .unwrap_or_default()
        }
        Format::Toml => splice_toml(None, "mcp_servers", &command, &args, true)
            .unwrap_or_else(|e| e.to_string()),
        Format::Yaml => {
            let rendered: Vec<String> = args.iter().map(|a| format!("      - {a:?}")).collect();
            format!(
                "mcpServers:\n  - name: {ENTRY_NAME}\n    command: {command:?}\n    args:\n{}",
                rendered.join("\n")
            )
        }
        Format::Code => render_sdk_snippet(harness, &command, &args),
    }
}

/// A snippet for an SDK, in the language its users write.
///
/// Kept short and unrunnable-as-is on purpose: a copy-paste-ready agent would be this repository
/// shipping an agent, and the thing being demonstrated is one argument.
fn render_sdk_snippet(harness: &Harness, command: &str, args: &[String]) -> String {
    let rendered: Vec<String> = args.iter().map(|a| format!("{a:?}")).collect();
    let list = rendered.join(", ");
    match harness.id {
        "openai-agents-sdk" => format!(
            "from agents import Agent\nfrom agents.mcp import MCPServerStdio\n\n\
             warrantor = MCPServerStdio(params={{\n    \"command\": {command:?},\n    \
             \"args\": [{list}],\n}})\n\n\
             agent = Agent(name=\"worker\", mcp_servers=[warrantor])\n"
        ),
        "langchain" => format!(
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n\n\
             client = MultiServerMCPClient({{\n    \"{ENTRY_NAME}\": {{\n        \
             \"command\": {command:?},\n        \"args\": [{list}],\n        \
             \"transport\": \"stdio\",\n    }}\n}})\ntools = await client.get_tools()\n"
        ),
        "pydantic-ai" => format!(
            "from pydantic_ai import Agent\nfrom pydantic_ai.mcp import MCPServerStdio\n\n\
             warrantor = MCPServerStdio({command:?}, args=[{list}])\n\
             agent = Agent(\"anthropic:claude-sonnet-4-5\", toolsets=[warrantor])\n"
        ),
        // The Claude Agent SDK, and anything else that reads the same map shape.
        _ => format!(
            "options = {{\n    \"mcp_servers\": {{\n        \"{ENTRY_NAME}\": {{\n            \
             \"command\": {command:?},\n            \"args\": [{list}],\n        }}\n    }},\n\
             # Restrict allowed tools to this server if you want the warrant to be the agent's\n\
             \x20   # WHOLE reachable surface -- otherwise the SDK's own file and bash tools stay\n\
             \x20   # outside it. See `warrantor agents show {}`.\n}}\n",
            harness.id
        ),
    }
}

/// Group the registry by kind, preserving declaration order within each group.
#[must_use]
pub fn by_kind() -> BTreeMap<&'static str, Vec<Harness>> {
    let mut grouped: BTreeMap<&'static str, Vec<Harness>> = BTreeMap::new();
    for harness in registry() {
        grouped
            .entry(harness.kind.label())
            .or_default()
            .push(harness);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session for the tests, so the field names are asserted rather than the argument order.
    fn session<'a>(warrant_id: &'a str, upstreams: &'a [String]) -> Session<'a> {
        Session {
            exe: "warrantor",
            warrant_id,
            root: "/home/a/.warrantor",
            upstreams,
        }
    }

    #[test]
    fn every_id_is_unique_and_lowercase() {
        let mut seen = std::collections::BTreeSet::new();
        for harness in registry() {
            assert!(
                seen.insert(harness.id),
                "duplicate harness id {}",
                harness.id
            );
            assert!(
                harness
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "{} is typed on a command line",
                harness.id
            );
        }
    }

    #[test]
    fn no_harness_claims_more_coverage_than_it_has() {
        // The rule this registry exists to enforce. A terminal coding agent ships its own shell
        // and file tools; claiming McpOnly for one would be the `CLAUDE.md` lie in a struct.
        for harness in registry() {
            if harness.kind == Kind::CodingAgent {
                assert_ne!(
                    harness.coverage,
                    Coverage::McpOnly,
                    "{} is a terminal coding agent: its own tools do not traverse MCP",
                    harness.id
                );
            }
        }
    }

    #[test]
    fn no_two_harnesses_claim_the_same_command() {
        // `agents detect` resolves each command on PATH and reports what it found. Two harnesses
        // sharing one would make a single binary on PATH report as two installed agents, and an
        // operator would wire the wrong one. Worth asserting now that the registry has grown past
        // the point where a collision is obvious by reading it.
        let mut seen: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for harness in registry() {
            if let Some(command) = harness.command {
                if let Some(previous) = seen.insert(command, harness.id) {
                    panic!(
                        "{previous} and {} both claim the command {command:?}",
                        harness.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_manual_entry_says_where_to_put_it_specifically_enough_to_act_on() {
        // A `Manual` entry exists because this build will not guess a path. That is only honest if
        // the entry then says where the operator should look -- "somewhere in its settings" would
        // be the refusal without the remedy, which is the shape of the `--upstream` defect.
        for harness in registry() {
            if let Wiring::Manual { where_to, .. } = harness.wiring {
                assert!(
                    where_to.len() > 25,
                    "{}'s where_to is too vague to act on: {where_to:?}",
                    harness.id
                );
                assert!(
                    where_to.contains('`')
                        || where_to.contains("Settings")
                        || where_to.contains("settings")
                        || where_to.contains("option"),
                    "{}'s where_to names no concrete file, setting or API: {where_to:?}",
                    harness.id
                );
            }
        }
    }

    #[test]
    fn every_harness_carries_a_note_that_says_something() {
        // The note is where an entry earns its place: what an operator needs that the structured
        // fields do not carry. An empty or boilerplate one means the entry was added to make a
        // list longer.
        for harness in registry() {
            assert!(
                harness.note.len() > 40,
                "{} has no substantive note",
                harness.id
            );
        }
    }

    #[test]
    fn a_harness_with_no_mcp_client_is_not_given_a_config_file() {
        for harness in registry() {
            if harness.coverage == Coverage::ProcessOnly {
                assert_eq!(
                    harness.wiring,
                    Wiring::None,
                    "{} has no MCP client, so writing it a config would be writing a file that \
                     does nothing -- which is what the Python generator did",
                    harness.id
                );
            }
        }
    }

    #[test]
    fn the_warrant_id_is_in_the_arguments_so_stale_wiring_fails_closed() {
        let (command, args) = server_command(&Session {
            exe: "/usr/local/bin/warrantor",
            ..session("w-abc", &[])
        });
        assert_eq!(command, "/usr/local/bin/warrantor");
        assert_eq!(
            args,
            vec!["mcp", "--agent", "w-abc", "--root", "/home/a/.warrantor"],
            "the root is written explicitly: a harness started by an editor or a container              resolves a DIFFERENT store from HOME when it is absent"
        );
    }

    #[test]
    fn upstreams_are_carried_into_the_generated_command() {
        let (_, args) = server_command(&session("w-1", &["files=npx server".to_string()]));
        assert_eq!(
            args,
            vec![
                "mcp",
                "--agent",
                "w-1",
                "--root",
                "/home/a/.warrantor",
                "--upstream",
                "files=npx server"
            ]
        );
    }

    #[test]
    fn splicing_json_keeps_everything_that_was_already_there() {
        let existing = r#"{"mcpServers":{"other":{"command":"x"}},"unrelated":42}"#;
        let entry = server_entry(&session("w-1", &[]), false);
        let out = splice_json(Some(existing), "mcpServers", &entry, false).expect("splices");
        let parsed: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(parsed["unrelated"], json!(42));
        assert_eq!(parsed["mcpServers"]["other"]["command"], json!("x"));
        assert_eq!(parsed["mcpServers"]["warrantor"]["args"][2], json!("w-1"));
        assert_eq!(
            parsed["mcpServers"]["warrantor"]["args"][3],
            json!("--root")
        );
    }

    #[test]
    fn splicing_json_into_nothing_creates_the_file_contents() {
        let entry = server_entry(&session("w-1", &[]), false);
        let out = splice_json(None, "mcpServers", &entry, false).expect("splices");
        let parsed: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(
            parsed["mcpServers"]["warrantor"]["command"],
            json!("warrantor")
        );
        assert!(out.ends_with('\n'), "files end in a newline");
    }

    #[test]
    fn an_unreadable_config_is_never_overwritten() {
        // The file might be a configuration somebody needs, and "it was not valid JSON" is not a
        // licence to replace it.
        let entry = server_entry(&session("w-1", &[]), false);
        let error =
            splice_json(Some("{not json"), "mcpServers", &entry, false).expect_err("refuses");
        assert!(matches!(error, WireError::NotJson(_)), "{error:?}");
    }

    #[test]
    fn an_existing_warrantor_entry_names_the_warrant_it_points_at() {
        let first = server_entry(&session("w-old", &[]), false);
        let file = splice_json(None, "mcpServers", &first, false).expect("first");
        let second = server_entry(&session("w-new", &[]), false);
        let error = splice_json(Some(&file), "mcpServers", &second, false).expect_err("refuses");
        let rendered = error.to_string();
        assert!(rendered.contains("w-old"), "{rendered}");
        assert!(rendered.contains("--replace"), "{rendered}");
        // And --replace goes through.
        let replaced = splice_json(Some(&file), "mcpServers", &second, true).expect("replaces");
        assert!(replaced.contains("w-new"));
        assert!(!replaced.contains("w-old"));
    }

    #[test]
    fn splicing_toml_replaces_only_its_own_section() {
        let existing = "[mcp_servers.other]\ncommand = \"x\"\nargs = []\n\n\
                        [mcp_servers.warrantor]\ncommand = \"old\"\nargs = []\n\n\
                        [profiles.default]\nmodel = \"m\"\n";
        let out = splice_toml(
            Some(existing),
            "mcp_servers",
            "new",
            &["mcp".to_string(), "--agent".to_string(), "w-1".to_string()],
            true,
        )
        .expect("splices");
        assert!(out.contains("[mcp_servers.other]"), "{out}");
        assert!(out.contains("[profiles.default]"), "{out}");
        assert!(out.contains("model = \"m\""), "{out}");
        assert!(!out.contains("\"old\""), "{out}");
        assert!(out.contains("command = \"new\""), "{out}");
        assert_eq!(out.matches("[mcp_servers.warrantor]").count(), 1, "{out}");
    }

    #[test]
    fn splicing_toml_refuses_a_file_it_cannot_read_correctly() {
        // A multi-line string is the one construct where a line starting with `[` need not be a
        // section header, and a section splicer that guessed would corrupt the file silently.
        let existing = "notes = \"\"\"\n[not a header]\n\"\"\"\n";
        let error =
            splice_toml(Some(existing), "mcp_servers", "x", &[], true).expect_err("refuses");
        assert!(matches!(error, WireError::TomlTooRich(_)), "{error:?}");
    }

    #[test]
    fn a_windows_path_survives_toml_rendering() {
        let out = splice_toml(
            None,
            "mcp_servers",
            r"C:\Program Files\warrantor\warrantor.exe",
            &[],
            true,
        )
        .expect("splices");
        assert!(
            out.contains(r#"command = "C:\\Program Files\\warrantor\\warrantor.exe""#),
            "{out}"
        );
    }

    #[test]
    fn a_typed_entry_says_it_is_a_local_server() {
        let entry = server_entry(&session("w-1", &[]), true);
        assert_eq!(entry["type"], json!("local"));
        let untyped = server_entry(&session("w-1", &[]), false);
        assert!(untyped.get("type").is_none());
    }

    #[test]
    fn every_manual_wiring_renders_something_a_person_can_paste() {
        for harness in registry() {
            if let Wiring::Manual { format, .. } = harness.wiring {
                let block = render_manual(&harness, format, &session("w-1", &[]));
                assert!(
                    block.contains("w-1"),
                    "{}'s block must name the warrant: {block}",
                    harness.id
                );
                assert!(!block.trim().is_empty(), "{} renders nothing", harness.id);
            }
        }
    }
}
