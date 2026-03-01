pub mod access;
pub mod agent;
pub mod check;
pub mod init;
pub mod recovery;
pub mod secret;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent-vault", about = "Zero-trust credential manager for AI agents")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault in the current (or specified) directory
    Init {
        /// Directory to initialize (defaults to current directory)
        directory: Option<String>,
    },

    /// Add a new agent to the vault
    AddAgent {
        /// Name of the agent
        name: String,
    },

    /// Remove an agent from the vault
    RemoveAgent {
        /// Name of the agent
        name: String,
    },

    /// List all agents in the vault
    ListAgents,

    /// Grant an agent access to a group
    Grant {
        /// Agent name
        agent: String,
        /// Group name
        group: String,
    },

    /// Revoke an agent's access to a group
    Revoke {
        /// Agent name
        agent: String,
        /// Group name
        group: String,
    },

    /// Set (create or update) a secret
    Set {
        /// Secret path (e.g. stripe/api-key)
        path: String,

        /// Secret value
        value: Option<String>,

        /// Read value from file
        #[arg(long)]
        from_file: Option<String>,

        /// Group to assign the secret to (defaults to first component of path)
        #[arg(long)]
        group: Option<String>,
    },

    /// Get (decrypt) a secret
    Get {
        /// Secret path (e.g. stripe/api-key)
        path: String,

        /// Path to private key file
        #[arg(long)]
        key: Option<String>,
    },

    /// List all secrets in the vault
    List {
        /// Filter by group
        #[arg(long)]
        group: Option<String>,
    },

    /// Audit the vault for issues
    Check,

    /// Recover an agent (generate new keypair, re-encrypt secrets)
    RecoverAgent {
        /// Agent name
        name: String,
    },

    /// Restore an agent's original private key from escrow
    RestoreAgent {
        /// Agent name
        name: String,

        /// Path to write the restored key
        #[arg(long = "to")]
        to_path: String,
    },
}

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Init { directory } => init::run(directory),
        Commands::AddAgent { name } => agent::run_add(&name),
        Commands::RemoveAgent { name } => agent::run_remove(&name),
        Commands::ListAgents => agent::run_list(),
        Commands::Grant { agent, group } => access::run_grant(&agent, &group),
        Commands::Revoke { agent, group } => access::run_revoke(&agent, &group),
        Commands::Set {
            path,
            value,
            from_file,
            group,
        } => secret::run_set(&path, value.as_deref(), from_file.as_deref(), group.as_deref()),
        Commands::Get { path, key } => secret::run_get(&path, key.as_deref()),
        Commands::List { group } => secret::run_list(group.as_deref()),
        Commands::Check => check::run(),
        Commands::RecoverAgent { name } => recovery::run_recover(&name),
        Commands::RestoreAgent { name, to_path } => recovery::run_restore(&name, &to_path),
    }
}
