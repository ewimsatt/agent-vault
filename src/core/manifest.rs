use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::VaultError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    #[serde(default)]
    pub owners: Vec<Owner>,
    #[serde(default)]
    pub agents: Vec<AgentEntry>,
    #[serde(default)]
    pub groups: Vec<Group>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Owner {
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEntry {
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub secrets: Vec<String>,
}

impl Manifest {
    pub fn new(owner_name: &str) -> Self {
        Self {
            version: 1,
            owners: vec![Owner {
                name: owner_name.to_string(),
                public_key: "owner.pub".to_string(),
            }],
            agents: vec![],
            groups: vec![],
        }
    }

    pub fn load(path: &Path) -> Result<Self, VaultError> {
        let contents = std::fs::read_to_string(path)?;
        let manifest: Manifest = serde_yaml::from_str(&contents)?;
        Ok(manifest)
    }

    pub fn save(&self, path: &Path) -> Result<(), VaultError> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }

    /// Add an agent with no group access.
    pub fn add_agent(&mut self, name: &str) -> Result<(), VaultError> {
        if self.agents.iter().any(|a| a.name == name) {
            return Err(VaultError::AgentExists(name.to_string()));
        }
        self.agents.push(AgentEntry {
            name: name.to_string(),
            groups: vec![],
        });
        Ok(())
    }

    /// Remove an agent, returning the groups they belonged to.
    pub fn remove_agent(&mut self, name: &str) -> Result<Vec<String>, VaultError> {
        let idx = self
            .agents
            .iter()
            .position(|a| a.name == name)
            .ok_or_else(|| VaultError::AgentNotFound(name.to_string()))?;
        let agent = self.agents.remove(idx);
        Ok(agent.groups)
    }

    /// Grant an agent access to a group.
    pub fn grant(&mut self, agent_name: &str, group_name: &str) -> Result<(), VaultError> {
        // Ensure group exists
        if !self.groups.iter().any(|g| g.name == group_name) {
            return Err(VaultError::GroupNotFound(group_name.to_string()));
        }
        let agent = self
            .agents
            .iter_mut()
            .find(|a| a.name == agent_name)
            .ok_or_else(|| VaultError::AgentNotFound(agent_name.to_string()))?;
        if !agent.groups.contains(&group_name.to_string()) {
            agent.groups.push(group_name.to_string());
        }
        Ok(())
    }

    /// Revoke an agent's access to a group.
    pub fn revoke(&mut self, agent_name: &str, group_name: &str) -> Result<(), VaultError> {
        let agent = self
            .agents
            .iter_mut()
            .find(|a| a.name == agent_name)
            .ok_or_else(|| VaultError::AgentNotFound(agent_name.to_string()))?;
        agent.groups.retain(|g| g != group_name);
        Ok(())
    }

    /// Ensure a group exists, creating it if necessary.
    pub fn ensure_group(&mut self, group_name: &str) {
        if !self.groups.iter().any(|g| g.name == group_name) {
            self.groups.push(Group {
                name: group_name.to_string(),
                secrets: vec![],
            });
        }
    }

    /// Add a secret path to a group.
    pub fn add_secret_to_group(&mut self, group_name: &str, secret_path: &str) {
        self.ensure_group(group_name);
        let group = self.groups.iter_mut().find(|g| g.name == group_name).unwrap();
        if !group.secrets.contains(&secret_path.to_string()) {
            group.secrets.push(secret_path.to_string());
        }
    }

    /// Get all agent names that have access to a group.
    pub fn agents_in_group(&self, group_name: &str) -> Vec<String> {
        self.agents
            .iter()
            .filter(|a| a.groups.contains(&group_name.to_string()))
            .map(|a| a.name.clone())
            .collect()
    }

    /// Get all secret paths in a group.
    pub fn secrets_in_group(&self, group_name: &str) -> Vec<String> {
        self.groups
            .iter()
            .find(|g| g.name == group_name)
            .map(|g| g.secrets.clone())
            .unwrap_or_default()
    }

    /// Get all groups an agent belongs to.
    pub fn agent_groups(&self, agent_name: &str) -> Option<Vec<String>> {
        self.agents
            .iter()
            .find(|a| a.name == agent_name)
            .map(|a| a.groups.clone())
    }

    /// Get all agent names that are authorized for a specific secret path.
    pub fn authorized_agents_for_secret(&self, secret_path: &str) -> Vec<String> {
        // Find which group(s) contain this secret
        let groups: Vec<&str> = self
            .groups
            .iter()
            .filter(|g| g.secrets.contains(&secret_path.to_string()))
            .map(|g| g.name.as_str())
            .collect();

        // Collect agents that belong to any of those groups
        let mut agents: Vec<String> = self
            .agents
            .iter()
            .filter(|a| a.groups.iter().any(|ag| groups.contains(&ag.as_str())))
            .map(|a| a.name.clone())
            .collect();
        agents.sort();
        agents.dedup();
        agents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_operations() {
        let mut m = Manifest::new("alice");
        m.add_agent("bot1").unwrap();
        m.ensure_group("stripe");
        m.add_secret_to_group("stripe", "stripe/api-key");
        m.grant("bot1", "stripe").unwrap();

        assert_eq!(m.agents_in_group("stripe"), vec!["bot1"]);
        assert_eq!(
            m.authorized_agents_for_secret("stripe/api-key"),
            vec!["bot1"]
        );

        m.revoke("bot1", "stripe").unwrap();
        assert!(m.agents_in_group("stripe").is_empty());
    }
}
