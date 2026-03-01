/**
 * Manifest parsing for vault access control.
 *
 * The manifest.yaml file defines which agents can access which groups of secrets.
 * It contains no secret material — only plaintext policy.
 */

import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import { ManifestError } from "./errors.js";

/** A single agent entry in the manifest. */
export interface ManifestAgent {
  name: string;
  groups: string[];
}

/** A secret group entry in the manifest. */
export interface ManifestGroup {
  name: string;
  secrets: string[];
}

/** Parsed manifest data. */
interface ManifestData {
  version?: number;
  owners?: Array<{ name: string; public_key?: string }>;
  agents?: Array<{ name: string; groups?: string[] }>;
  groups?: Array<{ name: string; secrets?: string[] }>;
}

/**
 * Parsed manifest.yaml — access control policy.
 */
export class Manifest {
  private readonly _data: ManifestData;
  private readonly _agents: Map<string, ManifestAgent>;
  private readonly _groups: Map<string, ManifestGroup>;

  constructor(data: ManifestData) {
    this._data = data;

    this._agents = new Map();
    for (const a of data.agents ?? []) {
      this._agents.set(a.name, {
        name: a.name,
        groups: [...(a.groups ?? [])],
      });
    }

    this._groups = new Map();
    for (const g of data.groups ?? []) {
      this._groups.set(g.name, {
        name: g.name,
        secrets: [...(g.secrets ?? [])],
      });
    }
  }

  /**
   * Load a manifest from a YAML file.
   *
   * @param filePath - Absolute path to manifest.yaml.
   * @returns Parsed Manifest.
   * @throws ManifestError if the file is missing or invalid.
   */
  static load(filePath: string): Manifest {
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch (err) {
      throw new ManifestError(
        `Manifest not found: ${filePath}`,
      );
    }

    let data: ManifestData;
    try {
      data = (yaml.load(content) as ManifestData) ?? {};
    } catch (err) {
      throw new ManifestError(
        `Invalid manifest YAML: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    return new Manifest(data);
  }

  /** Return the list of groups an agent belongs to. */
  agentGroups(agentName: string): string[] {
    const agent = this._agents.get(agentName);
    return agent ? [...agent.groups] : [];
  }

  /** Return the list of secret paths in a group. */
  groupSecrets(groupName: string): string[] {
    const group = this._groups.get(groupName);
    return group ? [...group.secrets] : [];
  }

  /** Return agent names authorized for a given secret. */
  agentsForSecret(secretPath: string): string[] {
    const agents: string[] = [];
    for (const [agentName, agent] of this._agents) {
      for (const groupName of agent.groups) {
        const group = this._groups.get(groupName);
        if (group && group.secrets.includes(secretPath)) {
          agents.push(agentName);
          break;
        }
      }
    }
    return agents;
  }

  /** Return all agents with their group memberships. */
  listAgents(): ManifestAgent[] {
    return Array.from(this._agents.values());
  }

  /** Return all group names. */
  listGroups(): string[] {
    return Array.from(this._groups.keys());
  }

  /**
   * Return all secret paths, optionally filtered by group.
   *
   * @param group - Optional group name to filter by.
   */
  listSecrets(group?: string): string[] {
    if (group !== undefined) {
      return this.groupSecrets(group);
    }
    const secrets: string[] = [];
    for (const g of this._groups.values()) {
      secrets.push(...g.secrets);
    }
    return secrets;
  }
}
