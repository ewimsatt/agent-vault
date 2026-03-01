/**
 * Secret metadata parsing.
 */

import { readFileSync } from "node:fs";
import yaml from "js-yaml";

/** Plaintext metadata for a single secret. */
export interface SecretMetadata {
  /** Secret name identifier. */
  name: string;
  /** Group this secret belongs to. */
  group: string;
  /** When the secret was first created. */
  createdAt: Date;
  /** When the secret was last rotated. */
  rotatedAt: Date;
  /** Optional expiration date. */
  expiresAt?: Date;
  /** List of agent names authorized to access this secret. */
  authorizedAgents: string[];
}

/**
 * Parse a datetime value from YAML, which may be a Date object or ISO string.
 */
function parseDate(val: unknown): Date {
  if (val instanceof Date) {
    return val;
  }
  if (typeof val === "string") {
    const d = new Date(val);
    if (!isNaN(d.getTime())) {
      return d;
    }
  }
  return new Date(0);
}

/**
 * Parse a .meta YAML file into a SecretMetadata object.
 *
 * @param filePath - Absolute path to the .meta file.
 * @returns Parsed SecretMetadata.
 */
export function parseMetadataFile(filePath: string): SecretMetadata {
  const content = readFileSync(filePath, "utf-8");
  return parseMetadata(content);
}

/**
 * Parse metadata from a YAML string.
 *
 * @param content - YAML string content.
 * @returns Parsed SecretMetadata.
 */
export function parseMetadata(content: string): SecretMetadata {
  const data = (yaml.load(content) as Record<string, unknown>) ?? {};

  return {
    name: typeof data.name === "string" ? data.name : "",
    group: typeof data.group === "string" ? data.group : "",
    createdAt: parseDate(data.created),
    rotatedAt: parseDate(data.rotated),
    expiresAt: data.expires ? parseDate(data.expires) : undefined,
    authorizedAgents: Array.isArray(data.authorized_agents)
      ? (data.authorized_agents as string[])
      : [],
  };
}
