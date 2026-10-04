/**
 * Secret metadata parsing.
 */

import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import { MetadataError } from "./errors.js";

/** Plaintext metadata for a single secret. */
export interface SecretMetadata {
  name: string;
  group: string;
  createdAt: Date;
  rotatedAt: Date;
  expiresAt?: Date;
  authorizedAgents: string[];
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/** Parse a strict RFC 3339 timestamp without YAML implicit Date coercion. */
function parseDate(value: unknown, field: string): Date {
  if (typeof value !== "string") {
    throw new MetadataError(`invalid metadata: ${field} must be an RFC 3339 timestamp with a timezone`);
  }
  const match = RFC3339.exec(value);
  if (!match) {
    throw new MetadataError(`invalid metadata: ${field} must be an RFC 3339 timestamp with a timezone`);
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const isLeapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, isLeapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1] ||
    hour > 23 || minute > 59 || second > 59
  ) {
    throw new MetadataError(`invalid metadata: ${field} is not a real RFC 3339 timestamp`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new MetadataError(`invalid metadata: ${field} is not a real RFC 3339 timestamp`);
  }
  return parsed;
}

/** Parse a .meta YAML file into a complete SecretMetadata record. */
export function parseMetadataFile(filePath: string): SecretMetadata {
  try {
    return parseMetadata(readFileSync(filePath, "utf-8"));
  } catch (error) {
    if (error instanceof MetadataError) throw error;
    throw new MetadataError(`invalid metadata file ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Parse metadata from a YAML string. */
export function parseMetadata(content: string): SecretMetadata {
  try {
    // JSON_SCHEMA leaves date-like scalars as strings, matching Python's BaseLoader.
    const data = yaml.load(content, { schema: yaml.JSON_SCHEMA });
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new MetadataError("invalid metadata: expected a mapping");
    }
    const values = data as Record<string, unknown>;
    if (typeof values.name !== "string" || typeof values.group !== "string") {
      throw new MetadataError("invalid metadata: name and group must be strings");
    }
    if (!Array.isArray(values.authorized_agents) || !values.authorized_agents.every((agent) => typeof agent === "string")) {
      throw new MetadataError("invalid metadata: authorized_agents must be a list of strings");
    }
    return {
      name: values.name,
      group: values.group,
      createdAt: parseDate(values.created, "created"),
      rotatedAt: parseDate(values.rotated, "rotated"),
      expiresAt: values.expires === undefined || values.expires === null
        ? undefined
        : parseDate(values.expires, "expires"),
      authorizedAgents: values.authorized_agents,
    };
  } catch (error) {
    if (error instanceof MetadataError) throw error;
    throw new MetadataError(`invalid metadata: ${error instanceof Error ? error.message : String(error)}`);
  }
}
