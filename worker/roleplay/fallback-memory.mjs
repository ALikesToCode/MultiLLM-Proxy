import { compactableDialogue } from "./directives.mjs";

const MEMORY_FIELDS = [
  "character_facts",
  "relationships",
  "world_state",
  "open_threads",
  "tone_style",
];
const MAX_ARCHIVED_MESSAGES = 16;
const MAX_FIELD_ITEMS = 8;
const MAX_FIELD_CHARACTERS = 240;
const MAX_SUMMARY_CHARACTERS = 4_000;

function normalizedText(value) {
  return typeof value === "string"
    ? value.replace(/\s+/g, " ").trim()
    : "";
}

function middleExcerpt(value, maximumCharacters) {
  const normalized = normalizedText(value);
  if (normalized.length <= maximumCharacters) {
    return normalized;
  }
  if (maximumCharacters < 12) {
    return normalized.slice(0, maximumCharacters);
  }
  const marker = " … ";
  const available = maximumCharacters - marker.length;
  const leading = Math.ceil(available * 0.6);
  const trailing = available - leading;
  return `${normalized.slice(0, leading)}${marker}${normalized.slice(
    -trailing,
  )}`;
}

function selectedMessageIndexes(messages) {
  const selected = new Set();
  if (messages.length) {
    selected.add(0);
  }

  for (
    let index = messages.length - 1;
    index >= 0 && selected.size < MAX_ARCHIVED_MESSAGES;
    index -= 1
  ) {
    selected.add(index);
  }
  return [...selected].sort((left, right) => left - right);
}

function messageLabel(message) {
  const role =
    typeof message?.role === "string" && message.role
      ? message.role
      : "unknown";
  const name =
    typeof message?.name === "string" && message.name
      ? `:${message.name}`
      : "";
  return `[${role}${name}]`;
}

function renderArchivedDialogue(messages, characterBudget) {
  const indexes = selectedMessageIndexes(messages);
  if (!indexes.length || characterBudget < 80) {
    return "";
  }

  const labels = indexes.map((index) => messageLabel(messages[index]));
  const structuralCharacters =
    labels.reduce((total, label) => total + label.length + 2, 0) +
    Math.max(0, indexes.length - 1);
  const contentBudget = Math.max(
    24,
    Math.floor(
      (characterBudget - structuralCharacters) / indexes.length,
    ),
  );
  const lines = indexes.map(
    (index, position) =>
      `${labels[position]} ${middleExcerpt(
        messages[index]?.content,
        contentBudget,
      )}`,
  );
  return lines.join("\n").slice(0, characterBudget);
}

function boundedMemoryFields(memory) {
  return Object.fromEntries(
    MEMORY_FIELDS.map((field) => [
      field,
      Array.isArray(memory?.[field])
        ? memory[field]
            .filter((item) => typeof item === "string")
            .map((item) =>
              normalizedText(item).slice(0, MAX_FIELD_CHARACTERS),
            )
            .filter(Boolean)
            .slice(0, MAX_FIELD_ITEMS)
        : [],
    ]),
  );
}

export function createExtractiveCompactionDigest(state, plan, settings) {
  const archivedDialogue = compactableDialogue(plan.olderMessages);
  const summaryLimit = Math.min(
    MAX_SUMMARY_CHARACTERS,
    Math.max(
      1_000,
      Math.floor((settings.memoryTargetTokens ?? 500) * 4),
    ),
  );
  const priorSummary = normalizedText(state.memory?.summary);
  const priorBudget = priorSummary
    ? Math.min(1_200, Math.floor(summaryLimit * 0.35))
    : 0;
  const prior = middleExcerpt(priorSummary, priorBudget);
  const priorSection = prior ? `[Prior continuity]\n${prior}\n\n` : "";
  const archiveHeader =
    `[Archived dialogue excerpts from ${archivedDialogue.length} prior ` +
    "messages; some messages or text may be omitted]\n";
  const archiveBudget = Math.max(
    0,
    summaryLimit - priorSection.length - archiveHeader.length,
  );
  const archived = renderArchivedDialogue(
    archivedDialogue,
    archiveBudget,
  );

  return {
    compact: true,
    summary: `${priorSection}${archiveHeader}${archived}`.slice(
      0,
      summaryLimit,
    ),
    ...boundedMemoryFields(state.memory),
  };
}
