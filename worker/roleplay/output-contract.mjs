const IMAGE_PROMPT_MARKER = /^\s*IMAGE PROMPT:\s*$/gim;
const OOC_PREFIX = /^\s*(?:\[\s*)?\(?\s*ooc\b/i;
const EXPLICIT_IMAGE_SKIP =
  /\b(?:no[\s_-]+image|skip(?:\s+the)?\s+image\s+prompt|omit(?:\s+the)?\s+image\s+prompt|without(?:\s+an?|\s+the)?\s+image\s+prompt|do\s+not\s+include(?:\s+an?|\s+the)?\s+image\s+prompt|don['’]t\s+include(?:\s+an?|\s+the)?\s+image\s+prompt)\b/i;
const NON_STORY_REQUEST =
  /^\s*(?:please\s+)?(?:summar(?:y|ize)|planning|plan\b|prompt[\s_-]*edit|edit\s+(?:this|the)\s+prompt|q\s*&\s*a|question\b|utility\b|analysis\b|analy[sz]e\b|explain\b|compare\b|list\b|translate\b|rewrite\b|configure\b|how\b|why\b|what\s+(?:is|are|does|do|did|caused|causes)\b)/i;
const POSITIVE_CONTRACT_LANGUAGE =
  /\b(?:mandatory|required|must|non-negotiable|exactly\s+one|always\s+include|every\s+story\s+response|story\s+output\s+order)\b/i;
const NEGATED_CONTRACT_LANGUAGE =
  /(?:\b(?:omit|skip|without|do\s+not\s+include|don['’]t\s+include|no)\s+(?:an?\s+|the\s+)?image\s+prompt\b|\bimage\s+prompt\b.{0,32}\b(?:is\s+)?(?:optional|not\s+required|not\s+mandatory)\b)/i;
const CONTINUATION_META =
  /\b(?:the\s+(?:response\s+above|response|previous\s+response|preceding\s+response)\s+(?:was|is)\s+already(?:\s+fully)?(?:\s+emitted\s+and)?\s+complete|no\s+continuation\s+is\s+needed|the\s+next\s+story\s+turn\s+belongs\s+to)\b/i;

export const REQUIRED_IMAGE_PROMPT_FIELDS = Object.freeze([
  "camera",
  "primary_subject",
  "setting",
  "lighting",
  "composition",
]);

const CANONICAL_FIELD_LABELS = Object.freeze({
  camera: "Camera",
  primary_subject: "Primary subject",
  expression: "Expression",
  hair_grooming: "Hair and grooming",
  clothing: "Clothing",
  ear_styling: "Ear styling",
  accessories: "Accessories",
  pose: "Pose",
  setting: "Setting",
  secondary_subjects: "Secondary subjects",
  lighting: "Lighting",
  composition: "Composition",
  rendering: "Rendering",
  glamour_read: "Glamour read",
  mood: "Mood",
});

const FIELD_ALIASES = Object.freeze([
  ["Camera", ["camera"], "current"],
  ["Primary subject", ["primary_subject"], "current"],
  ["Expression", ["expression"], "current"],
  ["Hair and grooming", ["hair_grooming"], "current"],
  ["Clothing", ["clothing"], "current"],
  ["Ear styling", ["ear_styling"], "current"],
  ["Pose", ["pose"], "current"],
  ["Setting", ["setting"], "current"],
  ["Secondary subjects", ["secondary_subjects"], "current"],
  ["Composition", ["composition"], "current"],
  ["Rendering", ["rendering"], "current"],
  ["Background/setting", ["setting"], "legacy"],
  ["Main character focus", ["primary_subject"], "legacy"],
  ["Outfit", ["clothing"], "legacy"],
  ["Hair and makeup", ["hair_grooming"], "legacy"],
  ["Glamour read", ["glamour_read"], "legacy"],
  ["Pose and expression", ["pose", "expression"], "legacy"],
  ["Composition and camera", ["composition", "camera"], "legacy"],
  ["Mood", ["mood"], "legacy"],
  ["Accessories", ["accessories"], "shared"],
  ["Lighting", ["lighting"], "shared"],
]);

function normalizedLabel(value) {
  return String(value ?? "").trim().replace(/\s+/g, " ").toLowerCase();
}

const ALIAS_BY_LABEL = new Map(
  FIELD_ALIASES.map(([label, fields, schema]) => [
    normalizedLabel(label),
    Object.freeze({ fields: Object.freeze(fields), schema }),
  ]),
);

function messageContent(message) {
  return typeof message?.content === "string" ? message.content : "";
}

function latestUserContent(messages) {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index]?.role === "user") {
      return messageContent(messages[index]);
    }
  }
  return "";
}

function lineDeclaresMandatoryImagePrompt(line) {
  return (
    /\bimage\s+prompt\b/i.test(line) &&
    POSITIVE_CONTRACT_LANGUAGE.test(line) &&
    !NEGATED_CONTRACT_LANGUAGE.test(line)
  );
}

function declaresMandatoryImagePrompt(directives) {
  return directives.some((directive) =>
    messageContent(directive)
      .split(/\r?\n/)
      .some(lineDeclaresMandatoryImagePrompt),
  );
}

function schemaFromKinds(kinds) {
  const current = kinds.has("current");
  const legacy = kinds.has("legacy");
  if (current && legacy) {
    return "mixed";
  }
  if (current) {
    return "current";
  }
  if (legacy) {
    return "legacy";
  }
  return "unknown";
}

function declaredImagePromptSchema(directives) {
  const fields = new Set();
  const kinds = new Set();
  for (const directive of directives) {
    for (const line of messageContent(directive).split(/\r?\n/)) {
      const header = /^\s*([^:\n]{1,80})\s*:\s*/.exec(line);
      const alias = header
        ? ALIAS_BY_LABEL.get(normalizedLabel(header[1]))
        : null;
      if (!alias) {
        continue;
      }
      for (const field of alias.fields) {
        fields.add(field);
      }
      kinds.add(alias.schema);
    }
  }
  return { fields: [...fields], schema: schemaFromKinds(kinds) };
}

function turnSkipsImagePrompt(messages) {
  const latestUser = latestUserContent(messages).trim();
  return (
    EXPLICIT_IMAGE_SKIP.test(latestUser) ||
    OOC_PREFIX.test(latestUser) ||
    NON_STORY_REQUEST.test(latestUser)
  );
}

function imagePromptMarkers(content) {
  return [...String(content ?? "").matchAll(IMAGE_PROMPT_MARKER)];
}

function parsedImagePromptFields(block) {
  const populated = new Set();
  const kinds = new Set();
  let active = null;
  let value = [];

  const finishActive = () => {
    if (active && value.join("\n").trim()) {
      for (const field of active.fields) {
        populated.add(field);
      }
      kinds.add(active.schema);
    }
    active = null;
    value = [];
  };

  for (const line of String(block ?? "").split(/\r?\n/)) {
    const header = /^\s*([^:\n]{1,80})\s*:\s*(.*)$/.exec(line);
    if (header) {
      finishActive();
      active = ALIAS_BY_LABEL.get(normalizedLabel(header[1])) ?? null;
      value = active ? [header[2]] : [];
      continue;
    }
    if (active) {
      value.push(line);
    }
  }
  finishActive();

  return { fields: populated, schema: schemaFromKinds(kinds) };
}

export function analyzeRoleplayOutputContract(content, contract) {
  const value = typeof content === "string" ? content : "";
  const markers = imagePromptMarkers(value);
  const markerCount = markers.length;
  const marker = markers.at(-1);
  const block = marker
    ? value.slice((marker.index ?? 0) + marker[0].length)
    : "";
  const parsedFields = parsedImagePromptFields(block);
  const requiredFields = contract?.requiredFields?.length
    ? contract.requiredFields
    : REQUIRED_IMAGE_PROMPT_FIELDS;
  const missingFields = requiredFields.filter(
    (field) => !parsedFields.fields.has(field),
  );
  const metaAfterMarker = marker
    ? CONTINUATION_META.test(value.slice(marker.index ?? 0))
    : false;
  const blockFinal = Boolean(marker && block.trim() && !metaAfterMarker);
  const required = Boolean(contract?.imagePromptRequired);

  return {
    satisfied:
      !required ||
      (markerCount === 1 && blockFinal && missingFields.length === 0),
    required,
    missingFields,
    missingFieldLabels: missingFields.map(
      (field) => CANONICAL_FIELD_LABELS[field] ?? field,
    ),
    detectedFields: [...parsedFields.fields],
    schema: parsedFields.schema,
    markerCount,
    blockFinal,
  };
}

export function cleanRoleplayOutput(content, contract) {
  const original = typeof content === "string" ? content : "";
  let cleaned = original;
  const firstMarker = imagePromptMarkers(cleaned)[0];
  if (firstMarker) {
    const afterMarker = cleaned.slice(firstMarker.index ?? 0);
    const meta = CONTINUATION_META.exec(afterMarker);
    if (meta) {
      cleaned = cleaned
        .slice(0, (firstMarker.index ?? 0) + meta.index)
        .trimEnd();
    }
  }

  let markers = imagePromptMarkers(cleaned);
  if (contract?.imagePromptRequired && markers.length > 1) {
    const first = markers[0];
    const last = markers.at(-1);
    const story = cleaned.slice(0, first.index ?? 0).trimEnd();
    const finalBlock = cleaned.slice(last.index ?? 0).trimStart();
    cleaned = story ? `${story}\n\n${finalBlock}` : finalBlock;
    markers = imagePromptMarkers(cleaned);
  }

  return {
    content: cleaned,
    changed: cleaned !== original,
    removedCharacters: Math.max(0, original.length - cleaned.length),
    markerCountBefore: imagePromptMarkers(original).length,
    markerCountAfter: markers.length,
  };
}

export function applyRoleplayOutputContract(parsed, directives, settings) {
  const imagePromptDeclared = declaresMandatoryImagePrompt(directives);
  const imagePromptRequired =
    imagePromptDeclared && !turnSkipsImagePrompt(parsed.messages);
  const declared = declaredImagePromptSchema(directives);
  const minimumOutputTokens = settings.imagePromptMinOutputTokens;
  const budgetAdjusted =
    imagePromptRequired &&
    parsed.maxTokens !== null &&
    parsed.maxTokens < minimumOutputTokens;

  return {
    ...parsed,
    maxTokens: budgetAdjusted ? minimumOutputTokens : parsed.maxTokens,
    outputContract: {
      imagePromptDeclared,
      imagePromptRequired,
      imagePromptFields: declared.fields,
      requiredFields: REQUIRED_IMAGE_PROMPT_FIELDS,
      schema: declared.schema,
      budgetAdjusted,
    },
  };
}

export function roleplayOutputContractSatisfied(content, contract) {
  return analyzeRoleplayOutputContract(content, contract).satisfied;
}

function renderRoleplayOutputContractReminder(contract) {
  if (!contract?.imagePromptRequired) {
    return "";
  }
  return [
    "[Caller-required final output contract]",
    "For this story response, reserve enough output budget to finish exactly one complete IMAGE PROMPT: block at the end.",
    "Required canonical fields: Camera, Primary subject, Setting, Lighting, and Composition. Legacy aliases and combined Camera/Composition labels remain accepted.",
    "Optional fields depend on what is visible. Never restart a completed story or add a second IMAGE PROMPT block.",
    "Honor every exception in the caller's protected directives, including explicit no-image and non-story/OOC replies. Never discuss this reminder in the response.",
  ].join("\n");
}

export function reinforceRoleplayMessages(messages, contract) {
  const reminder = renderRoleplayOutputContractReminder(contract);
  if (!reminder) {
    return messages;
  }

  let insertionIndex = messages.length;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index]?.role === "user") {
      insertionIndex = index;
      break;
    }
  }
  return [
    ...messages.slice(0, insertionIndex),
    { role: "system", content: reminder },
    ...messages.slice(insertionIndex),
  ];
}
