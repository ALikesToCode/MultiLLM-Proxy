const IMAGE_PROMPT_MARKER = /^\s*IMAGE PROMPT:\s*$/im;
const MANDATORY_LANGUAGE =
  /\b(?:mandatory|required|non-negotiable|must|contract violation)\b/i;
const NO_IMAGE_COMMAND = /\bno[\s_-]+image\b/i;
const OOC_PREFIX = /^\s*(?:\[\s*)?\(?\s*ooc\b/i;
const STANDARD_IMAGE_PROMPT_FIELDS = Object.freeze([
  "Background/setting",
  "Main character focus",
  "Outfit",
  "Accessories",
  "Hair and makeup",
  "Glamour read",
  "Pose and expression",
  "Lighting",
  "Composition and camera",
  "Mood",
]);

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

function declaresMandatoryImagePrompt(directives) {
  return directives.some((directive) => {
    const content = messageContent(directive);
    return (
      IMAGE_PROMPT_MARKER.test(content) &&
      MANDATORY_LANGUAGE.test(content)
    );
  });
}

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function declaredImagePromptFields(directives) {
  return STANDARD_IMAGE_PROMPT_FIELDS.filter((field) => {
    const pattern = new RegExp(
      `^\\s*${escapeRegularExpression(field)}\\s*:`,
      "im",
    );
    return directives.some((directive) =>
      pattern.test(messageContent(directive)),
    );
  });
}

function turnSkipsImagePrompt(messages) {
  const latestUser = latestUserContent(messages);
  return (
    NO_IMAGE_COMMAND.test(latestUser) ||
    OOC_PREFIX.test(latestUser)
  );
}

export function applyRoleplayOutputContract(
  parsed,
  directives,
  settings,
) {
  const imagePromptDeclared = declaresMandatoryImagePrompt(directives);
  const imagePromptRequired =
    imagePromptDeclared && !turnSkipsImagePrompt(parsed.messages);
  const imagePromptFields = imagePromptDeclared
    ? declaredImagePromptFields(directives)
    : [];
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
      imagePromptFields,
      budgetAdjusted,
    },
  };
}

export function roleplayOutputContractSatisfied(content, contract) {
  if (!contract?.imagePromptRequired) {
    return true;
  }
  if (typeof content !== "string" || !content.trim()) {
    return false;
  }
  const matches = [...content.matchAll(new RegExp(IMAGE_PROMPT_MARKER, "gim"))];
  const marker = matches.at(-1);
  if (!marker) {
    return false;
  }
  const imagePrompt = content.slice(
    (marker.index ?? 0) + marker[0].length,
  );
  if (!imagePrompt.trim()) {
    return false;
  }
  return (contract.imagePromptFields ?? []).every((field) => {
    const pattern = new RegExp(
      `^\\s*${escapeRegularExpression(field)}\\s*:\\s*\\S`,
      "im",
    );
    return pattern.test(imagePrompt);
  });
}

function renderRoleplayOutputContractReminder(contract) {
  if (!contract?.imagePromptRequired) {
    return "";
  }
  return [
    "[Caller-required final output contract]",
    "For this story response, reserve enough output budget to finish exactly one complete IMAGE PROMPT: block at the end.",
    "Follow the caller's exact image-prompt field order and content rules. The response is incomplete until the final field of that block is finished.",
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
