const IMAGE_PROMPT_MARKER = /^\s*IMAGE PROMPT:\s*$/im;
const MANDATORY_LANGUAGE =
  /\b(?:mandatory|required|non-negotiable|must|contract violation)\b/i;
const NO_IMAGE_COMMAND = /\bno[\s_-]+image\b/i;
const OOC_PREFIX = /^\s*(?:\[\s*)?\(?\s*ooc\b/i;

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
      budgetAdjusted,
    },
  };
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
