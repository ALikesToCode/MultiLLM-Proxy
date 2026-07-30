const PROTECTED_ROLES = new Set(["system", "developer"]);

function isMessage(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof value.role === "string" &&
      typeof value.content === "string",
  );
}

function directiveSignature(message) {
  return JSON.stringify([
    message.role,
    message.name ?? "",
    message.content,
  ]);
}

export function isProtectedDirective(message) {
  return (
    isMessage(message) &&
    PROTECTED_ROLES.has(message.role.toLowerCase())
  );
}

export function splitProtectedMessages(messages) {
  const directives = [];
  const dialogue = [];

  for (const message of Array.isArray(messages) ? messages : []) {
    if (!isMessage(message)) {
      continue;
    }
    if (isProtectedDirective(message)) {
      directives.push(message);
    } else {
      dialogue.push(message);
    }
  }
  return { directives, dialogue };
}

export function compactableDialogue(messages) {
  return splitProtectedMessages(messages).dialogue;
}

function storedDirectives(stateDirectives, legacyDirectives) {
  const persisted = splitProtectedMessages(stateDirectives).directives;
  const seen = new Set(persisted.map(directiveSignature));
  const migrated = [...persisted];

  for (const directive of legacyDirectives) {
    const signature = directiveSignature(directive);
    if (!seen.has(signature)) {
      migrated.push(directive);
      seen.add(signature);
    }
  }
  return migrated;
}

export function prepareProtectedContext(state, parsed, memoryEnabled) {
  const stored = splitProtectedMessages(state.messages);
  const incoming = splitProtectedMessages(parsed.messages);
  const retainedDirectives = storedDirectives(
    state.directives,
    stored.directives,
  );

  let activeDirectives = incoming.directives;
  if (memoryEnabled && parsed.historyMode === "append") {
    activeDirectives = [
      ...retainedDirectives,
      ...incoming.directives,
    ];
  } else if (
    memoryEnabled &&
    parsed.historyMode === "auto" &&
    incoming.directives.length === 0
  ) {
    activeDirectives = retainedDirectives;
  }

  return {
    activeDirectives,
    parsed: {
      ...parsed,
      messages: incoming.dialogue,
    },
    state: memoryEnabled
      ? {
          ...state,
          directives: activeDirectives,
          messages: stored.dialogue,
        }
      : state,
  };
}
