import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeRoleplayOutputContract,
  applyRoleplayOutputContract,
  cleanRoleplayOutput,
} from "../worker/roleplay/output-contract.mjs";

const SETTINGS = { imagePromptMinOutputTokens: 2_048 };
const REQUIRED_CONTRACT = {
  imagePromptRequired: true,
  requiredFields: [
    "camera",
    "primary_subject",
    "setting",
    "lighting",
    "composition",
  ],
};

const CURRENT_DIRECTIVE = {
  role: "system",
  content: [
    "Story output order: story, exactly one IMAGE PROMPT, then end.",
    "IMAGE PROMPT:",
    "Camera:",
    "Primary subject:",
    "Expression:",
    "Hair and grooming:",
    "Clothing:",
    "Ear styling:",
    "Accessories:",
    "Pose:",
    "Setting:",
    "Lighting:",
    "Composition:",
    "Rendering:",
  ].join("\n"),
};

function contractFor(user, directive = CURRENT_DIRECTIVE) {
  return applyRoleplayOutputContract(
    {
      messages: [{ role: "user", content: user }],
      maxTokens: 512,
    },
    [directive],
    SETTINGS,
  ).outputContract;
}

function output(lines) {
  return ["*Story beat.*", "", "IMAGE PROMPT:", ...lines].join("\n");
}

test("current schema accepts required fields with optional fields omitted", () => {
  const analysis = analyzeRoleplayOutputContract(
    output([
      "Camera:",
      "First-person medium shot.",
      "Primary subject: young adult woman with dark hair.",
      "Setting: old library.",
      "Lighting: warm sunset.",
      "Composition: subject centered beyond a desk.",
    ]),
    REQUIRED_CONTRACT,
  );

  assert.equal(analysis.satisfied, true);
  assert.equal(analysis.schema, "current");
  assert.deepEqual(analysis.missingFields, []);
  assert.equal(analysis.markerCount, 1);
  assert.equal(analysis.blockFinal, true);
});

test("legacy schema maps combined and renamed canonical fields", () => {
  const analysis = analyzeRoleplayOutputContract(
    output([
      "Background/setting: old library.",
      "Main character focus: young adult woman with dark hair.",
      "Lighting: warm sunset.",
      "Composition and camera: first-person medium shot, subject centered.",
    ]),
    REQUIRED_CONTRACT,
  );

  assert.equal(analysis.satisfied, true);
  assert.equal(analysis.schema, "legacy");
  assert.deepEqual(analysis.missingFields, []);
});

test("mixed current and legacy aliases satisfy one canonical contract", () => {
  const analysis = analyzeRoleplayOutputContract(
    output([
      "Camera: first-person medium shot.",
      "Main character focus: young adult woman with dark hair.",
      "Background/setting: old library.",
      "Lighting: warm sunset.",
      "Composition: subject centered beyond a desk.",
    ]),
    REQUIRED_CONTRACT,
  );

  assert.equal(analysis.satisfied, true);
  assert.equal(analysis.schema, "mixed");
});

test("unknown schema cannot pass through an empty required-field set", () => {
  const analysis = analyzeRoleplayOutputContract(
    output(["Creative direction: polished classroom still."]),
    REQUIRED_CONTRACT,
  );

  assert.equal(analysis.satisfied, false);
  assert.deepEqual(analysis.missingFields, [
    "camera",
    "primary_subject",
    "setting",
    "lighting",
    "composition",
  ]);
});

test("multiple image markers are rejected and defensive cleanup leaves one", () => {
  const duplicated = [
    output([
      "Camera: first-person shot.",
      "Primary subject: young adult woman.",
      "Setting: library.",
      "Lighting: sunset.",
      "Composition: centered subject.",
    ]),
    "*Repeated story turn.*",
    output([
      "Camera: first-person shot.",
      "Primary subject: young adult woman.",
      "Setting: hallway.",
      "Lighting: fluorescent panels.",
      "Composition: receding corridor.",
    ]),
  ].join("\n");

  assert.equal(
    analyzeRoleplayOutputContract(duplicated, REQUIRED_CONTRACT).satisfied,
    false,
  );
  const cleaned = cleanRoleplayOutput(duplicated, REQUIRED_CONTRACT);
  assert.equal(cleaned.markerCountBefore, 2);
  assert.equal(cleaned.markerCountAfter, 1);
  assert.equal(
    analyzeRoleplayOutputContract(cleaned.content, REQUIRED_CONTRACT).satisfied,
    true,
  );
});

test("activation is sentence-scoped and ignores a negated requirement", () => {
  const negated = {
    role: "system",
    content: [
      "Detailed prose is mandatory.",
      "IMAGE PROMPT is optional and not required.",
      "IMAGE PROMPT:",
    ].join("\n"),
  };

  assert.equal(contractFor("Continue.", negated).imagePromptDeclared, false);
  assert.equal(contractFor("Continue.").imagePromptRequired, true);
});

test("non-story and explicit skip turns bypass image contract repair", () => {
  const requests = [
    "No image this turn.",
    "Skip the image prompt and continue.",
    "OOC: explain the last reply.",
    "Summary of the conversation.",
    "Planning for the next arc.",
    "Question: which model handled this?",
    "Utility: count the characters.",
    "Analyze the prose structure.",
    "Why is the proxy retrying?",
  ];

  for (const request of requests) {
    assert.equal(
      contractFor(request).imagePromptRequired,
      false,
      request,
    );
  }
});

test("continuation meta after a complete block makes the block non-final", () => {
  const content = `${output([
    "Camera: first-person shot.",
    "Primary subject: young adult woman.",
    "Setting: library.",
    "Lighting: sunset.",
    "Composition: centered subject.",
  ])}The response above was already complete. No continuation is needed.`;

  const analysis = analyzeRoleplayOutputContract(content, REQUIRED_CONTRACT);
  assert.equal(analysis.satisfied, false);
  assert.equal(analysis.blockFinal, false);
  assert.doesNotMatch(
    cleanRoleplayOutput(content, REQUIRED_CONTRACT).content,
    /already complete|No continuation/i,
  );
});
