import assert from "node:assert/strict";
import test from "node:test";
import { createArtifact, dropForeignProviderSections, site } from "../worker/knowledge/evidence.mjs";
import { parseProductSites } from "../worker/knowledge/product-sites.mjs";
import { filterProviderSites } from "../worker/knowledge/provider-site-filter.mjs";
import { fixture } from "./knowledge_fixture.mjs";

const ask = { product: "flask", query: "Which hook events add context?" };
const section = url => ({ kind: "derived_context", provider: "mintlify",
  text: `Wallets.\nSource: ${url}\n--------------------------------` });

test("site approximation isolates each supported tenant and two-label public suffix", () => {
  for (const suffix of ["github.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
    "readthedocs.io", "gitbook.io", "mintlify.app", "co.uk", "com.au", "co.jp"]) {
    assert.equal(site(`https://docs.first.${suffix}/guide`), `first.${suffix}`);
    assert.notEqual(site(`https://first.${suffix}/guide`), site(`https://second.${suffix}/guide`));
    assert.equal(site(`https://${suffix}/`), suffix);
  }
  assert.equal(site("https://www.docs.openai.com/guide"), "openai.com");
  assert.equal(site("not a URL"), null);
});

test("code-host sites are scoped to owners and raw GitHub content uses the same owner", () => {
  for (const host of ["github.com", "gitlab.com", "bitbucket.org"]) {
    assert.equal(site(`https://${host}/Pallets/project/tree/main/docs`), `${host}/pallets`);
    assert.notEqual(site(`https://${host}/pallets/first`), site(`https://${host}/unrelated/second`));
    assert.equal(site(`https://${host}/`), host);
  }
  assert.equal(site("https://raw.githubusercontent.com/Pallets/flask/main/docs.rst"), "github.com/pallets");
  assert.equal(site("https://www.github.com/pallets/flask"), "github.com/pallets");
  assert.equal(site("https://github.com/bad%20owner/project"), null);
});

test("management accepts scoped sites and rejects arbitrary paths, uppercase owners and unsafe hosts", () => {
  const input = { product: "Flask", pin: ["github.com/pallets", "raw.githubusercontent.com/pallets",
    "gitlab.com/team.docs", "bitbucket.org/team_name", "docs.first.github.io", "docs.example.co.uk"] };
  assert.deepEqual(parseProductSites(input, true).pin,
    ["github.com/pallets", "gitlab.com/team.docs", "bitbucket.org/team_name", "first.github.io", "example.co.uk"]);
  for (const host of ["github.com/Pallets", "github.com/", "github.com/pallets/repo", "github.com//pallets",
    "github.com/%70allets", "github.com/.hidden", "github.com/" + "x".repeat(101),
    "example.org/pallets", "localhost/pallets", "gitlab.com/team?key=value", "gitlab.com/team#fragment",
    "user@github.com/pallets", "github.com:443/pallets", "https://github.com/pallets"]) {
    assert.throws(() => parseProductSites({ product: "flask", block: [host] }, true), { code: "invalid_request" });
  }
  assert.throws(() => parseProductSites({ product: "flask", pin: ["github.com/pallets"],
    unpin: ["raw.githubusercontent.com/pallets"] }, true), { code: "invalid_request" });
});

test("learning, pins, blocks and enforce decisions use identical tenant and owner boundaries", async () => {
  const f = await fixture();
  for (const url of ["https://first.github.io/docs", "https://raw.githubusercontent.com/pallets/flask/main/docs.rst"]) {
    const artifact = await createArtifact({ ...f.source, url }, f.text, "exa");
    await f.storage.put(`artifact:${artifact.id}`, { ...artifact, status: "live" });
    await f.authority.call("product_sites.learn", { id: artifact.id });
  }
  const registry = await f.authority.call("product_sites.update", { product: "flask", pin: ["gitlab.com/pallets"],
    block: ["bitbucket.org/unrelated"] });
  assert.equal(registry.sites["first.github.io"].verified, 1);
  assert.equal(registry.sites["github.com/pallets"].verified, 1);
  for (const url of ["https://first.github.io/docs", "https://github.com/pallets/flask/blob/main/docs",
    "https://raw.githubusercontent.com/pallets/flask/main/docs.rst", "https://gitlab.com/pallets/project/docs"]) {
    assert.equal(filterProviderSites([section(url)], ask, [], registry, "enforce").items.length, 1);
  }
  for (const url of ["https://second.github.io/docs", "https://github.com/unrelated/repo/docs",
    "https://gitlab.com/unrelated/project/docs"]) {
    const result = filterProviderSites([section(url)], ask, [], registry, "enforce");
    assert.equal(result.items.length, 0);
    assert.equal(result.flagged[0].reason, "unverified_site");
  }
  const url = "https://bitbucket.org/unrelated/project/docs";
  const result = filterProviderSites([section(url)], ask, [url], registry, "enforce");
  assert.equal(result.items.length, 0);
  assert.equal(result.flagged[0].reason, "blocked");
  assert.equal(filterProviderSites([section("https://bitbucket.org/pallets/project/docs")], ask,
    ["https://bitbucket.org/pallets/other"], registry, "enforce").items.length, 1);
});

test("legacy filtering and provider-documentation evidence never trust another tenant or owner", () => {
  for (const [trusted, foreign] of [["https://first.github.io/docs", "https://second.github.io/docs"],
    ["https://github.com/pallets/flask", "https://github.com/unrelated/project"],
    ["https://gitlab.com/pallets/flask", "https://gitlab.com/unrelated/project"],
    ["https://bitbucket.org/pallets/flask", "https://bitbucket.org/unrelated/project"]]) {
    assert.equal(dropForeignProviderSections([section(foreign)], ask, [trusted]).items.length, 0);
    const documented = { kind: "provider_documentation", provider: "context7", text: `Source: ${trusted}` };
    assert.deepEqual(dropForeignProviderSections([section(foreign), documented], ask, []).items, [documented]);
    assert.equal(dropForeignProviderSections([section(trusted)], ask, [trusted]).items.length, 1);
  }
  const raw = "https://raw.githubusercontent.com/pallets/flask/main/docs.rst";
  assert.equal(dropForeignProviderSections([section(raw)], ask, ["https://github.com/pallets/flask"]).items.length, 1);
});
