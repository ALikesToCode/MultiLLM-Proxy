/** Resolve explicit deployment targets before any remote command. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function deploymentTarget({ database, mainConfig = "wrangler.jsonc", knowledgeConfig = "wrangler.knowledge.jsonc",
  env = process.env, read = path => JSON.parse(readFileSync(path, "utf8")) } = {}) {
  mainConfig = resolve(mainConfig); knowledgeConfig = resolve(knowledgeConfig);
  const main = read(mainConfig), knowledge = read(knowledgeConfig);
  database ||= env.D1_DATABASE;
  if (!database) throw Error("Select D1 explicitly with --database or D1_DATABASE; no default database is used");
  const binding = config => config.d1_databases?.find(item => item.binding === "INTELLIGENCE_DB");
  const first = binding(main), second = binding(knowledge);
  if (!first?.database_id || first.database_name !== database || second?.database_name !== database
      || first.database_id !== second.database_id) throw Error("Selected D1 must match INTELLIGENCE_DB in both configurations");
  if (!main.name || !knowledge.name) throw Error("Both Worker names must be configured");
  return { database, main, knowledge, mainConfig, knowledgeConfig,
    origin: env.DEPLOY_STATUS_URL || main.vars?.WORKBENCH_WORKER_URL,
    workers: {
      main: { label: "Main Worker", name: main.name, config: mainConfig, fingerprinted: true },
      knowledge: { label: "Knowledge Worker", name: knowledge.name, config: knowledgeConfig, fingerprinted: false },
    } };
}
