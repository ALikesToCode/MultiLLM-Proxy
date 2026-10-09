-- Existing public contracts keep their explicit scope grants; unknown tools are denied.
CREATE TABLE IF NOT EXISTS tool_grants (
  principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 128),
  tool_name TEXT NOT NULL CHECK(length(tool_name) BETWEEN 1 AND 128),
  scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json) AND json_type(scopes_json) = 'array' AND json_array_length(scopes_json) > 0),
  allowed INTEGER NOT NULL CHECK(allowed IN (0, 1)),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),
  PRIMARY KEY (principal_id, tool_name)
);
CREATE INDEX IF NOT EXISTS tool_grants_tool ON tool_grants(tool_name, principal_id);

-- Principal rows override these compatibility grants, including explicit denials.
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'chat', '["chat"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'create_video', '["chat"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'generate_image', '["chat"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'generate_images_batch', '["chat"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'get_video', '["chat"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_alexandria_execute', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_alexandria_inspect', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_alexandria_receipt', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_alexandria_search', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_artifact', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_context', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_context7_docs', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_context7_resolve_library', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_deepwiki_ask', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_deepwiki_contents', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_deepwiki_structure', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_exa_answer', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_exa_code_context', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_exa_contents', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_exa_search', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_crawl', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_crawl_status', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_extract', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_extract_status', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_map', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_scrape', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_firecrawl_search', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_handoff_delete', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_handoff_get', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_handoff_list', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_handoff_save', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_job_cancel', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_memos_purge', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_memos_stats', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_mintlify_context', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_policy_update', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_product_sites_get', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_product_sites_update', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_search', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_discover', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_find', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_get', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_import', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_preview', '["knowledge:read"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_report', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_skills_sync', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_source_refresh', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_source_register', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_source_update', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'knowledge_status', '["knowledge:manage"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'list_models', '["models"]', 1, 0);
INSERT OR IGNORE INTO tool_grants (principal_id, tool_name, scopes_json, allowed, revision) VALUES ('*', 'media_providers', '["chat"]', 1, 0);
