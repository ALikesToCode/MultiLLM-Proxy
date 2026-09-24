const MAX_SNAPSHOT_BYTES = 256 * 1024;
const MAX_INDEX_RESULTS = 20;
const INDEX_PAGE_SIZE = 50;
const MAX_RECONCILE_PAGES = 10;
const MAX_CHUNK_PAGES = 11;
const ITEM_STATES = new Set(["completed", "error", "skipped", "queued", "running", "outdated"]);
const encoder = new TextEncoder();

export class CorpusError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CorpusError";
    this.code = code;
  }
}

function invalid(code = "invalid_snapshot") {
  return new CorpusError(code, "The knowledge corpus returned invalid or unavailable evidence.");
}

function validKey(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 1024
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateArtifact(artifact) {
  if (!artifact || !validKey(artifact.snapshot_key) || !validKey(artifact.index_key)
    || typeof artifact.content_hash !== "string" || !/^[a-f0-9]{64}$/.test(artifact.content_hash)
    || !Number.isSafeInteger(artifact.byte_length) || artifact.byte_length < 1
    || artifact.byte_length > MAX_SNAPSHOT_BYTES) throw invalid();
}

function assertRemovable(artifact) {
  validateArtifact(artifact);
  if (!/^[a-f0-9]{64}$/.test(artifact.id ?? "")
    || artifact.snapshot_key !== `snapshots/${artifact.id}.txt`
    || artifact.index_key !== `revisions/${artifact.id}.txt`
    || artifact.item_id && !/^[A-Za-z0-9_-]{1,128}$/.test(artifact.item_id)) throw invalid("invalid_artifact_removal");
}

async function hash(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("");
}

async function checkedBytes(artifact, text) {
  validateArtifact(artifact);
  if (typeof text !== "string") throw invalid();
  const bytes = encoder.encode(text);
  if (bytes.byteLength !== artifact.byte_length || await hash(bytes) !== artifact.content_hash) throw invalid();
  return bytes;
}

async function readBounded(object) {
  if (!object.body || !Number.isSafeInteger(object.size) || object.size < 0 || object.size > MAX_SNAPSHOT_BYTES) {
    throw invalid("snapshot_too_large");
  }
  const reader = object.body.getReader();
  const parts = [];
  let size = 0;
  let ended = false;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) { ended = true; break; }
      size += chunk.value.byteLength;
      if (size > MAX_SNAPSHOT_BYTES) throw invalid("snapshot_too_large");
      parts.push(chunk.value);
    }
  } finally {
    if (!ended) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw invalid(); }
}

function itemReference(value, key) {
  if (!value || typeof value.id !== "string" || !value.id || value.key !== key) throw invalid("invalid_index_response");
  return value;
}

function itemInfo(value, key) {
  itemReference(value, key);
  if (!ITEM_STATES.has(value.status)) throw invalid("invalid_index_response");
  return value;
}

async function readIndex(callback) {
  for (let attempt = 0; ; attempt += 1) {
    try { return await callback(); }
    catch (error) {
      // The binding intermittently rejects its own account context before a metadata read.
      // Uploads, deletions and billable search requests never use this retry path.
      if (attempt >= 2 || error?.message !== "Invalid ctx.props: missing accountId or accountTag") throw error;
    }
  }
}

function chunkMatches(chunk, bytes) {
  if (!chunk || typeof chunk.text !== "string" || !chunk.text
    || !Number.isSafeInteger(chunk.start_byte) || !Number.isSafeInteger(chunk.end_byte)
    || chunk.start_byte < 0 || chunk.end_byte <= chunk.start_byte
    || chunk.end_byte > bytes.byteLength) return false;
  const textBytes = encoder.encode(chunk.text);
  if (textBytes.byteLength !== chunk.end_byte - chunk.start_byte) return false;
  return textBytes.every((byte, index) => byte === bytes[chunk.start_byte + index]);
}

function legacySearchChunks(response) {
  if (!response || !Array.isArray(response.data) || response.data.length > MAX_INDEX_RESULTS) {
    throw invalid("invalid_index_response");
  }
  const chunks = [];
  for (const item of response.data) {
    if (!item || !validKey(item.filename) || !Number.isFinite(item.score)
      || !Array.isArray(item.content) || !item.content.length
      || chunks.length + item.content.length > MAX_INDEX_RESULTS) throw invalid("invalid_index_response");
    for (const content of item.content) {
      if (content?.type !== "text") throw invalid("invalid_index_response");
      chunks.push({ text: content.text, score: content.score ?? item.score, item: { key: item.filename } });
    }
  }
  return { chunks };
}

/** Immutable evidence storage and the managed index's provider-specific contract. */
export class KnowledgeCorpus {
  constructor(env) {
    this.bucket = env.KNOWLEDGE_SNAPSHOTS;
    this.index = env.KNOWLEDGE_INDEX;
    this.searchAI = env.KNOWLEDGE_SEARCH_AI;
    this.searchInstance = env.KNOWLEDGE_SEARCH_INSTANCE;
  }

  requireBucket() {
    if (!this.bucket?.get || !this.bucket?.put) throw invalid("snapshot_storage_unavailable");
    return this.bucket;
  }

  requireIndex() {
    if (!this.index?.items || !this.index?.search) throw invalid("index_unavailable");
    return this.index;
  }

  async putSnapshot(artifact, text) {
    const bytes = await checkedBytes(artifact, text);
    const bucket = this.requireBucket();
    const result = await bucket.put(artifact.snapshot_key, bytes, {
      onlyIf: { etagDoesNotMatch: "*" },
      sha256: artifact.content_hash,
      httpMetadata: { contentType: "text/plain; charset=utf-8" },
      customMetadata: { content_hash: artifact.content_hash },
    });
    if (result === null && await this.getSnapshot(artifact) !== text) throw invalid("snapshot_conflict");
    return { key: artifact.snapshot_key, created: result !== null };
  }

  /** Remove bytes a write created for a revision that lost retention permission meanwhile. */
  async discardSnapshot(artifact) {
    assertRemovable(artifact);
    await this.requireBucket().delete(artifact.snapshot_key);
  }

  async getSnapshot(artifact) {
    validateArtifact(artifact);
    const object = await this.requireBucket().get(artifact.snapshot_key);
    if (object === null) return null;
    const text = await readBounded(object);
    await checkedBytes(artifact, text);
    return text;
  }

  async search(request) {
    if (!request || typeof request.query !== "string" || !request.query.trim()
      || encoder.encode(request.query).byteLength > 16384) throw invalid("invalid_search_request");
    const retrieval = {
      retrieval_type: "hybrid", max_num_results: MAX_INDEX_RESULTS,
      return_on_failure: false, context_expansion: 0,
    };
    if (typeof request.product === "string" && request.product
      && encoder.encode(request.product).byteLength <= 64) retrieval.filters = { product: request.product };
    const response = this.searchAI ? await this.searchWithAI(request, retrieval.filters)
      : await this.requireIndex().search({
      query: request.query,
      ai_search_options: {
        retrieval, query_rewrite: { enabled: false }, reranking: { enabled: false },
        cache: { enabled: false },
      },
    });
    if (!response || !Array.isArray(response.chunks) || response.chunks.length > MAX_INDEX_RESULTS) {
      throw invalid("invalid_index_response");
    }
    let bytes = 0;
    return response.chunks.map(chunk => {
      if (!chunk || typeof chunk.text !== "string" || !chunk.text || !validKey(chunk.item?.key)
        || !Number.isFinite(chunk.score)) throw invalid("invalid_index_response");
      bytes += encoder.encode(chunk.text).byteLength;
      if (bytes > MAX_SNAPSHOT_BYTES) throw invalid("index_response_too_large");
      return { text: chunk.text, index_key: chunk.item.key, score: chunk.score };
    });
  }

  async searchWithAI(request, filters) {
    if (typeof this.searchAI.autorag !== "function"
      || typeof this.searchInstance !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(this.searchInstance)) {
      throw invalid("index_unavailable");
    }
    // Select one transport before dispatch. Never retry a billable query through
    // another binding when the first request has an unknown outcome.
    const response = await this.searchAI.autorag(this.searchInstance).search({
      query: request.query, rewrite_query: false, max_num_results: MAX_INDEX_RESULTS,
      reranking: { enabled: false },
      ...(filters ? { filters: { type: "eq", key: "product", value: filters.product } } : {}),
    });
    return legacySearchChunks(response);
  }

  async uploadRevision(artifact, text) {
    await checkedBytes(artifact, text);
    const result = await this.requireIndex().items.upload(artifact.index_key, text, {
      metadata: {
        artifact_id: artifact.id, content_hash: artifact.content_hash,
        product: artifact.product, version_kind: artifact.version.kind,
        version: artifact.version.version ?? "unknown",
      },
    });
    return itemReference(result, artifact.index_key);
  }

  async reconcileRevision(artifact, itemId) {
    validateArtifact(artifact);
    const index = this.requireIndex();
    if (itemId) {
      const item = itemInfo(await readIndex(() => index.items.get(itemId).info()), artifact.index_key);
      if (item.id !== itemId) throw invalid("invalid_index_response");
      return item;
    }
    for (let page = 1; page <= MAX_RECONCILE_PAGES; page += 1) {
      const response = await readIndex(() => index.items.list({ search: artifact.index_key, source: "builtin", page, per_page: INDEX_PAGE_SIZE }));
      if (!response || !Array.isArray(response.result) || response.result.length > INDEX_PAGE_SIZE) {
        throw invalid("invalid_index_response");
      }
      const matches = response.result.filter(item => item?.key === artifact.index_key);
      if (matches.length > 1) throw invalid("ambiguous_index_revision");
      if (matches.length === 1) return itemInfo(matches[0], artifact.index_key);
      const total = response.result_info?.total_count;
      if (response.result.length < INDEX_PAGE_SIZE || Number.isSafeInteger(total) && page * INDEX_PAGE_SIZE >= total) return null;
    }
    throw invalid("index_reconciliation_incomplete");
  }

  async verifySearchable(artifact, item) {
    validateArtifact(artifact);
    itemInfo(item, artifact.index_key);
    if (item.status !== "completed" || item.next_action != null) return false;
    const text = await this.getSnapshot(artifact);
    if (text === null) return false;
    const bytes = encoder.encode(text);
    const index = this.requireIndex();
    let offset = 0;
    let expectedTotal;
    for (let page = 0; page < MAX_CHUNK_PAGES; page += 1) {
      const response = await readIndex(() => index.items.get(item.id).chunks({ limit: 100, offset }));
      if (!response || !Array.isArray(response.result) || response.result.length > 100
        || !Number.isSafeInteger(response.result_info?.total) || response.result_info.total < 1
        || response.result_info.total > 1024 || response.result_info.offset !== offset) return false;
      if (expectedTotal !== undefined && response.result_info.total !== expectedTotal) return false;
      expectedTotal = response.result_info.total;
      if (!response.result.length || response.result.some(chunk =>
        !chunkMatches(chunk, bytes) || chunk.item?.key && chunk.item.key !== artifact.index_key)) return false;
      offset += response.result.length;
      if (offset === response.result_info.total) return true;
      if (offset > response.result_info.total) return false;
    }
    return false;
  }

  async removeArtifact(artifact) {
    assertRemovable(artifact);
    // An upload can be accepted before publication records its item on the artifact, so
    // reconcile by the immutable index key whether or not this revision was published.
    if (artifact.item_id || this.index?.items) {
      const item = await this.reconcileRevision(artifact);
      if (item && artifact.item_id && item.id !== artifact.item_id) throw invalid("invalid_artifact_removal");
      if (item) await this.requireIndex().items.delete(item.id);
    }
    await this.requireBucket().delete(artifact.snapshot_key);
  }
}
