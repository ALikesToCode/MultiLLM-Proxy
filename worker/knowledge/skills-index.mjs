import { embeddingCosine } from "./memo-store.mjs";

const terms = text => text.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
export class SkillsIndex {
  constructor(records) {
    this.records = records;
    this.postings = new Map();
    this.lengths = new Map();
    let total = 0;
    for (const record of records) {
      const counts = new Map();
      let length = 0;
      for (const [text, weight] of [[record.name, 3], [record.description, 2], [record.index_text, 1]]) {
        for (const term of terms(text)) { counts.set(term, (counts.get(term) ?? 0) + weight); length += weight; }
      }
      this.lengths.set(record.skill_id, length); total += length;
      for (const [term, count] of counts) {
        if (!this.postings.has(term)) this.postings.set(term, new Map());
        this.postings.get(term).set(record.skill_id, count);
      }
    }
    this.average = total / (records.length || 1) || 1;
  }
  find(request, embedding = null) {
    const queryTerms = [...new Set(terms(request.query))].slice(0, 64);
    const lexical = new Map(), matched = new Map();
    for (const term of queryTerms) {
      const posting = this.postings.get(term);
      if (!posting) continue;
      const idf = Math.log(1 + (this.records.length - posting.size + 0.5) / (posting.size + 0.5));
      for (const [id, tf] of posting) {
        const score = idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * this.lengths.get(id) / this.average));
        lexical.set(id, (lexical.get(id) ?? 0) + score);
        if (!matched.has(id)) matched.set(id, []);
        matched.get(id).push(term);
      }
    }
    const maximum = Math.max(0, ...lexical.values()) || 1;
    const results = [];
    for (const record of this.records) {
      if (request.roots && !request.roots.includes(record.root)) continue;
      const bm25 = (lexical.get(record.skill_id) ?? 0) / maximum;
      const cosine = embedding && record.embedding ? embeddingCosine(embedding.values, record.embedding.values) : 0;
      if (!bm25 && cosine <= 0) continue;
      const score = bm25 + cosine + 0.03 * Math.log1p(record.helpful);
      results.push({ skill_id: record.skill_id, name: record.name, description: record.description,
        score: Math.round(score * 1000000) / 1000000, why: matched.get(record.skill_id) ?? [], files: record.files.map(file => file.path) });
    }
    return results.sort((a, b) => b.score - a.score || a.skill_id.localeCompare(b.skill_id)).slice(0, request.limit);
  }
}
