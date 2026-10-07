import { embeddingCosine } from "./memo-store.mjs";

// Confidence measures evidence independently of normalized ranking scores.
export const DISTINCTIVE_IDF = 3.5;
export const MIN_MATCHES = 3;
export const MIN_DISTINCTIVE = 2;
export const LONG_QUERY_TERMS = 20;
export const SINGLE_NAME_MIN_DOCUMENTS = 3;
export const SINGLE_NAME_DOCUMENT_RATIO = 0.03;
const STOPWORDS = new Set(("a about above after again against all also am an and any are as at be because been before being below between both but by can could did do does doing done down during each else etc few for from further get got had has have having he her here hers him his how i if in into is it its itself just let lets like may me might more most must my myself no nor not now of off ok okay on once only or other our ours out over own please same shall she should so some such than thank thanks that the their theirs them then there these they this those through to too under until up us very was we were what when where which while who whom why will with would yes you your yours").split(" "));
export const terms = text => (text.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [])
  .filter(term => term.length > 1 && !STOPWORDS.has(term))
  .map(term => term.length > 3 && term.endsWith("s") && !/(ss|us|is)$/.test(term) ? term.slice(0, -1) : term);
export class SkillsIndex {
  constructor(records, { confidentCosine } = {}) {
    this.records = records;
    // Uncalibrated semantic confidence is disabled unless explicitly configured.
    this.confidentCosine = confidentCosine !== undefined && confidentCosine !== ""
      && Number.isFinite(Number(confidentCosine)) && Number(confidentCosine) > 0 && Number(confidentCosine) <= 1
      ? Number(confidentCosine) : null;
    this.documents = new Map();
    this.ndf = new Map();
    this.fdf = new Map();
    this.postings = new Map();
    this.lengths = new Map();
    let total = 0;
    for (const record of records) {
      const name = new Set(terms(record.name));
      const nd = new Set([...name, ...terms(record.description)]);
      this.documents.set(record.skill_id, { name, nd });
      for (const term of nd) this.ndf.set(term, (this.ndf.get(term) ?? 0) + 1);
      const counts = new Map();
      let length = 0;
      for (const [text, weight] of [[record.name, 3], [record.description, 2], [record.index_text, 1]]) {
        for (const term of terms(text)) { counts.set(term, (counts.get(term) ?? 0) + weight); length += weight; }
      }
      this.lengths.set(record.skill_id, length); total += length;
      for (const [term, count] of counts) {
        if (!this.postings.has(term)) this.postings.set(term, new Map());
        this.postings.get(term).set(record.skill_id, count);
        this.fdf.set(term, (this.fdf.get(term) ?? 0) + 1);
      }
    }
    this.average = total / (records.length || 1) || 1;
  }
  nidf(term) {
    const frequency = this.ndf.get(term) ?? 0;
    return Math.log(1 + (this.records.length - frequency + 0.5) / (frequency + 0.5));
  }
  confidence(id, query, cosine, mode) {
    const { name, nd } = this.documents.get(id);
    const nameTerms = [...name];
    const nameHit = nameTerms.length > 0 && nameTerms.every(term => query.has(term))
      && (nameTerms.length > 1 ? nameTerms.some(term => this.nidf(term) >= DISTINCTIVE_IDF)
        : this.fdf.get(nameTerms[0]) <= Math.max(SINGLE_NAME_MIN_DOCUMENTS, SINGLE_NAME_DOCUMENT_RATIO * this.records.length));
    const hits = [...nd].filter(term => query.has(term));
    const strong = hits.length >= MIN_MATCHES && hits.filter(term => this.nidf(term) >= DISTINCTIVE_IDF).length
      >= MIN_DISTINCTIVE + Math.floor(query.size / LONG_QUERY_TERMS);
    const semantic = mode === "hybrid" && this.confidentCosine !== null && cosine >= this.confidentCosine;
    return nameHit || strong || semantic ? "high" : "low";
  }
  find(request, embedding = null) {
    const query = new Set(terms(request.query));
    const queryTerms = [...query].slice(0, 64);
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
      const confidence = this.confidence(record.skill_id, query, cosine, request.mode);
      if (request.min_confidence === "high" && confidence !== "high") continue;
      const score = bm25 + cosine + 0.03 * Math.log1p(record.helpful);
      results.push({ skill_id: record.skill_id, name: record.name, description: record.description, confidence,
        score: Math.round(score * 1000000) / 1000000, why: matched.get(record.skill_id) ?? [], files: record.files.map(file => file.path) });
    }
    return results.sort((a, b) => b.score - a.score || a.skill_id.localeCompare(b.skill_id)).slice(0, request.limit);
  }
}
