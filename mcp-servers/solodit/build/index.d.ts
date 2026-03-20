#!/usr/bin/env node
/**
 * Krait Solodit MCP Server
 *
 * Exposes three tools for live Solodit search during Krait skill execution:
 *   - search_similar_findings: find similar exploits for a detected vulnerability
 *   - get_enrichment: fetch high-quality findings for a protocol type
 *   - validate_hypothesis: check if a suspected bug has historical precedent
 *
 * Requires CYFRIN_API_KEY environment variable.
 */
export {};
