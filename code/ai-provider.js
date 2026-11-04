const fs = require('node:fs');
const path = require('node:path');

function loadLocalEnv() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || match[1] in process.env) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}

loadLocalEnv();

function configuration() {
  const apiKey = process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || '';
  const model = 'gpt-4.1-mini';
  const base = (process.env.LLM_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const endpoint = process.env.LLM_CHAT_COMPLETIONS_URL || `${base}/chat/completions`;
  return { enabled: Boolean(apiKey), provider: process.env.LLM_PROVIDER || (process.env.OPENAI_API_KEY ? 'OpenAI' : 'OpenAI-compatible'), model, endpoint, apiKey };
}

function minimizedCase(caseResult, request) {
  const findings = (caseResult.findings || []).map((item, index) => ({
    finding_number: index + 1,
    operation: item.op || item.operation || '',
    system: item.system || item.system_id || '',
    resource_type: String(item.category || item.data_category || '').replace(/[^A-Za-z0-9_ -]/g, '').slice(0, 60),
    policy_action: item.policy_action || '',
    evidence_reference: item.evidence || item.evidence_id || ''
  }));
  return {
    status: caseResult.deletion_status,
    audit_cutoff: request?.audit_at || '',
    evidence_gap: Boolean(caseResult.missing_evidence || (!findings.length && caseResult.deletion_status === 'INCOMPLETE')),
    findings
  };
}

async function explainCase(caseResult, request) {
  const config = configuration();
  if (!config.enabled) return { configured: false, provider: config.provider, model: config.model || null, explanation: null,
    message: 'AI explanations are not configured. Set LLM_API_KEY in code/.env, then restart the server.' };

  const facts = minimizedCase(caseResult, request);
  const body = {
    model: config.model,
    temperature: 0.1,
    max_tokens: 350,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: 'Explain a deletion audit to a beginner in concise plain language. Use only the supplied structured facts. Do not decide or alter the status, invent databases, identifiers, evidence, policies, or findings, and do not propose actions beyond the stated policy_action. If evidence_gap is true, say that absence is unverified rather than claiming data remains. Return JSON with keys summary (string) and points (array of strings, at most 4).' },
      { role: 'user', content: JSON.stringify(facts) }
    ]
  };
  let response;
  try {
    response = await fetch(config.endpoint, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${config.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(25000)
    });
  } catch (error) {
    return { configured: true, provider: config.provider, model: config.model, explanation: null, message: `AI service could not be reached (${error.name === 'TimeoutError' ? 'timeout' : 'network error'}).` };
  }
  if (!response.ok) return { configured: true, provider: config.provider, model: config.model, explanation: null, message: `AI provider returned HTTP ${response.status}. Check the provider URL, model, and key.` };

  let payload;
  try { payload = await response.json(); }
  catch { return { configured: true, provider: config.provider, model: config.model, explanation: null, message: 'AI provider returned an unreadable response.' }; }
  const content = payload?.choices?.[0]?.message?.content;
  if (typeof content !== 'string') return { configured: true, provider: config.provider, model: config.model, explanation: null, message: 'AI provider response did not contain a text explanation.' };
  try {
    const explanation = JSON.parse(content);
    const summary = typeof explanation.summary === 'string' ? explanation.summary.slice(0, 1200) : '';
    const points = Array.isArray(explanation.points) ? explanation.points.filter(x => typeof x === 'string').slice(0, 4).map(x => x.slice(0, 400)) : [];
    if (!summary) throw new Error('Missing summary');
    return { configured: true, provider: config.provider, model: config.model, explanation: { summary, points }, usage: payload.usage || null };
  } catch {
    return { configured: true, provider: config.provider, model: config.model, explanation: null, message: 'AI provider response did not match the required explanation format.' };
  }
}

module.exports = { configuration, explainCase, minimizedCase };
