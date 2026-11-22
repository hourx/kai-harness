/**
 * promptfoo provider for an OpenAI-compatible gateway (default: local vanarouter).
 *
 * Why a custom provider instead of the built-in `openai:chat:<model>` target:
 * redteam plugins such as `system-prompt-override` hand over a whole messages array,
 * which the built-in target JSON-parses and rejects with
 *   "Chat Completion prompt is not a valid JSON string".
 * This provider accepts both plain strings and stringified message arrays.
 *
 * promptfoo instantiates this export, so it MUST be a class -- exporting a bare
 * function fails with "(intermediate value) is not a constructor".
 *
 * Env: NEX_GATEWAY (default http://127.0.0.1:20128/v1), NEX_MODEL (required or nex-n2-6-hore),
 *      NEX_KEY (bearer token; never store it in the config file).
 */
const GATEWAY = (process.env.NEX_GATEWAY || 'http://127.0.0.1:20128/v1').replace(/\/+$/, '');
const MODEL = process.env.NEX_MODEL || 'nex-n2-6-hore';
const MAX_TOKENS = Number(process.env.NEX_MAX_TOKENS || 1024);

function toMessages(prompt, context) {
  const raw = typeof prompt === 'string' ? prompt : JSON.stringify(prompt);
  const head = raw.trim();
  if (head.startsWith('[') || head.startsWith('{')) {
    try {
      const parsed = JSON.parse(head);
      if (Array.isArray(parsed)) return parsed;
      if (parsed && Array.isArray(parsed.messages)) return parsed.messages;
      if (parsed && parsed.content) return [parsed];
    } catch (e) { /* plain text that merely starts with a brace */ }
  }
  const messages = [];
  const sys = context && context.vars ? context.vars.system : undefined;
  if (typeof sys === 'string' && sys.trim()) messages.push({ role: 'system', content: sys });
  messages.push({ role: 'user', content: raw });
  return messages;
}

class GatewayProvider {
  id() {
    return 'openai-compatible-gateway';
  }

  // Subclasses (see grader.js) override this to grade with a different model.
  // promptfoo does NOT forward a provider's `config` block to a JS file provider,
  // so the model has to travel through the environment, not through the YAML.
  modelFor(context) {
    const cfg = (context && context.config) || {};
    return cfg.model || MODEL;
  }

  async callApi(prompt, context) {
    const model = this.modelFor(context);
    const messages = toMessages(prompt, context).map((m) => ({
      role: m.role || 'user',
      content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
    }));

    const res = await fetch(`${GATEWAY}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.NEX_KEY || ''}`,
      },
      body: JSON.stringify({ model, messages, temperature: 0, max_tokens: MAX_TOKENS }),
    });

    const body = await res.json();
    if (!res.ok) throw new Error(`gateway ${res.status}: ${JSON.stringify(body).slice(0, 300)}`);
    const u = body.usage || {};
    return {
      output: (body.choices && body.choices[0] && body.choices[0].message && body.choices[0].message.content) || JSON.stringify(body).slice(0, 500),
      tokenUsage: {
        total: u.total_tokens || 0,
        prompt: u.prompt_tokens || 0,
        completion: u.completion_tokens || 0,
      },
    };
  }
}

module.exports = GatewayProvider;
