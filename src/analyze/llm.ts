// The only LLM protocol cspgen speaks: the OpenAI-compatible chat API, served by
// Ollama, LM Studio, vLLM, OpenRouter and OpenAI. Plain fetch, no SDK.

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LlmClient {
  readonly model: string;
  /** Returns the raw text of the answer; `schema` asks the server for JSON of that shape, when it supports it. */
  complete(messages: ChatMessage[], schema: { name: string; schema: object }): Promise<string>;
}

export class LlmError extends Error {}

export interface OpenAiCompatibleOptions {
  baseUrl: string;
  model: string;
  apiKey?: string;
  /** Sent only when set: "none" turns off thinking on Ollama; some non-reasoning models reject the field. */
  reasoningEffort?: string;
  timeoutMs?: number;
}

export function openAiCompatible({ baseUrl, model, apiKey, reasoningEffort, timeoutMs = 15 * 60_000 }: OpenAiCompatibleOptions): LlmClient {
  const url = `${baseUrl.replace(/\/+$/, '')}/chat/completions`;
  return {
    model,
    async complete(messages, schema) {
      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
          },
          body: JSON.stringify({
            model,
            messages,
            temperature: 0,
            response_format: { type: 'json_schema', json_schema: { name: schema.name, schema: schema.schema } },
            ...(reasoningEffort ? { reasoning_effort: reasoningEffort } : {}),
            // Streamed so that a slow local model does not hit fetch's timeout while waiting for headers.
            stream: true,
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          const body = (await response.text()).slice(0, 500);
          throw new LlmError(`${url} answered ${response.status}: ${body}`);
        }
        return await readStream(response, url);
      } catch (e) {
        if (e instanceof LlmError) throw e;
        throw new LlmError(`request to ${url} failed: ${(e as Error).message}`);
      }
    },
  };
}

/** Joins the content deltas of a server-sent events stream. */
async function readStream(response: Response, url: string): Promise<string> {
  if (!response.body) throw new LlmError(`${url} returned no body`);
  let content = '';
  let buffer = '';
  const decoder = new TextDecoder();
  const handle = (line: string) => {
    if (!line.startsWith('data:')) return;
    const data = line.slice(5).trim();
    if (data === '' || data === '[DONE]') return;
    const event = JSON.parse(data) as { choices?: { delta?: { content?: string } }[]; error?: { message?: string } };
    if (event.error) throw new LlmError(`${url} failed: ${event.error.message ?? JSON.stringify(event.error)}`);
    content += event.choices?.[0]?.delta?.content ?? '';
  };
  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk as Uint8Array, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop()!;
    lines.forEach(handle);
  }
  handle(buffer);
  if (content === '') throw new LlmError(`${url} returned an empty answer`);
  return content;
}

/** True when the API runs on this machine, for the banner. */
export function isLocal(baseUrl: string): boolean {
  const host = new URL(baseUrl).hostname;
  return host === 'localhost' || host === '[::1]' || host.startsWith('127.') || host.endsWith('.local');
}

/** Parses JSON from a model answer, tolerating a Markdown fence around it. */
export function parseJsonAnswer(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  const body = (fenced ? fenced[1]! : text).trim();
  return JSON.parse(body);
}
