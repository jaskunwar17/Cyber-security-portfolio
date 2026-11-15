# Cyber AI Agent

A local security triage app for messages, URLs, and logs. Shows risk signals, evidence, and next steps; exports JSON reports.

### Run

Requires Node.js 22+; no dependencies to install.

```sh
cd cyber-ai-agent
node --env-file-if-exists=.env server.js
```

Open **http://127.0.0.1:3000**. Try a sample or paste your own text.

### Optional AI

Copy `.env.example` to `.env` and set `OPENAI_API_KEY`. Restart, then enable **AI summary** in the app. This sends the submitted text to OpenAI; API usage may incur charges. Keys stay on the server. [API documentation](https://developers.openai.com/api/reference/resources/responses/methods/create).

Without a key, analysis uses local rules. Signals are indicators, not proof of maliciousness. The app never visits submitted URLs or runs submitted commands. Analysis history is not stored on the server.

### Test

```sh
node --test
```
