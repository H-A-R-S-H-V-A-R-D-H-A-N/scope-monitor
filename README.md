# scope-monitor

Watches every public HackerOne + Bugcrowd program (via
[arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data),
which crawls both platforms every ~30 min) and Telegrams you when:

- a new program launches
- a program disappears (removed, renamed, or taken private)
- a program gets a new in-scope target
- a program removes an in-scope target
- anything else changes on a program record that isn't a scope add/remove
  (flagged as "non-scope change — check manually", covers policy/payout/rule text)

Sources: HackerOne, Bugcrowd, Intigriti. YesWeHack and Federacy are
intentionally never fetched.

**Caveat on Intigriti field names:** confirmed `endpoint`/`type` for scope
items from a public reference using this same dataset, but the top-level
program name/URL fields are best-effort (multiple candidates tried, same as
the other platforms). If Intigriti alerts show a blank name or URL, tell me
and it's a one-line fix in `parseProgram()`'s candidate list.

## Setup

1. Create a **public** GitHub repo, push this code to it. Public repos get
   unlimited GitHub Actions minutes on the free tier; private repos are
   capped at 2,000 min/month. This repo only mirrors already-public program
   scope data, so there's nothing sensitive in it — your Telegram token and
   chat ID live in encrypted Actions secrets, never in the repo itself.
2. Create a Telegram bot via [@BotFather](https://t.me/BotFather), grab the token.
3. Get your chat ID: message your bot once, then hit
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and read `chat.id` from
   the response.
4. In the repo: Settings → Secrets and variables → Actions → New repository secret:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
5. Settings → Actions → General → Workflow permissions → set to
   "Read and write permissions" (needed so the workflow can commit `state.json` back).
6. Trigger it once manually: Actions tab → scope-monitor → Run workflow.
   First run has no previous state, so it just sends a baseline message
   ("N HackerOne programs, M Bugcrowd programs, monitoring starts now") and
   commits `state.json`. Every run after that will diff against it.

## Local test

```
export TELEGRAM_BOT_TOKEN=xxx
export TELEGRAM_CHAT_ID=xxx
go run .
```

## If a field comes through blank or wrong

I wrote `main.go`'s field parsing defensively (multiple candidate key names
per field — `getField()`) because I couldn't fetch the live 17MB
`hackerone_data.json` / `bugcrowd_data.json` to lock down exact field names
against the current schema. If you see a blank program name, blank URL, or
scope items that look wrong in a Telegram message, tell me the platform and
which field, and it's a one-line fix in the `candidates` list passed to
`parseProgram()` in `main.go`.

The hash-based fallback (`✏️ UPDATED (non-scope change)` alerts) means even
if a field mapping is wrong, you won't silently miss a change — you'll just
get a less specific alert telling you to go look at the program page directly.

## Extending to private/invited programs

This only covers *public* scope. Your private Bugcrowd/HackerOne invites
(Amplitude, Storytel, Discord, etc.) aren't in bounty-targets-data. That'd
need a second job hitting HackerOne's authenticated API
(`/v1/hackers/programs/{handle}/structured_scopes`, HTTP Basic Auth with your
username + API token) — happy to build that as a follow-up if you want it.
