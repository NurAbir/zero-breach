# Signing the indicator set

The updater (`scan/update-iocs.py`) fetches a fresh indicator list over HTTPS and
checks it against a published SHA-256. That proves the file arrived intact from
GitHub, but not — on its own — that *you* published it, because the hash is served
from the same place as the file. A **detached signature** closes that gap: it lets
anyone confirm the list was signed by the key you control, even if GitHub itself
were compromised.

This is optional. The tool works without it. But for a security tool used by
people who may be targeted, it is worth doing.

## Why the maintainer must generate the key, not a tool

The private key is the thing an adversary would want: whoever holds it can publish
an indicator list that every user trusts. **Generate it yourself, on a machine you
control, and never paste it anywhere** — not into a chat, an issue, a CI secret you
are unsure of, or a tool. If the private key is ever exposed, rotate it (generate a
new pair, publish the new public key, re-sign).

## One-time setup

Install [minisign](https://jedisct1.github.io/minisign/) (it is a single small
binary; packages exist for Windows, macOS and Linux). Then:

```
minisign -G -p minisign.pub -s minisign.key
```

- Commit **`minisign.pub`** to the repository root. It is public; it is how users
  verify. Put its contents in this file too (below) so it is easy to find.
- Keep **`minisign.key`** secret and backed up offline. It never goes in the repo.

## Signing a release of the indicator file

Each time you update `iocs/adfection_iocs.txt` (and run `python build/build.py`):

```
minisign -S -s minisign.key -m iocs/adfection_iocs.txt
```

This writes `iocs/adfection_iocs.txt.minisig`. Commit it alongside the updated
indicator file and its `.sha256`.

## How a user verifies (documented for them in the README/updater)

```
minisign -Vm adfection_iocs.txt -P <the public key below>
```

If it reports a good signature, the list was signed by your key. The scanner's
`update-iocs.py` points here for this step; it does not run minisign itself,
because verifying a signature needs a cryptography library and the scanner has a
strict no-dependencies rule. The one manual command above is the whole step.

## Public key

```
(paste the contents of minisign.pub here once generated)
```
