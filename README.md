# kearikan.com

Source for my personal security-research blog, built with Jekyll and hosted
on GitHub Pages with a custom domain.

## Local dev

```
bundle install
bundle exec jekyll serve
```

Site is served at `http://localhost:4000`.

## Adding a writeup

**Only publish a writeup once the vendor's advisory (CVE / GHSA / bulletin)
is actually public.** "Reported," "accepted," or "fixed" is not
"published" — verify the advisory is live before adding the post, e.g.:

```
gh api repos/<owner>/<repo>/security-advisories/<GHSA-id> --jq '{state, published_at, cve_id, credits}'
```

`state` must be `published`. Check `credits` too while you're there — it's
easy to miss if you only pull a trimmed set of fields from the advisories
*list* endpoint instead of reading the single advisory.

1. Copy `drafts/writeup-template.md` to `_writeups/<slug>.md`
2. Fill in the front matter (`title`, `date`, `target`, `severity`,
   `identifier`, `advisory_url`, `summary`) and the body
3. Set `date:` to the advisory's own `published_at` date — **not** the day
   the post is actually written. Posts are dated to match when the finding
   became public, so the blog's timeline reflects disclosure dates, not
   authoring dates.
4. `bundle exec jekyll serve` to preview, then commit and push

## Deploy

Push to `main` — GitHub Pages builds and deploys automatically.
