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
is actually public.** "Reported" or "accepted" is not "published" — verify
the advisory is live before adding the post.

1. Copy `drafts/writeup-template.md` to `_writeups/<slug>.md`
2. Fill in the front matter (`title`, `date`, `target`, `severity`,
   `identifier`, `advisory_url`, `summary`) and the body
3. `bundle exec jekyll serve` to preview, then commit and push

## Deploy

Push to `main` — GitHub Pages builds and deploys automatically.
