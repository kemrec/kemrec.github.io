---
layout: default
title: About
permalink: /about/
---

<h1>About</h1>

<div class="about-body">

<p>
I'm Kaya Emre Arıkan — an independent security researcher. I spend most of my
time reading source code, tracing patch diffs, and looking for the class of
bugs that survive a code review because nobody thought to check the boundary
condition: auth bypasses, injection, deserialization, race conditions, and
the odd firmware-level RCE.
</p>

<p>
My research spans open-source ecosystems — web frameworks, cloud SDKs,
container runtimes, CI tooling, and the occasional piece of embedded
firmware — reported through coordinated disclosure to maintainers, CNAs, and
bug bounty programs (HackerOne, Bugcrowd, GitHub Security Advisories, MSRC,
Google OSS VRP).
</p>

<h2>What's on this site</h2>
<p>
<a href="{{ '/writeups/' | relative_url }}">Writeups</a> of my own findings —
published <strong>only</strong> after the vendor's own advisory (CVE / GHSA /
security bulletin) is already public. Nothing here pre-empts a disclosure
still in progress.
</p>
<p>
<a href="{{ '/research/' | relative_url }}">Research</a> notes on bugs that
were already fixed upstream by the time I got to them: patch-diff studies and
security-boundary checks, verified against released builds and linked to the
public fix.
</p>

<h2>Elsewhere</h2>
<p>
<a href="https://github.com/{{ site.author.github }}" target="_blank" rel="noopener">github.com/{{ site.author.github }}</a>
</p>

<div class="disclosure-note">
<strong>Disclosure policy:</strong> every vulnerability is reported privately
to the affected vendor or maintainer first. I follow coordinated disclosure
and only publish technical details once a public advisory already exists —
never before, regardless of vendor response time.
</div>

</div>
