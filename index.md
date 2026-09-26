---
layout: default
title: Home
---

<div class="hero">
  <h1>{{ site.author.name }}</h1>
  <div class="tagline">{{ site.tagline }}</div>
  <p>
    I find and responsibly disclose vulnerabilities in open-source software —
    from web frameworks to CLI tools to language runtimes. This is where I
    write up the findings that vendors have already made public.
  </p>
</div>

<div class="section-title">Recent writeups</div>

{% assign writeups = site.writeups | sort: 'date' | reverse %}
{% if writeups.size > 0 %}
<ul class="writeup-list">
  {% for w in writeups limit:5 %}
  <li class="writeup-item">
    <a href="{{ w.url | relative_url }}">
      <div class="row">
        <span class="title">{{ w.title }}</span>
        {% if w.severity %}<span class="badge {{ w.severity | downcase }}">{{ w.severity }}</span>{% endif %}
        <span class="meta">{{ w.date | date: '%Y-%m-%d' }}</span>
      </div>
      {% if w.summary %}<div class="summary">{{ w.summary }}</div>{% endif %}
    </a>
  </li>
  {% endfor %}
</ul>
<p><a href="{{ '/writeups/' | relative_url }}">view all writeups &rarr;</a></p>
{% else %}
<div class="empty-state">
  Nothing published yet. Check back soon — new writeups go up as
  advisories I've reported become <span class="mono">publicly disclosed</span>.
</div>
{% endif %}
