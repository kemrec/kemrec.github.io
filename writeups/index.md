---
layout: default
title: Writeups
permalink: /writeups/
---

<h1>Writeups</h1>
<p>All findings below were privately reported to the vendor first and are
published here only once a public advisory (CVE / GHSA / security bulletin)
already exists.</p>

<div class="section-title">All writeups</div>

{% assign writeups = site.writeups | sort: 'date' | reverse %}
{% if writeups.size > 0 %}
<ul class="writeup-list">
  {% for w in writeups %}
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
{% else %}
<div class="empty-state">
  No writeups yet. First posts land here once a finding I've reported gets a
  public <span class="mono">CVE</span> or <span class="mono">GHSA</span>.
</div>
{% endif %}
