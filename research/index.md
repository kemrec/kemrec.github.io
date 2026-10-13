---
layout: default
title: Research
permalink: /research/
---

<h1>Research</h1>
<p>N-day research notes: bugs I looked into after the fix was already public.
Sometimes there is no CVE at all, just a patch that quietly closed something
interesting; sometimes a CVE exists but the vendor advisory withholds the
technical detail. Every post links to the upstream fix and describes behavior
verified against released builds.</p>

<div class="section-title">All research</div>

{% assign research = site.research | sort: 'date' | reverse %}
{% if research.size > 0 %}
<ul class="writeup-list">
  {% for r in research %}
  <li class="writeup-item">
    <a href="{{ r.url | relative_url }}" title="{{ r.title | escape }}">
      <div class="row">
        <span class="meta">{{ r.date | date: '%Y-%m-%d' }}</span>
        <span class="title">{{ r.title }}</span>
        {% if r.severity %}<span class="badge {{ r.severity | downcase }}">{{ r.severity }}</span>{% endif %}
      </div>
    </a>
  </li>
  {% endfor %}
</ul>
{% else %}
<div class="empty-state">
  No research notes yet.
</div>
{% endif %}
