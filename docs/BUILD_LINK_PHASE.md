# Swift build: link phase on ARM (Orange Pi)

On ARM SBCs, `swift build -c release` can sit at **"[900+/905] Linking AppAttestBackend"** for 5–15 minutes with no obvious `swiftc` in `ps`. That’s the **link phase**, not a hung build.

## Normal time ranges (realistic)

On an Orange Pi / Pi-class board:

| Build type | Time |
|------------|------|
| **First release build** | 10–30 minutes |
| **Linking step alone** | 5–15 minutes |
| **Subsequent builds** | 2–8 minutes (if nothing big changed) |

If you touched crypto-heavy files or `main.swift` a lot, expect the long end.

## What’s actually happening

You’re doing a cold-ish release build of Swift, Vapor, NIO, CryptoKit, ASN.1, TLS, and App Attest crypto on an ARM SBC with limited RAM and slow storage. That’s basically asking a bicycle to tow a boat.

During the **link phase**, Swift often:

- uses **zero** `swiftc` processes
- pins **one** core
- looks completely dead in `ps`
- is still working — grinding symbols like a caffeinated raccoon

So the command looks stuck while it’s linking. That’s normal.

## What’s going on (phase table)

| Phase        | What you see                      | `ps | grep swiftc` |
|-------------|------------------------------------|----------------------------------|
| Compilation | `[1/905] … [900/905] …`           | `swiftc` processes               |
| **Linking** | `[903/905] Linking AppAttestBackend` | Often **nothing** — normal      |
| Post-link   | `Build complete`                  | —                                |

During linking, the **linker** (`ld` or `ld.gold`) runs under SwiftPM. On Linux/ARM it often:

- doesn’t show up clearly in `ps | grep swiftc`
- uses a lot of CPU and/or disk I/O
- takes a long time for big binaries (Vapor + Crypto + CBOR + AsyncHTTPClient → ~100MB)

So “no swiftc” during that step does **not** mean the build is stuck.

## How to tell: alive vs stuck

### 1. Quick check (another terminal)

```bash
ls -lh .build/aarch64-unknown-linux-gnu/release/AppAttestBackend
```

- **If the file appears or grows over time** → still linking
- **If it doesn’t exist yet** → still linking (or compiling)
- **If its mtime updates** → still linking

Also run `top`. If you see `ld`, `clang`, or `swift` at 5–30% CPU and some disk activity: that’s not stuck. That’s ARM suffering quietly.

### 2. Link heartbeat (recommended)

In a **second terminal**:

```bash
./scripts/link-heartbeat.sh
```

It prints every 30s: binary/artifact mtimes, RAM/Swap, and any `ld`/`swift`/`cc1` processes.

- **Alive:** binary appears and grows, or `.build` has recently touched files; RAM/swap or `ld` active.
- **Stuck:** CPU ~0%, no disk I/O, binary and `.build` unchanged for 10+ minutes.

### 3. Manual checks

- **Binary timestamp:**  
  `stat .build/aarch64-unknown-linux-gnu/release/AppAttestBackend`  
  If it updates every minute or two, the linker is still writing.

- **CPU / I/O:**  
  `top` or `htop` — high CPU or `ld`/`cc1` work → alive.  
  `iotop` — disk I/O with low CPU → still alive.

- **Memory:**  
  `free -h` — if swap is growing and RAM is full, linking will be slow; 5–15 minutes is plausible.

### 4. When it’s really stuck

Only if **all** of these hold:

- CPU near 0%
- No disk I/O
- Binary (or `.build`) timestamp unchanged for **10+** minutes
- No new `swift build` output

Then:

```bash
sudo pkill -9 ld swift swiftc
rm -rf .build
./scripts/deploy.sh
```

Do **not** spam rebuilds; that makes it worse.

## What not to do

- **Don’t Ctrl-C** unless it’s been 20+ minutes with **zero** file changes (binary mtime, `.build` activity).
- **Don’t restart systemd** — that doesn’t fix a slow build.
- **Don’t assume Cursor (or the IDE) broke something** — it’s the toolchain and the hardware.
- **Don’t start “fixing” code mid-link** — that’s how you waste another hour.
- **Don’t run two Swift builds at the same time.** No `swift build` in one terminal and `deploy.sh` in another, no IDE builds in the background. SwiftPM locks `.build`; only one process gets to run. It will lock you out and stare.

Let it cook.

## SwiftPM lock: “another instance is running”

**What that message means, in plain English:**

Another SwiftPM process already has a lock on `.build`, so this one is politely standing there doing nothing. It’s not compiling. It’s not linking. It’s literally waiting for the other process to finish or die. This is normal, annoying, and extremely on-brand for SwiftPM on ARM.

### What’s almost certainly happening

One of these:

1. **A previous `swift build` or `deploy.sh` is still linking** — let it finish.
2. **A previous build crashed or was Ctrl-C’d and left the lock behind** — see Step 3.
3. **You ran two builds in parallel** — SwiftPM uses a global lock on `.build`. Only one process gets to live.

### Step 1: Confirm who’s holding the lock

```bash
ps aux | grep -E "swift|swiftc|clang|ld" | grep -v grep
```

If you see `swift build`, `swiftc`, `clang`, or `ld.lld` / `ld.gold`: it’s still working. Slowly. Painfully. Correctly. Let it finish.

### Step 2: Decide if it’s actually stuck

In another terminal:

```bash
./scripts/link-heartbeat.sh
```

- **Alive:** `.build/.../AppAttestBackend` appearing or growing; mtime changing; disk or CPU activity. Do not touch it. This is ARM linking being a menace.
- **Dead:** For 10–15 minutes: no file changes, no CPU, no linker process. Then it’s probably dead.

### Step 3: If it’s dead, cleanly kill it (once)

Only if you’re sure:

```bash
pkill -f "swift build"
pkill -f swiftc
```

Then choose a rebuild path (§ Rebuild path below): usually **Option B** (`SKIP_CLEAN=1 ./scripts/deploy.sh`); if `.build` is corrupted or incremental keeps failing, **Option C** (`rm -rf .build` then `./scripts/deploy.sh`). Do **not** spam retries.

### Important rule going forward

**Never run two Swift builds at the same time on the Pi. Ever.**

No `swift build` in one terminal and `deploy.sh` in another. No IDE builds in the background. SwiftPM will just lock you out and stare.

### Why this keeps happening

You’re doing Swift, Vapor, CryptoKit, ASN.1, TLS, release mode, on ARM, with limited RAM. That’s basically asking a Raspberry-class machine to tow a boat uphill. Nothing is broken. Nothing is wrong. It’s just slow and serialized.

### Safe mental model

- One build at a time.
- If SwiftPM says “another instance is running”, believe it.
- Use `link-heartbeat.sh` instead of panicking.
- Kill only after real inactivity (10–15 min, no CPU, no I/O, no file changes).

Annoying, but now you know exactly how to handle it without spiraling.

## Rebuild path (after cancel or lock)

You didn’t brick anything. You just pulled the emergency brake. Here’s the clean, fastest, least-painful path back — explicit so you don’t summon SwiftPM hell again.

### Step 0: Make sure nothing is still holding the lock

Confirm SwiftPM is truly dead:

```bash
ps aux | grep -E "swift build|swiftc|clang|ld" | grep -v grep
```

- **Nothing** → good, continue.
- **Something** → wait 30–60s; if it’s clearly stuck:

```bash
pkill -f "swift build"
pkill -f swiftc
```

Do **not** start another build until this is clean.

### Choose your rebuild path

**Option A: “I just want it to compile and test logic”**

Fastest. No systemd. No release.

```bash
cd /home/orangepi/Developer/appattest-backend
./scripts/build-fast.sh
```

- Debug, incremental, much faster link.
- Produces a binary; does **not** restart the service.
- Use when: fixing compiler errors, changing crypto logic, you want feedback now.

---

**Option B: “I want the service running with new code, but don’t nuke everything”**

Right choice ~90% of the time. **Use this after canceling a build, once, cleanly.**

```bash
cd /home/orangepi/Developer/appattest-backend
SKIP_CLEAN=1 ./scripts/deploy.sh
```

- Incremental release, reuses `.build`, enforces all deployment invariants.
- Restarts systemd only if the binary changed.

---

**Option C: “Everything is cursed, start from scratch”**

Only if: you killed SwiftPM mid-link, `.build` is clearly corrupted, or incremental keeps failing in weird ways.

```bash
cd /home/orangepi/Developer/appattest-backend
rm -rf .build
./scripts/deploy.sh
```

Yes, it’s slow. Nuclear option.

### While it’s building

In a **second terminal**:

```bash
./scripts/link-heartbeat.sh
```

Shows: binary growing, timestamps changing, linker alive but quiet. If there’s activity → do nothing. Let it cook.

### Mental model

- SwiftPM on ARM is serial and slow.
- Linking can look idle for 5–15 minutes.
- After canceling mid-link: stop all builds, then **one** clean build. Never stack. One at a time. Always.

### Recommendation after a cancel

👉 **Option B:** `SKIP_CLEAN=1 ./scripts/deploy.sh`, then start the heartbeat and walk away for a few minutes.

## Tuning (optional)

### For low-RAM ARM: cap both compiler and linker (recommended)

Once a build finishes, use **both** of these before the next deploy. Slower per core, but far more predictable on Pi-class boards:

```bash
export SWIFT_EXEC_MAX_PROCESSES=1
export LINKER_EXTRA_FLAGS="-Xlinker --thread-count=1"
./scripts/deploy.sh
```

- `SWIFT_EXEC_MAX_PROCESSES=1` — fewer parallel `swiftc` jobs → less RAM, smoother on 4–8GB SBCs.
- `LINKER_EXTRA_FLAGS` — less linker thrashing; `--thread-count=1` for **gold** (`ld.gold`). For **lld**: use `-Xlinker --threads=1` instead.

`deploy.sh` passes `$LINKER_EXTRA_FLAGS` through to `swift build`. One `-Xlinker <flag>` per flag; for multiple:  
`LINKER_EXTRA_FLAGS="-Xlinker --thread-count=1 -Xlinker -Wl,--no-gnu-unique"`.

### Add swap

If you haven’t already, add swap. It helps linking a lot when RAM is tight.

### Cap linker only (if compiler is fine)

If the linker is thrashing but compile is OK:

For **gold** (`ld.gold`):

```bash
export LINKER_EXTRA_FLAGS="-Xlinker --thread-count=1"
./scripts/deploy.sh
```

For **lld** (if installed and used):

```bash
export LINKER_EXTRA_FLAGS="-Xlinker --threads=1"
./scripts/deploy.sh
```

### Limit Swift compiler only (if linker is fine)

If `free` shows heavy swap during the build but linking is OK:

```bash
export SWIFT_EXEC_MAX_PROCESSES=1
./scripts/deploy.sh
```

### Reduce binary size

- **Strip (safe, done in `deploy.sh`):**  
  `strip` is run on the release binary before hash/restart. Cuts a noticeable amount of size.

- **Optimize for size (trade speed):**  
  Only if you accept a performance trade-off:

  ```bash
  swift build -c release -Xswiftc -Osize --product AppAttestBackend
  ```

  Do **not** use this in `deploy.sh` by default; document it for special cases.

## Why it hits this project

1. **Big binary** — ~100MB; linkers are slow on that.
2. **Swift on Linux/ARM** — not a primary path for Apple; tooling is less tuned.
3. **Stack** — Vapor + Crypto + async + CBOR is a real backend, not a tiny binary.

## Fast builds (testing)

We separated **thinking, building, and deploying**. That’s the whole game.

### Inner loop: `build-fast.sh` (90% of the time)

| | |
|--|--|
| **Command** | `./scripts/build-fast.sh` |
| **What** | Debug, incremental, no clean, no service restart, no invariant ceremony |
| **When** | Fixing logic, chasing compiler errors. “Does it compile?” |
| **If it feels slow** | Something is genuinely wrong. |

### Outer loop: `SKIP_CLEAN=1 ./scripts/deploy.sh`

| | |
|--|--|
| **Command** | `SKIP_CLEAN=1 ./scripts/deploy.sh` |
| **What** | Release build, incremental, still enforces invariants, still safe. Way faster than nuking `.build`. |
| **When** | The service must restart; behavior differs in release; you want to verify the real binary. “Does it work live?” |

### Ceremony: full `./scripts/deploy.sh`

| | |
|--|--|
| **Command** | `./scripts/deploy.sh` |
| **What** | Cold start, CI-style. “Prove it from nothing.” |
| **When** | Shipping, or after `rm -rf .build` / toolchain change. “Am I shipping?” |
| **Vibe** | You should almost feel annoyed when you have to use it. That’s correct. |

### What `build-fast` does and doesn’t do

`build-fast.sh` builds the **latest binary on disk** (debug, incremental) but does **not** deploy it.

| | |
|--|--|
| PASS | Binary on disk is updated (newest code) |
| FAIL | systemd keeps running the **old release** binary |
| FAIL | No restart, no hash update, no invariant checks |

- **Run the binary by hand** after `build-fast` → you’re running the latest code.
- **`curl` the server or check logs via systemd** → you are not. The service is still the old release.

This is intentional. It’s the whole point of “fast.”

### Mental model: three states

There are three states, not one:

1. **Built binary on disk**
2. **Deployed binary hash** (`.deployed_binary_hash`)
3. **Running service process** (systemd)

`build-fast.sh` only touches **#1**. `deploy.sh` is the only thing that moves **#2 → #3**. Never expect systemd to change unless `deploy.sh` runs.

### Testing flow

- **While fixing compile / crypto / logic errors:** `build-fast`. Fast, no linking pain, no systemd churn. Just “does this code make sense?”
- **When you want the service to actually run new code:** `SKIP_CLEAN=1 ./scripts/deploy.sh`. Incremental release, enforces invariants, updates the running process. Slow, but correct.

### Why this setup is good

You accidentally built real CI/CD separation: `build-fast` = developer inner loop; `deploy.sh` = production gate; systemd = runtime truth; `/health` + CANARY = cryptographic receipts. This is how grown-up backend systems work. iOS just hides it from you.

### Aliases (optional but smart)

Add to your shell on the Pi (e.g. `~/.bashrc`):

```bash
alias sf='./scripts/build-fast.sh'
alias sd='SKIP_CLEAN=1 ./scripts/deploy.sh'
alias sdc='./scripts/deploy.sh'
```

Then:

- **`sf`** → does it compile?
- **`sd`** → does it work live?
- **`sdc`** → am I shipping?

That muscle memory matters more than flags.

### Reality check

**Bottom line:** `build-fast` → latest binary on disk, **not** running in systemd. `deploy.sh` → latest binary, **running**. Never expect systemd to change unless `deploy.sh` runs.

**About the slowness:** Swift + release + CryptoKit + Vapor + ARM + limited RAM + static-ish linking is the worst-case combo. The speed hacks we added are basically the ceiling unless you: cross-compile on a Mac, switch to a beefier board, or accept debug builds while iterating. Yes, it’s painfully slow. No, you didn’t mess up. You’re not stuck — you’re doing real backend work now. It’s brutal, but you’re past the toy phase. This is the good pain.

## Summary

- **Link phase with no `swiftc` in `ps` is normal.**
- **“Another instance of SwiftPM is already running”** = something else has the `.build` lock; your process is waiting, not building. One build at a time. See § SwiftPM lock.
- **After a cancel or lock:** Step 0 (pkill until clean), then § Rebuild path: A = compile only, B = incremental deploy (use this), C = nuclear.
- **`build-fast` vs `deploy`:** build-fast = latest on disk only; deploy = moves that into systemd. Three states: built on disk, deployed hash, running process. deploy.sh alone updates the running process.
- Use `./scripts/link-heartbeat.sh` in another terminal to see that the build is still working.
- Only kill and clean if you’ve confirmed it’s stuck (no CPU, no I/O, no timestamp change for 10+ minutes).
- On ARM + Swift + crypto + release: **it’s not broken, you didn’t mess it up — it’s annoying, slow, and unfortunately normal. Let it cook.**
