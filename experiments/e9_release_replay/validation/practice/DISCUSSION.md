# Practice items: discussion notes (open only after both raters have finished)

These notes come from checking each item's source at the release commit (17 Oct 2026). The suggested label is a reference for calibration, not the only acceptable answer: what matters is that both raters apply the same rules for the same reasons. The real sample's label mix is unknown, so judge every real item on its own evidence.

## P01: zwave-js-ui v11.15.1 · npm `socket.io-parser` 4.2.4 · GHSA-677m-j7p3-52f9 (CVE-2026-33151)
- **Advisory:** a crafted Socket.IO packet makes the *server* buffer an unbounded number of binary attachments, leading to out-of-memory (DoS). The 4.x line is affected below 4.2.6.
- **Is it shipped?** Yes. `socket.io` is in `dependencies` in `package.json` (not `devDependencies`).
- **Is it used?** Yes. `api/lib/SocketManager.ts` creates a Socket.IO `Server`, and the UI talks to the backend over it. The parser handles every incoming packet, before any application-level handler runs.
- **Suggested label:** **PLAUSIBLE.**
- **Example evidence:** "socket.io Server created in api/lib/SocketManager.ts; parser processes all client packets; DoS reachable by any client that can open the UI socket."
- **Teaching point:** for a library on the request path, *used at runtime + affected version* is enough for PLAUSIBLE. You do not need to prove that it is exploitable.

## P02: traefik v3.7.6 · npm `vitest` 4.0.3 · GHSA-5xrq-8626-4rwp (CVE-2026-47429)
- **Advisory:** arbitrary file read when the **Vitest UI server** is listening and exposed to the network, or on Windows.
- **Is it shipped?** No, although `webui/package.json` lists `vitest` under `dependencies`, not `devDependencies`. The lockfile has no dev flag at all, which is why the replay counted it as runtime.
- **Is it used?** Only in tests. It is imported only by `src/utils/test.tsx` and `*.spec.ts` files, and run by the `test` scripts. Traefik ships the dashboard as **built static files** (`webui/embed.go`: `//go:embed static`, produced by `vite build`), so the test runner is not in the product.
- **Suggested label:** **NOT_PLAUSIBLE.**
- **Example evidence:** "vitest only imported by test files and the test scripts; product embeds the built webui/static assets (embed.go); test runner not shipped."
- **Teaching point:** do not trust the dependency section alone. Check what actually ends up in the shipped artefact. A misplaced declaration is common.

## P03: headscale v0.27.1 · Go `github.com/opencontainers/runc` v1.3.2 · GHSA-9493-h29p-rfm2 (CVE-2025-31133)
- **Advisory:** container escape in **runc**, the container runtime, through masked-path mount races. It only matters for software that *runs containers with runc*.
- **Is it shipped?** No. runc is `// indirect` in `go.mod`. It arrives through `github.com/ory/dockertest` and `github.com/docker/docker`, which are imported only under `integration/` and `cmd/hi` (the integration-test runner). The server (`cmd/headscale`, `hscontrol/`) does not import them.
- **Suggested label:** **NOT_PLAUSIBLE.**
- **Example evidence:** "runc indirect via dockertest; imported only in integration/ and cmd/hi test harness; headscale server neither links nor runs containers."
- **Teaching points:**
  - `go.sum` lists the whole module graph, test-only modules included.
  - The affected functionality (spawning containers) is not something the product does.
  - Watch for false grep hits: searching "runc" also matches "trunc**ate**".

## Calibration checklist after the discussion
- [ ] We agree on what counts as "shipped": the built artefact or binary, not the dependency file.
- [ ] We agree that PLAUSIBLE needs runtime use plus an affected version, not a proven exploit.
- [ ] We agree to use UNDETERMINED when we can't decide within about 20 minutes, instead of guessing.
- [ ] We write file paths in `evidence` so that adjudication is quick.
