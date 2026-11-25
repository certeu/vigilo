# api-recon reference

## Where APIs hide in a front end
- Next.js: `self.__next_f.push(...)` payloads, `/_next/data/<build>/<page>.json`,
  route manifests (`_buildManifest.js`), server actions (POST to the page URL with
  `Next-Action` header).
- Vite/React/Vue bundles: `fetch(`/`axios.`/`$http.` calls, `baseURL` constants,
  route tables (`path: "/notes/:id"`), GraphQL documents (`query X {`, `mutation`).
- OpenAPI/Swagger: `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs`.
- GraphQL: one endpoint, many operations — the operation NAME is the surface.
- tRPC: `/api/trpc/<router>.<procedure>`; batch calls `?batch=1&input=`.

## Template inference rules (discovery.routes)
- A path segment is parameter-shaped when it is numeric (`{id}`), a UUID
  (`{uuid}`), long hex (`{hex}`) or a long mixed token (`{token}`).
- Confidence: high ≥ 3 samples, medium = 2, low = 1 parameter-shaped sample.
- One sample is a guess: look for the list view that enumerates siblings before
  testing ownership across ids.

## Correlation
- static_only: the code names it, nothing called it. Another role? Feature flag?
  Dead code still deployed? Try it as each identity before concluding.
- runtime_only: called but not in the code you read: another bundle (lazy chunk),
  server-generated URL, or a redirect target.
- both: the strongest evidence; prioritise these for api-security.
