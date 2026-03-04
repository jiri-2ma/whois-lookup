# WHOIS Lookup

Self-hosted static single-page app for domain and IP registration lookups via RDAP.

## Usage

Open `index.html` in a browser. Enter a domain (e.g. `google.com`) or IP address (e.g. `8.8.8.8`).

## How it works

- Queries [RDAP](https://about.rdap.org/) via the `rdap.org` proxy (handles TLD routing, supports CORS)
- Parses structured JSON response into a summary card
- Full raw RDAP JSON available in collapsible section
- No backend, no dependencies, no build step

## Deployment

Push to GitLab — GitLab Pages deploys automatically via `.gitlab-ci.yml`.

## Security

- CSP restricts scripts to `self`, fetch to `rdap.org` only
- All data rendered via `textContent` (no `innerHTML` with external data)
- Client-side rate limiting (2.5s cooldown)
- Zero dependencies
