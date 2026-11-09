# Cloudflare Deanon: Read the Platform

**Author:** mar

**OSINT** · 200 pts (easy)
Evidence: `files/nestegg-capital.html` (the public page as served)

**TL;DR.** The registration number is printed on the public NestEgg Capital site in three places —
the `<title>`, the header bar and the trust bar. It is `NEC-7731-0049`; the answer boundary is
explicit that the displayed value is the answer, so no registry lookup or historical guess applies.

## Solve

**Reconnaissance.** The fraud unit's call note (2291-07) supplies the only seed needed:
`https://cs-adwi-covsec-lab-1.eu`, described by the customer as the NestEgg Capital investment
site, "licensed by the Lower Dunwich Financial Supervisory Board". The task is Task 1 of the
Cloudflare Deanon pair — read the platform, not find its origin (that is the sibling challenge).

Fetching the public page is all that is needed:

```bash
curl -skL https://cs-adwi-covsec-lab-1.eu/ -o nestegg.html
```

**The answer.** The registration number is not buried: it is in the page title, the header and the
licensing line.

```html
<title>NestEgg Capital | Reg. No. NEC-7731-0049</title>
<meta name="description" content="NestEgg Capital, Reg. No. NEC-7731-0049. Guaranteed returns, paid weekly.">
...
<div class="reg">Reg. No. NEC-7731-0049</div>
...
Licensed by the Lower Dunwich Financial Supervisory Board | Licence LD-FSB-2210 | Reg. No. NEC-7731-0049
```

One `grep` is enough:

```bash
grep -o 'NEC-[0-9-]*' nestegg.html | sort -u
# NEC-7731-0049
```

**Why this is the whole task.** The challenge is deliberately split: the interesting work
(de-anonymising the host behind Cloudflare) is Task 2, and this first task only asks what the site
claims about itself. The answer boundary closes the obvious shortcuts — a company-registry lookup
is out of scope for a simulated company and would not match the platform's own displayed value, and
historically archived copies are likewise out of bounds.

**Dead ends.**

- **Registry lookup.** "Lower Dunwich" is fictional, and even a real registry hit would not be the
  value the simulated platform displays. The boundary says: displayed value only.
- **Wayback / cached copies.** The boundary rules out historical results; the live page is the
  source of truth.
- **Jumping to the origin hunt.** The IP behind Cloudflare is a different answer (sibling challenge
  "Cloudflare Deanon: Find the Origin"); it does not help here.

**Flag:** `CSCTF{NEC-7731-0049}`

The saved response is in `files/nestegg-capital.html`; the number appears at lines 5, 6, 37 and 47.

*AI: Hermes (DeepSeek 4.1 Flash) wrote this up from the team's saved page and submission note; the
flag is the value the platform accepted.*
