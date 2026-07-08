# Security Policy

## Scope & Intended Use

MonarchDomain is a passive/active recon tool built for **authorized** security
testing - bug bounty programs you're enrolled in, or engagements you have
explicit written permission for. Running it against systems without
authorization may be illegal in your jurisdiction.

## Reporting a Vulnerability in MonarchDomain Itself

If you find a security issue *in this tool's code* (e.g. command injection via
a crafted domain/wordlist, unsafe file handling), please report it privately:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this repo, or
- Email the maintainer directly (see GitHub profile) instead of filing a public issue.

Please include:
- Affected version (`monarchdomain.sh --version`)
- Steps to reproduce
- Impact assessment

We aim to acknowledge reports within 5 business days.

## Responsible Disclosure for Findings Made *Using* This Tool

MonarchDomain may surface real vulnerabilities on third-party targets. Any
such findings must be reported to the target owner (or their bug bounty
program) through their own disclosure process - not through this repository's
issue tracker.
