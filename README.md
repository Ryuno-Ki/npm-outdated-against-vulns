# npm-outdated-against-vulns

Exploring, whether `npm outdated` can be matched with vuln db

Currently it does two things:

1. Running `npm outdated --json` as child process (because npm's API is ugly)
2. Fetching the RSS feed of SNYK.io's Vulnerability Database and parsing it

The idea is to have this script run on startup of a server or while CI (say,
by Jenkins).

This way you are not only informed about outdated packages, but also whether
you need to update them in order to mitigiate security risks.

## License

Because of the terms of uses of SNYK.io's feed, this project is licensed as
OpenSource Software under AGPL-v3. See [LICENSE](./LICENSE) for details.
