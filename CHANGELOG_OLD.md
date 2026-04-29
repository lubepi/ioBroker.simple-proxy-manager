# Older changes
## 0.1.5 (2026-03-13)

- Fix GitHub repository checker issues (E8903, E8912)
- Migrate dependabot automerge workflow to new iobroker-bot-orga action
- Add github-actions ecosystem to dependabot config
- Add CI workflow dependency: adapter-tests now requires check-and-lint
- Add auto-merge configuration

## 0.1.4

- Add CI/CD workflows (test-and-release) and adapter tests
- Add dependabot auto-merge workflow
- Fix: use `this.setInterval`/`this.clearInterval` per ioBroker best practices
- Fix: remove redundant mocha devDependency (included in @iobroker/testing)
- Clean up README installation section

## 0.1.3

- Add ESLint with @iobroker/eslint-config, auto-fix all issues
- Add @alcalzone/release-script with all plugins
- Add .vscode/settings.json with JSON schema definitions

## 0.1.2

- Update dependencies to satisfy adapter checker requirements
- Add responsive layout (xs/lg/xl) to jsonConfig
- Add Changelog and License sections to README

## 0.1.1

- Fix crash on unknown HTTPS host (421 response instead of UNCAUGHT_EXCEPTION)
- Add i18n for all 11 ioBroker languages
- Update dependencies (@iobroker/adapter-core, @iobroker/testing)

## 0.1.0

- Initial release
