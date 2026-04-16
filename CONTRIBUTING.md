# Contributing to Auto XDP

Thanks for your interest in improving Auto XDP. >w<

## Ways to Contribute

- Report bugs and regressions
- Suggest improvements
- Improve documentation
- Submit code changes for fixes or new features

## Before Start

1. Check existing [issues](https://github.com/Kookiejarz/Auto_XDP/issues) and open a new one if needed.
2. Keep changes focused and minimal. State reason(s) for big change(s) in major logic flows in order for passing quick inspections.

## Getting Started

1. Fork the repository and create a branch:
   - `feature/<short-description>` for features
   - `fix/<short-description>` for bug fixes
   - `docs/<short-description>` for documentation
2. Make your changes with clear commits.
3. Run local checks (see below).
4. Open a Pull Request against `main` with:
   - What changed
   - Why it changed
   - What is its impact regarding the project
   - Is there any alternative solution for this issue that you've considered? (Mandatory for PRs under `fix` section)
   - How it was validated

## Local Validation

Run the same baseline checks used in CI:

```bash
bash -n setup_xdp.sh
bash -n axdp
python3 -m py_compile xdp_port_sync.py
bash ./setup_xdp.sh --dry-run
bash ./setup_xdp.sh --help >/dev/null
```

## Coding Guidelines

- Follow existing style in each file.
- Avoid unrelated refactors in the same PR.
- Keep shell scripts portable.
- Keep changes compatible with the project’s current runtime usage.

## Pull Request Expectations

- One logical change per PR whenever possible.
- Include testing notes in the PR description.
- Be responsive to review feedback and follow-up questions.

## Security

If you discover a security issue, please open an issue with clear reproduction details and impact notes.
Avoid committing secrets, credentials, or private infrastructure details.

## In the End

Thanks again for contributing to Auto XDP! Every suggestion means a loooooot to me! <3 ❤️

## License

By contributing, you agree that your contributions are provided under the project’s [MIT License](./LICENSE).
