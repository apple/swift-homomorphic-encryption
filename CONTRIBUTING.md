# Welcome to the Swift Homomorphic Encryption community

Homomorphic encryption library and privacy-preserving applications in Swift.

We welcome contributors of all backgrounds and experience levels. A community with diverse perspectives builds software with lasting impact.

* 🤝 [How you can help](#how-you-can-help)
* ⚙️ [Setting up your environment](#setting-up-your-environment)
* 📝 [Submitting issues and pull requests](#submitting-issues-and-pull-requests)
* 🔀 [Pull requests](#pull-requests)
* ❤️ [Code of conduct](#code-of-conduct)

## How you can help

* Report mathematical or implementation bugs
* Improve documentation explaining cryptographic schemes and workflows
* Triage issues and test performance on various CPU architectures
* Propose algorithmic optimizations and hardware acceleration hooks

There may be a help wanted or good first issue to jump into as a springboard.

## Setting up your environment

Prerequisites:

* Swift 6.2 or later
* [pre-commit](https://pre-commit.com/)

Clone the repository and build:
```
git clone --recurse-submodules https://github.com/apple/swift-homomorphic-encryption.git
cd swift-homomorphic-encryption
swift build -c release
```

## Submitting issues and pull requests

We maintain high standards to ensure quality across the project.

Your contributions are evaluated on:

* Technical quality and correctness
* Adherence to existing conventions and architectural patterns
* Demonstrated understanding of the implementation and its implications
* Clarity of communication
* Maintainability

You may use productivity tools, including AI-assisted coding, to help you work more efficiently. However, you remain fully accountable for all submitted code, issues, pull requests, and comments. AI-generated content must meet the same standards as human-written contributions. Review, validate, and, as needed, refine or rearrange AI-assisted work so the final contribution reflects your human creativity, understanding, and control. Use your voice and expression when producing written materials. Misuse of AI tools in your contributions and conversations may be considered a violation of our Code of Conduct.

### Issues

Before submitting an issue:

* Search [existing issues](https://github.com/apple/swift-homomorphic-encryption/issues) to avoid duplicates.
* Write a clear, concise title and a detailed description. Ensure all information is accurate and fully understood by you.
* Include precise steps to reproduce the issue, expected behavior, and actual behavior. Verify these steps yourself.
* Specify your environment, Swift Homomorphic Encryption version, and any relevant configurations.
* Explain the severity and impact of the problem.
* For security issues, please see the [Swift Homomorphic Encryption security advisories](https://github.com/apple/swift-homomorphic-encryption?tab=security-ov-file). Do not open a public GitHub issue.

### Proposing features

We welcome feature requests. Describe the proposed changes needed and why they matter. Please do not start with a pull request. Use the issue template that best matches your needs.

### Help wanted and good first issues

https://github.com/apple/swift-homomorphic-encryption/contribute

Good first issues are mentoring opportunities. They help you learn the codebase, build your foundation as a contributor, and grow into an active participant in the community.

Help wanted issues are open to all contributors and often require deeper familiarity with the project.

These labels are about the journey, not the fastest path to a solution. If you use AI-assisted tools on these issues, use them in a way that supports your learning. Make sure you can explain your approach and that your work meets our standards above.

## Pull requests

⚠️ **Important**: You must submit an issue and consult with the cryptography team before proposing new cryptographic schemes, parameter sets, or serialization changes.

Pull requests represent proposed solutions or enhancements. When submitting a pull request, verify it meets these expectations:

* Address the stated problem or feature request completely and effectively. You must fully understand and validate your proposed solution.
* Solutions must be thorough, handle edge cases, and integrate cleanly.
* Include comprehensive tests that validate your changes and prevent regressions.

### Pull request style guide and format

Follow our coding style and formatting to maintain a consistent, readable codebase.

* Follow strict cryptographic validation conventions.
* Document mathematical foundations and references for every algorithm.
* Format code using the pre-commit suite [here](https://github.com/apple/swift-homomorphic-encryption/blob/main/.pre-commit-config.yaml).
* Write comprehensive and clear documentation. Concisely explain the reason behind complex decisions.
* Write clear, concise, and descriptive commit messages.

### Build
```
swift build -c release
```

### Testing

All contributions require thorough testing.

**Local testing**: Ensure all existing tests pass before submitting:
```
swift test -c release
```

**Automated tests**: New features and bug fixes require corresponding automated tests that validate the intended behavior and prevent regressions.

### Running CI

CI runs automatically on pull requests. It executes unit tests, numerical correctness tests, and performance benchmarks on macOS and Linux runners.

## Code of conduct

We are committed to fostering a community where different experiences and perspectives come together to create and collaborate. Good collaboration depends on honest feedback and respect for the time and effort every contributor brings to this project. [Please review our Code of Conduct](https://github.com/apple/.github/blob/main/CODE_OF_CONDUCT.md); all community members are expected to adhere to it.
