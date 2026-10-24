# Contributing to APK Blueprint Analyzer

Thank you for your interest in contributing! This guide will help you get
started.

## Code of Conduct

Please treat all contributors and users with respect. We are committed to
providing a welcoming and inclusive experience for everyone.

## Scope of Contributions

APK Blueprint Analyzer is a **read-only static analysis** tool. Contributions
must align with this mission:

### ✅ Welcome

- New analyzers that extract information from APK contents
- Improved detection of libraries, SDKs, or frameworks
- Better permission explanations and risk assessments
- Report format improvements (Markdown, JSON, HTML)
- Documentation improvements and usage examples
- Bug fixes and test coverage improvements
- Performance optimizations
- Accessibility and internationalization

### ❌ Out of Scope

- APK modification, repacking, or patching capabilities
- License-bypass or DRM-circumvention features
- Malware generation or distribution tooling
- Obfuscation-defeat mechanisms designed for piracy
- Any feature that facilitates unauthorized use of applications

## Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/your-username/apk-blueprint-analyzer.git
   cd apk-blueprint-analyzer
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

3. **Install in editable mode with dev dependencies**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests**

   ```bash
   pytest
   ```

## Adding a New Analyzer

1. Create a new module in `src/apk_blueprint_analyzer/` (e.g.,
   `my_analyzer.py`).
2. Implement a class or function that accepts parsed APK data and returns
   structured results.
3. Register it in `report_generator.py` so it is included in the output
   pipeline.
4. Add a corresponding report section generator.
5. Write tests in `tests/test_my_analyzer.py`.
6. Update `docs/architecture.md` if the analyzer introduces a new concept.

## Pull Request Guidelines

- **Branch naming**: `feature/short-description` or `fix/short-description`
- **Commit messages**: Use clear, imperative-mood messages (e.g., "Add SDK
  version detector")
- **Tests**: Every new feature or bug fix should include tests
- **Type hints**: All public functions must have complete type annotations
- **Docstrings**: Every public function and class must have a docstring
- **Lint**: Run `flake8` and `mypy` before submitting

## Reporting Issues

Please open an issue with:

- A clear title and description
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
