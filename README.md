# Vintar

**Precision Security Toolkit**

Vintar is a modular, standalone security testing toolkit written in Python.

Built for learning, experimenting with, and understanding web security vulnerabilities through hands-on development.

The project focuses on precise vulnerability verification, automation, and extensibility without depending on external security testing tools.

> [!NOTE]
> Vintar is in early development. The current version provides basic HTTP request and response inspection. Vulnerability testing modules are planned.

## Features

### Available

- Standalone CLI powered by Typer
- HTTP GET and POST requests
- Custom HTTP request bodies
- HTTP response status inspection
- Response time measurement
- Response body size measurement
- Automated tests using pytest

### Planned

- Custom HTTP headers and cookies
- Query parameter handling
- SQL injection testing module
- Boolean-based and time-based blind SQL injection verification
- Automated response analysis
- Binary search optimization
- JSON reporting
- Additional security testing modules

## Requirements

- Python 3.13+
- uv

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/<your-username>/vintar.git
cd vintar
uv sync
```

## Usage

Display available commands:

```bash
uv run vintar --help
```

Check the version:

```bash
uv run vintar version
```

Send an HTTP GET request:

```bash
uv run vintar http send GET http://127.0.0.1:8000/
```

Send an HTTP POST request:

```bash
uv run vintar http send POST http://127.0.0.1:8000/ \
  --body '{"message":"hello vintar"}'
```

Example output:

```text
Target: http://127.0.0.1:8000/
Method: GET
Status: 200
Response time: 0.004s
Content size: 527 bytes
```

## Development

Run tests:

```bash
uv run pytest -v
```

Run lint checks:

```bash
uv run ruff check .
```

Format code:

```bash
uv run ruff format .
```

## Architecture

```text
src/vintar/
├── __init__.py
├── cli.py
└── core/
    ├── __init__.py
    └── http.py
```

Vintar separates CLI commands from core HTTP functionality.

Future vulnerability testing modules will use the shared HTTP client instead of implementing their own networking logic.

## Roadmap

- [x] Initialize Python project with uv
- [x] Implement CLI foundation
- [x] Implement HTTP GET and POST support
- [x] Add request body support
- [x] Add HTTP response inspection
- [x] Add automated HTTP client tests
- [ ] Add custom headers and cookies
- [ ] Add query parameter support
- [ ] Introduce structured request and response models
- [ ] Implement the first SQL injection testing module
- [ ] Add reporting and result export
- [ ] Expand vulnerability testing modules

## Security

Vintar is intended for educational purposes and authorized security testing only.

Only use Vintar against systems you own or have explicit permission to test.

## License

A license has not yet been selected.
