# Vintar

**Precision Security Toolkit**

Vintar is a modular, standalone security testing toolkit written in Python.

Built for learning, experimenting with, and understanding web security vulnerabilities through hands-on development.

The project focuses on precise vulnerability verification, automation, and extensibility without depending on external security testing tools.

> [!NOTE]
> Vintar is in early development. The current version provides HTTP request and response inspection, configurable timeouts, and response size limits. Vulnerability testing modules are under development.

## Features

### Available

- Standalone CLI powered by Typer
- HTTP GET and POST requests
- Custom HTTP request bodies
- Custom HTTP headers and cookies
- Query parameter handling, including repeated parameter names
- HTTP response status and header inspection
- Response time measurement
- Structured HTTP response model (`HttpResult`)
- Response body capture and size measurement
- Configurable HTTP request timeouts
- Streaming response handling with configurable size limits
- Truncated response detection
- Automated tests using pytest
- Code linting and formatting with Ruff

### Planned

- Structured HTTP request templates
- Injection point identification and payload placement
- SQL injection testing module
- Boolean-based and time-based blind SQL injection verification
- Automated response analysis and false-positive reduction
- Request rate limiting and execution budgets
- Binary search optimization
- JSON reporting and result export
- Additional security testing modules

## Requirements

- Python 3.13+
- uv

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/natori-hrj/vintar.git
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

Send a request with custom headers:

```bash
uv run vintar http send GET http://127.0.0.1:8000/ \
  --header "X-Test: vintar"
```

Send a request with cookies:

```bash
uv run vintar http send GET http://127.0.0.1:8000/ \
  --cookie "session=test123"
```

Send a request with query parameters:

```bash
uv run vintar http send GET http://127.0.0.1:8000/ \
  --param "category=Pets" \
  --param "page=1"
```

Configure the request timeout:

```bash
uv run vintar http send GET http://127.0.0.1:8000/ \
  --timeout 15
```

Example output:

```text
Target: http://127.0.0.1:8000/
Method: GET
Status: 200
Response time: 0.004s
Content size: 527 bytes
```

### HTTP Response Model

The HTTP core returns a structured `HttpResult` object.

```python
result.status_code
result.elapsed
result.body
result.headers
result.size
result.truncated
```

Responses are read using streaming with a configurable maximum body size.

When a response exceeds the configured limit, Vintar retains the captured portion and marks the result as truncated.

The default maximum response size is 1 MiB.

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

Check formatting without modifying files:

```bash
uv run ruff format --check .
```

## Architecture

```text
src/vintar/
├── __init__.py
├── cli.py
└── core/
    ├── __init__.py
    ├── http.py
    └── models.py
```

Vintar separates CLI commands, HTTP transport, and response models.

Future vulnerability testing modules will reuse the shared HTTP core rather than implementing their own networking logic.

The planned SQL injection module will separate request templates, payload generation, injection, response analysis, and scanning orchestration.

## Roadmap

- [x] Initialize Python project with uv
- [x] Implement CLI foundation
- [x] Implement HTTP GET and POST support
- [x] Add request body support
- [x] Add custom headers and cookies
- [x] Add query parameter support
- [x] Introduce structured HTTP response model
- [x] Add configurable request timeout
- [x] Implement streaming response size limits
- [x] Add truncated response detection
- [x] Add automated HTTP client tests
- [ ] Introduce structured request templates
- [ ] Implement injection point handling
- [ ] Add request rate limiting and execution budgets
- [ ] Implement Boolean-based SQL injection verification
- [ ] Add automated response analysis
- [ ] Implement Time-based SQL injection verification
- [ ] Add JSON reporting and result export
- [ ] Expand vulnerability testing modules

## Security

Vintar is intended for educational purposes and authorized security testing only.

Only use Vintar against systems you own or have explicit permission to test.

## License

A license has not yet been selected.
