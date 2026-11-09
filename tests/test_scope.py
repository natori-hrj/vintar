import pytest

from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope


@pytest.fixture
def policy() -> ScopePolicy:
    return ScopePolicy(
        allowed_origins=frozenset(
            {
                AllowedOrigin("http", "localhost", 8000),
                AllowedOrigin("http", "127.0.0.1", 8000),
            }
        )
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://LOCALHOST:8000",
    ],
)
def test_allowed_scope(url: str, policy: ScopePolicy):
    validate_scope(url, policy)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9000",
        "http://example.com:8000",
        "http://evil-localhost:8000",
        "file:///etc/passwd",
        "ftp://localhost:8000",
    ],
)
def test_rejected_scope(url: str, policy: ScopePolicy):
    with pytest.raises(ValueError):
        validate_scope(url, policy)


def test_empty_allowed_origins():
    with pytest.raises(ValueError):
        ScopePolicy(allowed_origins=frozenset())


def test_invalid_port():
    with pytest.raises(ValueError):
        AllowedOrigin("http", "localhost", 70000)


def test_explicit_zero_port_is_not_treated_as_default_port():
    default_port_policy = ScopePolicy(
        allowed_origins=frozenset({AllowedOrigin("http", "localhost", 80)})
    )

    with pytest.raises(ValueError):
        validate_scope("http://localhost:0", default_port_policy)
