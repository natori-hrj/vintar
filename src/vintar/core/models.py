from dataclasses import dataclass


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    elapsed: float
    body: bytes
    headers: dict[str, str]
    truncated: bool = False

    @property
    def size(self) -> int:
        return len(self.body)
