from dataclasses import replace

from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)


def inject(
    template: RequestTemplate,
    point: InjectionPoint,
    payload: str,
) -> RequestTemplate:
    """Inject a raw, unencoded payload into the request template.

    The HTTP transport layer is responsible for URL encoding.
    The original template is never modified.
    """

    if point.location != InjectionLocation.QUERY:
        raise ValueError("Unsupported injection location.")

    params = list(template.params)
    occurrence = 0

    for index, (name, value) in enumerate(params):
        if name != point.name:
            continue

        if occurrence == point.occurrence:
            if point.mode == InjectionMode.REPLACE:
                new_value = payload
            elif point.mode == InjectionMode.APPEND:
                new_value = value + payload
            else:
                raise ValueError("Unsupported injection mode.")

            params[index] = (name, new_value)

            return replace(template, params=tuple(params))

        occurrence += 1

    raise ValueError(
        f"Injection point not found: {point.name} (occurrence={point.occurrence})"
    )
