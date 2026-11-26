"""Pure runtime target binding for validated regression cases."""

from dataclasses import replace

import httpx

from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.regression.cases import AnyRegressionCase
from vintar.regression.cases_v2 import PostJsonRegressionCase, QueryRegressionCaseV2


def parse_runtime_origin(value: str) -> AllowedOrigin:
    """Parse one unambiguous HTTP(S) origin."""
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "?" in value
        or "#" in value
        or "@" in value
        or "\\" in value
        or "%" in value
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError("Invalid origin.")

    authority = value.partition("://")[2].removesuffix("/")
    if not authority or authority.endswith(":"):
        raise ValueError("Invalid origin.")

    url = httpx.URL(value)

    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
        or url.path not in {"", "/"}
        or url.query
        or url.fragment
    ):
        raise ValueError("Invalid origin.")

    port = url.port
    if port is None:
        port = 443 if url.scheme == "https" else 80

    return AllowedOrigin(
        scheme=url.scheme,
        host=url.host,
        port=port,
    )


def bind_runtime_target(
    case: AnyRegressionCase,
    *,
    target: AllowedOrigin,
    trusted_scope: ScopePolicy,
    post_json_policy: object | None = None,
) -> AnyRegressionCase:
    """Copy a validated case onto an independently authorized origin.

    Schema v1's original absolute origin is a placeholder in this workflow.
    The raw request path and all injection inputs remain unchanged.
    """
    if not isinstance(case, AnyRegressionCase):
        raise TypeError("Invalid regression case.")
    if type(target) is not AllowedOrigin:
        raise TypeError("Invalid runtime target.")
    if type(trusted_scope) is not ScopePolicy:
        raise TypeError("Invalid trusted scope.")

    if target not in trusted_scope.allowed_origins:
        raise ValueError("Runtime target is not authorized.")

    original_url = (
        case.url
        if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2))
        else case.template.url
    )
    original = httpx.URL(original_url)
    rebound_url = original.copy_with(
        scheme=target.scheme,
        host=target.host,
        port=target.port,
    )

    if rebound_url.raw_path != original.raw_path:
        raise ValueError("Runtime target binding changed the request path.")

    if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2)):
        from vintar.regression.post_json_policy import PostJsonRuntimePolicy

        if post_json_policy is None:
            raise ValueError(
                "post_json_runtime_policy_required: POST JSON target binding has no trusted runtime policy. Supply trusted operator policy independently of the case and specification."
            )
        if not isinstance(post_json_policy, PostJsonRuntimePolicy):
            raise TypeError("Invalid POST JSON runtime policy.")
        candidates = tuple(
            approval
            for approval in post_json_policy.approvals
            if approval.case_id == case.case_id
            and approval.identity_id == case.identity_id
        )
        if not candidates:
            raise ValueError(
                "post_json_case_not_approved: The trusted runtime policy does not approve this case identifier. Add an exact operator-controlled approval or bind a different reviewed case."
            )
        case_method = "POST" if isinstance(case, PostJsonRegressionCase) else "GET"
        case_path = (
            case.approval.path
            if isinstance(case, PostJsonRegressionCase)
            else original.path
        )
        matches = tuple(
            approval
            for approval in candidates
            if approval.method == case_method
            and approval.path == case_path
            and approval.origin == target
        )
        if len(matches) != 1:
            raise ValueError(
                "post_json_operation_not_approved: The trusted runtime policy does not approve the exact POST operation and origin. Approve the bound origin and reviewed literal path in trusted operator configuration."
            )
        approval = matches[0]
        environment_class = (
            case.approval.environment_class
            if isinstance(case, PostJsonRegressionCase)
            else case.environment_class
        )
        post_mismatch = isinstance(case, PostJsonRegressionCase) and (
            approval.operation_definition_sha256
            != case.approval.operation_definition_sha256
            or approval.baseline_body_sha256 != case.approval.baseline_body_sha256
            or case.approval.side_effect != "no_side_effect"
            or approval.allowed_side_effect != "no_side_effect"
        )
        if (
            post_mismatch
            or environment_class not in approval.allowed_environment_classes
        ):
            raise ValueError(
                "post_json_approval_mismatch: The reviewed case does not intersect the trusted runtime approval. Review the operation, baseline, environment, and no_side_effect classification, then update trusted policy independently."
            )
        if isinstance(case, PostJsonRegressionCase):
            post_rebound = replace(
                case,
                url=str(rebound_url),
                scope=ScopePolicy(allowed_origins=frozenset({target})),
            )
            validate_scope(post_rebound.url, trusted_scope)
            return post_rebound
        query_rebound = replace(
            case,
            url=str(rebound_url),
            scope=ScopePolicy(allowed_origins=frozenset({target})),
        )
        validate_scope(query_rebound.url, trusted_scope)
        return query_rebound

    rebound = replace(
        case,
        template=replace(case.template, url=str(rebound_url)),
        scope=ScopePolicy(allowed_origins=frozenset({target})),
    )

    # Case reconstruction revalidates the full injection plan.
    validate_scope(rebound.template.url, trusted_scope)
    return rebound
