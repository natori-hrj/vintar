"""Shared YAML parsing for workflow action policy tests."""

import yaml


def collect_workflow_uses(source: str) -> tuple[str, ...]:
    """Collect job and step ``uses`` values from parsed workflow YAML."""
    workflow = yaml.safe_load(source)
    assert type(workflow) is dict, "Workflow YAML must contain a top-level mapping."
    jobs = workflow.get("jobs")
    assert type(jobs) is dict, "Workflow YAML must contain a jobs mapping."
    values: list[str] = []
    for job_id, job in jobs.items():
        assert type(job) is dict, f"Workflow job {job_id!r} must be a mapping."
        entries = (job, *job.get("steps", []))
        for entry in entries:
            assert type(entry) is dict, (
                f"Workflow job {job_id!r} contains a non-mapping step."
            )
            uses = entry.get("uses")
            if uses is not None:
                assert type(uses) is str, (
                    f"Workflow job {job_id!r} has a non-string uses value."
                )
                values.append(uses)
    return tuple(values)
