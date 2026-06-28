from __future__ import annotations

from ida_pseudoforge.core.projection_policy import (
    DEFAULT_PROJECTION_POLICY,
    normalize_projection_policy,
    projection_policy_choices,
    projection_policy_description,
    projection_policy_label,
)

try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None


def ask_projection_policy(current_policy: str = DEFAULT_PROJECTION_POLICY, warn=None) -> str | None:
    if ida_kernwin is None:
        return normalize_projection_policy(current_policy)

    choices = projection_policy_choices()
    labels = [
        "%s - %s" % (projection_policy_label(policy), projection_policy_description(policy))
        for policy in choices
    ]
    current = normalize_projection_policy(current_policy)
    try:
        selected_index = choices.index(current)
    except ValueError:
        selected_index = 0

    form = None
    try:
        form = ida_kernwin.Form(
            r"""BUTTON YES* Analyze
BUTTON CANCEL Cancel
PseudoForge Analyze projection policy

<Projection policy:{policy}>
""",
            {
                "policy": ida_kernwin.Form.DropdownListControl(
                    items=labels,
                    readonly=True,
                    selval=selected_index,
                    swidth=78,
                ),
            },
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            return None
        selected = int(form.policy.value)
        if selected < 0 or selected >= len(choices):
            if warn is not None:
                warn("Invalid PseudoForge projection policy selection.")
            return None
        return choices[selected]
    finally:
        if form is not None:
            try:
                form.Free()
            except Exception:
                pass


def format_projection_policy_summary(policy: str) -> str:
    normalized = normalize_projection_policy(policy)
    return "Projection policy: %s (%s)" % (
        projection_policy_label(normalized),
        projection_policy_description(normalized),
    )
