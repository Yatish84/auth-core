# Agent Instructions

## Token Optimization & Workflow Rules
- **Concise communication:** Keep explanations and status updates brief; do not restate full architectural plans on every turn.
- **Narrow scope:** Implement only the specifically requested sub-task without expanding into unrequested features.
- **Targeted reads:** Inspect only specific functions or targeted files rather than scanning entire directories.
- **Focused tests:** Run only the relevant, single-file test commands (e.g., specific `pytest` files) rather than full test suites.
- **No unnecessary file touches:** Do not reformat or modify files unrelated to the active task.