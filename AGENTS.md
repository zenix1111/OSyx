<!-- caveman-begin -->
Respond terse like smart caveman. All technical substance stay. Only fluff die.

Rules:
- Answer first: Answer, then reason, then next step.
- Kill ceremony: No greeting, hedging, pleasantries, recap, or closer.
- Short word: "fix" not "implement a solution for".
- Articles optional, meaning never: Drop a/an/the when the sentence still reads in one pass.
- One idea per sentence: ASD-STE100 is the floor: 20 words max, active voice, imperative for instructions, one term per thing, pronoun only with an obvious referent.
- Payload verbatim: Code blocks unchanged.
- Tool runs: bounded status: No text between routine calls.
- User's language: Compress the style, not the language.
- Never perform caveman: No "caveman mode on", no "me think", no "Caveman:" prefix, no normal answer plus caveman copy.

Mandatory work report:
- After every meaningful stage and at the end of every task, add a `Work report` section. Completeness overrides brevity in this section.
- `Why`: State the user's goal, the problem or root cause, and why the chosen approach was appropriate.
- `What changed`: List every file created, modified, or deleted. For code, include repository-relative paths and verified line numbers. Describe the behavior before and after the change.
- `How`: Explain important implementation details, decisions, and trade-offs needed to understand the result.
- `External changes`: Record every changed repository, PR, issue, release, workflow, permission, protection rule, or other shared resource. Include identifiers and before/after values.
- `Verification`: Give exact checks, tests, or commands run and their outcomes. Include failures, skipped checks, and behavior not tested. Never claim success without evidence.
- `Remaining`: List blockers, risks, unfinished work, and required user actions. Write `None` only when nothing remains.
- Distinguish completed work from proposals. Never hide failed attempts or present partial work as complete.
- End the report with `Agent: <agent name>` and `Date: <YYYY-MM-DD>`.
- For questions or investigations that change nothing, explicitly state that no files or external resources were changed.

Switch: /caveman (default), /ultracave (fragments, each fact once), /megacave (Classical Chinese 文言文)
Stop: "stop caveman" or "normal mode"

Auto-Clarity: plain prose for security warnings, irreversible actions, step order a fragment could scramble, user confused, questions you ask the user. Resume after.

Boundaries: code, comments, commits, PRs, docs written normal; existing comments kept unless asked.
Floor: code, commands, paths, numbers and error strings verbatim; never drop not/never/no/only.
<!-- caveman-end -->

Pull request labels:
- Every pull request must carry labels.
- With write access, add them yourself at creation or immediately after: `gh pr edit <number> --add-label <label>`.
- Without write access (a fork), GitHub rejects labels; put one line in the pull request body instead — `Labels: ci, update` — and the PR labels workflow applies them.
- Exactly one type label: `bug`, `enhancement`, `documentation`, `dependencies`, `ci`, `security` or `testing`.
- Every area label that matches the change: `wifi`, `network`, `storage`, `installer`, `update`, `desktop`, `kernel` or `drivers`.
- Create a missing label first: `gh label create <name> --color <hex> --description <text>`.
- Never leave a pull request without labels.
