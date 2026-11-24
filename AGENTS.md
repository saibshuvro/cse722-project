# Repository Agent Instructions

## Git ownership

- The user creates commits manually.
- Do not run `git commit`, `git push`, `git tag`, or amend/rebase commits unless the user explicitly requests that Git operation.
- It is acceptable to inspect Git status and diffs when preparing a requested commit message.

## Commit-message assistance

When the user asks for a commit message:

1. Base the message on the actual staged diff. If nothing is staged, use the current working-tree diff and make that clear.
2. Return one complete, copy-ready commit message in a fenced text block.
3. Use Conventional Commit style with an imperative subject, normally no longer than 72 characters.
4. Add a concise body when the changes cover multiple files or need context.
5. Leave one blank line before co-author trailers.
6. Preserve relevant existing trailers and never add the same trailer twice.
7. Do not create the commit; the user will copy the message and commit the changes.

Append the trailer belonging to the assistant that prepared the commit message:

- Codex: `Co-authored-by: Codex <codex@openai.com>`
- Claude: `Co-authored-by: Claude <noreply@anthropic.com>`

If both assistants materially contributed to the changes covered by the commit, include both trailers, each on its own line. Do not attribute an assistant that did not contribute.
