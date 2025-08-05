# Rule Guidelines

- **Meta fields**: Always include `description`, `author`, `platform`, `threat_type`, and `updated`.
- **Strings section**: Use `nocase`, `ascii`, or `wide` modifiers as needed.
- **Condition section**: Avoid overly permissive patterns; prefer `any of` or `2 of` over `all of`.
- **Cross-platform awareness**: Use platform‑specific strings if necessary, wrapped with include logic or separate rule toggles.
- **Testing**: Use benign and malicious sample sets to fine-tune.
