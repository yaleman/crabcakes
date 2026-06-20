# Agents

## Error handling

- Represent each behaviorally distinct failure as a `CrabCakesError` variant.
- Derive HTTP status codes, redirects, and UI actions by matching the variant. `Display` text is presentation-only and must never drive control flow.
