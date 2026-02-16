### Purpose

This directory contains Markdown sources for manual pages (section 1) for the
POK tools. Each file should read like a `man` page: concise, consistent, and
focused on usage.

### File naming

- Use one command per file.
- Name the file after the command, for example `pok-client.md`.

### Required sections and order

Use these sections in this order:

- `### NAME`
- `### SYNOPSIS`
- `### DESCRIPTION`
- `### OPTIONS`
- `### EXAMPLES`
- `### SEE ALSO`

Optional sections (only when relevant) include:

- `### SIGNALS`
- `### ENVIRONMENT`
- `### FILES`
- `### EXIT STATUS`
- `### SECURITY NOTES`

### Style rules

- **Language**: English only.
- **Headings**: Use `###` headings as shown above.
- **Line wrapping**: Prefer wrapping prose at ~80 columns. Do not reflow
  unrelated text.
- **NAME line**:
  - Format: `command - one-line description`
  - Use an ASCII hyphen (`-`), not an em dash.
  - Keep it lowercase and punctuation-free (no trailing period).
- **Typography in prose**:
  - Command names: bold, for example **pok-client**.
  - Literal flags, keywords, file paths, and record types: backticks, for
    example ``-k``, `host:port`, `keydir/public/<keyID>`, `TXT`.
  - Placeholders / metavariables: italics, for example *keydir*, *HOST*,
    *PORT*, *prog*.
- **Terminology**:
  - Use stable phrasing for repeated concepts (for example, prefer “Suppress
    error messages.” for quiet mode across pages).
  - Keep hyphenation consistent (for example, “key-exchange timeout”).
  - Use consistent identifier spelling (for example, `serverID`, `gatewayID`).

### OPTIONS formatting (definition lists)

Write options and positional arguments using Markdown definition lists:

`-q`
:   Quiet mode. Suppress error messages.

`-k` *keydir*
:   Server key directory (required).

*HOST*
:   Server hostname or IP address to connect to.

Rules:

- Put the option (or argument) on its own line.
- Put the description on the next line, starting with `:   ` (a single colon,
  three spaces).
- Indent wrapped continuation lines by 4 spaces so they align visually.
- If an option takes a value, show the placeholder after the flag (italic),
  and use a meaningful name (`*seconds*`, `*hex-string*`, `*pattern*`).

### EXAMPLES

- Use fenced code blocks with `bash`.
- Include short comments for context.
- Include representative output only when it helps understanding.

### SEE ALSO

- Use `command(1)` references.
- Keep the list short and relevant.

### Template

Use this as a starting point:

````text
### NAME

command - one-line summary

### SYNOPSIS

`command [options] ARG ...`

### DESCRIPTION

Describe what the command does, the mental model, and any important
constraints.

### OPTIONS

`-q`
:   Quiet mode. Suppress error messages.

*ARG*
:   Describe positional arguments.

### EXAMPLES

```bash
command --example
```

### SEE ALSO

other-command(1)
````
