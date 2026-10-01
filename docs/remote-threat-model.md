# Remote MCP: threat model of the output policy

The remote MCP (`mcp.defarm.net`) lets a partner's AI assistant read what the partner's API key
can already read. What the tools return goes to a third-party LLM provider. This document says
what the output policy (`forModel` in `src/remote/tools.ts`) protects against, and what it does
not.

## In scope: accidental personal data from partners

Partners write free-form data into DeFarm: row columns become item metadata, and event payloads
are free. An ERP can put a CPF, a phone number or an e-mail in an observation field, in any common
human formatting. The policy keeps that from reaching the LLM provider by default:

1. **Fail-closed keys.** Only allowlisted keys pass. Personal and location keys are denied by
   substring, and any unknown key becomes `"[omitido]"`.
2. **Identifiers by format.** The value of an identifier (SISBOV, chip, DFID, UUID, hash, CID,
   trusted URL path) passes untouched only when the whole value matches the expected format.
3. **Free text** (every other string) goes through three layers:
   - a scrub of CPF, CNPJ, Brazilian phone numbers and e-mails, also on the percent-decoded
     value and after mapping every Unicode digit to ASCII;
   - **code-like values are cut whole**: escapes and entities (`&#`, `%u`, `\u`), percent-encoding
     left over after decoding, base64 or hex tokens of 16 or more characters, and 8 or more digits
     once separators, zero-width characters and spelled-out digits are removed. ISO and BR dates,
     year ranges and DFIDs do not count;
   - **a length cap**: 120 characters, or 400 for API messages, with `…[truncado]`.

   **Numbers of the animal itself (decision of 2026-10-01).** A run of 8 or more digits in free
   text is omitted, unless it is an animal identifier already known in the same context of the
   response, with an animal type:
   - in a per-row error: the `identifier_value` of that error (for a tag replacement, the
     replaced number);
   - in an animal's detail or history: its `identifiers[]` and canonical identifiers (SISBOV,
     numeroElementoIdentificacao, chip), and only for that item, never its list siblings.

   A number with a non-animal type (CPF, CNPJ, document) never releases text. DFIDs are kept by
   format. This applies only to API messages, anchored on the response path (`errors[].message`,
   top-level `error_message`, `result_summary.errors[].message`, `rows[].error_message`), and to
   public-fact fields (`motivo`, vaccine, medication...). A `message` key anywhere else, such as in
   a payload or partner metadata, is ordinary free text. A generic 14- or 15-digit pattern is not
   used: it also matches other national numbers, such as the 15-digit health card (CNS).

   How preservation works:
   - **Detection ignores the preserved number.** Detection runs on the remaining text with the
     known number removed, so digits on both sides of it still add up. In
     `52998 <known> 224725`, the 11 digits of a CPF are still caught.
   - **Composite identifier values.** A value such as `A,B` (written by `ambiguous_identifier`) is
     split. Each part is checked and preserved on its own, and the structured `identifier_value`
     passes only when every part matches the format.
   - **API messages are masked token by token.** They are DeFarm templates, so only the offending
     token becomes `[omitido]` and the explanation stays. Partner free text and fact fields are
     still omitted whole.
   - **No in-band marker.** Text is split into kept and free pieces, so nothing in the input can
     imitate a marker. Private-use characters (BMP and planes 15/16) and zero-width characters
     are also stripped from all input first.
   - **The length cap never splits a kept number or a DFID.** It cuts before them.

   **GTA (decision of 2026-10-01).** The GTA number is not sent to the LLM provider. A movement
   event keeps its type and date. A GTA number in free text falls under the 8+ digit rule.

A person's name in free text cannot be detected reliably. The untrusted-data notice tells the
assistant that free text may still contain personal data and must not be repeated verbatim.

## Out of scope: deliberate obfuscation by the author of the data

Anyone who writes data into a circuit can encode it in ways no filter enumerates: base32, ROT13,
digits in emoji, numbers in words in another language, and so on. That author already has the
data and has the API and CSV exports. The MCP filter is not the boundary against them, and the
structural controls above are meant to keep accidents out, not to stop a determined author.

## Prompt injection

Partner-written content can contain text aimed at the reader's assistant. This is mitigated by
the **untrusted-data envelope**: every tool result with partner data comes as `{notice, data}`, and
the notice says that `data` is data to report, never instructions. The output filter does not
attempt to detect injection.

## Workspace isolation

Which items, events and ingestions a key can see is decided by the DeFarm API, not by the MCP. The
MCP has no credential of its own: it forwards the partner's key on every call. A filter bug can
leak a field of data the key could already read; it cannot widen what the key can read.
