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

   API messages (`message`, `error_message` of per-row errors) quote the animal number, and that
   explanation is what the assistant needs. In those fields only, an animal-number token (14 or
   15 digits, `BR` + 15 digits, DFID; a 14-digit token that is a valid CNPJ is not kept) is held
   aside before the scrub and put back after it. The rest of the message is scrubbed as usual.
   Partner free text (`motivo` and the like) has no such exemption.

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
