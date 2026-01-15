using System.Text;

namespace Dipsy.Security.Ldap;

public static class LdapEncoder
{
    // RFC 4515: Escape *, (, ), \, NUL in LDAP filter values.
    // Also escape / and control chars for defense in depth.
    // 
    // This escapes the VALUE portion in filter comparisons (e.g., the user input in (uid={value}))
    // NOT the filter syntax operators. Don't escape the &, |, (, ), = that form the filter structure.
    // Example: (&(givenName={EscapeThis})(sn={EscapeThis})(department={EscapeThis}))
    // 
    public static string? EscapeFilterValue(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // Convert to UTF-8 bytes first (handles multi-byte characters correctly)
        byte[] utf8Bytes = Encoding.UTF8.GetBytes(input);
        var sb = new StringBuilder(utf8Bytes.Length * 3); // Each byte can be \XX

        foreach (byte b in utf8Bytes)
        {
            switch (b)
            {
                // Required escapes per RFC 4515
                case 0x5c: sb.Append(@"\5c"); break; // \
                case 0x2a: sb.Append(@"\2a"); break; // *
                case 0x28: sb.Append(@"\28"); break; // (
                case 0x29: sb.Append(@"\29"); break; // )
                case 0x00: sb.Append(@"\00"); break; // NUL

                // OWASP recommends escaping / (forward slash)
                // Not in RFC 4515 minimal set but provides defense in depth
                case 0x2f: sb.Append(@"\2f"); break; // /

                // Escape control chars (0x00-0x1F, 0x7F) and high bytes (0x80-0xFF)
                // Control chars avoid parsing edge cases
                // High bytes (0x80+) are from UTF-8 multi-byte sequences
                default:
                    if (b < 0x20 || b >= 0x7F)
                        sb.Append('\\').Append(b.ToString("x2"));
                    else
                        sb.Append((char)b); // Safe ASCII printable character
                    break;
            }
        }

        return sb.ToString();
    }

    // RFC 4514: Escape leading '#', ALL leading/trailing spaces, and: , + " \ < > ; =
    // Also escape control chars.
    // 
    // ⚠️ IMPORTANT: Only use this if you truly must construct a DN from untrusted input.
    // Prefer searching by attribute (escaped filter value) and using the DN returned by the directory.
    // 
    // This escapes the VALUE portion of an RDN (e.g., the "John Doe" in CN=John Doe)
    // NOT the entire DN structure. Don't escape the commas and equals that separate RDN components.
    // Example: CN=<EscapeThisValue>,OU=<EscapeThisValue>,DC=example,DC=com

    public static string? EscapeDnValue(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var runes = input.EnumerateRunes().ToArray();

        int leadingSpaces = 0;
        while (leadingSpaces < runes.Length && runes[leadingSpaces].Value == 0x20)
            leadingSpaces++;

        int trailingSpaces = 0;
        while (trailingSpaces < runes.Length && runes[runes.Length - 1 - trailingSpaces].Value == 0x20)
            trailingSpaces++;

        var sb = new StringBuilder(input.Length * 2);
        Span<byte> utf8 = stackalloc byte[4];

        for (int runeIndex = 0; runeIndex < runes.Length; runeIndex++)
        {
            Rune rune = runes[runeIndex];

            if (rune.Value == 0x20)
            {
                if (runeIndex < leadingSpaces || runeIndex >= runes.Length - trailingSpaces)
                {
                    sb.Append(@"\ ");
                    continue;
                }
            }

            if (rune.Value == (int)'#' && (runeIndex == 0 || runeIndex == leadingSpaces))
            {
                sb.Append(@"\#");
                continue;
            }

            if (rune.IsAscii)
            {
                char c = (char)rune.Value;
                switch (c)
                {
                    case '\\': sb.Append(@"\\"); break;
                    case ',': sb.Append(@"\,"); break;
                    case '+': sb.Append(@"\+"); break;
                    case '"': sb.Append("\\\""); break;
                    case '<': sb.Append(@"\<"); break;
                    case '>': sb.Append(@"\>"); break;
                    case ';': sb.Append(@"\;"); break;
                    case '=': sb.Append(@"\="); break; // optional
                    case '\0': sb.Append(@"\00"); break;
                    default:
                        if (c < 0x20 || c == 0x7F)
                            sb.Append('\\').Append(((int)c).ToString("x2"));
                        else
                            sb.Append(c);
                        break;
                }
            }
            else
            {
                int n = rune.EncodeToUtf8(utf8);
                for (int i = 0; i < n; i++)
                    sb.Append('\\').Append(utf8[i].ToString("x2"));
            }
        }

        return sb.ToString();
    }
}
