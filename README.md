# LdapEncoder

A .NET library for securely encoding LDAP filter values and Distinguished Name (DN) values to prevent LDAP injection attacks.

[![.NET 10](https://img.shields.io/badge/.NET-10-blue)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Overview

This library provides RFC-compliant encoding methods for LDAP operations:

- **`EscapeFilterValue`**: Encodes values for use in LDAP search filters (RFC 4515)
- **`EscapeDnValue`**: Encodes values for use in Distinguished Names (RFC 4514)

Both methods provide defense-in-depth by escaping not only the minimum required characters but also additional potentially dangerous characters and all control characters.

### API

```csharp
public static string? EscapeFilterValue(string? input)
public static string? EscapeDnValue(string? input)
```

Both methods accept nullable strings and return `null` for `null` input, or an empty string for empty input.

## Installation

### NuGet Package

```bash
dotnet add package LdapEncoder
```

### Manual Installation

Clone this repository and add a reference to the project:

```bash
git clone https://github.com/dipsylala/Dipsy.Security.Ldap.git
dotnet add reference path/to/Dipsy.Security.Ldap/src/LdapEncoder/LdapEncoder.csproj
```

## Usage

### Escaping Filter Values

Use `EscapeFilterValue` when constructing LDAP search filters with user input:

```csharp
using Dipsy.Security.Ldap;

// User input that needs to be escaped
string userInput = "John*(admin)";

// Escape for use in filter (returns null if input is null)
string? escapedValue = LdapEncoder.EscapeFilterValue(userInput);

// Use in LDAP filter
string filter = $"(&(objectClass=user)(cn={escapedValue}))";
// Result: (&(objectClass=user)(cn=John\2a\28admin\29))
```

#### What gets escaped in filter values

- `*` (asterisk) → `\2a`
- `(` (left parenthesis) → `\28`
- `)` (right parenthesis) → `\29`
- `\` (backslash) → `\5c`
- `/` (forward slash) → `\2f` (OWASP recommendation)
- NUL byte → `\00`
- Control characters (0x00-0x1F, 0x7F)
- Non-ASCII characters (as UTF-8 hex sequences)

### Escaping DN Values

Use `EscapeDnValue` when constructing Distinguished Names with user input:

```csharp
using Dipsy.Security.Ldap;

// User input for DN value
string userInput = "Doe, John";

// Escape for use in DN (returns null if input is null)
string? escapedValue = LdapEncoder.EscapeDnValue(userInput);

// Use in DN
string dn = $"CN={escapedValue},OU=Users,DC=example,DC=com";
// Result: CN=Doe\, John,OU=Users,DC=example,DC=com
```

#### What gets escaped in DN values

- `,` (comma) → `\,`
- `+` (plus) → `\+`
- `"` (quote) → `\"`
- `\` (backslash) → `\\`
- `<` (less than) → `\<`
- `>` (greater than) → `\>`
- `;` (semicolon) → `\;`
- `=` (equals) → `\=`
- Leading `#` → `\#`
- Leading/trailing spaces → `\ ` (backslash-space)
- NUL byte → `\00`
- Control characters (0x00-0x1F, 0x7F)
- Non-ASCII characters (as UTF-8 hex sequences)

⚠️ **Important Note**: When possible, prefer searching for objects by their attributes (using escaped filter values) and using the DN returned by the directory server, rather than constructing DNs from user input.

## Security Considerations

### LDAP Injection Prevention

LDAP injection is a serious security vulnerability that occurs when untrusted data is included in LDAP queries without proper encoding. This library helps prevent LDAP injection by:

1. **Escaping special characters** that have meaning in LDAP syntax
2. **Handling multi-byte UTF-8** characters correctly
3. **Escaping control characters** that could cause parsing issues
4. **Following RFC standards** (RFC 4515 for filters, RFC 4514 for DNs)

### Example Attack Prevention

**Without encoding** (vulnerable):

```csharp
// Attacker input: "admin)(&(password=*"
string filter = $"(&(uid={userInput})(password={password}))";
// Becomes: (&(uid=admin)(&(password=*)(password=secret))
// This always returns true if an admin user exists!
```

**With encoding** (safe):

```csharp
string escapedInput = LdapEncoder.EscapeFilterValue(userInput);
string filter = $"(&(uid={escapedInput})(password={password}))";
// Becomes: (&(uid=admin\29\28&\28password=\2a)(password=secret))
// The malicious characters are escaped and treated as literal text
```

### Best Practices

1. **Always escape user input** before including it in LDAP queries
2. **Use the right method**:
   - `EscapeFilterValue` for search filter values
   - `EscapeDnValue` for DN component values
3. **Don't escape LDAP syntax**: Only escape the VALUE portions, not the structural operators like `&`, `|`, `=`, `,` that are part of your query structure
4. **Prefer server-returned DNs**: When possible, use DNs returned by the directory server rather than constructing them from user input

## Examples

### Complete Filter Example

```csharp
using System.DirectoryServices.Protocols;
using Dipsy.Security.Ldap;

public void SearchUsers(string firstName, string lastName)
{
    // Escape user inputs (handles null safely)
    string? escapedFirstName = LdapEncoder.EscapeFilterValue(firstName);
    string? escapedLastName = LdapEncoder.EscapeFilterValue(lastName);
    
    // Construct filter with escaped values
    string filter = $"(&(objectClass=person)(givenName={escapedFirstName})(sn={escapedLastName}))";
    
    // Use with LDAP connection
    var searchRequest = new SearchRequest(
        "DC=example,DC=com",
        filter,
        SearchScope.Subtree
    );
    
    // Execute search...
}
```

### Complete DN Example

```csharp
using System.DirectoryServices.Protocols;
using Dipsy.Security.Ldap;

public void CreateUser(string commonName, string organizationalUnit)
{
    // Escape user inputs (handles null safely)
    string? escapedCN = LdapEncoder.EscapeDnValue(commonName);
    string? escapedOU = LdapEncoder.EscapeDnValue(organizationalUnit);
    
    // Construct DN with escaped values
    string dn = $"CN={escapedCN},OU={escapedOU},DC=example,DC=com";
    
    // Use with LDAP connection
    var addRequest = new AddRequest(dn, "person");
    
    // Add attributes and execute...
}
```

### Handling Unicode

```csharp
// Unicode is properly encoded as UTF-8 hex sequences
string input = "café";
string? escaped = LdapEncoder.EscapeFilterValue(input);
// Result: "caf\c3\a9"

string input2 = "北京";
string? escaped2 = LdapEncoder.EscapeFilterValue(input2);
// Result: "\e5\8c\97\e4\ba\ac"
```

## Running Tests

The project includes comprehensive unit tests using xUnit:

```bash
# Run all tests
dotnet test

# Run tests with detailed output
dotnet test --logger "console;verbosity=detailed"

# Run tests with coverage (requires coverlet)
dotnet test /p:CollectCoverage=true
```

## Building the Library

```bash
# Restore dependencies
dotnet restore

# Build the library
dotnet build

# Create NuGet package
dotnet pack -c Release
```

## Requirements

- .NET 10.0 or later

## Comparison with Microsoft AntiXSS

For a detailed comparison of this library's output with Microsoft's AntiXSS LDAP encoder, see [COMPARISON.md](COMPARISON.md). The comparison includes:

- Side-by-side output comparisons for filter and DN encoding
- Analysis of encoding format differences
- RFC compliance verification
- Injection payload testing results

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [RFC 4515 - LDAP: String Representation of Search Filters](https://tools.ietf.org/html/rfc4515)
- [RFC 4514 - LDAP: String Representation of Distinguished Names](https://tools.ietf.org/html/rfc4514)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)

## Acknowledgments

This library implements LDAP encoding as specified in RFC 4515 and RFC 4514, with additional security measures recommended by OWASP.
