using Dipsy.Security.Ldap;
using Xunit;
using Xunit.Abstractions;

namespace LdapEncoder.Comparison;

public class LdapEncoderComparisonTests
{
    private readonly ITestOutputHelper _output;

    public LdapEncoderComparisonTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CompareFilterEncoding_CommonTestCases()
    {
        var testCases = new[]
        {
            "JohnDoe",                          // Simple text
            "*",                                // Wildcard
            "(",                                // Left paren
            ")",                                // Right paren
            "\\",                               // Backslash
            "\0",                               // NUL byte
            "a*b",                              // Asterisk in context
            "(test)",                           // Parentheses
            @"test\value",                      // Backslash in context
            "test\0value",                      // NUL in context
            "CN=user/admin",                    // Forward slash
            "user*()\\name/",                   // Multiple special chars
            "café",                             // Unicode
            "北京",                              // Chinese
            "*)(uid=*))(|(uid=*",               // Injection attempt
            "admin)(&(password=*",              // Injection attempt
            "test\x01\x1F\x7Fvalue",           // Control chars
            "a\nb\rc\td",                       // Common whitespace
            "",                                 // Empty string
        };

        _output.WriteLine("FILTER VALUE ENCODING COMPARISON");
        _output.WriteLine("=".PadRight(120, '='));
        _output.WriteLine($"{"Input",-30} | {"Our Encoder",-40} | {"AntiXSS Encoder",-40}");
        _output.WriteLine("-".PadRight(120, '-'));

        foreach (var input in testCases)
        {
            var ourResult = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(input);
            var antiXssResult = Microsoft.Security.Application.Encoder.LdapFilterEncode(input);

            var displayInput = input.Replace("\0", "\\0")
                                   .Replace("\x01", "\\x01")
                                   .Replace("\x1F", "\\x1F")
                                   .Replace("\x7F", "\\x7F")
                                   .Replace("\n", "\\n")
                                   .Replace("\r", "\\r")
                                   .Replace("\t", "\\t");

            if (displayInput.Length > 28)
                displayInput = displayInput.Substring(0, 25) + "...";

            _output.WriteLine($"{displayInput,-30} | {ourResult,-40} | {antiXssResult,-40}");
            
            // Highlight differences
            if (ourResult != antiXssResult)
            {
                _output.WriteLine($"{">>> DIFFERENCE DETECTED <<<",-30} | {"",-40} | {""}");
            }
        }

        _output.WriteLine("=".PadRight(120, '='));
    }

    [Fact]
    public void CompareDnEncoding_CommonTestCases()
    {
        var testCases = new[]
        {
            "JohnDoe",                          // Simple text
            "john",                             // Simple lowercase
            "hash#tag",                         // Hash not leading
            "test,ou=users",                    // Comma and equals
            "CN=admin",                         // Equals
            @"user\name",                       // Backslash
            "Doe, John",                        // Comma with space
            "C++",                              // Plus signs
            "say \"hello\"",                    // Quotes
            "<tag>",                            // Angle brackets
            "CN=user;admin",                    // Semicolon
            "key=value",                        // Equals
            @"a,b+c""d\e<f>g;h=i",             // All special chars
            "test\0value",                      // NUL byte
            "café",                             // Unicode
            "北京",                              // Chinese
            " leading",                         // Leading space
            "trailing ",                        // Trailing space
            " John Doe ",                       // Both spaces
            "#start",                           // Leading hash
            "#hashtag",                         // Leading hash
            "test\x01\x1F\x7Fvalue",           // Control chars
            "",                                 // Empty string
        };

        _output.WriteLine("");
        _output.WriteLine("DN VALUE ENCODING COMPARISON");
        _output.WriteLine("=".PadRight(120, '='));
        _output.WriteLine($"{"Input",-30} | {"Our Encoder",-40} | {"AntiXSS Encoder",-40}");
        _output.WriteLine("-".PadRight(120, '-'));

        foreach (var input in testCases)
        {
            var ourResult = Dipsy.Security.Ldap.LdapEncoder.EscapeDnValue(input);
            var antiXssResult = Microsoft.Security.Application.Encoder.LdapDistinguishedNameEncode(input);

            var displayInput = input.Replace("\0", "\\0")
                                   .Replace("\x01", "\\x01")
                                   .Replace("\x1F", "\\x1F")
                                   .Replace("\x7F", "\\x7F")
                                   .Replace("\n", "\\n")
                                   .Replace("\r", "\\r")
                                   .Replace("\t", "\\t");

            if (displayInput.Length > 28)
                displayInput = displayInput.Substring(0, 25) + "...";

            _output.WriteLine($"{displayInput,-30} | {ourResult,-40} | {antiXssResult,-40}");
            
            // Highlight differences
            if (ourResult != antiXssResult)
            {
                _output.WriteLine($"{">>> DIFFERENCE DETECTED <<<",-30} | {"",-40} | {""}");
            }
        }

        _output.WriteLine("=".PadRight(120, '='));
    }

    [Fact]
    public void DetailedComparison_InjectionPayloads()
    {
        var injectionPayloads = new[]
        {
            "*)(uid=*))(|(uid=*",               // OR injection
            "admin)(&(password=*",              // AND injection
            "*)(&(objectClass=*",               // Class injection
            "*)(userPassword=*",                // Password exposure
            "\\*)(objectClass=*",               // Escaped wildcard attempt
        };

        _output.WriteLine("");
        _output.WriteLine("INJECTION PAYLOAD COMPARISON");
        _output.WriteLine("=".PadRight(120, '='));

        foreach (var payload in injectionPayloads)
        {
            _output.WriteLine($"Payload: {payload}");
            _output.WriteLine("-".PadRight(120, '-'));

            var ourResult = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(payload);
            var antiXssResult = Microsoft.Security.Application.Encoder.LdapFilterEncode(payload);

            _output.WriteLine($"Our Encoder:     {ourResult}");
            _output.WriteLine($"AntiXSS Encoder: {antiXssResult}");
            
            if (ourResult != antiXssResult)
            {
                _output.WriteLine(">>> DIFFERENCE DETECTED <<<");
                _output.WriteLine($"Length difference: Our={ourResult?.Length}, AntiXSS={antiXssResult?.Length}");
            }
            else
            {
                _output.WriteLine("✓ Results match");
            }

            _output.WriteLine("");
        }

        _output.WriteLine("=".PadRight(120, '='));
    }

    [Fact]
    public void NullHandling_Comparison()
    {
        _output.WriteLine("");
        _output.WriteLine("NULL HANDLING COMPARISON");
        _output.WriteLine("=".PadRight(120, '='));

        string? nullInput = null;

        var ourFilterResult = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(nullInput);
        var antiXssFilterResult = Microsoft.Security.Application.Encoder.LdapFilterEncode(nullInput);

        _output.WriteLine($"Filter Encoding - null input:");
        _output.WriteLine($"  Our Encoder:     {ourFilterResult ?? "(null)"}");
        _output.WriteLine($"  AntiXSS Encoder: {antiXssFilterResult ?? "(null)"}");
        _output.WriteLine($"  Match: {ourFilterResult == antiXssFilterResult}");
        _output.WriteLine("");

        var ourDnResult = Dipsy.Security.Ldap.LdapEncoder.EscapeDnValue(nullInput);
        var antiXssDnResult = Microsoft.Security.Application.Encoder.LdapDistinguishedNameEncode(nullInput);

        _output.WriteLine($"DN Encoding - null input:");
        _output.WriteLine($"  Our Encoder:     {ourDnResult ?? "(null)"}");
        _output.WriteLine($"  AntiXSS Encoder: {antiXssDnResult ?? "(null)"}");
        _output.WriteLine($"  Match: {ourDnResult == antiXssDnResult}");

        _output.WriteLine("=".PadRight(120, '='));
    }
}
