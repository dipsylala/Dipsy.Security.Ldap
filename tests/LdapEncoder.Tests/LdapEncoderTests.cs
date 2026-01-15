using Dipsy.Security.Ldap;

namespace LdapEncoder.Tests;

public class LdapEncoderTests
{
    #region EscapeFilterValue Tests

    [Theory]
    [InlineData(null, null)]                                     // Null input returns null
    [InlineData("", "")]                                         // Empty input returns empty
    [InlineData("JohnDoe", "JohnDoe")]                           // Simple text unchanged
    [InlineData("*", @"\2a")]                                    // Asterisk
    [InlineData("(", @"\28")]                                    // Left parenthesis
    [InlineData(")", @"\29")]                                    // Right parenthesis
    [InlineData("\\", @"\5c")]                                   // Backslash
    [InlineData("\0", @"\00")]                                   // NUL byte
    [InlineData("a*b", @"a\2ab")]                                // Asterisk in context
    [InlineData("(test)", @"\28test\29")]                        // Parentheses
    [InlineData(@"test\value", @"test\5cvalue")]                 // Backslash in context
    [InlineData("test\0value", @"test\00value")]                 // NUL byte in context
    [InlineData("CN=user/admin", @"CN=user\2fadmin")]            // Forward slash
    [InlineData("user*()\\name/", @"user\2a\28\29\5cname\2f")]   // Multiple special chars
    [InlineData("café", @"caf\c3\a9")]                           // Unicode (UTF-8)
    public void EscapeFilterValue_VariousInputs_EscapesCorrectly(string? input, string? expected)
    {
        // Act
        var result = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(input);

        // Assert
        Assert.Equal(expected, result);
    }

    // [Fact] used here because this test requires multiple Contains assertions on a single result
    // which doesn't fit the simple input/expected pattern of [Theory]
    [Fact]
    public void EscapeFilterValue_ControlCharacters_Escaped()
    {
        // Arrange
        var input = "test\x01\x1F\x7Fvalue";

        // Act
        var result = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(input);

        // Assert
        Assert.Contains(@"\01", result);
        Assert.Contains(@"\1f", result);
        Assert.Contains(@"\7f", result);
    }

    // [Fact] used here because this test uses multiple assertion types (Contains/DoesNotContain)
    // to verify complex behavior that goes beyond simple input/output comparison
    [Fact]
    public void EscapeFilterValue_ComplexInjectionPayload_EscapesCorrectly()
    {
        // Arrange
        string payload = "*)(uid=*))(|(uid=*";

        // Act
        string? result = Dipsy.Security.Ldap.LdapEncoder.EscapeFilterValue(payload);

        // Assert - required escapes appear
        Assert.Contains(@"\2a", result); // *
        Assert.Contains(@"\28", result); // (
        Assert.Contains(@"\29", result); // )

        // Assert - raw characters are gone
        Assert.DoesNotContain("*", result);
        Assert.DoesNotContain("(", result);
        Assert.DoesNotContain(")", result);

        // Assert we didn't remove the uid
        Assert.Contains("uid=", result);
    }

    #endregion

    #region EscapeDnValue Tests

    [Theory]
    [InlineData(null, null)]                                     // Null input returns null
    [InlineData("", "")]                                         // Empty input returns empty
    [InlineData("JohnDoe", "JohnDoe")]                           // Simple text unchanged
    [InlineData("john", "john")]                                 // Simple text unchanged
    [InlineData("hash#tag", "hash#tag")]                         // Hash not leading - not escaped
    [InlineData("test,ou=users", @"test\,ou\=users")]            // Comma and equals
    [InlineData("CN=admin", @"CN\=admin")]                       // Equals
    [InlineData(@"user\name", @"user\\name")]                    // Backslash
    [InlineData("Doe, John", @"Doe\, John")]                     // Comma with space
    [InlineData("C++", @"C\+\+")]                                // Plus signs
    [InlineData("say \"hello\"", @"say \""hello\""")]            // Quotes
    [InlineData("<tag>", @"\<tag\>")]                            // Angle brackets
    [InlineData("CN=user;admin", @"CN\=user\;admin")]            // Semicolon and equals
    [InlineData("key=value", @"key\=value")]                     // Equals
    [InlineData(@"a,b+c""d\e<f>g;h=i", @"a\,b\+c\""d\\e\<f\>g\;h\=i")] // All special chars
    [InlineData("test\0value", @"test\00value")]                 // NUL byte
    [InlineData("café", @"caf\c3\a9")]                           // Unicode (UTF-8)
    [InlineData(" John Doe, Jr. ", @"\ John Doe\, Jr.\ ")]       // Complex example
    public void EscapeDnValue_VariousInputs_EscapesCorrectly(string? input, string? expected)
    {
        // Act
        var result = Dipsy.Security.Ldap.LdapEncoder.EscapeDnValue(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(" leading", @"\ leading")]                       // Leading space escaped
    [InlineData("trailing ", @"trailing\ ")]                     // Trailing space escaped
    [InlineData(" John", @"\ John")]                             // Leading space
    [InlineData("John ", @"John\ ")]                             // Trailing space
    [InlineData(" John Doe ", @"\ John Doe\ ")]                  // Leading and trailing spaces
    [InlineData("#start", @"\#start")]                           // Leading # escaped
    [InlineData("#hashtag", @"\#hashtag")]                       // Leading hash
    public void EscapeDnValue_LeadingTrailingSpecialChars_EscapesCorrectly(string? input, string? expected)
    {
        // Act
        var result = Dipsy.Security.Ldap.LdapEncoder.EscapeDnValue(input);

        // Assert
        Assert.Equal(expected, result);
    }

    // [Fact] used here because this test requires multiple Contains assertions on a single result
    // which doesn't fit the simple input/expected pattern of [Theory]
    [Fact]
    public void EscapeDnValue_ControlCharacters_Escaped()
    {
        // Arrange
        var input = "test\x01\x1F\x7Fvalue";

        // Act
        var result = Dipsy.Security.Ldap.LdapEncoder.EscapeDnValue(input);

        // Assert
        Assert.Contains(@"\01", result);
        Assert.Contains(@"\1f", result);
        Assert.Contains(@"\7f", result);
    }

    #endregion
}
