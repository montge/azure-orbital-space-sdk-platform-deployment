using System.Text.RegularExpressions;

namespace Microsoft.Azure.SpaceFx.PlatformServices.Deployment;

/// <summary>
/// Utility class providing input validation methods to prevent command injection attacks.
/// This class implements whitelist-based validation to ensure user inputs cannot be exploited
/// to execute arbitrary commands when passed to shell processes.
/// </summary>
public partial class Utils {
    public static class InputValidation {
        // Regex patterns for validation
        private static readonly Regex DockerImageNameRegex = new Regex(@"^[a-z0-9][a-z0-9._/-]*$", RegexOptions.Compiled);
        private static readonly Regex DockerTagRegex = new Regex(@"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$", RegexOptions.Compiled);
        private static readonly Regex HelmParameterKeyRegex = new Regex(@"^[a-zA-Z0-9_.\-]+$", RegexOptions.Compiled);
        private static readonly Regex HelmParameterValueRegex = new Regex(@"^[a-zA-Z0-9_.\-:/\s]+$", RegexOptions.Compiled);
        private static readonly Regex SafeFileNameRegex = new Regex(@"^[a-zA-Z0-9_.\-]+$", RegexOptions.Compiled);

        // Shell metacharacters that should be rejected
        private static readonly char[] ShellMetacharacters = { ';', '&', '|', '$', '`', '\n', '\r', '(', ')', '<', '>', '\\', '*', '?', '[', ']', '{', '}', '!', '#', '~', '"', '\'', '%' };

        /// <summary>
        /// Validates a Docker image name to prevent command injection.
        /// Docker image names must contain only lowercase letters, digits, periods, underscores, slashes, and hyphens.
        /// They must start with a lowercase letter or digit.
        /// </summary>
        /// <param name="imageName">The Docker image name to validate</param>
        /// <returns>True if the image name is valid and safe, false otherwise</returns>
        /// <example>
        /// Valid: "myapp", "registry.local/myapp", "my-app_v2"
        /// Invalid: "MyApp", "app;rm -rf", "app`whoami`"
        /// </example>
        public static bool IsValidDockerImageName(string imageName) {
            if (string.IsNullOrWhiteSpace(imageName)) {
                return false;
            }

            // Check length (Docker spec: max 255 characters for repository name)
            if (imageName.Length > 255) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(imageName)) {
                return false;
            }

            // Validate against regex pattern
            if (!DockerImageNameRegex.IsMatch(imageName)) {
                return false;
            }

            // Additional check: each component between slashes should be valid
            string[] components = imageName.Split('/');
            foreach (string component in components) {
                if (string.IsNullOrWhiteSpace(component)) {
                    return false;
                }
                // Each component should not start or end with special characters (except digits/letters)
                if (component.StartsWith(".") || component.StartsWith("-") ||
                    component.EndsWith(".") || component.EndsWith("-")) {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Validates a Docker image tag to prevent command injection.
        /// Docker tags must contain only alphanumeric characters, underscores, periods, and hyphens.
        /// They must start with an alphanumeric character or underscore and be max 128 characters.
        /// </summary>
        /// <param name="tag">The Docker image tag to validate</param>
        /// <returns>True if the tag is valid and safe, false otherwise</returns>
        /// <example>
        /// Valid: "latest", "v1.0.0", "build_123", "sha-abc123"
        /// Invalid: "v1;rm -rf", "tag`whoami`", "tag&amp;echo"
        /// </example>
        public static bool IsValidDockerTag(string tag) {
            if (string.IsNullOrWhiteSpace(tag)) {
                return false;
            }

            // Check length (Docker spec: max 128 characters)
            if (tag.Length > 128) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(tag)) {
                return false;
            }

            // Validate against regex pattern
            return DockerTagRegex.IsMatch(tag);
        }

        /// <summary>
        /// Validates a Helm parameter key to prevent command injection.
        /// Helm parameter keys should contain only alphanumeric characters, dots, hyphens, and underscores.
        /// </summary>
        /// <param name="parameterKey">The Helm parameter key to validate</param>
        /// <returns>True if the parameter key is valid and safe, false otherwise</returns>
        /// <example>
        /// Valid: "services.app.enabled", "replicas", "image-tag"
        /// Invalid: "key;whoami", "key`ls`", "key&amp;rm"
        /// </example>
        public static bool IsValidHelmParameterKey(string parameterKey) {
            if (string.IsNullOrWhiteSpace(parameterKey)) {
                return false;
            }

            // Check length (reasonable limit)
            if (parameterKey.Length > 256) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(parameterKey)) {
                return false;
            }

            // Validate against regex pattern
            return HelmParameterKeyRegex.IsMatch(parameterKey);
        }

        /// <summary>
        /// Validates a Helm parameter value to prevent command injection.
        /// Helm parameter values should contain only safe characters.
        /// This allows alphanumeric characters, spaces, dots, hyphens, underscores, colons, and forward slashes.
        /// </summary>
        /// <param name="parameterValue">The Helm parameter value to validate</param>
        /// <returns>True if the parameter value is valid and safe, false otherwise</returns>
        /// <example>
        /// Valid: "true", "my-app-v1.0", "2023-01-01T00:00:00Z"
        /// Invalid: "value;whoami", "value`ls`", "value&amp;rm"
        /// </example>
        public static bool IsValidHelmParameterValue(string parameterValue) {
            if (string.IsNullOrWhiteSpace(parameterValue)) {
                return false;
            }

            // Check length (reasonable limit)
            if (parameterValue.Length > 1024) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(parameterValue)) {
                return false;
            }

            // Validate against regex pattern
            return HelmParameterValueRegex.IsMatch(parameterValue);
        }

        /// <summary>
        /// Validates a file name to prevent path traversal and command injection attacks.
        /// File names should contain only alphanumeric characters, dots, hyphens, and underscores.
        /// Path traversal sequences (.., /, \) are rejected.
        /// </summary>
        /// <param name="fileName">The file name to validate</param>
        /// <returns>True if the file name is valid and safe, false otherwise</returns>
        /// <example>
        /// Valid: "config.yaml", "app-v1.0.tar", "model_123.pkl"
        /// Invalid: "../../../etc/passwd", "file;rm", "file`whoami`"
        /// </example>
        public static bool IsValidFileName(string fileName) {
            if (string.IsNullOrWhiteSpace(fileName)) {
                return false;
            }

            // Check length (reasonable limit for file names)
            if (fileName.Length > 255) {
                return false;
            }

            // Check for path traversal attempts
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\")) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(fileName)) {
                return false;
            }

            // Validate against regex pattern
            return SafeFileNameRegex.IsMatch(fileName);
        }

        /// <summary>
        /// Validates a file path to prevent path traversal attacks while allowing valid paths.
        /// This method ensures the resolved path stays within the expected base directory.
        /// </summary>
        /// <param name="filePath">The file path to validate</param>
        /// <param name="baseDirectory">The base directory that the path should be contained within</param>
        /// <returns>True if the path is valid and within the base directory, false otherwise</returns>
        /// <example>
        /// IsValidFilePath("/var/data/file.txt", "/var/data") -> true
        /// IsValidFilePath("/var/data/../etc/passwd", "/var/data") -> false
        /// </example>
        public static bool IsValidFilePath(string filePath, string baseDirectory) {
            if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(baseDirectory)) {
                return false;
            }

            try {
                // Get the full canonical paths
                string fullPath = Path.GetFullPath(filePath);
                string fullBasePath = Path.GetFullPath(baseDirectory);

                // Ensure the base path ends with directory separator
                if (!fullBasePath.EndsWith(Path.DirectorySeparatorChar.ToString())) {
                    fullBasePath += Path.DirectorySeparatorChar;
                }

                // Check if the file path is within the base directory
                if (!fullPath.StartsWith(fullBasePath, StringComparison.OrdinalIgnoreCase)) {
                    return false;
                }

                // Additional check for shell metacharacters in the resolved path
                if (ContainsShellMetacharacters(fullPath)) {
                    return false;
                }

                return true;
            } catch (Exception) {
                // Any exception during path resolution indicates an invalid path
                return false;
            }
        }

        /// <summary>
        /// Checks if a string contains any shell metacharacters that could be used for command injection.
        /// </summary>
        /// <param name="input">The string to check</param>
        /// <returns>True if shell metacharacters are found, false otherwise</returns>
        private static bool ContainsShellMetacharacters(string input) {
            if (string.IsNullOrEmpty(input)) {
                return false;
            }

            return input.IndexOfAny(ShellMetacharacters) >= 0;
        }

        /// <summary>
        /// Validates a registry host name (e.g., "registry.local:5000").
        /// Allows alphanumeric characters, dots, hyphens, and colons (for port numbers).
        /// </summary>
        /// <param name="registryHost">The registry host to validate</param>
        /// <returns>True if the registry host is valid and safe, false otherwise</returns>
        public static bool IsValidRegistryHost(string registryHost) {
            if (string.IsNullOrWhiteSpace(registryHost)) {
                return false;
            }

            // Check length
            if (registryHost.Length > 255) {
                return false;
            }

            // Check for shell metacharacters
            if (ContainsShellMetacharacters(registryHost)) {
                return false;
            }

            // Pattern: hostname or IP address, optionally with port
            // Examples: "registry.local", "localhost:5000", "192.168.1.1:5000"
            Regex registryHostRegex = new Regex(@"^[a-zA-Z0-9][a-zA-Z0-9.\-]*(:[0-9]{1,5})?$", RegexOptions.Compiled);

            return registryHostRegex.IsMatch(registryHost);
        }
    }
}
