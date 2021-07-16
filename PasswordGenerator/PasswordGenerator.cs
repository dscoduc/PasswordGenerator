using System;
using System.Linq;

/// <summary>
/// Credit to https://www.siepman.nl/blog/random-password-generator-with-numbers-and-special-characters
/// 
/// </summary>
namespace PasswordGenerator
{
    /// <summary>
    /// Sign DLL offline (assumes Code Signing certificate is in User Certificate Store):
    ///     signtool.exe sign /v /s My /a /t http://timestamp.digicert.com c:\temp\PasswordGenerator.dll
    /// 
    /// Usage examples:
    /// 
    /// PowerShell:
    /// 
    ///     PS C:\>[Reflection.Assembly]::LoadFile("PasswordGenerator.dll")
    /// 
    ///     PS C:\>[PasswordGenerator.PasswordGenerator]::GeneratePassword()
    ///         OUTPUT ==> Lyw%SuQdKk49*E
    /// 
    ///     PS C:\>[PasswordGenerator.PasswordGenerator]::GeneratePassword(25)
    ///         OUTPUT ==> nx6+=xRAS6P!8P5z6g$)Fg)vc
    ///     
    ///     -- or --
    /// 
    ///     PS C:\>$minimumLengthPassword = 16
    ///     PS C:\>$maximumLengthPassword = 24
    ///     PS C:\>$minimumLowerCaseChars = 2
    ///     PS C:\>$minimumUpperCaseChars = 2
    ///     PS C:\>$minimumNumericChars = 2
    ///     PS C:\>$minimumSpecialChars = 2
    ///     
    ///     PS C:\>[PasswordGenerator.PasswordGenerator]$pw = [PasswordGenerator.PasswordGenerator]::new(
    ///         $minimumLengthPassword, 
    ///         $maximumLengthPassword,
    ///         $minimumLowerCaseChars,
    ///         $minimumUpperCaseChars,
    ///         $minimumNumericChars,
    ///         $minimumSpecialChars)
    ///
    ///     PS C:\>$pw.Generate()
    ///         OUTPUT ==> GdPk(5Ap5(%UqZeyv= +NrbA
    /// 
    /// C#:
    /// 
    ///     var pw = new PasswordGenerator.PasswordGenerator();
    ///     pw.GeneratePassword();
    ///         OUTPUT ==> Lyw%SuQdKk49*E
    ///         
    ///     -- or --
    /// 
    ///     var pw = new PasswordGenerator.PasswordGenerator();
    ///     pw.GeneratePassword(25);
    ///         OUTPUT ==> nx6+=xRAS6P!8P5z6g$)Fg)vc
    ///         
    ///     -- or --
    /// 
    ///     var pw = new PasswordGenerator.PasswordGenerator(16, 24, 2, 2, 2, 2)
    ///     pw.Generate();
    ///         OUTPUT ==> GdPk(5Ap5(%UqZeyv= +NrbA
    /// </summary>
    public class PasswordGenerator
    {
        public int MinimumLengthPassword { get; private set; }
        public int MaximumLengthPassword { get; private set; }
        public int MinimumLowerCaseChars { get; private set; }
        public int MinimumUpperCaseChars { get; private set; }
        public int MinimumNumericChars { get; private set; }
        public int MinimumSpecialChars { get; private set; }

        public static string AllLowerCaseChars { get; private set; }
        public static string AllUpperCaseChars { get; private set; }
        public static string AllNumericChars { get; private set; }
        public static string AllSpecialChars { get; private set; }
        private readonly string _allAvailableChars;

        private readonly RandomSecureVersion _randomSecure = new RandomSecureVersion();
        private int _minimumNumberOfChars;

        /// <summary>
        /// Initializes the PasswordGenerator with the default definition set of password requirements
        /// </summary>
        static PasswordGenerator()
        {
            // Ranges not using confusing characters
            AllLowerCaseChars = GetCharRange('a', 'z', exclusiveChars: "l");
            AllUpperCaseChars = GetCharRange('A', 'Z', exclusiveChars: "IO");
            AllNumericChars = GetCharRange('2', '9');
            AllSpecialChars = "!#%*()$?+-=";
        }

        /// <summary>
        /// Initializes the PasswordGenerator with a custom defined set of password requirements
        /// </summary>
        /// <param name="minimumLengthPassword">Minimum number of total characters in the generated password</param>
        /// <param name="maximumLengthPassword">Maximum number of total characters in the generated password</param>
        /// <param name="minimumLowerCaseChars">Minimum number of lowercase characters in the generated password</param>
        /// <param name="minimumUpperCaseChars">Minimum number of uppercase characters in the generated password</param>
        /// <param name="minimumNumericChars">Minimum number of numeric characters in the generated password</param>
        /// <param name="minimumSpecialChars">Minimum number of special characters in the generated password</param>
        public PasswordGenerator(
            int minimumLengthPassword = 12,
            int maximumLengthPassword = 24,
            int minimumLowerCaseChars = 2,
            int minimumUpperCaseChars = 2,
            int minimumNumericChars = 2,
            int minimumSpecialChars = 2)
        {
            if (minimumLengthPassword < 1) { throw new ArgumentException("The minimumlength cannot be smaller than 1.", "minimumLengthPassword"); }
            if (minimumLowerCaseChars < 0) { throw new ArgumentException("The minimumLowerCase cannot be smaller than 0.", "minimumLowerCaseChars"); }
            if (minimumUpperCaseChars < 0) { throw new ArgumentException("The minimumUpperCase cannot be smaller than 0.", "minimumUpperCaseChars"); }
            if (minimumNumericChars < 0) { throw new ArgumentException("The minimumNumeric cannot be smaller than 0.", "minimumNumericChars"); }
            if (minimumSpecialChars < 0) { throw new ArgumentException("The minimumSpecial cannot be smaller than 0.", "minimumSpecialChars"); }

            // Check if min length is greater than max length
            if (minimumLengthPassword > maximumLengthPassword) {
                // set max equal to min
                maximumLengthPassword = minimumLengthPassword;
            }

            _minimumNumberOfChars = minimumLowerCaseChars + minimumUpperCaseChars + minimumNumericChars + minimumSpecialChars;
            if (minimumLengthPassword < _minimumNumberOfChars)
            {
                throw new ArgumentException(
                    "The minimum length ot the password cannot be smaller than the sum " +
                    "of the minimum characters of all catagories.",
                    "maximumLengthPassword");
            }

            this.MinimumLengthPassword = minimumLengthPassword;
            this.MaximumLengthPassword = maximumLengthPassword;

            this.MinimumLowerCaseChars = minimumLowerCaseChars;
            this.MinimumUpperCaseChars = minimumUpperCaseChars;
            this.MinimumNumericChars = minimumNumericChars;
            this.MinimumSpecialChars = minimumSpecialChars;

            this._allAvailableChars =
                OnlyIfOneCharIsRequired(minimumLowerCaseChars, AllLowerCaseChars) +
                OnlyIfOneCharIsRequired(minimumUpperCaseChars, AllUpperCaseChars) +
                OnlyIfOneCharIsRequired(minimumNumericChars, AllNumericChars) +
                OnlyIfOneCharIsRequired(minimumSpecialChars, AllSpecialChars);
        }

        /// <summary>
        /// Generate a new password using the default set of password settings
        /// </summary>
        public static string GeneratePassword()
        {
            var pwg = new PasswordGenerator();
            return pwg.Generate();
        }

        /// <summary>
        /// Generate a new password using a specific length along with the default set of password settings
        /// </summary>
        public static string GeneratePassword(int length)
        {
            var pwg = new PasswordGenerator(length, length);
            return pwg.Generate();
        }

        public string Generate()
        {
            var lengthOfPassword = _randomSecure.Next(MinimumLengthPassword, MaximumLengthPassword);

            // Get the required number of characters of each catagory and 
            // add random charactes of all catagories
            var minimumChars = GetRandomString(AllLowerCaseChars, MinimumLowerCaseChars) +
                            GetRandomString(AllUpperCaseChars, MinimumUpperCaseChars) +
                            GetRandomString(AllNumericChars, MinimumNumericChars) +
                            GetRandomString(AllSpecialChars, MinimumSpecialChars);
            var rest = GetRandomString(_allAvailableChars, lengthOfPassword - minimumChars.Length);
            var unshuffeledResult = minimumChars + rest;

            // Shuffle the result so the order of the characters are unpredictable
            var result = unshuffeledResult.ShuffleTextSecure();
            return result;
        }

        private string OnlyIfOneCharIsRequired(int minimum, string allChars)
        {
            return minimum > 0 || _minimumNumberOfChars == 0 ? allChars : string.Empty;
        }

        private string GetRandomString(string possibleChars, int lenght)
        {
            var result = string.Empty;
            for (var position = 0; position < lenght; position++)
            {
                var index = _randomSecure.Next(possibleChars.Length);
                result += possibleChars[index];
            }
            return result;
        }

        private static string GetCharRange(char minimum, char maximum, string exclusiveChars = "")
        {
            var result = string.Empty;
            for (char value = minimum; value <= maximum; value++)
            {
                result += value;
            }
            if (!string.IsNullOrEmpty(exclusiveChars))
            {
                var inclusiveChars = result.Except(exclusiveChars).ToArray();
                result = new string(inclusiveChars);
            }
            return result;
        }
    }
}
