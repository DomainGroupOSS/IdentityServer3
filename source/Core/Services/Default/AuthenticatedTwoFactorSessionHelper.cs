using System;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using IdentityModel;
using IdentityServer3.Core.Configuration.Hosting;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Internal.CryptoLibrary;

namespace IdentityServer3.Core.Services.Default
{
    internal class AuthenticatedTwoFactorTwoFactorSessionHelper : IAuthenticatedTwoFactorSessionHelper
    {
        internal const int Base64TwoFactorTokenLength = 64; //Length in base64 characters
        internal const int MacComponentLength = 32; //Length in bytes
        internal const int TwoFactorTokenComponentLength = 16; //Length in bytes
        private static readonly object SyncLock = new object();
        private readonly byte[] _key;

        private readonly UTF8Encoding _utf8 = new UTF8Encoding(false, true);
        private static volatile AuthenticatedTwoFactorTwoFactorSessionHelper _instance;

        internal AuthenticatedTwoFactorTwoFactorSessionHelper(byte[] key)
        {
            _key = key;
        }

        public string Create(string subjectId)
        {
            var id = CryptoRandom.CreateRandomKey(TwoFactorTokenComponentLength);

            var mac = CalculateMac(subjectId, id);

            return GenerateTokenWithMac(id, mac);
        }

        public bool Validate(string subjectId, string incomingTWoFactorToken)
        {
            if (string.IsNullOrEmpty(incomingTWoFactorToken) || incomingTWoFactorToken.Length != Base64TwoFactorTokenLength) return false;

            if (string.IsNullOrEmpty(subjectId)) throw new ArgumentException("subjectId was null or empty.");

            byte[] binarySessionID;
            try
            {
                binarySessionID = Convert.FromBase64String(incomingTWoFactorToken.AddBase64Padding());
            }
            catch (FormatException)
            {
                return false;
            }

            if (binarySessionID.Length != TwoFactorTokenComponentLength + MacComponentLength) return false;

            var twoFactorTokenComponent = new byte[TwoFactorTokenComponentLength];
            Array.Copy(binarySessionID, twoFactorTokenComponent, TwoFactorTokenComponentLength);

            var expectedMac = CalculateMac(subjectId, twoFactorTokenComponent);

            return ValidateMac(expectedMac, binarySessionID);
        }

        internal static AuthenticatedTwoFactorTwoFactorSessionHelper Instance(string machineKey)
        {
            if (_instance == null)
            {
                lock (SyncLock)
                {
                    if (_instance == null)
                    {
                        var kdf = new KbkdfHmacSha256Ctr();
                        if (!Regex.IsMatch(machineKey, "^[0-9a-fA-F]+$"))
                        {
                            throw new ApplicationException("Invalid machine validation key was specified");
                        }
                        var hexbinary = SoapHexBinary.Parse(machineKey);
                        var keyMaterial = hexbinary.Value;
                        hexbinary.Value = new byte[0];

                        var key = kdf.DeriveKey(256, keyMaterial, "idsrv.twofactor.token");
                        Array.Clear(keyMaterial, 0, keyMaterial.Length);

                        _instance = new AuthenticatedTwoFactorTwoFactorSessionHelper(key);
                    }
                }
            }
            return _instance;
        }

        private byte[] CalculateMac(string subjectId, byte[] sessionID)
        {
            var userNameBits = _utf8.GetBytes(subjectId);

            var input = new byte[subjectId.Length + sessionID.Length];
            Array.Copy(userNameBits, input, subjectId.Length);
            Array.Copy(sessionID, 0, input, subjectId.Length, sessionID.Length);

            byte[] mac;
            using (var hmac = new HMACSHA256(_key))
            {
                mac = hmac.ComputeHash(input);
            }

            return mac;
        }

        private string GenerateTokenWithMac(byte[] id, byte[] mac)
        {
            var result = new byte[id.Length + mac.Length];

            Array.Copy(id, result, id.Length);
            Array.Copy(mac, 0, result, id.Length, mac.Length);

            return Convert.ToBase64String(result).TrimEnd('=');
        }

        //Hamper timing attacks.
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private bool ValidateMac(byte[] expectedMac, byte[] binaryTwoFactorToken)
        {
            var macDiffers = false;
            for (var i = 0; i < MacComponentLength; i++)
            {
                macDiffers = macDiffers | expectedMac[i] != binaryTwoFactorToken[i + TwoFactorTokenComponentLength];
            }

            return !macDiffers;
        }
    }
}