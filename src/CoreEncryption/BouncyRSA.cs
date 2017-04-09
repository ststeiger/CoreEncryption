
using System;
using System.IO;
using System.Security.Cryptography;

namespace CoreEncryption
{


    // RSA: (Ron) Rivest, (Adi) Shamir, (Leonard) Adleman
    public class BouncyRsa : System.Security.Cryptography.RSA
    {

        private Org.BouncyCastle.Crypto.AsymmetricKeyParameter m_keyParameter;
        private Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair m_keyPair;


        /*
        public static void aaaaaaa()
        {
            ECParameters params1;
            ECDsa ss = ECDsa.Create();
            CngKey key = null;            
            ECDsaCng sa = new ECDsaCng(key);
        }
        */

        
        // GenerateRsaKeyPair(1024)
        public static Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair GenerateRsaKeyPair(int strength)
        {
            Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator gen = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();

            // new Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters()

            Org.BouncyCastle.Security.SecureRandom secureRandom =
                new Org.BouncyCastle.Security.SecureRandom(new Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator());

            Org.BouncyCastle.Crypto.KeyGenerationParameters keyGenParam =
                new Org.BouncyCastle.Crypto.KeyGenerationParameters(secureRandom, strength);


            gen.Init(keyGenParam);

            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
            return kp;
            // Org.BouncyCastle.Crypto.AsymmetricKeyParameter priv = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)kp.Private;
        } // End Sub GenerateRsaKeyPair 



        public BouncyRsa(string publicKey, bool b)
        {
            using (System.IO.StringReader keyReader = new System.IO.StringReader(publicKey))
            {
                m_keyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)new Org.BouncyCastle.OpenSsl.PemReader(keyReader).ReadObject();
            }
        }


        public BouncyRsa()
        {
            m_keyPair = GenerateRsaKeyPair(2048);
            m_keyParameter = m_keyPair.Public;
        }


        public BouncyRsa(string privateKey)
        {

            using (System.IO.StringReader txtreader = new System.IO.StringReader(privateKey))
            {
                m_keyPair = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(txtreader).ReadObject();
            }
            
            m_keyParameter = m_keyPair.Public;
        }


        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding decryptEngine =
                new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(new Org.BouncyCastle.Crypto.Engines.RsaEngine());

            decryptEngine.Init(false, m_keyPair.Private);

            // string decrypted = System.Text.Encoding.UTF8.GetString(
            return decryptEngine.ProcessBlock(data, 0, data.Length);
            //);
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding encryptEngine =
              new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(new Org.BouncyCastle.Crypto.Engines.RsaEngine());

            encryptEngine.Init(true, m_keyParameter);

            // string encrypted = System.Convert.ToBase64String(
            return encryptEngine.ProcessBlock(data, 0, data.Length);
            // );
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotImplementedException();
        }


        public static byte[] SHA256(string text)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);

            Org.BouncyCastle.Crypto.Digests.Sha256Digest digester = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            byte[] retValue = new byte[digester.GetDigestSize()];
            digester.BlockUpdate(bytes, 0, bytes.Length);
            digester.DoFinal(retValue, 0);
            return retValue;
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            // https://github.com/neoeinstein/bouncycastle/blob/master/crypto/src/security/SignerUtilities.cs
            var dsi = new Org.BouncyCastle.Crypto.Signers.RsaDigestSigner(
                new Org.BouncyCastle.Crypto.Digests.Sha256Digest()
                )
            ;

            dsi.Init(true, this.m_keyPair.Private);
            dsi.BlockUpdate(hash, 0, hash.Length);


            return dsi.GenerateSignature();

            System.Console.WriteLine(hashAlgorithm);
            return null;
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            System.Console.WriteLine(hashAlgorithm);
            return true;
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            System.Console.WriteLine(hashAlgorithm);
            throw new NotImplementedException();
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            System.Console.WriteLine(data);

            return data;
            // byte[] data = System.Text.Encoding.UTF8.GetBytes(text);

            Org.BouncyCastle.Crypto.Digests.Sha256Digest digester = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            byte[] retValue = new byte[digester.GetDigestSize()];
            digester.BlockUpdate(data, 0, data.Length);
            digester.DoFinal(retValue, 0);
            return retValue;
        }


    }


} // End Namespace CoreEncryption 
