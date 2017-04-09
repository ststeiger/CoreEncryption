
using System;
using System.IO;
using System.Security.Cryptography;

namespace CoreEncryption
{


    // DSA: Digital Signature Algorithm
    // ecDSA Elliptic Curve Digital Signature Algorithm
    public class BouncyECDSA : System.Security.Cryptography.ECDsa
    {

        Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters m_privKey;
        Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters m_pubKey;


        public BouncyECDSA(Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters privKey)
        {
            this.m_privKey = privKey;
        } // End Constructor 


        public BouncyECDSA(Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters pubKey)
        {
            this.m_pubKey = pubKey;
        } // End Constructor 


        public BouncyECDSA(Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair kp)
        {
            this.m_privKey = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)kp.Private;
            this.m_pubKey = (Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)kp.Public;
        } // End Constructor 
        

        public override byte[] SignHash(byte[] hash)
        {
            // byte[] hash = System.Text.Encoding.UTF8.GetBytes(strHash);


            // https://github.com/neoeinstein/bouncycastle/blob/master/crypto/src/security/SignerUtilities.cs
            // algorithms["SHA-256/ECDSA"] = "SHA-256withECDSA";
            // algorithms["SHA-384/ECDSA"] = "SHA-384withECDSA";
            // algorithms["SHA-512/ECDSA"] = "SHA-512withECDSA";

            // base.SignatureAlgorithm
            Org.BouncyCastle.Crypto.ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, m_privKey);
            signer.BlockUpdate(hash, 0, hash.Length);
            return signer.GenerateSignature();
        } // End Function SignHash 


        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            // byte[] hash = System.Text.Encoding.UTF8.GetBytes(strHash);
            // byte[] signature = System.Convert.FromBase64String(strSignature);

            // base.SignatureAlgorithm
            Org.BouncyCastle.Crypto.ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(false, m_pubKey);
            signer.BlockUpdate(hash, 0, hash.Length);
            return signer.VerifySignature(signature);
        } // End Function VerifyHash 


        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            throw new NotImplementedException();
        }


        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            throw new NotImplementedException();
        }


    } // End Class BouncyECDSA : System.Security.Cryptography.ECDsa 


} // End Namespace CoreEncryption 
