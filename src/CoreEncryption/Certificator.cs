
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Generators;


namespace CoreEncryption
{


    public class Certificator
    {


        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = Org.BouncyCastle.Utilities.BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name


            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerPrivKey, random);

            // correcponding private key
            Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo info = 
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // merge into X509Certificate2
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
                throw new Org.BouncyCastle.OpenSsl.PemException("malformed sequence in RSA private key");

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            // x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            return x509;

        }












        // http://stackoverflow.com/questions/36942094/how-can-i-generate-a-self-signed-cert-without-using-obsolete-bouncycastle-1-7-0
        public static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateX509Cert2(string certName)
        {

            var keypairgen = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
            keypairgen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(
                new Org.BouncyCastle.Security.SecureRandom(
                    new Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator()
                    )
                    , 1024
                    //, 512
                    )
            );

            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keypair = keypairgen.GenerateKeyPair();

            // --- Until here we generate a keypair



            var random = new Org.BouncyCastle.Security.SecureRandom(
                    new Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator()
            );


            // SHA1WITHRSA
            // SHA256WITHRSA
            // SHA384WITHRSA
            // SHA512WITHRSA

            // SHA1WITHECDSA
            // SHA224WITHECDSA
            // SHA256WITHECDSA
            // SHA384WITHECDSA
            // SHA512WITHECDSA

            Org.BouncyCastle.Crypto.ISignatureFactory signatureFactory =
                new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA512WITHRSA", keypair.Private, random)
            ;



            var gen = new Org.BouncyCastle.X509.X509V3CertificateGenerator();


            var CN = new Org.BouncyCastle.Asn1.X509.X509Name("CN=" + certName);
            var SN = Org.BouncyCastle.Math.BigInteger.ProbablePrime(120, new Random());

            gen.SetSerialNumber(SN);
            gen.SetSubjectDN(CN);
            gen.SetIssuerDN(CN);
            gen.SetNotAfter(DateTime.Now.AddYears(1));
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            gen.SetPublicKey(keypair.Public);
            

            // -- Are these necessary ? 

            // public static readonly DerObjectIdentifier AuthorityKeyIdentifier = new DerObjectIdentifier("2.5.29.35");
            // OID value: 2.5.29.35
            // OID description: id-ce-authorityKeyIdentifier
            // This extension may be used either as a certificate or CRL extension. 
            // It identifies the public key to be used to verify the signature on this certificate or CRL.
            // It enables distinct keys used by the same CA to be distinguished (e.g., as key updating occurs).


            // http://stackoverflow.com/questions/14930381/generating-x509-certificate-using-bouncy-castle-java
            gen.AddExtension(
            Org.BouncyCastle.Asn1.X509.X509Extensions.AuthorityKeyIdentifier.Id,
            false,
            new Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier(
                Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keypair.Public),
                new Org.BouncyCastle.Asn1.X509.GeneralNames(new Org.BouncyCastle.Asn1.X509.GeneralName(CN)),
                SN
            ));

            // OID value: 1.3.6.1.5.5.7.3.1
            // OID description: Indicates that a certificate can be used as an SSL server certificate.
            gen.AddExtension(
                Org.BouncyCastle.Asn1.X509.X509Extensions.ExtendedKeyUsage.Id,
                false,
                new Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage(
                    new System.Collections.Generic.List<object>()
                    {
                        new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.5.5.7.3.1")
                    }
                )
            );


            gen.AddExtension(
                new Org.BouncyCastle.Asn1.DerObjectIdentifier("2.5.29.19"),
                false,
                new Org.BouncyCastle.Asn1.X509.BasicConstraints(false) // true if it is allowed to sign other certs
            );

            gen.AddExtension(
                new Org.BouncyCastle.Asn1.DerObjectIdentifier("2.5.29.15"),
                true,
                new Org.BouncyCastle.X509.X509KeyUsage(
                    Org.BouncyCastle.X509.X509KeyUsage.DigitalSignature |
                    Org.BouncyCastle.X509.X509KeyUsage.NonRepudiation |
                    Org.BouncyCastle.X509.X509KeyUsage.KeyEncipherment |
                    Org.BouncyCastle.X509.X509KeyUsage.DataEncipherment)
            );


            // -- End are these necessary ? 

            Org.BouncyCastle.X509.X509Certificate bouncyCert = gen.Generate(signatureFactory);
            // Org.BouncyCastle.X509.X509Certificate bouncyCert = gen.Generate(keypair.Private);

            bouncyCert.GetPublicKey();

            byte[] ba = bouncyCert.GetEncoded();

            using (System.IO.TextWriter textWriter = new System.IO.StringWriter())
            {
                Org.BouncyCastle.OpenSsl.PemWriter pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter);

                pemWriter.WriteObject(bouncyCert);
                pemWriter.WriteObject(keypair.Private);
                pemWriter.Writer.Flush();

                string privateKey = textWriter.ToString();
                System.Console.WriteLine(privateKey);
            } // End Using textWriter 


            string certFile = @"D:\mycert.cert";
            using (System.IO.FileStream fs = System.IO.File.OpenWrite(certFile))
            {
                using (System.IO.TextWriter textWriter = new System.IO.StreamWriter(fs))
                {
                    Org.BouncyCastle.OpenSsl.PemWriter pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter);

                    pemWriter.WriteObject(bouncyCert);
                    pemWriter.WriteObject(keypair.Private);
                    pemWriter.Writer.Flush();

                    string privateKey = textWriter.ToString();
                    System.Console.WriteLine(privateKey);
                } // End Using textWriter 

            } // End Using fs 


            // https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.X509Certificates/src/System/Security/Cryptography/X509Certificates/X509Certificate.cs
            // https://github.com/dotnet/corefx/blob/master/src/System.Security.Cryptography.X509Certificates/src/System/Security/Cryptography/X509Certificates/X509Certificate2.cs



            // System.Security.Cryptography.X509Certificates.X509Certificate2 msCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(ba);
            System.Security.Cryptography.X509Certificates.X509Certificate2 msCert = 
                new System.Security.Cryptography.X509Certificates
                .X509Certificate2(ba, null
                , System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
                

                // System.Security.Cryptography.X509Certificates.X509KeyStorageFlag.PersistKeySet |
                 // System.Security.Cryptography.X509Certificates.X509KeyStorageFlag.MachineKeySet |
                 // System.Security.Cryptography.X509Certificates.X509KeyStorageFlag.Exportable
                );

            msCert = new X509Certificate2(certFile,null, X509KeyStorageFlags.MachineKeySet);
            object obj = msCert.GetRSAPrivateKey();
            System.Console.WriteLine(obj);

            if (msCert.HasPrivateKey)
                Console.WriteLine(msCert.HasPrivateKey);

            return msCert;
        }


    }


}
