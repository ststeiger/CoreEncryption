
namespace CoreEncryption
{



    public class CustomAsymmetricKey : Microsoft.IdentityModel.Tokens.AsymmetricSecurityKey
    {


        //
        // Summary:
        //     Gets or sets Microsoft.IdentityModel.Tokens.CryptoProviderFactory.
        public new Microsoft.IdentityModel.Tokens.CryptoProviderFactory CryptoProviderFactory
        {
            get
            {
                return null;
            }
            set { }
        }

        public new string KeyId
        {
            get
            {
                return "";
            }
            set { }
        }




        public override bool HasPrivateKey
        {
            get
            {
                return true;
            }
        }

        public override int KeySize
        {
            get
            {
                return 1024;
            }
        }


        // System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey();
        // System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPublicKey();

        // System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions.GetECDsaPrivateKey();
        // System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions.GetECDsaPublicKey();


        public System.Security.Cryptography.AsymmetricAlgorithm PrivateKey
        {
            get
            {
                return null;
            }
        }

        public System.Security.Cryptography.AsymmetricAlgorithm PublicKey
        {
            get
            {
                return null;
            }
        }

        public System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate
        {
            get
            {
                return null;
            }
        }

    }


}
