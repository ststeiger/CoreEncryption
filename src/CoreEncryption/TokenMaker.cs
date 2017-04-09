using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CoreEncryption
{


    // https://github.com/aspnet/Security/blob/master/src/Microsoft.AspNetCore.Authentication.JwtBearer/Events/IJwtBearerEvents.cs
    // http://codereview.stackexchange.com/questions/45974/web-api-2-authentication-with-jwt
    public class TokenMaker
    {


        class SecurityConstants
        {
            public static string TokenIssuer = "SomeIssuer";
            public static string TokenAudience = "SomeAudience";
            public static int TokenLifetimeMinutes = 60 * 24;


            public static int bitSize = 128;



            public static Microsoft.IdentityModel.Tokens.SecurityKey RsaKey
            {
                get {

                    return new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(
                        SimpleECDSA.GetMsEcdsaProvider()
                    );

                    return new Microsoft.IdentityModel.Tokens.RsaSecurityKey(SimpleRSA.GetMsRsaProvider());

                    var rsa = new BouncyRsa();
                    return new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);


                    System.Security.Cryptography.X509Certificates.X509Certificate2 cert2 =
                        Certificator.CreateX509Cert2("someName")
                    ;

                    
                    Microsoft.IdentityModel.Tokens.SecurityKey secKey =
                        new Microsoft.IdentityModel.Tokens.X509SecurityKey(cert2);

                    return secKey;
                }
            }


            public static Microsoft.IdentityModel.Tokens.SymmetricSecurityKey SymKey
            {
                get
                {
                    string pw = "";
                    int n = bitSize / 8;
                    for (int i = 0; i < n; ++i)
                    {
                        pw += "x";
                    }

                    byte[] ba = System.Text.Encoding.UTF8.GetBytes(pw);
                    return new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(ba);
                }

            }

        }


        public static string IssueToken()
        {
            Microsoft.IdentityModel.Tokens.SecurityKey sKey = SecurityConstants.SymKey;

            sKey = SecurityConstants.RsaKey;

            // sKey = SecurityConstants.RsaKey;
            // sKey = new CustomAsymmetricKey();
            // System.Security.Cryptography.X509Certificates.X509Certificate2 cert2 = DotNetUtilities.CreateX509Cert2("mycert");
            // SecurityKey secKey = new X509SecurityKey(cert2);


            List<Claim> claimList = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "userName"),
                new Claim(ClaimTypes.Role, "role") // Not sure what this is for
            };


            
            //JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            System.IdentityModel.Tokens.Jwt2.JwtSecurityTokenHandler tokenHandler = new System.IdentityModel.Tokens.Jwt2.JwtSecurityTokenHandler();
            SecurityTokenDescriptor desc = makeSecurityTokenDescriptor(sKey, claimList);
            string strToken = tokenHandler.CreateJwtSecurityToken(desc).ToString(); 
            System.Console.WriteLine(strToken);

            return tokenHandler.CreateEncodedJwt(desc);
        }


        private static SecurityTokenDescriptor makeSecurityTokenDescriptor(SecurityKey sSKey, List<Claim> claimList)
        {
            var now = DateTime.UtcNow;
            Claim[] claims = claimList.ToArray();
            return new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = SecurityConstants.TokenIssuer,
                Audience = SecurityConstants.TokenAudience,
                IssuedAt = System.DateTime.UtcNow,
                Expires = System.DateTime.UtcNow.AddMinutes(SecurityConstants.TokenLifetimeMinutes),
                NotBefore = System.DateTime.UtcNow.AddTicks(-1),

                //SigningCredentials = new SigningCredentials(sSKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha512Signature)
                //SigningCredentials = new SigningCredentials(sSKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha512)
                // SigningCredentials = new SigningCredentials(sSKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256)
                //SigningCredentials = new SigningCredentials(sSKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha512)

                SigningCredentials = new SigningCredentials(sSKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha512Signature)
            };

        } // End Function makeSecurityTokenDescriptor 


        public static ClaimsPrincipal ValidateJwtToken(string jwtToken)
        {
            SecurityKey sSKey = null;
            var tokenHandler = new JwtSecurityTokenHandler();

            // Parse JWT from the Base64UrlEncoded wire form 
            //(<Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>)
            JwtSecurityToken parsedJwt = tokenHandler.ReadToken(jwtToken) as JwtSecurityToken;

            TokenValidationParameters validationParams =
                new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidAudience = SecurityConstants.TokenAudience,
                    ValidIssuers = new List<string>() { SecurityConstants.TokenIssuer },
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    IssuerSigningKey = sSKey,
                };

            SecurityToken secT;
            return tokenHandler.ValidateToken("token", validationParams, out secT);
        } // End Function ValidateJwtToken 


    }


}
