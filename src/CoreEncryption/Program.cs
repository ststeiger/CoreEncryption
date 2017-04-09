
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace CoreEncryption
{


    public class Program
    {


        public static int Main(string[] args)
        {
            var cos = SimpleECDSA.GetMsEcdsaProvider();
            System.Console.WriteLine(cos);
            string fooToken = TokenMaker.IssueToken();
            System.Console.WriteLine(fooToken);
            return 0;
        }


    }


}
