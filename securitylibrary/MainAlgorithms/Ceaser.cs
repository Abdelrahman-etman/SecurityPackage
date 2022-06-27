using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string encrypted_text = "";
            for(int i = 0; i < plainText.Length; i++)
            {
                int c = (plainText[i] - 'a' + key) % 26;

                encrypted_text += (char)('A' + c);
            }

            return encrypted_text;
            

          
        }

        public string Decrypt(string cipherText, int key)
        {
            string plain_text = "";
            for(int i = 0; i < cipherText.Length; i++)
            {
                int c = (cipherText[i] - 'A' -  key + 26) % 26;
                plain_text += (char)('a' + c);
            }

            return plain_text;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int c = plainText[0] - 'a';
            int c2 = cipherText[0] - 'A';
            return (c2 - c + 26) % 26;
        }
    }
}
