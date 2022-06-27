using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        public void solve(int idx, int n, ref List<int> arr, ref List<List<int>> permutations)
        {
            if (idx == n)
            {
                List<int> tmp = new List<int>();
                for (int i = 0; i < arr.Count; i++)
                    tmp.Add(arr[i]);
                permutations.Add(tmp);
                return;
            }
            for (int i = idx; i < n; i++)
            {
                int tmp = arr[idx];
                arr[idx] = arr[i];
                arr[i] = tmp;

                solve(idx + 1, n, ref arr, ref permutations);

                tmp = arr[idx];
                arr[idx] = arr[i];
                arr[i] = tmp;
            }
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToUpper();
            for (int sz = 2; sz <= 7; sz++)
            {
                List<int> arr = new List<int>();
                for (int i = 1; i <= sz; i++)
                    arr.Add(i);
                List<List<int>> permutations = new List<List<int>>();
                solve(0, sz, ref arr, ref permutations);
                for (int i = 0; i < permutations.Count; i++)
                {
                    string cipher = Encrypt(plainText, permutations[i]);
                    if (String.Compare(cipher, cipherText) == 0)
                        return permutations[i];
                }
            }
            List<int> ret = new List<int>();
            return ret;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int depth = key.Count;
            int textSize = cipherText.Length, rows = textSize / depth;
            if (textSize % depth != 0)
                rows++;
            int zyada = textSize % depth;
            int[] arr = new int[depth + 5];
            for (int i = 0; i < key.Count; i++)
                arr[key[i]] = i;
            int[,] table = new int[rows, depth];
            for (int i = 0; i < rows; i++)
                for (int j = 0; j < depth; j++)
                    table[i, j] = -1;
            int idx = 0;
            for (int i = 1; i <= depth; i++)
            {
                int to;
                if (arr[i] >= depth - zyada)
                    to = rows - 1;
                else
                    to = rows;
                for (int j = 0; j < to; j++)
                {
                    if (idx >= cipherText.Length)
                        table[j, arr[i]] = -1;
                    else
                        table[j, arr[i]] = cipherText[idx] - 'a';
                    idx++;
                }
            }
            string plain = "";
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    if (table[i, j] != -1)
                        plain += (char)(table[i, j] + 'a');
                }
            }
            return plain;
            
            // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            
            plainText = plainText.ToLower();
            int depth = key.Count;
            int textSize = plainText.Length, rows = textSize / depth;
            if (textSize % depth != 0)
                rows++;
            int[,] table = new int[rows, depth];
            int idx = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    if (idx >= plainText.Length)
                        table[i, j] = -1;
                    else
                        table[i, j] = plainText[idx] - 'a';
                    idx++;
                }
            }
            int[] arr = new int[depth + 5];
            for (int i = 0; i < key.Count; i++)
            {
                arr[key[i]] = i;
            }
            string cipher = "";
            for (int i = 1; i <= key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (table[j, arr[i]] != -1)
                        cipher += (char) ('a' + table[j, arr[i]]);
                }
            }
            return cipher.ToUpper();
            
            // throw new NotImplementedException();
        }
    }
}
