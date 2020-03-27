using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace MapleShark
{
    class TripleDESCipher
    {
        public static string Decrypt(byte[] aData, byte[] aKey)
        {
            TripleDESCryptoServiceProvider pCipher = new TripleDESCryptoServiceProvider();
            pCipher.BlockSize = 64;
            pCipher.Mode = CipherMode.ECB;
            pCipher.Padding = PaddingMode.None;
            pCipher.FeedbackSize = 64;
            pCipher.GenerateIV();
            MethodInfo mi = pCipher.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] aObj = { aKey, pCipher.Mode, pCipher.IV, pCipher.FeedbackSize, 1 };
            ICryptoTransform pTransform = mi.Invoke(pCipher, aObj) as ICryptoTransform;
            byte[] aResult = pTransform.TransformFinalBlock(aData, 0, aData.Length);
            pCipher.Clear();
            return Encoding.UTF8.GetString(aResult);
        }
    }
}
