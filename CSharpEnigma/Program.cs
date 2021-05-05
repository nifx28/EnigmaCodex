using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CSharpEnigma
{
    internal class Program
    {
        /// <summary>
        /// 使用方法：加密 ".\bin\Debug\CSharpEnigma.exe" enc "TestData\SrcFile.txt" "TestData\EncFile.txt"
        /// 使用方法：解密 ".\bin\Debug\CSharpEnigma.exe" dec "TestData\EncFile.txt" "TestData\DecFile.txt"
        /// </summary>
        /// <param name="args"></param>
        private static int Main(string[] args)
        {
            // 取得組件資訊。
            var assem = Assembly.GetExecutingAssembly();
            Console.Title =
                assem.GetCustomAttribute<AssemblyTitleAttribute>().Title + " - " +    // 標題。
                assem.GetCustomAttribute<AssemblyDescriptionAttribute>().Description; // 描述。

            try
            {
                var fileName = Path.GetFileNameWithoutExtension(assem.Location);

                if (args.Length < 3)
                {
                    Console.WriteLine(
                        $"缺少必要的參數！{Environment.NewLine}" +
                        $"使用方法：加密 {fileName} enc [要被加密的檔案] [加密之後的檔案]{Environment.NewLine}" +
                        $"使用方法：解密 {fileName} dec [要被解密的檔案] [解密之後的檔案]");

                    Console.Write("請按任意鍵繼續 . . . ");
                    Console.ReadKey(true);
                    return 1;
                }

                string basePath = AppDomain.CurrentDomain.BaseDirectory; // ".\bin\Debug"
                string srcPath = Path.Combine(basePath, args[1]), // 參數1：要被加密的檔名 "TestData\SrcFile.txt"。
                                                                  // 參數2：加密之後的檔名 "TestData\EncFile.txt"。
                       encPath = Path.Combine(basePath, args[2]); // 參數1：要被解密的檔名 "TestData\EncFile.txt"。
                                                                  // 參數2：解密之後的檔名 "TestData\DecFile.txt"。

                int typeCode = -1;
                var typeStr = string.Empty;

                switch (args[0].ToLowerInvariant())
                {
                    case "enc":
                        typeCode = 1;
                        typeStr = "加密";
                        break;
                    case "dec":
                        typeCode = 2;
                        typeStr = "解密";
                        break;
                    default:
                        throw new Exception($"{fileName} {args[0]} 無此功能！");
                }

                // 加密：
                //    ".\bin\Debug\TestData\SrcFile.txt"
                //    ".\bin\Debug\TestData\EncFile.txt"
                if (!File.Exists(srcPath))
                {
                    throw new Exception($@"找不到 ""{srcPath}"" 要被{typeStr}的檔案！");
                }

                // 解密：
                //    ".\bin\Debug\TestData\EncFile.txt"
                //    ".\bin\Debug\TestData\DecFile.txt"
                if (File.Exists(encPath))
                {
                    //throw new Exception($@"{typeStr}之後的 ""{encPath}"" 檔案已存在！");
                }

                // https://docs.microsoft.com/en-us/dotnet/standard/security/encrypting-data
                // Encrypting data | Microsoft Docs

                byte[] encKey = Encoding.UTF8.GetBytes(
                            ConfigurationManager.AppSettings["EncKey"]); // 從 CSharpEnigma.exe.config (App.config) 讀取金鑰。
                int keyLen = 32;

                if (encKey.Length < keyLen)
                {
                    var list = new List<byte>();
                    list.AddRange(encKey);

                    while (list.Count < keyLen)
                    {
                        list.AddRange(encKey);
                    }

                    encKey = list.ToArray();
                }

                if (encKey.Length > keyLen)
                {
                    encKey = encKey
                        .Take(keyLen) // 只取 32 位元組 (256 位元)。
                        .ToArray();
                }

                if (typeCode == 1) // 加密。
                {
                    var srcContent = string.Empty;

                    using (var srcReader = new StreamReader(srcPath))
                    {
                        srcContent = srcReader.ReadToEnd();
                    }

                    using (FileStream encFile = File.OpenWrite(encPath))
                    {
                        var algName = new CngAlgorithm("AES");
                        var keyName = Guid.NewGuid().ToString();
                        CngKey cngKey = CngKey.Create(algName, keyName);

                        try
                        {
                            using (Aes aes = new AesCng(keyName) { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                            {
                                int keySize = aes.KeySize / 8;

                                if (keySize != keyLen)
                                {
                                    throw new Exception($"加密演算法的金鑰長度 {keySize} 不符合 {keyLen} 加密金鑰長度！");
                                }

                                // 把 初始化向量 (IV) 寫入加密檔頭。
                                byte[] iv = aes.IV;
                                encFile.Write(iv, 0, iv.Length);

                                using (var crypto = new CryptoStream(encFile, aes.CreateEncryptor(encKey, iv), CryptoStreamMode.Write))
                                using (var writer = new StreamWriter(crypto))
                                {
                                    writer.Write(srcContent);
                                }
                            }
                        }
                        finally
                        {
                            cngKey.Delete();
                        }
                    }
                }
                else if (typeCode == 2) // 解密。
                {
                    using (FileStream encFile = File.OpenRead(srcPath))
                    using (var encWriter = new StreamWriter(encPath, false, new UTF8Encoding(true))) // UTF-8 (含BOM)。
                    {
                        var algName = new CngAlgorithm("AES");
                        var keyName = Guid.NewGuid().ToString();
                        CngKey cngKey = CngKey.Create(algName, keyName);

                        try
                        {
                            using (Aes aes = new AesCng(keyName) { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                            {
                                int keySize = aes.KeySize / 8;

                                if (keySize != keyLen)
                                {
                                    throw new Exception($"加密演算法的金鑰長度 {keySize} 不符合 {keyLen} 加密金鑰長度！");
                                }

                                int ivLen = aes.IV.Length, cbLen = 0;
                                byte[] iv = new byte[ivLen];

                                while (ivLen > 0)
                                {
                                    int cb = encFile.Read(iv, cbLen, ivLen);

                                    if (cb == 0)
                                    {
                                        break;
                                    }

                                    cbLen += cb;
                                    ivLen -= cb;
                                }

                                using (var crypto = new CryptoStream(encFile, aes.CreateDecryptor(encKey, iv), CryptoStreamMode.Read))
                                using (var reader = new StreamReader(crypto))
                                {
                                    encWriter.Write(reader.ReadToEnd());
                                }
                            }
                        }
                        finally
                        {
                            cngKey.Delete();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    ex = ex.InnerException;
                }

                Console.Error.WriteLine($"{ex.GetType().Name}: {ex.Message}{Environment.NewLine}{ex.StackTrace}");
            }

            Console.Write("請按任意鍵繼續 . . . ");
            Console.ReadKey(true);
            return 0;
        }
    }
}