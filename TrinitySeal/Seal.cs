using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Security.Principal;
using System.Collections.Generic;

using Newtonsoft.Json;

using Leaf.xNet;

namespace TrinitySeal {
    public class Seal {
        private static Random rand = new Random();

        private static Dictionary<string, string> Vars = new Dictionary<string, string>();

        public static string Secret { get; set; }

        internal static string Key { get; set; }

        internal static string Salt { get; set; }

        private static string Session_ID(int length) {
            return new string(Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", length)
              .Select(s => s[rand.Next(s.Length)]).ToArray());
        }

        private static void Start_Session() {
            Key = Convert.ToBase64String(Encoding.Default.GetBytes(Session_ID(32)));
            Salt = Convert.ToBase64String(Encoding.Default.GetBytes(Session_ID(16)));
        }

        public static string Initialize(string version) {
            Start_Session();

            using (var request = new HttpRequest()) {
                request.UserAgent = "TrinitySeal";

                var PostData = new Dictionary<string, string>() {
                    ["programtoken"] = Handler.Payload_ENCRYPT(Secret),
                    ["session_id"] = Key,
                    ["session_salt"] = Salt
                };

                var result = request.Post("https://auth.trinityseal.me/program.php", new FormUrlEncodedContent(PostData));

                return Handler.Payload_DECRYPT(result.ToString());
            }
        }

        public static string Register(string username, string password, string email, string token, bool message = true) {
            using (var request = new HttpRequest()) {
                request.UserAgent = "TrinitySeal";

                var PostData = new Dictionary<string, string>() {
                    ["username"] = Handler.Payload_ENCRYPT(username),
                    ["password"] = Handler.Payload_ENCRYPT(password),
                    ["email"] = Handler.Payload_ENCRYPT(email),
                    ["hwid"] = Handler.Payload_ENCRYPT(WindowsIdentity.GetCurrent().User.Value),
                    ["token"] = Handler.Payload_ENCRYPT(token),
                    ["programtoken"] = Handler.Payload_ENCRYPT(Secret),
                    ["session_id"] = Key,
                    ["session_salt"] = Salt
                };

                var result = request.Post("https://auth.trinityseal.me/register.php", new FormUrlEncodedContent(PostData));

                return Handler.Payload_DECRYPT(result.ToString());
            }
        }

        public static string Login(string username, string password, bool message = true) {
            using (var request = new HttpRequest()) {
                request.UserAgent = "TrinitySeal";

                var PostData = new Dictionary<string, string>() {
                    ["username"] = Handler.Payload_ENCRYPT(username),
                    ["password"] = Handler.Payload_ENCRYPT(password),
                    ["hwid"] = Handler.Payload_ENCRYPT(WindowsIdentity.GetCurrent().User.Value),
                    ["programtoken"] = Handler.Payload_ENCRYPT(Secret),
                    ["timestamp"] = Handler.Payload_ENCRYPT(Handler.EncryptDateTime(DateTime.Now.ToString())),
                    ["session_id"] = Key,
                    ["session_salt"] = Salt
                };

                var result = request.Post("https://auth.trinityseal.me/login.php", new FormUrlEncodedContent(PostData));

                return Handler.Payload_DECRYPT(result.ToString());
            }
        }

        public static string GrabVariables(string secretkey, string programtoken, string username, string password) {
            using (var request = new HttpRequest()) {
                request.UserAgent = "TrinitySeal";

                var PostData = new Dictionary<string, string>() {
                    ["programtoken"] = Handler.Payload_ENCRYPT(programtoken), // This is a different secret ig ¯\_(ツ)_/¯
                    ["username"] = Handler.Payload_ENCRYPT(username),
                    ["password"] = Handler.Payload_ENCRYPT(password),
                    ["hwid"] = Handler.Payload_ENCRYPT(WindowsIdentity.GetCurrent().User.Value), // Secure af hwid check uwu
                    ["key"] = Handler.Payload_ENCRYPT(secretkey),
                    ["session_id"] = Key,
                    ["session_salt"] = Salt
                };

                var result = request.Post("https://auth.trinityseal.me/variables.php", new FormUrlEncodedContent(PostData));

                dynamic json = JsonConvert.DeserializeObject(Handler.Payload_DECRYPT(result.ToString()));

                foreach (var _var in json.vars)
                    Vars.Add((string)_var.Name, Handler.Payload_DECRYPT((string)_var.Value));

                return Handler.Payload_DECRYPT(result.ToString());
            }
        }

        public static void SaveVars() {
            if (Vars.Count == 0)
                return;

            File.WriteAllText(
                Path.Combine(
                    Path.GetDirectoryName(
                        Assembly.GetExecutingAssembly().Location),
                    "trinityvars.json"),
                JsonConvert.SerializeObject(Vars));
        }
    }
}