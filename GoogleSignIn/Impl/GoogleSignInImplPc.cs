#if UNITY_EDITOR || UNITY_STANDALONE
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UnityEngine;

namespace Google.Impl
{

    public static class PkceUtil
    {
        // Rastgele 64 bayt üretip base64url ile encode eder
        public static string GenerateCodeVerifier()
        {
            var randomBytes = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(randomBytes);

            return Base64UrlEncode(randomBytes);
        }

        // code_challenge oluşturur (SHA256 + Base64URL)
        public static string ComputeCodeChallenge(string codeVerifier)
        {
            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.ASCII.GetBytes(codeVerifier);
                var hash = sha.ComputeHash(bytes);
                return Base64UrlEncode(hash);
            }
        }

        // Normal Base64 → URL-safe Base64 (PKCE standardına göre)
        private static string Base64UrlEncode(byte[] input)
        {
            var s = Convert.ToBase64String(input);   // standart Base64
            s = s.Split('=')[0];                     // '=' padding’leri kaldır
            s = s.Replace('+', '-');                 // '+' → '-'
            s = s.Replace('/', '_');                 // '/' → '_'
            return s;
        }
    }

    internal class GoogleSignInImplPc : ISignInImpl, FutureAPIImpl<GoogleSignInUser>
    {
        GoogleSignInConfiguration configuration;

        public bool Pending { get; private set; }

        public GoogleSignInStatusCode Status { get; private set; }

        public GoogleSignInUser Result { get; private set; }

        public string OutCode { get; private set; }

        protected string codeVerifier, codeChallenge;

        public GoogleSignInImplPc(GoogleSignInConfiguration configuration)
        {
            this.configuration = configuration;
            codeVerifier = PkceUtil.GenerateCodeVerifier();
            codeChallenge = PkceUtil.ComputeCodeChallenge(codeVerifier);
        }

        public void Disconnect()
        {
            Result = null;
            Status = GoogleSignInStatusCode.CANCELED;
            Debug.Log("[GoogleSignInImplPc] User disconnected");
        }

        public void EnableDebugLogging(bool flag)
        {
            Debug.Log($"[GoogleSignInImplPc] Debug logging {(flag ? "enabled" : "disabled")}");
        }

        public Future<GoogleSignInUser> SignIn()
        {
            SigningIn();
            return new Future<GoogleSignInUser>(this);
        }

        public Future<GoogleSignInUser> SignInSilently()
        {
            SigningIn();
            return new Future<GoogleSignInUser>(this);
        }

        public void SignOut()
        {
            Result = null;
            Status = GoogleSignInStatusCode.CANCELED;
            Debug.Log("[GoogleSignInImplPc] User signed out");
        }

        static HttpListener BindLocalHostFirstAvailablePort()
        {
            ushort minPort = 49215;
#if UNITY_EDITOR_WIN
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            return Enumerable.Range(minPort, ushort.MaxValue - minPort).Where((i) => !listeners.Any((x) => x.Port == i)).Select((port) =>
            {
#elif UNITY_EDITOR_OSX
                return Enumerable.Range(minPort, ushort.MaxValue - minPort).Select((port) => {
#else
                return Enumerable.Range(0,10).Select((i) => UnityEngine.Random.Range(minPort,ushort.MaxValue)).Select((port) => {
#endif
                try
                {
                    Debug.Log($"[GoogleSignInImplPc] BindLocalHostFirstAvailablePort, trying port: {port}");
                    var listener = new HttpListener();
                    listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                    listener.Start();
                    return listener;
                }
                catch (System.Exception e)
                {
                    Debug.LogException(e);
                    return null;
                }
            }).FirstOrDefault((listener) => listener != null);
        }

        void SigningIn()
        {
            Pending = true;
            Status = GoogleSignInStatusCode.API_NOT_CONNECTED;

            var httpListener = BindLocalHostFirstAvailablePort();
            if (httpListener == null)
            {
                Debug.LogError("[GoogleSignInImplPc] Failed to bind to any local port");
                Status = GoogleSignInStatusCode.INTERNAL_ERROR;
                Pending = false;
                return;
            }

            try
            {
                var openURL = "https://accounts.google.com/o/oauth2/v2/auth?" + Uri.EscapeUriString("scope=openid email profile&response_type=code&redirect_uri=" + httpListener.Prefixes.FirstOrDefault() + "&client_id=" + configuration.DesktopClientId + $"&code_challenge={codeChallenge}&code_challenge_method=S256");
                Debug.Log($"[GoogleSignInImplPc] Opening URL: {openURL}");
                Application.OpenURL(openURL);
            }
            catch (Exception e)
            {
                Debug.LogException(e);
                Status = GoogleSignInStatusCode.INTERNAL_ERROR;
                Pending = false;
                httpListener.Stop();
                throw;
            }

            var taskScheduler = TaskScheduler.FromCurrentSynchronizationContext();
            httpListener.GetContextAsync().ContinueWith(async (task) =>
            {
                try
                {
                    Debug.Log($"[GoogleSignInImplPc] Received callback: {task.Status}");
                    var context = task.Result;
                    var queryString = context.Request.Url.Query;
                    var queryDictionary = System.Web.HttpUtility.ParseQueryString(queryString);

                    if (queryDictionary == null || queryDictionary.Get("code") is not string code || string.IsNullOrEmpty(code))
                    {
                        // Check if user canceled or there was an error
                        var error = queryDictionary?.Get("error");
                        if (error == "access_denied")
                        {
                            Status = GoogleSignInStatusCode.CANCELED;
                        }
                        else
                        {
                            Status = GoogleSignInStatusCode.INVALID_ACCOUNT;
                        }

                        context.Response.StatusCode = 400;
                        context.Response.OutputStream.Write(Encoding.UTF8.GetBytes("Authentication failed. You can close this page and go back to app."));
                        context.Response.Close();
                        return;
                    }

                    context.Response.StatusCode = 200;
                    context.Response.OutputStream.Write(Encoding.UTF8.GetBytes("Authentication successful! You can close this page and go back to app."));
                    context.Response.Close();

                    //var tokenRequestBody = $"code={code}&client_id={configuration.DesktopClientId}&code_verifier={codeVerifier}&redirect_uri={httpListener.Prefixes.FirstOrDefault()}&grant_type=authorization_code";

                    //var jobj = await HttpWebRequest.CreateHttp("https://www.googleapis.com/oauth2/v4/token")
                    //    .Post("application/x-www-form-urlencoded", tokenRequestBody)
                    //    .ContinueWith((t) => JObject.Parse(t.Result), taskScheduler);

                    //var accessToken = (string)jobj.GetValue("access_token");
                    //var user = new GoogleSignInUser();

                    //if (configuration.RequestAuthCode)
                    //    user.AuthCode = code;

                    //if (configuration.RequestIdToken)
                    //    user.IdToken = (string)jobj.GetValue("id_token");

                    //var request = HttpWebRequest.CreateHttp("https://openidconnect.googleapis.com/v1/userinfo");
                    //request.Method = "GET";
                    //request.Headers.Add("Authorization", "Bearer " + accessToken);

                    //var data = await request.GetResponseAsStringAsync().ContinueWith((t) => t.Result, taskScheduler);
                    //var userInfo = JObject.Parse(data);

                    //user.UserId = (string)userInfo.GetValue("sub");
                    //user.DisplayName = (string)userInfo.GetValue("name");

                    //if (configuration.RequestEmail)
                    //    user.Email = (string)userInfo.GetValue("email");

                    //if (configuration.RequestProfile)
                    //{
                    //    user.GivenName = (string)userInfo.GetValue("given_name");
                    //    user.FamilyName = (string)userInfo.GetValue("family_name");
                    //    user.ImageUrl = Uri.TryCreate((string)userInfo.GetValue("picture"), UriKind.Absolute, out var url) ? url : null;
                    //}

                    OutCode = code;
                    //Result = user;
                    Status = GoogleSignInStatusCode.SUCCESS;
                    //Debug.Log($"[GoogleSignInImplPc] Sign-in successful for user: {user.DisplayName}");
                    Debug.Log($"[GoogleSignInImplPc] Sign-in successful");
                }
                catch (Exception e)
                {
                    // Determine appropriate error status based on exception type
                    if (e is WebException webEx)
                    {
                        if (webEx.Status == WebExceptionStatus.Timeout)
                        {
                            Status = GoogleSignInStatusCode.TIMEOUT;
                        }
                        else if (webEx.Status == WebExceptionStatus.ConnectFailure ||
                                 webEx.Status == WebExceptionStatus.NameResolutionFailure)
                        {
                            Status = GoogleSignInStatusCode.NETWORK_ERROR;
                        }
                        else
                        {
                            Status = GoogleSignInStatusCode.INTERNAL_ERROR;
                        }
                    }
                    else if (e is TaskCanceledException)
                    {
                        Status = GoogleSignInStatusCode.CANCELED;
                    }
                    else
                    {
                        Status = GoogleSignInStatusCode.ERROR;
                    }

                    Debug.LogException(e);

                    if (e is AggregateException ae)
                    {
                        foreach (var inner in ae.InnerExceptions)
                            Debug.LogException(inner);
                    }
                }
                finally
                {
                    Pending = false;
                    httpListener.Stop();
                }
            }, taskScheduler);
        }
    }

    // Extension methods for HttpWebRequest
    internal static class HttpWebRequestExtensions
    {
        public static Task<string> Post(this HttpWebRequest request, string contentType, string body)
        {
            request.Method = "POST";
            request.ContentType = contentType;

            var bodyBytes = Encoding.UTF8.GetBytes(body);
            request.ContentLength = bodyBytes.Length;

            return Task.Run(async () =>
            {
                using (var stream = await request.GetRequestStreamAsync())
                {
                    await stream.WriteAsync(bodyBytes, 0, bodyBytes.Length);
                }

                using (var response = (HttpWebResponse)await request.GetResponseAsync())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    return await reader.ReadToEndAsync();
                }
            });
        }

        public static Task<string> GetResponseAsStringAsync(this HttpWebRequest request)
        {
            return Task.Run(async () =>
            {
                using (var response = (HttpWebResponse)await request.GetResponseAsync())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    return await reader.ReadToEndAsync();
                }
            });
        }
    }
}
#endif