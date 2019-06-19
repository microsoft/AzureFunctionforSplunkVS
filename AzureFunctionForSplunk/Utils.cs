//
// AzureFunctionForSplunkVS
//
// Copyright (c) Microsoft Corporation
//
// All rights reserved. 
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the ""Software""), to deal 
// in the Software without restriction, including without limitation the rights 
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is furnished 
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all 
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk
{
    public class TransmissionFaultMessage
    {
        public string id { get; set; }
        public string type { get; set; }

    }

    public class Utils
    {
        static string splunkCertThumbprint { get; set; }

        public Utils()
        {
            splunkCertThumbprint = getEnvironmentVariable("splunkCertThumbprint");
        }

        public static string getEnvironmentVariable(string name)
        {
            var result = System.Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
            if (result == null)
                return "";

            return result;
        }

        public static string getFilename(string basename)
        {

            var filename = "";
            var home = getEnvironmentVariable("HOME");
            if (home.Length == 0)
            {
                filename = "../../../" + basename;
            }
            else
            {
                filename = home + "\\site\\wwwroot\\" + basename;
            }
            return filename;
        }

        public static Dictionary<string, string> GetDictionary(string filename)
        {
            Dictionary<string, string> dictionary;
            try
            {
                string json = File.ReadAllText(filename);

                dictionary = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }
            catch (Exception)
            {
                dictionary = new Dictionary<string, string>();
                throw;
            }

            return dictionary;
        }

        public static string GetDictionaryValue(string key, Dictionary<string, string> dictionary)
        {
            string value = "";
            if (dictionary.TryGetValue(key, out value))
            {
                return value;
            } else
            {
                return null;
            }
        }

        public class SingleHttpClientInstance
        {
            private static readonly HttpClient HttpClient;

            static SingleHttpClientInstance()
            {
                HttpClient = new HttpClient();
            }

            public static async Task<HttpResponseMessage> SendToService(HttpRequestMessage req)
            {
                HttpResponseMessage response = await HttpClient.SendAsync(req);
                return response;
            }
        }

        public static bool ValidateMyCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErr)
        {
            // if user has not configured a cert, anything goes
            if (string.IsNullOrWhiteSpace(splunkCertThumbprint))
                return true;

            // if user has configured a cert, must match
            var thumbprint = cert.GetCertHashString();
            if (thumbprint == splunkCertThumbprint)
                return true;

            return false;
        }

        public static async Task obProxy(List<string> standardizedEvents, ILogger log)
        {
            string proxyAddress = Utils.getEnvironmentVariable("proxyAddress");
            if (proxyAddress.Length == 0)
            {
                log.LogError("Address of proxy function is required.");
                throw new ArgumentException();
            }

            string serviceResourceIDURI = Utils.getEnvironmentVariable("serviceResourceIDURI");
            if (serviceResourceIDURI.Length == 0)
            {
                log.LogError("The AAD service resource ID URI (serviceResourceIDURI) of the proxy app is required.");
                throw new ArgumentException();
            }

            string accessToken = "";
            try
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider("RunAs=App;AppId=f7550d72-1cfd-42da-82b9-b1ec64436e73;TenantId=b8b4c61c-f1ca-4aff-a0bd-9c6f01c3eca5;AppKey=a35f0723-ab8d-468e-b7e1-ab6ab39f3a5f");

                accessToken = await azureServiceTokenProvider.GetAccessTokenAsync(serviceResourceIDURI);
            } catch (Exception ex)
            {
                log.LogError($"Error acquiring token from AzureServiceTokenProvider: {ex.Message}");
                throw;
            }

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateMyCert);

            var client = new SingleHttpClientInstance();

            foreach (string item in standardizedEvents)
            {
                try
                {
                    var httpRequestMessage = new HttpRequestMessage
                    {
                        Method = HttpMethod.Post,
                        RequestUri = new Uri(proxyAddress),
                        Headers = {
                            { HttpRequestHeader.Authorization.ToString(), "Bearer " + accessToken }
                        },
                        Content = new StringContent(item, Encoding.UTF8, "application/json")
                    };

                    HttpResponseMessage response = await SingleHttpClientInstance.SendToService(httpRequestMessage);
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new System.Net.Http.HttpRequestException($"StatusCode from Proxy Function: {response.StatusCode}, and reason: {response.ReasonPhrase}");
                    }
                }
                catch (System.Net.Http.HttpRequestException e)
                {
                    throw new System.Net.Http.HttpRequestException("Sending to Proxy Function. Is the service running?", e);
                }
                catch (Exception f)
                {
                    throw new System.Exception("Sending to Proxy Function. Unplanned exception.", f);
                }
            }
        }

        public static async Task obHEC(List<string> standardizedEvents, ILogger log)
        {
            string splunkAddress = Utils.getEnvironmentVariable("splunkAddress");
            string splunkToken = Utils.getEnvironmentVariable("splunkToken");
            if (splunkAddress.Length == 0 || splunkToken.Length == 0)
            {
                log.LogError("Values for splunkAddress and splunkToken are required.");
                return;
            }

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateMyCert);

            var newClientContent = new StringBuilder();
            foreach (string item in standardizedEvents)
            {
                newClientContent.Append(item);
            }

            log.LogInformation(newClientContent.ToString());

            var client = new SingleHttpClientInstance();
            try
            {
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, splunkAddress);
                req.Headers.Accept.Clear();
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                req.Headers.Add("Authorization", "Splunk " + splunkToken);
                req.Content = new StringContent(newClientContent.ToString(), Encoding.UTF8, "application/json");
                HttpResponseMessage response = await SingleHttpClientInstance.SendToService(req);
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw new System.Net.Http.HttpRequestException($"StatusCode from Splunk: {response.StatusCode}, and reason: {response.ReasonPhrase}");
                }
            }
            catch (System.Net.Http.HttpRequestException e)
            {
                throw new System.Net.Http.HttpRequestException("Sending to Splunk. Is Splunk service running?", e);
            }
            catch (Exception f)
            {
                throw new System.Exception("Sending to Splunk. Unplanned exception.", f);
            }
        }

    }
}
