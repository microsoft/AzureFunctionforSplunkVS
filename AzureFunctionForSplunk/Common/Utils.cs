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
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.Common
{
    public class Utils
    {
        private static string splunkCertThumbprint { get; set; }
        private static string functionAppDirectory { get; set; }

        static Utils()
        {
            splunkCertThumbprint = GetEnvironmentVariable("splunkCertThumbprint");
            functionAppDirectory = new ExecutionContext().FunctionAppDirectory;
        }

        public static string GetEnvironmentVariable(string name)
        {
            var result = System.Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
            if (result == null)
                return "";

            return result;
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
            }
            else
            {
                return null;
            }
        }

        public class SingleHttpClientInstance
        {
            private static readonly HttpClient HttpClient;

            static SingleHttpClientInstance()
            {
                var handler = new SocketsHttpHandler
                {
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        RemoteCertificateValidationCallback = ValidateMyCert,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                    }
                };

                HttpClient = new HttpClient(handler);
            }

            public static async Task<HttpResponseMessage> SendToService(HttpRequestMessage req)
            {
                HttpResponseMessage response = await HttpClient.SendAsync(req);
                return response;
            }
        }

        //public static bool ValidateMyCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErr)
        //{
        //    // if user has not configured a cert, anything goes
        //    if (string.IsNullOrWhiteSpace(splunkCertThumbprint))
        //        return true;

        //    // if user has configured a cert, must match
        //    var thumbprint = cert.GetCertHashString();
        //    if (thumbprint == splunkCertThumbprint)
        //        return true;

        //    return false;
        //}

        public static bool ValidateMyCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErr)
        {
            // if user has not configured a cert, anything goes
            if (string.IsNullOrWhiteSpace(splunkCertThumbprint))
                return true;

            // if user has configured a cert, must match
            var numcerts = chain.ChainElements.Count;
            var cacert = chain.ChainElements[numcerts - 1].Certificate;

            var thumbprint = cacert.GetCertHashString().ToLower();
            if (thumbprint == splunkCertThumbprint)
                return true;

            return false;
        }

        public static async Task obEventhub(List<string> standardizedEvents, IAsyncCollector<string> outputEvents, ILogger log)
        {
            foreach (string item in standardizedEvents)
            {
                try
                {
                    await outputEvents.AddAsync(item);
                }
                catch (Exception ex)
                {
                    throw new System.Exception("Sending to event hub output. Unplanned exception: ", ex);
                }
            }
        }

        public static async Task obProxy(List<string> standardizedEvents, ILogger log)
        {
            string proxyAddress = Utils.GetEnvironmentVariable("proxyAddress");
            if (proxyAddress.Length == 0)
            {
                log.LogError("Address of proxy function is required.");
                throw new ArgumentException();
            }

            string serviceResourceIDURI = Utils.GetEnvironmentVariable("serviceResourceIDURI");
            if (serviceResourceIDURI.Length == 0)
            {
                log.LogError("The AAD service resource ID URI (serviceResourceIDURI) of the proxy app is required.");
                throw new ArgumentException();
            }

            string astpConnection = "";
            bool devEnvironment = Utils.GetEnvironmentVariable("FUNCTIONS_CORETOOLS_ENVIRONMENT").ToLower() == "true";
            if (devEnvironment)
            {
                astpConnection = Utils.GetEnvironmentVariable("astpConnectionString");
            }
            // log.LogInformation($"devEnvironment: {devEnvironment}, astpConnection: {astpConnection}");

            string accessToken = "";
            try
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider(
                    connectionString: astpConnection
                );

                accessToken = await azureServiceTokenProvider.GetAccessTokenAsync(serviceResourceIDURI);
            }
            catch (Exception ex)
            {
                log.LogError($"Error acquiring token from AzureServiceTokenProvider: {ex.Message}");
                throw;
            }

            StringBuilder bulkTransmission = new StringBuilder();
            foreach (string item in standardizedEvents)
            {
                bulkTransmission.Append(item);
            }
            try
            {
                var httpRequestMessage = new HttpRequestMessage
                {
                    Method = HttpMethod.Post,
                    RequestUri = new Uri(proxyAddress),
                    Headers = {
                        { HttpRequestHeader.Authorization.ToString(), "Bearer " + accessToken }
                    },
                    Content = new StringContent(bulkTransmission.ToString(), Encoding.UTF8)
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

        public static async Task obHEC(List<string> standardizedEvents, ILogger log)
        {
            string splunkAddress = Utils.GetEnvironmentVariable("splunkAddress");
            string splunkToken = Utils.GetEnvironmentVariable("splunkToken");
            if (splunkAddress.Length == 0 || splunkToken.Length == 0)
            {
                log.LogError("Values for splunkAddress and splunkToken are required.");
                throw new ArgumentException();
            }

            if (!string.IsNullOrWhiteSpace(splunkCertThumbprint))
            {
                if (!splunkAddress.ToLower().StartsWith("https"))
                {
                    throw new ArgumentException("Having provided a Splunk cert thumbprint, the address must be https://whatever");
                }
            }

            log.LogInformation($"Sending events count : {standardizedEvents.Count}");
            var client = new SingleHttpClientInstance();
            foreach (string item in standardizedEvents)
            {
                try
                {
                    var httpRequestMessage = new HttpRequestMessage
                    {
                        Method = HttpMethod.Post,
                        RequestUri = new Uri(splunkAddress),
                        Headers = {
                            { HttpRequestHeader.Authorization.ToString(), "Splunk " + splunkToken }
                        },
                        Content = new StringContent(item, Encoding.UTF8, "application/json")
                    };

                    HttpResponseMessage response = await SingleHttpClientInstance.SendToService(httpRequestMessage);
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
}