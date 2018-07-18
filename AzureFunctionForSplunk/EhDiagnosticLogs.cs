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
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.WebJobs.ServiceBus;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk
{
    public static class EhDiagnosticLogs
    {
        [FunctionName("EhDiagnosticLogs")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-diagnostics-logs%", Connection = "hubConnection")]string[] messages,
            TraceWriter log)
        {

            List<string> splunkEventMessages = null;
            try
            {
                splunkEventMessages = MakeSplunkEventMessages(messages, log);
            }
            catch (Exception ex)
            {
                log.Error($"{ex.Message}");
                throw ex;
            }

            string outputBinding = Utils.getEnvironmentVariable("outputBinding");
            if (outputBinding.ToUpper() == "HEC")
            {
                try
                {
                    await Utils.obHEC(splunkEventMessages, log);
                }
                catch (Exception ex)
                {
                    log.Error($"Error transmitting to Splunk.");
                    throw ex;
                }
            }
            else
            {
                log.Error("No or incorrect output binding specified. No messages sent to Splunk.");
                throw new System.ArgumentException("No or incorrect output binding specified. No messages sent to Splunk.");
            }

        }

        private static List<string> MakeSplunkEventMessages(string[] messages, TraceWriter log)
        {
            Dictionary<string, string> DiagnosticLogCategories = new Dictionary<string, string>();

            var filename = Utils.getFilename("DiagnosticLogCategories.json");

            // log.Info($"File name of categories dictionary is: {filename}");

            try
            {
                DiagnosticLogCategories = Utils.GetDictionary(filename);
            }
            catch (Exception ex)
            {
                log.Error($"Error getting categories json file. {ex.Message}");
            }

            List<string> splunkEventMessages = new List<string>();

            foreach (var message in messages)
            {
                var converter = new ExpandoObjectConverter();
                dynamic obj = JsonConvert.DeserializeObject<ExpandoObject>(message, converter);

                var records = obj.records;

                foreach (var record in records)
                {
                    var resourceId = record.resourceId;

                    var splunkEventMessage = new DiagnosticLogMessage(resourceId, record);

                    var resourceType = splunkEventMessage.ResourceType;

                    string category;
                    try
                    {
                        category = record.category;
                    } catch
                    {
                        category = "none";
                    }
                    var sourceType = Utils.GetDictionaryValue(resourceType.ToUpper() + "/" + category.ToUpper(), DiagnosticLogCategories) ?? "amdl:diagnostic";

                    splunkEventMessage.SetSourceType(sourceType);

                    splunkEventMessages.Add(splunkEventMessage.GetSplunkEventFromMessage());
                }
            }

            return splunkEventMessages;
        }
    }
}
