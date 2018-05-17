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
    public static class EhMetrics
    {
        [FunctionName("EhMetrics")]
        public static async Task Run([EventHubTrigger("%input-hub-name-metrics%", Connection = "hubConnection")]
            string[] messages, 
            TraceWriter log)
        {
            List<string> splunkEventMessages = MakeSplunkEventMessages(messages, log);

            string outputBinding = Utils.getEnvironmentVariable("outputBinding");
            if (outputBinding.ToUpper() == "HEC")
            {
                await Utils.obHEC(splunkEventMessages, log);
            }
            else
            {
                log.Info("No or incorrect output binding specified. No messages sent to Splunk.");
            }
        }

        private static List<string> MakeSplunkEventMessages(string[] messages, TraceWriter log)
        {
            Dictionary<string, string> MetricsCategories = new Dictionary<string, string>();

            var filename = Utils.getFilename("MetricsCategories.json");

            // log.Info($"File name of categories dictionary is: {filename}");

            try
            {
                MetricsCategories = Utils.GetDictionary(filename);
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
                    var resourceId = (string)record.resourceId;
                    var metricMessage = new MetricMessage(resourceId, record);

                    metricMessage.SplunkSourceType = Utils.GetDictionaryValue(metricMessage.ResourceType, MetricsCategories) ?? "amm:metrics";

                    string splunkEventMessage = metricMessage.GetSplunkEventFromMessage();

                    splunkEventMessages.Add(splunkEventMessage);
                }
            }

            return splunkEventMessages;
        }
    }
}
