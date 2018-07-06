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
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Dynamic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace AzureFunctionForSplunk
{
    public static class EhWadTelemetry
    {
        [FunctionName("EhWadTelemetry")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-wad%", Connection = "hubConnection")]
            string[] messages, 
            TraceWriter log)
        {
            //log.Info($"C# Event Hub trigger function processed messages: {messages}");
            List<string> splunkEventMessages = MakeSplunkEventMessages(messages, log);

            //foreach (var s in splunkEventMessages)
            //{
            //    log.Info($"{s}");
            //}

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
            Dictionary<string, string> WADCategories = new Dictionary<string, string>();

            var filename = Utils.getFilename("WadCategories.json");

            // log.Info($"File name of categories dictionary is: {filename}");

            try
            {
                WADCategories = Utils.GetDictionary(filename);
            }
            catch (Exception ex)
            {
                log.Error($"Error getting wad categories json file. {ex.Message}");
            }

            List<string> splunkEventMessages = new List<string>();

            // each message in the array of messages can contain records of various types
            // 1. perf counter
            // 2. Windows Event Log
            //string messagesJson = "{\"messages\": [";
            foreach (var message in messages)
            {
                //if (messagesJson != "{\"messages\": [")
                //    messagesJson += ",";
                //messagesJson += message;

                var converter = new ExpandoObjectConverter();
                dynamic obj = JsonConvert.DeserializeObject<ExpandoObject>(message, converter);

                var records = obj.records;
                foreach (var record in records)
                {
                    // see if it's perf counter
                    try
                    {
                        var metricName = record.metricName;
                        string splunkEventMessage = GetSplunkEventFromMessage(record, "azwad:perf");
                        splunkEventMessages.Add(splunkEventMessage);
                        continue;
                    } catch (Exception) { }

                    // see if it's WindowsEventLogsTable
                    try
                    {
                        if (record.category == "WindowsEventLogsTable")
                        {
                            string splunkEventMessage = GetSplunkEventFromMessage(record, "azwad:event");
                            splunkEventMessages.Add(splunkEventMessage);
                            continue;
                        }
                    } catch (Exception) { }

                    string s = GetSplunkEventFromMessage(record, "azwad:else");
                    splunkEventMessages.Add(s);
                    continue;
                }
            }
            //messagesJson += "]}";
            //log.Info($"Messages are: {messagesJson}");


            return splunkEventMessages;
        }

        public static string GetSplunkEventFromMessage(dynamic Message, string SplunkSourceType)
        {
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(Message);

            var s = "{";
            s += "\"sourcetype\": \"" + SplunkSourceType + "\",";
            s += "\"event\": " + json;
            s += "}";

            return s;

        }
    }
}
