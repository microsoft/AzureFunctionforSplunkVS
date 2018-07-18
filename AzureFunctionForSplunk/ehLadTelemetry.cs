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
using System.Collections.Generic;
using System.Dynamic;
using System.Threading.Tasks;
using System;

namespace AzureFunctionForSplunk
{
    public static class EhLadTelemetry
    {
        [FunctionName("EhLadTelemetry")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-lad%", Connection = "hubConnection")]
            string[] messages, 
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
            List<string> splunkEventMessages = new List<string>();

            // each message in the array of messages can contain records of various types
            // 1. perf counter
            // 2. syslog

            foreach (var message in messages)
            {
                var dictMessage = JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(message);
                bool isMetric = dictMessage.ContainsKey("metricName");
                bool isLog = dictMessage.ContainsKey("category");

                bool hasResourceId = dictMessage.ContainsKey("resourceId");
                string resourceId = "";
                if (hasResourceId)
                {
                    resourceId = dictMessage["resourceId"].ToString();
                }

                var expandoConverter = new ExpandoObjectConverter();
                var expandoMessage = JsonConvert.DeserializeObject<ExpandoObject>(message, expandoConverter);

                string splunkEventMessage = "";
                if (isMetric)
                {
                    var ladMetricMessage = new LadMetricMessage(resourceId.ToUpper(), expandoMessage)
                    {
                        SplunkSourceType = "azlm:compute:vm"
                    };

                    splunkEventMessage = ladMetricMessage.GetSplunkEventFromMessage();
                } else if (isLog)
                {
                    var ladLogMessage = new LadLogMessage(resourceId.ToUpper(), expandoMessage)
                    {
                        SplunkSourceType = "azll:compute:vm"
                    };

                    splunkEventMessage = ladLogMessage.GetSplunkEventFromMessage();
                } else
                {
                    log.Warning("Unexpected message format, resourceId was provided, but neither category nor metricName exists in message. Look for sourcetype='azlx:compute:vm'");
                    if (hasResourceId)
                    {
                        var ladLogMessage = new LadLogMessage(resourceId.ToUpper(), expandoMessage)
                        {
                            SplunkSourceType = "azlx:compute:vm"
                        };

                        splunkEventMessage = ladLogMessage.GetSplunkEventFromMessage();
                    } else
                    {
                        log.Warning("Unexpected message format, resourceId was not provided, and neither were category or metricName. Look for sourcetype='azlz:compute:vm'");

                        var ladUnknownMessage = new LadUnknownMessage(expandoMessage)
                        {
                            SplunkSourceType = "azlz:compute:vm"
                        };

                        splunkEventMessage = ladUnknownMessage.GetSplunkEventFromMessage();
                    }
                }

                if (splunkEventMessage != "") splunkEventMessages.Add(splunkEventMessage);
            }

            return splunkEventMessages;

        }
        
    }
}
