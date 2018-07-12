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
    public static class ehLadTelemetry
    {
        [FunctionName("ehLadTelemetry")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-lad%", Connection = "hubConnection")]
            string[] messages, 
            TraceWriter log)
        {
            //foreach (var s in messages)
            //{
            //    log.Info($"{s}");
            //}
            //return;

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
