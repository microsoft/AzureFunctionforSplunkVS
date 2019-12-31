using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;

namespace AzureFunctionForSplunk.LinuxVmTelementry
{
    public class LadSplunkEventMessages : SplunkEventMessages
    {
        protected override string CategoryFileName => "";

        public LadSplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context) : base(outputEvents, log, context)
        {
        }

        public override void Ingest(string[] records)
        {
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                if (((IDictionary<String, Object>)expandoRecord).ContainsKey("category"))
                {
                    AzureMonitorMessages.Add(new LadAzMonLog(expandoRecord));
                }
                else if (((IDictionary<String, Object>)expandoRecord).ContainsKey("metricName"))
                {
                    AzureMonitorMessages.Add(new LadAzMonMetric(expandoRecord));
                }
            }
        }
    }
}