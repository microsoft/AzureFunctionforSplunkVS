using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Dynamic;

namespace AzureFunctionForSplunk.MetricsLogs
{
    public class MetricSplunkEventMessages : SplunkEventMessages
    {
        protected override string CategoryFileName => "MetricsLogs/MetricsCategories.json";

        public MetricSplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context) : base(outputEvents, log, context)
        {
        }

        public override void Ingest(string[] records)
        {
            Log.LogInformation($"Ingest record count : {records.GetUpperBound(0)}");
            // sourceType depends on the ResourceType
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                var azMonMsg = new Metric(expandoRecord);

                var resourceType = azMonMsg.ResourceType;

                var sourceType = Utils.GetDictionaryValue(resourceType, Categories) ?? "amm:metrics";

                azMonMsg.SplunkSourceType = sourceType;

                AzureMonitorMessages.Add(azMonMsg);
            }
        }
    }
}