using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Collections.Generic;
using System.Dynamic;

namespace AzureFunctionForSplunk.SecurityCenterLogs
{
    public class SecurityLogSplunkEventMessages : SplunkEventMessages
    {
        protected override string CategoryFileName => "SecurityCenterLogs/SecurityLogCategories.json";

        public SecurityLogSplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context) : base(outputEvents, log, context)
        {
        }

        public override void Ingest(string[] records)
        {
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                var message = new AzSecurityLog(expandoRecord);

                var productName = "none";
                if (((IDictionary<string, object>)expandoRecord).ContainsKey("ProductName"))
                {
                    productName = ((IDictionary<string, object>)expandoRecord)["ProductName"].ToString();
                    message.SplunkSourceType = Utils.GetDictionaryValue("alerts", Categories) ?? "ascl:alerts";
                }
                else if (((IDictionary<string, object>)expandoRecord).ContainsKey("type"))
                {
                    productName = ((IDictionary<string, object>)expandoRecord)["type"].ToString();
                    message.SplunkSourceType = Utils.GetDictionaryValue("recommendations", Categories) ?? "ascl:security";
                }
                else
                {
                    message.SplunkSourceType = Utils.GetDictionaryValue("administrative", Categories) ?? "ascl:administrative";
                }

                AzureMonitorMessages.Add(message);
            }
        }
    }
}