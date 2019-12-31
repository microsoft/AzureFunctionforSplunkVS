using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;

namespace AzureFunctionForSplunk.DiagnosticLogs
{
    public class DiagnosticLogSplunkEventMessages : SplunkEventMessages
    {
        protected override string CategoryFileName => "DiagnosticLogs/DiagnosticLogCategories.json";

        public DiagnosticLogSplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context) : base(outputEvents, log, context)
        {
        }

        public override void Ingest(string[] records)
        {
            // Subscription-based: sourceType depends on the message category and the ResourceType
            // Tenant-based: sourceType depends on the message category and the ProviderType

            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                var azMonMsg = new DiagnosticLog(expandoRecord);

                var category = "none";
                if (((IDictionary<String, Object>)expandoRecord).ContainsKey("category"))
                {
                    category = ((IDictionary<String, Object>)expandoRecord)["category"].ToString();
                }

                var resourceType = azMonMsg.ResourceType;
                var providerName = azMonMsg.ProviderName;

                var logMessage = "";
                var sourceType = "";
                if (azMonMsg.TenantId.Length > 0)
                {
                    logMessage = $"********* ProviderName: {providerName}";
                    sourceType = Utils.GetDictionaryValue(providerName.ToUpper() + "/" + category.ToUpper(), Categories) ?? "amdl:diagnostic";
                }
                else
                {
                    logMessage = $"********* ResourceType: {resourceType}";
                    sourceType = Utils.GetDictionaryValue(resourceType.ToUpper() + "/" + category.ToUpper(), Categories) ?? "amdl:diagnostic";
                }

                // log categories that aren't yet in the DiagnosticLogCategories.json file.
                if (category != "none" && sourceType == "amdl:diagnostic")
                {
                    Log.LogInformation($"{logMessage}, category: {category} *********");
                }

                azMonMsg.SplunkSourceType = sourceType;

                AzureMonitorMessages.Add(azMonMsg);
            }
        }
    }
}