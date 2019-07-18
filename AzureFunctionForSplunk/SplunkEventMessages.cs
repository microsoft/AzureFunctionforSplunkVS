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
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk
{
    public abstract class SplunkEventMessages
    {
        public ILogger Log { get; set; }

        private string categoryFileName;

        public Dictionary<string, string> Categories = null;

        public string CategoryFileName
        {
            set
            {
                categoryFileName = value;

                var filename = Utils.getFilename(categoryFileName);

                Categories = new Dictionary<string, string>();

                try
                {
                    Categories = Utils.GetDictionary(filename);
                }
                catch (Exception ex)
                {
                    Log.LogError($"Error getting categories json file: {filename}. {ex.Message}");
                }
            }
        }

        public List<AzMonMessage> azureMonitorMessages { get; set; }
        public List<string> splunkEventMessages { get; set; }

        public abstract void Ingest(string[] records);

        public async Task Emit()
        {
            string outputBinding = Utils.getEnvironmentVariable("outputBinding");
            if (outputBinding.Length == 0)
            {
                Log.LogError("Value for outputBinding is required. Permitted values are: 'proxy', 'hec'.");
                return;
            }

            splunkEventMessages = new List<string>();
            foreach (var item in azureMonitorMessages)
            {
                splunkEventMessages.Add(item.GetSplunkEventFromMessage());
            }

            switch (outputBinding)
            {
                case "hec":
                    await Utils.obHEC(splunkEventMessages, Log);
                    break;
                case "proxy":
                    await Utils.obProxy(splunkEventMessages, Log);
                    break;
            }


        }

        public SplunkEventMessages(ILogger log)
        {
            Log = log;
            azureMonitorMessages = new List<AzMonMessage>();
        }
    }

    public class ActivityLogsSplunkEventMessages: SplunkEventMessages
    {
        public ActivityLogsSplunkEventMessages(ILogger log): base(log)
        {
            CategoryFileName = "ActivityLogCategories.json";
        }

        public override void Ingest(string[] records)
        {
            // sourceType depends on the message category

            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                string operationName = ((IDictionary<String, Object>)expandoRecord)["operationName"].ToString();

                var splits = operationName.Split('/');

                string sourceType = "";
                if (splits.Length < 3)
                {
                    // ASC Recommendation
                    sourceType = Utils.GetDictionaryValue("ascrecommendation", Categories) ?? "amal:asc:recommendation";
                }
                else if (splits.Length >= 3)
                {
                    var provider = splits[0].ToUpper();
                    var type = splits[1].ToUpper();
                    var operation = splits[2].ToUpper();

                    switch (provider)
                    {
                        case "MICROSOFT.SERVICEHEALTH":
                            sourceType = Utils.GetDictionaryValue("servicehealth", Categories) ?? "amal:serviceHealth";
                            break;

                        case "MICROSOFT.RESOURCEHEALTH":
                            sourceType = Utils.GetDictionaryValue("resourcehealth", Categories) ?? "amal:resourceHealth";
                            break;

                        case "MICROSOFT.INSIGHTS":
                            if (type == "AUTOSCALESETTINGS")
                            {
                                sourceType = Utils.GetDictionaryValue("autoscalesettings", Categories) ?? "amal:autoscaleSettings";
                            }
                            else if (type == "ALERTRULES")
                            {
                                sourceType = Utils.GetDictionaryValue("ascalert", Categories) ?? "amal:ascAlert";
                            }
                            else
                            {
                                sourceType = Utils.GetDictionaryValue("insights", Categories) ?? "amal:insights";
                            }
                            break;
                        case "MICROSOFT.SECURITY":
                            if (type == "APPLICATIONWHITELISTINGS")
                            {
                                if (operation == "ACTION")
                                {
                                    sourceType = Utils.GetDictionaryValue("ascalert", Categories) ?? "amal:asc:alert";
                                }
                                else
                                {
                                    sourceType = Utils.GetDictionaryValue("security", Categories) ?? "amal:security";
                                }
                            }
                            else if (type == "LOCATIONS")
                            {
                                sourceType = Utils.GetDictionaryValue("security", Categories) ?? "amal:security";
                            }
                            else if (type == "TASKS")
                            {
                                sourceType = Utils.GetDictionaryValue("ascrecommendation", Categories) ?? "amal:asc:recommendation";
                            }
                            break;
                        default:
                            {
                                // administrative category
                                sourceType = Utils.GetDictionaryValue("administrative", Categories) ?? "amal:administrative";
                                break;
                            }
                    }
                }

                azureMonitorMessages.Add(new AzMonActivityLog(expandoRecord, sourceType));
            }
        }
    }

    public class DiagnosticLogsSplunkEventMessages : SplunkEventMessages
    {
        public DiagnosticLogsSplunkEventMessages(ILogger log) : base(log)
        {
            CategoryFileName = "DiagnosticLogCategories.json";
        }

        public override void Ingest(string[] records)
        {
            // Subscription-based: sourceType depends on the message category and the ResourceType
            // Tenant-based: sourceType depends on the message category and the ProviderType

            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                var azMonMsg = new AzMonDiagnosticLog(expandoRecord);

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

                if (category != "none")
                {
                    Log.LogInformation($"{logMessage}, category: {category} *********");
                }

                azMonMsg.SplunkSourceType = sourceType;

                azureMonitorMessages.Add(azMonMsg);
            }
        }
    }

    public class MetricsSplunkEventMessages : SplunkEventMessages
    {
        public MetricsSplunkEventMessages(ILogger log) : base(log)
        {
            CategoryFileName = "MetricsCategories.json";
        }

        public override void Ingest(string[] records)
        {
            // sourceType depends on the ResourceType
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                var azMonMsg = new AzMonDiagnosticLog(expandoRecord);

                var resourceType = azMonMsg.ResourceType;

                var sourceType = Utils.GetDictionaryValue(resourceType, Categories) ?? "amm:metrics";

                azMonMsg.SplunkSourceType = sourceType;

                azureMonitorMessages.Add(azMonMsg);
            }
        }

    }

    public class WadSplunkEventMessages : SplunkEventMessages
    {
        public WadSplunkEventMessages(ILogger log) : base(log) { }

        public override void Ingest(string[] records)
        {
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                if (((IDictionary<String,Object>)expandoRecord).ContainsKey("category"))
                {
                    azureMonitorMessages.Add(new WadAzMonLog(expandoRecord));
                }
                else if (((IDictionary<String, Object>)expandoRecord).ContainsKey("metricName"))
                {
                    azureMonitorMessages.Add(new WadAzMonMetric(expandoRecord));
                }
            }
        }

    }

    public class LadSplunkEventMessages : SplunkEventMessages
    {
        public LadSplunkEventMessages(ILogger log) : base(log) { }

        public override void Ingest(string[] records)
        {
            foreach (var record in records)
            {
                var expandoConverter = new ExpandoObjectConverter();
                var expandoRecord = JsonConvert.DeserializeObject<ExpandoObject>(record, expandoConverter);

                if (((IDictionary<String, Object>)expandoRecord).ContainsKey("category"))
                {
                    azureMonitorMessages.Add(new LadAzMonLog(expandoRecord));
                }
                else if (((IDictionary<String, Object>)expandoRecord).ContainsKey("metricName"))
                {
                    azureMonitorMessages.Add(new LadAzMonMetric(expandoRecord));
                }
            }
        }

    }

}
