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
using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;

namespace AzureFunctionForSplunk.ActivityLogs
{
    public class ActivityLogSplunkEventMessages : SplunkEventMessages
    {
        protected override string CategoryFileName => "ActivityLogs/ActivityLogCategories.json";

        public ActivityLogSplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context) : base(outputEvents, log, context)
        {
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

                AzureMonitorMessages.Add(new ActivityLog(expandoRecord, sourceType));
            }
        }
    }
}