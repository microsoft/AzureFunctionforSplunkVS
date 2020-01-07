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