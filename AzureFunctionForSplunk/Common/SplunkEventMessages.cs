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
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.Common
{
    public abstract class SplunkEventMessages
    {
        public SplunkEventMessages(IAsyncCollector<string> outputEvents, ILogger log, ExecutionContext context)
        {
            Log = log;
            EventHubOutputEvents = outputEvents;
            AzureMonitorMessages = new List<AzMonMessage>();
            Categories = new Dictionary<string, string>();

            try
            {
                var filename = Path.Combine(context.FunctionAppDirectory ?? "", CategoryFileName);
                Categories = Utils.GetDictionary(filename);
            }
            catch (Exception ex)
            {
                Log.LogError($"Error getting categories json file: {CategoryFileName}. {ex.Message}");
            }
        }

        public Dictionary<string, string> Categories { get; private set; }
        public List<string> SplunkMessages { get; set; }
        public List<AzMonMessage> AzureMonitorMessages { get; set; }
        protected abstract string CategoryFileName { get; }
        protected ILogger Log { get; private set; }
        private IAsyncCollector<string> EventHubOutputEvents { get; set; }

        public async Task Emit()
        {
            string outputBinding = Utils.GetEnvironmentVariable("outputBinding");
            if (outputBinding.Length == 0)
            {
                Log.LogError("Value for outputBinding is required. Permitted values are: 'proxy', 'hec', 'eventhub'.");
                return;
            }

            SplunkMessages = new List<string>();
            foreach (var item in AzureMonitorMessages)
            {
                SplunkMessages.Add(item.GetSplunkEventFromMessage());
            }

            Log.LogInformation($"Emit record count : {SplunkMessages.Count}");

            switch (outputBinding)
            {
                case "hec":
                    await Utils.obHEC(SplunkMessages, Log);
                    break;

                case "proxy":
                    await Utils.obProxy(SplunkMessages, Log);
                    break;

                case "eventhub":
                    await Utils.obEventhub(SplunkMessages, EventHubOutputEvents, Log);
                    break;
            }
        }

        public abstract void Ingest(string[] records);
    }
}