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
using Microsoft.WindowsAzure.Storage.Blob;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.FaultProcessor
{
    public static class FaultProcessor
    {
        [FunctionName("FaultProcessor")]
        public static async Task Run(
            [QueueTrigger("%input-hub-name-faults%", Connection = "AzureWebJobsStorage")]string fault,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            ILogger log)
        {
            string outputBinding = Utils.GetEnvironmentVariable("outputBinding").ToLower();
            if (outputBinding.Length == 0)
            {
                log.LogError("Value for outputBinding is required. Permitted values are: 'proxy', 'hec', 'eventhub'.");
                return;
            }

            var faultData = JsonConvert.DeserializeObject<TransmissionFaultMessage>(fault);

            var blobReader = await blobFaultBinder.BindAsync<CloudBlockBlob>(
                    new BlobAttribute($"transmission-faults/{faultData.id}", FileAccess.ReadWrite));

            var json = await blobReader.DownloadTextAsync();

            try
            {
                List<string> faultMessages = await Task<List<string>>.Factory.StartNew(() => JsonConvert.DeserializeObject<List<string>>(json));

                switch (outputBinding)
                {
                    case "hec":
                        await Utils.obHEC(faultMessages, log);
                        break;

                    case "proxy":
                        await Utils.obProxy(faultMessages, log);
                        break;

                    case "eventhub":
                        await Utils.obEventhub(faultMessages, outputEvents, log);
                        break;
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex.Message);
                log.LogError($"FaultProcessor failed to transmit: {faultData.id}");
                throw new Exception("FaultProcessor failed to transmit");
            }

            await blobReader.DeleteAsync();

            log.LogInformation($"C# Queue trigger function FaultProcessor processed: {faultData.id}");
        }
    }
}