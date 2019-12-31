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