using System;
using System.IO;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk
{
    public static class FaultProcessor
    {
        [FunctionName("FaultProcessor")]
        public static async Task Run(
            [QueueTrigger("%input-hub-name-faults%", Connection = "AzureWebJobsStorage")]string fault,
            IBinder blobFaultBinder,
            ILogger log)
        {
            var faultData = JsonConvert.DeserializeObject<TransmissionFaultMessage>(fault);

            var blobReader = await blobFaultBinder.BindAsync<CloudBlockBlob>(
                    new BlobAttribute($"transmission-faults/{faultData.id}", FileAccess.ReadWrite));

            var json = await blobReader.DownloadTextAsync();
            
            try
            {
                List<string> faultMessages = await Task<List<string>>.Factory.StartNew(() => JsonConvert.DeserializeObject<List<string>>(json));
                await Utils.obHEC(faultMessages, log);
            } catch (Exception ex)
            {
                log.LogError(ex.Message);
                log.LogError($"FaultProcessor failed to send to Splunk: {faultData.id}");
                throw new Exception("FaultProcessor failed to send to Splunk");
            }

            await blobReader.DeleteAsync();

            log.LogInformation($"C# Queue trigger function FaultProcessor processed: {faultData.id}");
        }
    }
}
