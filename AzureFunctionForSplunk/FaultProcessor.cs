using System.IO;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace AzureFunctionForSplunk
{
    public static class FaultProcessor
    {
        [FunctionName("FaultProcessor")]
        public static async Task Run(
            [QueueTrigger("transmission-faults", Connection = "AzureWebJobsStorage")]string fault,
            IBinder blobFaultBinder,
            TraceWriter log)
        {
            var faultData = JsonConvert.DeserializeObject<TransmissionFaultMessage>(fault);

            var blobReader = await blobFaultBinder.BindAsync<CloudBlockBlob>(
                    new BlobAttribute($"transmission-faults/{faultData.id}", FileAccess.ReadWrite));

            var json = await blobReader.DownloadTextAsync();
            
            try
            {
                List<string> faultMessages = await Task<List<string>>.Factory.StartNew(() => JsonConvert.DeserializeObject<List<string>>(json));
                await Utils.obHEC(faultMessages, log);
            } catch
            {
                log.Error($"FaultProcessor failed to send to Splunk: {faultData.id}");
                throw;
            }

            await blobReader.DeleteAsync();

            log.Info($"C# Queue trigger function processed: {faultData.id}");
        }
    }
}
