using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.WindowsVmTelemetry
{
    public static class EhWadTelemetryExt
    {
        [FunctionName("EhWadTelemetryExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-wad%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-wad%")]string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<WadMessages, WadSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}