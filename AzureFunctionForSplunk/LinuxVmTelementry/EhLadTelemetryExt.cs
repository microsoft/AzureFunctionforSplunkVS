using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.LinuxVmTelementry
{
    public static class EhLadTelemetryExt
    {
        [FunctionName("EhLadTelemetryExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-lad%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-lad%")]string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<LadMessages, LadSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}