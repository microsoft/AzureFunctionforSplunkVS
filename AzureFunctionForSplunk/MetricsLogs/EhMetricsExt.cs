using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.MetricsLogs
{
    public static class EhMetricsExt
    {
        [FunctionName("EhMetricsExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-metrics%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-metrics%")]string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<MetricMessages, MetricSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}