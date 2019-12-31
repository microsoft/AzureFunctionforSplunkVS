using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.ActivityLogs
{
    public static class EhActivityLogsExt
    {
        [FunctionName("EhActivityLogsExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-activity-log%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-activity-log%")]string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<ActivityLogMessages, ActivityLogSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}