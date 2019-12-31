using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.SecurityCenterLogs
{
    public static class EhSecurityCenterLogsExt
    {
        [FunctionName("EhSecurityCenterLogsExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-security-log%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-security-log%")]
            string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]
            IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<SecurityLogMessages, SecurityLogSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}