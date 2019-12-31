using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace AzureFunctionForSplunk.DiagnosticLogs
{
    public static class EhDiagnosticLogsExt
    {
        [FunctionName("EhDiagnosticLogsExt")]
        public static async Task Run(
            [EventHubTrigger("%input-hub-name-diagnostic-logs%", Connection = "hubConnection", ConsumerGroup = "%consumer-group-diagnostic-logs%")]string[] messages,
            [EventHub("%output-hub-name-proxy%", Connection = "outputHubConnection")]IAsyncCollector<string> outputEvents,
            IBinder blobFaultBinder,
            IBinder incomingBatchBinder,
            Binder queueFaultBinder,
            ILogger log,
            ExecutionContext context)
        {
            var runner = new Runner();
            await runner.Run<DiagnosticLogMessages, DiagnosticLogSplunkEventMessages>(messages, blobFaultBinder, queueFaultBinder, incomingBatchBinder, outputEvents, log, context);
        }
    }
}