using AzureFunctionForSplunk.SecurityCenterLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace AzureFunctionForSplunk.Test.SecurityLog
{
    public class EventHubSecurityLogTests
    {
        [Fact]
        public async Task Eventhubtrigger_ShouldInitiate_RunnerActivityLog()
        {
            var events = new List<string>();
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var blobFaultBinder = new Mock<IBinder>();
            var incommingBatchBinder = new Mock<IBinder>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var context = new Mock<ExecutionContext>();

            await EhSecurityCenterLogsExt.Run(events.ToArray(), outputEvents.Object, blobFaultBinder.Object, incommingBatchBinder.Object, new Binder(), logger.Object, context.Object);

            logger.Verify(x => x.Log(LogLevel.Information, It.IsAny<Exception>(), "C# Event Hub trigger function processed a batch of messages: 0"), Times.AtLeastOnce);
        }
    }
}