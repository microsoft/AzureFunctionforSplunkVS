using AzureFunctionForSplunk.ActivityLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using Xunit;

namespace AzureFunctionForSplunk.Test
{
    public class RunnerTests
    {
        [Fact]
        public void Runner_Should_WriteLoginformation_NoMessagesProcessed()
        {
            var events = new List<string>();
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var blobFaultBinder = new Mock<IBinder>();
            var incommingBatchBinder = new Mock<IBinder>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var runner = new Runner();
            var context = new Mock<ExecutionContext>();

            runner.Run<ActivityLogMessages, ActivityLogSplunkEventMessages>(events.ToArray(), blobFaultBinder.Object, new Binder(), incommingBatchBinder.Object, outputEvents.Object, logger.Object, context.Object);

            logger.Verify(x => x.Log(LogLevel.Information, It.IsAny<Exception>(), "C# Event Hub trigger function processed a batch of messages: 0"), Times.AtLeastOnce);
        }
    }
}