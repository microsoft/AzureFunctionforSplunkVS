using AzureFunctionForSplunk.Common;
using AzureFunctionForSplunk.MetricsLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System.Collections.Generic;
using Xunit;

namespace AzureFunctionForSplunk.Test.MetricsLogs
{
    public class MetricSplunkEventMessagesTests
    {
        [Theory]
        [InlineData("MICROSOFT.EVENTHUB/NAMESPACES", "amm:eventhub:namespace")]
        [InlineData("XXXX.XXX/DEFAULT", "amm:metrics")]
        [InlineData("MICROSOFT.SQL/SERVERS", "amm:sqlserver:server")]
        public void SecurityLog_Should_IngestCorrectSplunkCluster(string resourceType, string expected)
        {
            var records = GenerateRecords(resourceType);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        static private List<AzMonMessage> CallIngest(string[] records)
        {
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var context = new Mock<ExecutionContext>();

            var eventMessages = new MetricSplunkEventMessages(outputEvents.Object, logger.Object, context.Object);

            eventMessages.Ingest(records);
            return eventMessages.AzureMonitorMessages;
        }

        static internal string[] GenerateRecords(string resourceType)
        {
            return new List<string>
            {
                "{ 'count': 76, 'total': 8590, 'minimum': 1, 'maximum': 569, 'average': 113.026315789474, 'resourceId': '/SUBSCRIPTIONS/XXXX-XXXX-XXXX-XXXX-XXXXX/RESOURCEGROUPS/RESOURCEGROUPNAME/PROVIDERS/" + resourceType + "/TYPENAMETHING', 'time': '2019-12-23T08:09:00.0000000Z', 'metricName': 'IncomingRequests', 'timeGrain': 'PT1M'}"
            }.ToArray();
        }
    }
}