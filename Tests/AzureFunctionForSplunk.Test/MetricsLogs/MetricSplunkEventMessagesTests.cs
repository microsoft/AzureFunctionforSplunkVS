//
// AzureFunctionForSplunkVS
//
// Copyright (c) Microsoft Corporation
//
// All rights reserved. 
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the ""Software""), to deal 
// in the Software without restriction, including without limitation the rights 
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is furnished 
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all 
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
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