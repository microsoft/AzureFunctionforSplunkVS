using AzureFunctionForSplunk.ActivityLogs;
using AzureFunctionForSplunk.Common;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace AzureFunctionForSplunk.Test.ActivityLog
{
    public class ActivityLogSplunkEventMessagesTests
    {
        [Theory]
        [InlineData("MICROSOFT.INSIGHTS", "ALERTRULES", "ANNOTATIONS", "amal:ascAlert")]
        [InlineData("MICROSOFT.SECURITY", "APPLICATIONWHITELISTINGS", "ACTION", "amal:ascAlert")]
        public void ActivityLog_Should_IngestAmalAscAlert(string providerName, string typeName, string operationName, string expected)
        {
            var records = GenerateRecords(providerName, typeName, operationName);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        [Fact]
        public void ActivityLog_Should_IngestAmalinsights()
        {
            var records = GenerateRecords("MICROSOFT.INSIGHTS", "AUTOSCALESETTINGS", "ANNOTATIONS");

            var results = CallIngest(records);

            Assert.Equal("amal:autoscaleSettings", results[0].SplunkSourceType);
        }

        [Theory]
        [InlineData("MICROSOFT.SECURITY", null, null, "amal:asc:recommendation")]
        [InlineData("MICROSOFT.SECURITY", "TASKS", "XXX", "amal:asc:recommendation")]
        public void ActivityLog_Should_IngestAmalRecommendation(string providerName, string typeName, string operationName, string expected)
        {
            var records = GenerateRecords(providerName, typeName, operationName);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        [Fact]
        public void ActivityLog_Should_IngestAmalResourceHealth()
        {
            var records = GenerateRecords("Microsoft.Resourcehealth", "healthevent", "Updated");

            var results = CallIngest(records);

            Assert.Equal("amal:resourceHealth", results[0].SplunkSourceType);
        }

        [Theory]
        [InlineData("MICROSOFT.SECURITY", "APPLICATIONWHITELISTINGS", "ANNOTATIONS", "amal:security")]
        [InlineData("MICROSOFT.SECURITY", "LOCATIONS", "ANNOTATIONS", "amal:security")]
        public void ActivityLog_Should_IngestAmalSecurity(string providerName, string typeName, string operationName, string expected)
        {
            var records = GenerateRecords(providerName, typeName, operationName);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        [Fact]
        public void ActivityLog_Should_IngestAmalServiceHealth()
        {
            var records = GenerateRecords("Microsoft.Servicehealth", "healthevent", "Updated");

            var results = CallIngest(records);

            Assert.Equal("amal:serviceHealth", results[0].SplunkSourceType);
        }

        [Fact]
        public void ActivityLog_ShouldDefault_IngestAmalAdministration()
        {
            var records = GenerateRecords("MICROSOFT.XXXX", "XXX", "XXX");

            var results = CallIngest(records);

            Assert.Equal("amal:administrative", results[0].SplunkSourceType);
        }

        [Fact]
        public void ActivityLog_ShouldDefaults_IngestAmalInsights()
        {
            var records = GenerateRecords("MICROSOFT.INSIGHTS", "COMPONENTS", "ANNOTATIONS");

            var results = CallIngest(records);

            Assert.Equal("amal:insights", results[0].SplunkSourceType);
        }

        static private List<AzMonMessage> CallIngest(string[] records)
        {
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var context = new Mock<ExecutionContext>();

            var eventMessages = new ActivityLogSplunkEventMessages(outputEvents.Object, logger.Object, context.Object);

            eventMessages.Ingest(records);
            return eventMessages.AzureMonitorMessages;
        }

        static internal string[] GenerateRecords(string providerName, string typeName, string operationName)
        {
            string[] array = new string[] { providerName, typeName, operationName };
            string value = string.Join("/", array.Where(s => !string.IsNullOrEmpty(s)));
            return new List<string>
            {
                "{ 'time': '2019-12-16T14:10:48.8530039Z', 'resourceId': '/SUBSCRIPTIONS/XXXXX-XXXX-XXX-XXXX-XXXXXX/RESOURCEGROUPS/RESOURCEGROUPNAME/PROVIDERS/MICROSOFT.INSIGHTS/COMPONENTS/NAMEBEACON', 'operationName': '" + value + "', 'category': 'Administrative', 'resultType': 'Start'}"
            }.ToArray();
        }
    }
}