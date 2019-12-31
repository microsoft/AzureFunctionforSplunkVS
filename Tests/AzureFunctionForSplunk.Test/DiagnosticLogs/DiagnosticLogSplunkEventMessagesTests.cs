using AzureFunctionForSplunk.Common;
using AzureFunctionForSplunk.DiagnosticLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace AzureFunctionForSplunk.Test.DiagnosticLogs
{
    public class DiagnosticLogSplunkEventMessagesTests
    {
        [Theory]
        [InlineData(null, "MICROSOFT.WEB", "FunctionAppLogs", "amdl:diagnostic")]
        [InlineData(null, "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS", "joblogs", "amdl:auto:acct:jobLogs")]
        [InlineData(null, "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS", "kube-apiserver", "amdl:aks:cluster")]
        [InlineData(null, "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS", "kube-controller-manager", "amdl:aks:manager")]
        public void SecurityLog_Should_IngestCorrectSplunkCluster(string providerName, string resourceType, string category, string expected)
        {
            var records = GenerateRecords(providerName, resourceType, category);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        static private List<AzMonMessage> CallIngest(string[] records)
        {
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var context = new Mock<ExecutionContext>();

            var eventMessages = new DiagnosticLogSplunkEventMessages(outputEvents.Object, logger.Object, context.Object);

            eventMessages.Ingest(records);
            return eventMessages.AzureMonitorMessages;
        }

        static internal string[] GenerateRecords(string providerName, string resourceType, string category)
        {
            string[] array = new string[] { providerName, resourceType, category };
            string value = string.Join("/", array.Where(s => !string.IsNullOrEmpty(s)));
            return new List<string>
            {
                "{ 'time': '2019-12-17T05:56:16.9310584Z', 'resourceId': '/SUBSCRIPTIONS/XXXX-XXXX-XXXX-XXXX-XXXXXX/RESOURCEGROUPS/RESOURCEGROUPNAME/PROVIDERS/"+ resourceType +"/SITES/NAMEDF', 'category': '"+ category +"', 'operationName': 'Microsoft.Web/sites/functions/log', 'level': 'Informational', 'location': 'West Europe'}"
            }.ToArray();
        }
    }
}