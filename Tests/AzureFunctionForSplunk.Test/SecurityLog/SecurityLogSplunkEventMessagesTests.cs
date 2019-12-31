using AzureFunctionForSplunk.Common;
using AzureFunctionForSplunk.SecurityCenterLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace AzureFunctionForSplunk.Test.SecurityLog
{
    public class SecurityLogSplunkEventMessagesTests
    {
        [Theory]
        [InlineData("Microsoft.Security", "assessments", null, "ascl:recommendation")]
        public void SecurityLog_Should_IngestAsclRecommendation(string providerName, string typeName, string operationName, string expected)
        {
            var records = GenerateRecommendationRecords(providerName, typeName, operationName);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        [Theory]
        [InlineData("Azure Security Center", "ascl:alerts")]
        public void SecurityLog_Should_IngestAsclAlert(string productName, string expected)
        {
            var records = GenerateAlertRecords(productName);

            var results = CallIngest(records);

            Assert.Equal(expected, results[0].SplunkSourceType);
        }

        static private List<AzMonMessage> CallIngest(string[] records)
        {
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var context = new Mock<ExecutionContext>();

            var eventMessages = new SecurityLogSplunkEventMessages(outputEvents.Object, logger.Object, context.Object);

            eventMessages.Ingest(records);
            return eventMessages.AzureMonitorMessages;
        }

        static internal string[] GenerateRecommendationRecords(string providerName, string typeName, string operationName)
        {
            string[] array = new string[] { providerName, typeName, operationName };
            string value = string.Join("/", array.Where(s => !string.IsNullOrEmpty(s)));
            return new List<string>
            {
                "{'AssessmentEventDataEnrichment': {     'Action': 'Insert',     'ApiVersion': '2019-01-01'   },   'id': '/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxxx/providers/Microsoft.Security/assessments/xxxxxx-xxxx-xxx-xxx-xxxxxxx',   'name': 'xxxxxx-xxxx-xxxx-xxxx-xxxxxxx',   'type': '" + value + "',   'properties': {     'resourceDetails': {       'source': 'Azure',       'id': '/subscriptions/xxxxx-xxxxx-xxxx-xxxx-xxxxx'     },     'displayName': 'Enable MFA for Azure Management App accounts with read permissions on your subscription',     'status': {       'code': 'Unhealthy',       'cause': 'N/A',       'description': 'N/A'     },     'additionalData': {       'usersWithNoMfaObjectIdList': [         'xxxx-xxxx-xxxx-xxxx-xxxxx',         'xxxx-xxxx-xxxx-xxxx-xxxxx'       ]     },     'metadata': {       'displayName': 'Enable MFA for Azure Management App accounts with read permissions on your subscription',       'assessmentType': 'BuiltIn',       'policyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/760a85ff-6162-42b3-8d70-698e268f648c',       'description': 'N/A',       'remediationDescription': 'N/A',       'severity': 'Low'     },     'links': {       'azurePortal': 'https://ms.portal.azure.com/?fea#blade/Microsoft_Azure_Security/RecommendationsBlade/assessmentKey/01b1ed4c-b733-4fee-b145-f23236e70cf3'     }   } }"
            }.ToArray();
        }

        static internal string[] GenerateAlertRecords(string productName)
        {
            return new List<string>
            {
                "{   'VendorName': 'Microsoft',   'AlertType': 'SUSPECT_SVCHOST',   'StartTimeUtc': '2016-12-20T13:38:00.000Z',   'EndTimeUtc': '2019-12-20T13:40:01.733Z',   'ProcessingEndTime': '2019-09-16T12:10:19.5673533Z',   'TimeGenerated': '2016-12-20T13:38:03.000Z',   'IsIncident': false,   'Severity': 'High',   'Status': 'New',   'ProductName': '" + productName + "',   'SystemAlertId': '2342409243234234_F2BFED55-5997-4FEA-95BD-BB7C6DDCD061',   'AzureResourceId': '/subscriptions/86057C9F-3CDD-484E-83B1-7BF1C17A9FF8/resourceGroups/backend-srv/providers/Microsoft.Compute/WebSrv1',   'AzureResourceSubscriptionId': '86057C9F-3CDD-484E-83B1-7BF1C17A9FF8',   'WorkspaceId': '077BA6B7-8759-4F41-9F97-017EB7D3E0A8',   'WorkspaceSubscriptionId': '86057C9F-3CDD-484E-83B1-7BF1C17A9FF8',   'WorkspaceResourceGroup': 'omsrg',   'AgentId': '5A651129-98E6-4E6C-B2CE-AB89BD815616',   'CompromisedEntity': 'WebSrv1',   'Intent': 'Execution',   'AlertDisplayName': 'Suspicious process detected',   'Description': 'Suspicious process named ‘SVCHOST.EXE’ was running from path: %{Process Path}',   'RemediationSteps': ['contact your security information team'],   'ExtendedProperties': {     'Process Path': 'c:/temp/svchost.exe',     'Account': 'Contoso/administrator',     'PID': 944,     'ActionTaken': 'Detected'   },   'Entities': [],   'ResourceIdentifiers': [ 		{ 			Type: 'AzureResource', 			AzureResourceId: '/subscriptions/86057C9F-3CDD-484E-83B1-7BF1C17A9FF8/resourceGroups/backend-srv/providers/Microsoft.Compute/WebSrv1' 		}, 		{ 			Type: 'LogAnalytics', 			WorkspaceId: '077BA6B7-8759-4F41-9F97-017EB7D3E0A8', 			WorkspaceSubscriptionId: '86057C9F-3CDD-484E-83B1-7BF1C17A9FF8', 			WorkspaceResourceGroup: 'omsrg', 			AgentId: '5A651129-98E6-4E6C-B2CE-AB89BD815616', 		}   ] }"
            }.ToArray();
        }
    }
}