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