using AzureFunctionForSplunk.Common;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace AzureFunctionForSplunk.DiagnosticLogs
{
    public class DiagnosticLog : AzMonMessage
    {
        public DiagnosticLog(dynamic message)
        {
            Message = message;

            if (((IDictionary<String, Object>)message).ContainsKey("resourceId"))
            {
                ResourceId = message.resourceId;
            }
            else if (((IDictionary<String, Object>)message).ContainsKey("resourceid"))
            {
                ResourceId = message.resourceid;
            }
            else
            {
                throw new Exception("Unable to extract resourceid or resourceId from the message.");
            }

            if (((IDictionary<String, Object>)message).ContainsKey("tenantId"))
            {
                TenantId = message.tenantId;

                var pattern = @"PROVIDERS/(.*?)(?:$)";
                Match m = Regex.Match(ResourceId.ToUpper(), pattern);
                ProviderName = m.Groups[1].Value;
            }

            base.GetStandardProperties();
            base.AddStandardProperties("amdl");
        }
    }
}