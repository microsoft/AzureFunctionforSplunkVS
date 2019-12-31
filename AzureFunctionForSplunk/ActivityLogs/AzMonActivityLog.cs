using AzureFunctionForSplunk.Common;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace AzureFunctionForSplunk.ActivityLogs
{
    public class AzMonActivityLog : AzMonMessage
    {
        public AzMonActivityLog(dynamic message, string sourceType)
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

            SplunkSourceType = sourceType;
            base.GetStandardProperties();
            base.AddStandardProperties("amal");
        }
    }
}