using AzureFunctionForSplunk.Common;
using System;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.MetricsLogs
{
    public class Metric : AzMonMessage
    {
        public Metric(dynamic message)
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

            base.GetStandardProperties();
            base.AddStandardProperties("amm");
        }
    }
}