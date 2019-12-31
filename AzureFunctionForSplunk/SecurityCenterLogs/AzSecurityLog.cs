using AzureFunctionForSplunk.Common;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.SecurityCenterLogs
{
    public class AzSecurityLog : AzMonMessage
    {
        public AzSecurityLog(dynamic message)
        {
            Message = message;

            if (((IDictionary<string, object>)message).ContainsKey("AzureResourceId"))
            {
                ResourceId = message.AzureResourceId;
            }
            else
            {
                ResourceId = message.properties.resourceDetails.id;
            }

            base.GetStandardProperties();
            base.AddStandardProperties("ascl");
        }
    }
}