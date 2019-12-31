using AzureFunctionForSplunk.Common;
using System;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.WindowsVmTelemetry
{
    public class WadAzMonLog : AzMonMessage
    {
        public WadAzMonLog(dynamic message)
        {
            Message = message;

            ResourceType = "MICROSOFT.COMPUTE/VIRTUALMACHINES";

            SplunkSourceType = "azwm:compute:vm";

            if (((IDictionary<String, Object>)message).ContainsKey("properties"))
            {
                var properties = message.properties;
                if (((IDictionary<String, Object>)properties).ContainsKey("RoleInstance"))
                {
                    string theName = message.properties.RoleInstance;

                    // if it's there at all, RoleInstance starts with _
                    if (theName.Length > 1) ResourceName = theName.Substring(1);
                }
            }

            AddStandardProperties("azwl");
        }
    }
}