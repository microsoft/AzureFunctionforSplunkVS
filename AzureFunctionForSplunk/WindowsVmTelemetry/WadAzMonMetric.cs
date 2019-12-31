using AzureFunctionForSplunk.Common;
using System;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.WindowsVmTelemetry
{
    public class WadAzMonMetric : AzMonMessage
    {
        public WadAzMonMetric(dynamic message)
        {
            Message = message;

            ResourceType = "MICROSOFT.COMPUTE/VIRTUALMACHINES";

            SplunkSourceType = "azwm:compute:vm";

            if (((IDictionary<String, Object>)message).ContainsKey("dimensions"))
            {
                var dimensions = message.dimensions;
                if (((IDictionary<String, Object>)dimensions).ContainsKey("RoleInstance"))
                {
                    string theName = message.dimensions.RoleInstance;

                    // if it's there at all, RoleInstance starts with _
                    if (theName.Length > 1) ResourceName = theName.Substring(1);
                }
            }

            AddStandardProperties("azwm");
        }
    }
}