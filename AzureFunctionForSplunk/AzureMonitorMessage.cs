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
using System.Text.RegularExpressions;

namespace AzureFunctionForSplunk
{
    public class AzureMonitorMessage
    {
        protected dynamic Message { get; set; }
        protected string ResourceId { get; set; }
        public string SubscriptionId { get; set; }
        public string ResourceType { get; set; }
        public string ResourceName { get; set; }
        public string ResourceGroup { get; set; }
        public string SplunkSourceType { get; set; }

        public AzureMonitorMessage()
        {
            SubscriptionId = "";
            ResourceGroup = "";
            ResourceName = "";
            ResourceType = "";
            SplunkSourceType = "";
        }

        public string GetSplunkEventFromMessage()
        {
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(Message);

            var s = "{";
            s += "\"sourcetype\": \"" + SplunkSourceType + "\",";
            s += "\"event\": " + json;
            s += "}";

            return s;

        }

        protected void GetStandardProperties()
        {
            var patternSubscriptionId = @"SUBSCRIPTIONS\/(.*?)\/";
            var patternResourceGroup = @"SUBSCRIPTIONS\/(?:.*?)\/RESOURCEGROUPS\/(.*?)(\/|\Z)";
            var patternResourceType = @"PROVIDERS\/(.*?\/.*?)(?:\/)";
            var patternResourceName = @"PROVIDERS\/(?:.*?\/.*?\/)(.*?)(?:\/|$)";
            var patternDatabase = @"PROVIDERS\/(.*?\/.*?)(?:\/)(?:.*\/)(.*DATABASES)";

            Match m = Regex.Match(ResourceId, patternSubscriptionId);
            SubscriptionId = m.Groups[1].Value;

            m = Regex.Match(ResourceId, patternResourceGroup);
            ResourceGroup = m.Groups[1].Value;

            m = Regex.Match(ResourceId, patternResourceName);
            ResourceName = m.Groups[1].Value;

            m = Regex.Match(ResourceId, patternDatabase);
            var group1 = m.Groups[1].Value;
            var group2 = m.Groups[2].Value;
            if (group2 == "DATABASES")
            {
                ResourceType = group1 + "/" + group2;
            } else
            {
                m = Regex.Match(ResourceId, patternResourceType);
                ResourceType = m.Groups[1].Value;
            }
        }
    }

    public class LadMetricMessage : AzureMonitorMessage
    {
        public LadMetricMessage(string resourceId, dynamic message)
        {
            ResourceId = resourceId;
            Message = message;

            GetStandardProperties();

            AddStandardProperties();

        }

        private void AddStandardProperties()
        {
            if (SubscriptionId != "")
            {
                Message.azlm_SubscriptionId = SubscriptionId;
            }
            if (ResourceGroup != "")
            {
                Message.azlm_ResourceGroup = ResourceGroup;
            }
            if (ResourceType != "")
            {
                Message.azlm_ResourceType = ResourceType;
            }
            if (ResourceName != "")
            {
                Message.azlm_ResourceName = ResourceName;
            }
        }
    }

    public class LadLogMessage : AzureMonitorMessage
    {
        public LadLogMessage(string resourceId, dynamic message)
        {
            ResourceId = resourceId;
            Message = message;

            GetStandardProperties();

            AddStandardProperties();

        }

        private void AddStandardProperties()
        {
            if (SubscriptionId != "")
            {
                Message.azll_SubscriptionId = SubscriptionId;
            }
            if (ResourceGroup != "")
            {
                Message.azll_ResourceGroup = ResourceGroup;
            }
            if (ResourceType != "")
            {
                Message.azll_ResourceType = ResourceType;
            }
            if (ResourceName != "")
            {
                Message.azll_ResourceName = ResourceName;
            }
        }
    }

    public class LadUnknownMessage : AzureMonitorMessage
    {
        public LadUnknownMessage(dynamic message)
        {
            ResourceId = "";
            Message = message;

        }

    }

    public class MetricMessage : AzureMonitorMessage
    {
        public MetricMessage(string resourceId, dynamic message)
        {
            ResourceId = resourceId;
            Message = message;

            GetStandardProperties();

            AddStandardProperties();

        }

        private void AddStandardProperties()
        {
            if (SubscriptionId != "")
            {
                Message.amm_SubscriptionId = SubscriptionId;
            }
            if (ResourceGroup != "")
            {
                Message.amm_ResourceGroup = ResourceGroup;
            }
            if (ResourceType != "")
            {
                Message.amm_ResourceType = ResourceType;
            }
            if (ResourceName != "")
            {
                Message.amm_ResourceName = ResourceName;
            }
        }
    }

    public class ActivityLogMessage : AzureMonitorMessage
    {

        public ActivityLogMessage(string resourceId, string sourceType, dynamic message)
        {
            ResourceId = resourceId;
            SplunkSourceType = sourceType;
            Message = message;

            GetStandardProperties();

            AddStandardProperties();

        }

        private void AddStandardProperties()
        {
            if (SubscriptionId != "")
            {
                Message.amal_SubscriptionId = SubscriptionId;
            }
            if (ResourceGroup != "")
            {
                Message.amal_ResourceGroup = ResourceGroup;
            }
            if (ResourceType != "")
            {
                Message.amal_ResourceType = ResourceType;
            }
            if (ResourceName != "")
            {
                Message.amal_ResourceName =ResourceName;
            }
        }
    }

    public class DiagnosticLogMessage : AzureMonitorMessage
    {

        public DiagnosticLogMessage(string resourceId, dynamic message)
        {
            ResourceId = resourceId;
            Message = message;

            GetStandardProperties();

            AddStandardProperties();

        }

        public void SetSourceType(string sourceType)
        {
            SplunkSourceType = sourceType;
        }

        private void AddStandardProperties()
        {
            if (SubscriptionId != "")
            {
                Message.amdl_SubscriptionId = SubscriptionId;
            }
            if (ResourceGroup != "")
            {
                Message.amdl_ResourceGroup = ResourceGroup;
            }
            if (ResourceType != "")
            {
                Message.amdl_ResourceType = ResourceType;
            }
            if (ResourceName != "")
            {
                Message.amdl_ResourceName = ResourceName;
            }
        }
    }

}
