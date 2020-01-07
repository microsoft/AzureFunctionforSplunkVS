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
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Text.RegularExpressions;

namespace AzureFunctionForSplunk.Common
{
    public class AzMonMessage
    {
        private ExpandoObject _Message;

        protected ExpandoObject Message
        {
            get
            {
                return _Message;
            }
            set
            {
                this._Message = value;

                if (((IDictionary<String, Object>)value).ContainsKey("time"))
                    MessageTime = ((dynamic)value).time;
                else
                    MessageTime = DateTime.Now;
            }
        }

        protected string ResourceId { get; set; }
        public string SubscriptionId { get; set; }
        public string ResourceType { get; set; }
        public string ResourceName { get; set; }
        public string ResourceGroup { get; set; }
        public string SplunkSourceType { get; set; }
        public DateTime MessageTime { get; set; }
        public string TenantId { get; set; }
        public string ProviderName { get; set; }

        public AzMonMessage()
        {
            SubscriptionId = "";
            ResourceId = "";
            ResourceGroup = "";
            ResourceName = "";
            ResourceType = "";
            SplunkSourceType = "";
            TenantId = "";
        }

        public string GetSplunkEventFromMessage()
        {
            ExpandoObject o = new ExpandoObject();
            ((IDictionary<String, Object>)o).Add("sourcetype", SplunkSourceType);
            ((IDictionary<String, Object>)o).Add("time", unixTime().ToString("0.000"));
            ((IDictionary<String, Object>)o).Add("event", Message);
            string json = Newtonsoft.Json.JsonConvert.SerializeObject(o);

            return json;
        }

        private double unixTime()
        {
            double unixTimestamp = MessageTime.Ticks - new DateTime(1970, 1, 1).Ticks;
            unixTimestamp /= TimeSpan.TicksPerSecond;
            return unixTimestamp;
        }

        protected void GetStandardProperties()
        {
            string pattern;

            pattern = @"SUBSCRIPTIONS\/(.*?)\/";
            Match m = Regex.Match(ResourceId.ToUpper(), pattern);
            SubscriptionId = m.Groups[1].Value;

            pattern = @"SUBSCRIPTIONS\/(?:.*?)\/RESOURCEGROUPS\/(.*?)(\/|\Z)";
            m = Regex.Match(ResourceId.ToUpper(), pattern);
            ResourceGroup = m.Groups[1].Value;

            pattern = @"PROVIDERS\/(?:.*?\/.*?\/)(.*?)(?:\/|$)";
            m = Regex.Match(ResourceId.ToUpper(), pattern);
            ResourceName = m.Groups[1].Value;

            pattern = @"PROVIDERS\/(.*?\/.*?)(?:\/)(?:.*\/)(.*DATABASES)";
            m = Regex.Match(ResourceId.ToUpper(), pattern);
            var group1 = m.Groups[1].Value;
            var group2 = m.Groups[2].Value;
            if (group2 == "DATABASES")
            {
                ResourceType = group1 + "/" + group2;
            }
            else
            {
                pattern = @"PROVIDERS\/(.*?\/.*?)(?:\/)";
                m = Regex.Match(ResourceId.ToUpper(), pattern);
                ResourceType = m.Groups[1].Value;
            }
        }

        protected void AddStandardProperties(string prefix)
        {
            if (TenantId != "")
            {
                ((IDictionary<String, Object>)Message).Add($"{prefix}_TenantId", TenantId);
            }
            if (SubscriptionId != "")
            {
                ((IDictionary<String, Object>)Message).Add($"{prefix}_SubscriptionId", SubscriptionId);
            }
            if (ResourceGroup != "")
            {
                ((IDictionary<String, Object>)Message).Add($"{prefix}_ResourceGroup", ResourceGroup);
            }
            if (ResourceType != "")
            {
                ((IDictionary<String, Object>)Message).Add($"{prefix}_ResourceType", ResourceType);
            }
            if (ResourceName != "")
            {
                ((IDictionary<String, Object>)Message).Add($"{prefix}_ResourceName", ResourceName);
            }
        }
    }
}