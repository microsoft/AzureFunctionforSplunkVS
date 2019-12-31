using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.Common
{
    public abstract class AzMonMessages
    {
        public AzMonMessages(ILogger log)
        {
            Log = log;
        }

        public ILogger Log { get; set; }

        public virtual List<string> DecomposeIncomingBatch(string[] messages)
        {
            List<string> decomposed = new List<string>();

            foreach (var message in messages)
            {
                dynamic obj = JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(message);

                if (((IDictionary<string, dynamic>)obj).ContainsKey("records"))
                {
                    var records = obj["records"];

                    foreach (var record in records)
                    {
                        string stringRecord = record.ToString();

                        decomposed.Add(stringRecord);
                    }
                }
                else
                {
                    Log.LogError("AzMonMessages: invalid message structure, missing 'records'");
                }
            }

            return decomposed;
        }
    }
}