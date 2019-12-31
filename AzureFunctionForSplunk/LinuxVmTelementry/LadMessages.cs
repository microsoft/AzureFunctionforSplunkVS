using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

namespace AzureFunctionForSplunk.LinuxVmTelementry
{
    public class LadMessages : AzMonMessages
    {
        public LadMessages(ILogger log) : base(log)
        {
        }

        public override List<string> DecomposeIncomingBatch(string[] messages)
        {
            List<string> decomposed = new List<string>();

            foreach (var record in messages)
            {
                string stringRecord = record.ToString();

                decomposed.Add(stringRecord);
            }

            return decomposed;
        }
    }
}