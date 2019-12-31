using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;

namespace AzureFunctionForSplunk.SecurityCenterLogs
{
    public class SecurityLogMessages : AzMonMessages
    {
        public SecurityLogMessages(ILogger log) : base(log)
        {
        }

        public override List<string> DecomposeIncomingBatch(string[] messages)
        {
            //Just return all for security messages they won't be comming in record arrays
            return messages.ToList();
        }
    }
}