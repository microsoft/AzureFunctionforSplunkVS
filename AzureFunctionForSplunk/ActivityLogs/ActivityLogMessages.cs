using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk.ActivityLogs
{
    public class ActivityLogMessages : AzMonMessages
    {
        public ActivityLogMessages(ILogger log) : base(log)
        {
        }
    }
}