using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk.MetricsLogs
{
    public class MetricMessages : AzMonMessages
    {
        public MetricMessages(ILogger log) : base(log)
        {
        }
    }
}