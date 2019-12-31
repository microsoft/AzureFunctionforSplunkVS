using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk.WindowsVmTelemetry
{
    public class WadMessages : AzMonMessages
    {
        public WadMessages(ILogger log) : base(log)
        {
        }
    }
}