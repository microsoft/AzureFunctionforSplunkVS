using AzureFunctionForSplunk.Common;
using Microsoft.Extensions.Logging;

namespace AzureFunctionForSplunk.DiagnosticLogs
{
    public class DiagnosticLogMessages : AzMonMessages
    {
        public DiagnosticLogMessages(ILogger log) : base(log)
        {
        }
    }
}