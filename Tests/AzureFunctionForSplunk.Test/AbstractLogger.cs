using Microsoft.Extensions.Logging;
using System;

namespace AzureFunctionForSplunk.Test
{
    public abstract class AbsctractLogger<T> : ILogger<T>
    {
        public IDisposable BeginScope<TState>(TState state)
        {
            throw new NotImplementedException();
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter) => Log(logLevel, exception, formatter(state, exception));

        public abstract void Log(LogLevel logLevel, Exception ex, string information);
    }
}