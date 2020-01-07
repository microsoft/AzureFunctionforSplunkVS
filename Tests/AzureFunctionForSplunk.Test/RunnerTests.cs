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
using AzureFunctionForSplunk.ActivityLogs;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using Xunit;

namespace AzureFunctionForSplunk.Test
{
    public class RunnerTests
    {
        [Fact]
        public void Runner_Should_WriteLoginformation_NoMessagesProcessed()
        {
            var events = new List<string>();
            var outputEvents = new Mock<IAsyncCollector<string>>();
            var blobFaultBinder = new Mock<IBinder>();
            var incommingBatchBinder = new Mock<IBinder>();
            var logger = new Mock<AbsctractLogger<ILogger>>();
            var runner = new Runner();
            var context = new Mock<ExecutionContext>();

            runner.Run<ActivityLogMessages, ActivityLogSplunkEventMessages>(events.ToArray(), blobFaultBinder.Object, new Binder(), incommingBatchBinder.Object, outputEvents.Object, logger.Object, context.Object);

            logger.Verify(x => x.Log(LogLevel.Information, It.IsAny<Exception>(), "C# Event Hub trigger function processed a batch of messages: 0"), Times.AtLeastOnce);
        }
    }
}