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
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.WindowsAzure.Storage.Queue;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;
using System.IO;
using Newtonsoft.Json;

namespace AzureFunctionForSplunk
{
    public class Runner
    {
        public async Task Run<T1, T2>(
            string[] messages,
            IBinder blobFaultBinder,
            Binder queueFaultBinder,
            TraceWriter log)
        {
            var azMonMsgs = (AzMonMessages)Activator.CreateInstance(typeof(T1), log);
            List<string> decomposed = null;
            try
            {
                decomposed = azMonMsgs.DecomposeIncomingBatch(messages);
            }
            catch (Exception)
            {
                throw;
            }

            int splunkMsgsCount = 0;
            if (decomposed.Count > 0)
            {
                var splunkMsgs = (SplunkEventMessages)Activator.CreateInstance(typeof(T2), log);
                try
                {
                    splunkMsgs.Ingest(decomposed.ToArray());
                    splunkMsgsCount += splunkMsgs.azureMonitorMessagesCount;

                    await splunkMsgs.Emit();
                    log.Info($"C# Event Hub trigger function processed a batch of messages, splunkMsgsCount: {splunkMsgsCount}");
                }
                catch (Exception exEmit)
                {
                    var id = Guid.NewGuid().ToString();

                    try
                    {
                        var blobWriter = await blobFaultBinder.BindAsync<CloudBlockBlob>(
                            new BlobAttribute($"transmission-faults/{id}", FileAccess.ReadWrite));

                        string json = await Task<string>.Factory.StartNew(() => JsonConvert.SerializeObject(splunkMsgs.splunkEventMessages));
                        await blobWriter.UploadTextAsync(json);
                    }
                    catch (Exception exFaultBlob)
                    {
                        log.Error($"Failed to write the fault blob: {id}. {exFaultBlob.Message}");
                    }

                    try
                    {
                        var qMsg = new TransmissionFaultMessage { id = id, type = typeof(T2).ToString() };
                        string qMsgJson = JsonConvert.SerializeObject(qMsg);

                        var queueWriter = await queueFaultBinder.BindAsync<CloudQueue>(
                            new QueueAttribute("transmission-faults"));
                        await queueWriter.AddMessageAsync(new CloudQueueMessage(qMsgJson));
                    }
                    catch (Exception exFaultQueue)
                    {
                        log.Error($"Failed to write the fault queue: {id}. {exFaultQueue.Message}");
                    }

                    log.Info($"C# Event Hub trigger function faulted a batch of messages, splunkMsgsCount: {splunkMsgsCount}, batch id: {id}");
                }
            }

        }
    }
}
