using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Contracts;
using Secbox.Sentinel.Engine;
using Secbox.Sentinel.Service;
using Secbox.Sentinel.Service.Pipe;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(opts =>
{
    opts.ServiceName = SentinelProtocol.ServiceName;
});

builder.Services.AddSingleton<EngineHost>(sp =>
{
    var loggers = sp.GetRequiredService<ILoggerFactory>();
    var host = new EngineHost(loggers);
    host.RegisterDefaultProviders();
    return host;
});

builder.Services.AddSingleton<ClientAuthenticator>();
builder.Services.AddSingleton<PipeServer>();
builder.Services.AddHostedService<SentinelWorker>();

builder.Logging.AddEventLog(opts =>
{
    opts.SourceName = SentinelProtocol.ServiceName;
});

await builder.Build().RunAsync();
