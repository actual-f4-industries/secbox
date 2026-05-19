using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Secbox.Sentinel.Contracts;
using Secbox.Sentinel.Engine;
using Secbox.Sentinel.Service;
using Secbox.Sentinel.Service.Alerts;
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
// AlertSpawner watches %PROGRAMDATA%\secbox\alerts for finding-JSON drops
// from the editor's ManagedCallSensor and launches SecboxAlertUI.exe in the
// active user's session via CreateProcessAsUser. Runs independently of the
// kernel ETW pipeline so a stalled editor doesn't prevent alerts.
builder.Services.AddHostedService<AlertSpawner>();

builder.Logging.AddEventLog(opts =>
{
    opts.SourceName = SentinelProtocol.ServiceName;
});

await builder.Build().RunAsync();
