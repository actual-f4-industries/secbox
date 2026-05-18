namespace Secbox.Core.RuntimeSensors.Sinks;

public interface IOutputSink : IAsyncDisposable
{
    string Id { get; }
    void Emit(AttributedFinding finding);
}
