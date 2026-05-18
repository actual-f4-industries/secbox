using Mono.Cecil;

namespace Secbox.Scanner.Finders;

// Formats Mono.Cecil references into the engine's AccessControl key format
// so the ported rule strings match unchanged. Mirrors
// sbox-public/engine/Sandbox.Access/AssemblyAccess.Touch.cs.
//
//   type   →  "{AssemblyName}/{TypeFullName}"
//   method →  "{AssemblyName}/{TypeFullName}.{MethodName}<G1,G2>( ParamType1, ParamType2 )"
internal static class MemberKey
{
    public static string ForType(TypeDefinition typeDef)
        => $"{typeDef.Module.Assembly.Name.Name}/{typeDef.FullName}";

    public static string ForMethod(MethodDefinition methodDef)
    {
        var key = $"{methodDef.Module.Assembly.Name.Name}/{methodDef.DeclaringType.FullName}.{methodDef.Name}";

        if (methodDef.HasGenericParameters)
        {
            var gparms = string.Join(",", methodDef.GenericParameters.Select(x => x.Name));
            if (!string.IsNullOrWhiteSpace(gparms))
                key += $"<{gparms}>";
        }

        if (methodDef.HasParameters)
        {
            var parms = string.Join(", ", methodDef.Parameters.Select(x => x.ParameterType.ToString()));
            key += $"( {parms} )";
        }
        else
        {
            key += "()";
        }

        return key;
    }

    public static string ForMethodRef(MethodReference methodRef)
    {
        var resolved = TryResolve(methodRef);
        if (resolved != null) return ForMethod(resolved);

        var asmName = methodRef.DeclaringType?.Scope?.Name ?? "<unknown>";
        var typeName = methodRef.DeclaringType?.FullName ?? "<unknown>";
        var key = $"{asmName}/{typeName}.{methodRef.Name}";

        if (methodRef.HasParameters)
        {
            var parms = string.Join(", ", methodRef.Parameters.Select(x => x.ParameterType.ToString()));
            key += $"( {parms} )";
        }
        else key += "()";

        return key;
    }

    public static string ForTypeRef(TypeReference typeRef)
    {
        var resolved = TryResolve(typeRef);
        if (resolved != null) return ForType(resolved);

        var asmName = typeRef?.Scope?.Name ?? "<unknown>";
        var typeName = typeRef?.FullName ?? "<unknown>";
        return $"{asmName}/{typeName}";
    }

    public static string AssemblyOf(MemberReference memberRef)
    {
        var declaring = memberRef as TypeReference ?? memberRef?.DeclaringType;
        return declaring?.Scope?.Name ?? "<unknown>";
    }

    static MethodDefinition? TryResolve(MethodReference r)
    {
        try { return r?.Resolve(); }
        catch { return null; }
    }

    static TypeDefinition? TryResolve(TypeReference r)
    {
        try { return r?.Resolve(); }
        catch { return null; }
    }
}
