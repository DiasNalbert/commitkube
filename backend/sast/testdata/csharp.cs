using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

public class FixtureController : Controller
{
    private readonly HttpClient _http = new HttpClient();

    public void SqlCases(SqlConnection conn, string id)
    {
        // ruleid: ck-csharp-sql-built-from-strings
        var cmd = new SqlCommand($"SELECT * FROM users WHERE id = {id}", conn);

        var q = "SELECT * FROM users WHERE name = '" + id + "'";
        // ruleid: ck-csharp-sql-built-from-strings
        cmd.CommandText = q;

        // ok: ck-csharp-sql-built-from-strings
        var safe = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
    }

    [HttpGet("run")]
    public IActionResult Run([FromQuery] string tool)
    {
        // ruleid: ck-csharp-command-from-request
        Process.Start(tool);
        // ok: ck-csharp-command-from-request
        Process.Start("git");
        return Ok();
    }

    [HttpGet("download")]
    public IActionResult Download([FromQuery] string name)
    {
        // ruleid: ck-csharp-path-from-request
        var bytes = File.ReadAllBytes(Path.Combine("/srv/files", name));
        // ok: ck-csharp-path-from-request
        var safe = File.ReadAllBytes(Path.Combine("/srv/files", Path.GetFileName(name)));
        return Ok();
    }

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        // ruleid: ck-csharp-ssrf-from-request
        await _http.GetAsync(url);
        // ok: ck-csharp-ssrf-from-request
        await _http.GetAsync($"https://api.example.com/users/{url}");
        return Ok();
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string next)
    {
        // ruleid: ck-csharp-open-redirect
        return Redirect(next);
    }

    [HttpGet("home")]
    public IActionResult Home()
    {
        // ok: ck-csharp-open-redirect
        return Redirect("/dashboard");
    }

    public void DeserializationCases()
    {
        // ruleid: ck-csharp-unsafe-deserialization
        var bf = new BinaryFormatter();
    }

    public void TlsCases(HttpClientHandler handler)
    {
        // ruleid: ck-csharp-tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
    }

    public void CryptoCases(Aes aes)
    {
        // ruleid: ck-csharp-weak-cipher
        var des = DES.Create();
        // ruleid: ck-csharp-weak-cipher
        aes.Mode = CipherMode.ECB;

        // ruleid: ck-csharp-weak-hash
        var md5 = MD5.Create();
        // ok: ck-csharp-weak-hash
        var sha = SHA256.Create();
    }
}
