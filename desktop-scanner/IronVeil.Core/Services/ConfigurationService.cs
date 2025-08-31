using IronVeil.Core.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace IronVeil.Core.Services;

public interface IConfigurationService
{
    AppConfiguration Configuration { get; }
    void SaveConfiguration();
    void ResetToDefaults();
    string GetSecureString(string key);
    void SetSecureString(string key, string value);
    void ClearSecureString(string key);
}

public class ConfigurationService : IConfigurationService
{
    private readonly AppConfiguration _configuration;
    private readonly Dictionary<string, byte[]> _secureStorage = new();
    private readonly byte[] _entropy;
    
    public AppConfiguration Configuration => _configuration;
    
    public ConfigurationService()
    {
        _configuration = AppConfiguration.Load();
        _entropy = GenerateEntropy();
    }
    
    public void SaveConfiguration()
    {
        _configuration.Save();
    }
    
    public void ResetToDefaults()
    {
        _configuration.Backend = new BackendSettings();
        _configuration.Scan = new ScanSettings();
        _configuration.Security = new SecuritySettings();
        _configuration.Application = new ApplicationSettings();
        SaveConfiguration();
    }
    
    public string GetSecureString(string key)
    {
        if (!_secureStorage.ContainsKey(key))
            return string.Empty;
        
        try
        {
            var encryptedData = _secureStorage[key];
            // Use AES encryption with user-specific entropy for cross-platform compatibility
            var decryptedData = DecryptData(encryptedData, _entropy);
            return Encoding.UTF8.GetString(decryptedData);
        }
        catch
        {
            return string.Empty;
        }
    }
    
    public void SetSecureString(string key, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            ClearSecureString(key);
            return;
        }
        
        try
        {
            var data = Encoding.UTF8.GetBytes(value);
            // Use AES encryption with user-specific entropy for cross-platform compatibility
            var encryptedData = EncryptData(data, _entropy);
            _secureStorage[key] = encryptedData;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to secure string: {ex.Message}", ex);
        }
    }
    
    public void ClearSecureString(string key)
    {
        if (_secureStorage.ContainsKey(key))
        {
            // Clear the encrypted data from memory
            if (_secureStorage[key] != null)
            {
                Array.Clear(_secureStorage[key], 0, _secureStorage[key].Length);
            }
            _secureStorage.Remove(key);
        }
    }
    
    private byte[] GenerateEntropy()
    {
        // Generate a unique entropy for this application instance
        var entropy = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(entropy);
        }
        return entropy;
    }

    private byte[] EncryptData(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();
        
        // Write IV first
        ms.Write(aes.IV, 0, aes.IV.Length);
        
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
        }
        
        return ms.ToArray();
    }

    private byte[] DecryptData(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        
        // Read IV from the beginning
        var iv = new byte[aes.IV.Length];
        Array.Copy(encryptedData, 0, iv, 0, iv.Length);
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor();
        using var ms = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var result = new MemoryStream();
        
        cs.CopyTo(result);
        return result.ToArray();
    }
}