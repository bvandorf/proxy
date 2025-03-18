using System;
using System.Text;

namespace CsProxyTools.Helpers;

public static class StringUtils
{
    /// <summary>
    /// Converts a byte array to a hexadecimal string without spaces
    /// </summary>
    public static string ToHexString(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        var hexChars = new char[data.Length * 2];
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            hexChars[i * 2] = GetHexChar(b >> 4);
            hexChars[i * 2 + 1] = GetHexChar(b & 0xF);
        }
        return new string(hexChars);
    }
    
    /// <summary>
    /// Converts a byte array to a formatted hexadecimal string with spaces
    /// </summary>
    public static string ToFormattedHexString(ReadOnlySpan<byte> data, int bytesPerGroup = 16, string separator = " ")
    {
        if (data.IsEmpty)
            return string.Empty;

        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sb.Append(data[i].ToString("x2"));
            
            // Add separator after each group (except at the end)
            if ((i + 1) % bytesPerGroup == 0 && i < data.Length - 1)
            {
                sb.Append(separator);
            }
            else if (i < data.Length - 1)
            {
                sb.Append(separator);
            }
        }
        return sb.ToString();
    }
    
    private static char GetHexChar(int value)
    {
        return (char)(value < 10 ? '0' + value : 'a' + (value - 10));
    }
    
    /// <summary>
    /// Gets a detailed preview of data with both text and hex representation, without truncation
    /// </summary>
    public static string GetDataPreview(ReadOnlyMemory<byte> data)
    {
        var span = data.Span;
        
        // Text representation (full, no truncation)
        string textPreview;
        
        try
        {
            // Get full text representation
            var rawText = Encoding.UTF8.GetString(span);
            
            // Replace non-printable characters with dots for readability
            var sb = new StringBuilder(rawText.Length);
            foreach (char c in rawText)
            {
                sb.Append(char.IsControl(c) && c != '\r' && c != '\n' && c != '\t' ? '.' : c);
            }
            textPreview = sb.ToString();
        }
        catch
        {
            textPreview = "[Non-text data]";
        }
        
        // Hex representation (full)
        var hexString = ToHexString(span);
        
        return $"TEXT: {textPreview}\nHEX:  {hexString}";
    }
} 