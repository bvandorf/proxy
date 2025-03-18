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
    
    private static char GetHexChar(int value)
    {
        return (char)(value < 10 ? '0' + value : 'a' + (value - 10));
    }
    
    /// <summary>
    /// Gets a preview of text data with hex representation
    /// </summary>
    public static string GetDataPreview(ReadOnlyMemory<byte> data, int maxTextLength = 100)
    {
        var span = data.Span;
        
        // Text representation (truncated if too long)
        var textLength = Math.Min(span.Length, maxTextLength);
        string textPreview;
        
        try
        {
            textPreview = Encoding.UTF8.GetString(span.Slice(0, textLength));
            if (span.Length > maxTextLength)
                textPreview += "...";
            
            // Replace non-printable characters with dots
            var sb = new StringBuilder(textPreview.Length);
            foreach (char c in textPreview)
            {
                sb.Append(char.IsControl(c) ? '.' : c);
            }
            textPreview = sb.ToString();
        }
        catch
        {
            textPreview = "[Non-text data]";
        }
        
        // Hex representation (full)
        var hexString = ToHexString(span);
        
        return $"{textPreview}\nHEX: {hexString}";
    }
} 