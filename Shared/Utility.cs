namespace BackEnd.Shared
{
    public static class Utility
    {
        public static string GetFileNameFromUrl(string url)
        {
            // Create a Uri object from the URL
            Uri uri = new Uri(url);

            // Get the last part of the path (file name)
            string fileName = System.IO.Path.GetFileName(uri.LocalPath);

            return fileName;
        }

        public static string GetLastPartAfterHyphen(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return string.Empty; // Handle empty or null strings
            }

            // Split the string by hyphen
            string[] parts = input.Split('-');

            // Return the last part
            return parts[^1]; // Using index from end operator (C# 8.0 and later)
        }
    }
}
