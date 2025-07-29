using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Cosmos;
using StackExchange.Redis;
using BackEnd.Entities;
using BackEnd.Models;
using System.Security.Cryptography;
using Azure.Storage.Blobs.Models;
using Azure;
using System.Reflection;
using Microsoft.Azure.Cosmos.Linq;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FeedsController : ControllerBase
    {
        private readonly CosmosDbContext _dbContext;
        private readonly BlobServiceClient _blobServiceClient;
        private readonly string _feedContainer = "media";
        private readonly IDatabase _redis;
        private readonly ILogger<FeedsController> _logger;
        private readonly string cdnBaseUrl = "https://socialnotebookscdn-ghcdgcdxc8andjgv.z02.azurefd.net/";

        public FeedsController(CosmosDbContext dbContext, BlobServiceClient blobServiceClient, ILogger<FeedsController> logger)
        {
            _dbContext = dbContext;
            _blobServiceClient = blobServiceClient;
            _logger = logger;
        }


        [HttpPost("uploadFeed")]
        public async Task<IActionResult> UploadFeed([FromForm] FeedUploadModel model, CancellationToken cancellationToken)
        {
            Console.WriteLine("UploadFeed API started.");

            try
            {
                if (model.File == null || string.IsNullOrEmpty(model.UserId) || string.IsNullOrEmpty(model.FileName))
                {
                    Console.WriteLine("Validation failed: File, UserId or FileName is missing.");
                    return BadRequest("Missing required fields.");
                }

                Console.WriteLine($"Received file: {model.File.FileName}, Size: {model.File.Length} bytes");
                Console.WriteLine($"UserId: {model.UserId}, UserName: {model.UserName}");

                var containerClient = _blobServiceClient.GetBlobContainerClient(_feedContainer);
                Console.WriteLine($"Connected to Blob Container: {_feedContainer}");

                var blobName = $"{ShortGuidGenerator.Generate()}_{Path.GetFileName(model.File.FileName)}";
                var blobClient = containerClient.GetBlobClient(blobName);
                Console.WriteLine($"Generated Blob Name: {blobName}");

                var mimeType = GetMimeType(model.File.FileName);

                using var fileStream = model.File.OpenReadStream();
                var blobHttpHeaders = new BlobHttpHeaders
                {
                    ContentType = mimeType,
                    CacheControl = "public, max-age=31536000"
                };

                Console.WriteLine("Uploading file to blob storage...");
                await blobClient.UploadAsync(fileStream, blobHttpHeaders, cancellationToken: cancellationToken);
                Console.WriteLine("File uploaded successfully.");

                var blobUrl = blobClient.Uri.ToString();
                Console.WriteLine($"Blob URL: {blobUrl}");

                var postId = ShortGuidGenerator.Generate();

                var userPost = new UserPost
                {
                    PostId = postId,
                    Title = model.ProfilePic,
                    Content = blobUrl,
                    Caption = string.IsNullOrEmpty(model.Caption) || model.Caption == "undefined" ? string.Empty : model.Caption,
                    AuthorId = model.UserId,
                    AuthorUsername = model.UserName,
                    DateCreated = DateTime.UtcNow,
                    LikeCount = 0,
                    CommentCount = 0,
                    LikeFlag = 0,
                    IsVerified = false,
                    Checksum = string.Empty
                };

                Console.WriteLine("Serialized Document: " + userPost.ToString());

                await _dbContext.PostsContainer.UpsertItemAsync(userPost, cancellationToken: cancellationToken);
                Console.WriteLine("Item upserted into Cosmos DB successfully.");

                return Ok(new
                {
                    Message = "Feed uploaded successfully.",
                    FeedId = userPost.PostId
                });
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Upload canceled by client or due to timeout.");
                return StatusCode(499, "Upload canceled by client or timed out.");
            }
            catch (CosmosException ex)
            {
                Console.WriteLine($"Cosmos DB error: {ex.StatusCode} - {ex.Message}");
                return StatusCode((int)ex.StatusCode, ex.Message);
            }
            catch (RequestFailedException ex) when (ex.Status == 412)
            {
                Console.WriteLine($"Blob precondition failed: {ex.Message}");
                return StatusCode(412, "Blob precondition failed. Please retry.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                return StatusCode(500, $"Error uploading feed: {ex.Message}");
            }
        }


        //[HttpPost("uploadFeed")]
        //public async Task<IActionResult> UploadFeed([FromForm] FeedUploadModel model, CancellationToken cancellationToken)
        //{
        //    Console.WriteLine("Starting UploadFeed API...");
        //    try
        //    {
        //        if (model.File == null || string.IsNullOrEmpty(model.UserId) || string.IsNullOrEmpty(model.FileName))
        //        {
        //            Console.WriteLine("Validation failed: Missing required fields.");
        //            return BadRequest("Missing required fields.");
        //        }

        //        Console.WriteLine($"Received file: {model.File.FileName}, Size: {model.File.Length} bytes");
        //        Console.WriteLine($"User ID: {model.UserId}, User Name: {model.UserName}");

        //        var containerClient = _blobServiceClient.GetBlobContainerClient(_feedContainer);
        //        Console.WriteLine($"Connecting to Blob Container: {_feedContainer}");

        //        var blobName = $"{ShortGuidGenerator.Generate()}_{Path.GetFileName(model.File.FileName)}";
        //        var blobClient = containerClient.GetBlobClient(blobName);
        //        Console.WriteLine($"Generated Blob Name: {blobName}");

        //        var mimeType = GetMimeType(model.File.FileName);

        //        // --- NEW: Use UploadAsync() instead of OpenWriteAsync() to avoid 412 errors ---
        //        using var fileStream = model.File.OpenReadStream();
        //        var blobHttpHeaders = new BlobHttpHeaders
        //        {
        //            ContentType = mimeType,
        //            CacheControl = "public, max-age=31536000" // 1-year cache
        //        };

        //        // Upload file in one step, setting headers immediately
        //        Console.WriteLine("Starting file upload...");
        //        await blobClient.UploadAsync(fileStream, blobHttpHeaders, cancellationToken: cancellationToken);
        //        Console.WriteLine("File uploaded successfully.");

        //        var blobUrl = blobClient.Uri.ToString();
        //        Console.WriteLine($"Blob URL: {blobUrl}");

        //        // Save Post Info in Cosmos DB
        //        var userPost = new UserPost
        //        {
        //            PostId = ShortGuidGenerator.Generate(),
        //            Title = model.ProfilePic,
        //            Content = blobUrl,
        //            Caption = string.IsNullOrEmpty(model.Caption) || model.Caption == "undefined" ? string.Empty : model.Caption,
        //            AuthorId = model.UserId,
        //            AuthorUsername = model.UserName,
        //            DateCreated = DateTime.UtcNow
        //        };

        //        await _dbContext.PostsContainer.UpsertItemAsync(userPost, new PartitionKey(userPost.PostId));
        //        Console.WriteLine("User post successfully saved to Cosmos DB.");

        //        return Ok(new
        //        {
        //            Message = "Feed uploaded successfully.",
        //            FeedId = userPost.PostId
        //        });
        //    }
        //    catch (OperationCanceledException)
        //    {
        //        Console.WriteLine("Upload was canceled by the client or due to timeout.");
        //        return StatusCode(499, "Upload was canceled due to timeout or client cancellation.");
        //    }
        //    catch (RequestFailedException ex) when (ex.Status == 412) // Handle precondition failure
        //    {
        //        Console.WriteLine($"Blob precondition failed: {ex.Message}");
        //        return StatusCode(412, "Blob precondition failed. Please retry.");
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"Error during upload: {ex.Message}");
        //        return StatusCode(500, $"Error uploading feed: {ex.Message}");
        //    }
        //}

        [HttpGet("getUserFeeds")]
        public async Task<IActionResult> GetUserFeeds(int pageNumber = 1, int pageSize = 10)
        {
            try
            {
                Console.WriteLine("GetUserFeeds API started.");

                var userPosts = new List<UserPost>();
                var queryString = $"SELECT * FROM f WHERE f.type = 'post' ORDER BY f.dateCreated DESC OFFSET {(pageNumber - 1) * pageSize} LIMIT {pageSize}";
                Console.WriteLine($"Executing query: {queryString}");

                var queryFromPostsContainer = _dbContext.PostsContainer
                    .GetItemQueryIterator<UserPost>(new QueryDefinition(queryString), requestOptions: new QueryRequestOptions { MaxItemCount = pageSize });

                while (queryFromPostsContainer.HasMoreResults)
                {
                    var response = await queryFromPostsContainer.ReadNextAsync();
                    Console.WriteLine($"Fetched {response.Count} posts from Cosmos DB.");
                    userPosts.AddRange(response.ToList());
                }

                Console.WriteLine("Returning posts to client.");
                return Ok(new { BlogPostsMostRecent = userPosts });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving feeds: {ex.Message}");
                return StatusCode(500, $"Error retrieving feeds: {ex.Message}");
            }
        }



        //[HttpGet("getUserFeeds")]
        //public async Task<IActionResult> GetUserFeeds(string? userId = null, int pageNumber = 1, int pageSize = 2)
        //{
        //    try
        //    {
        //        var userPosts = new List<UserPost>();
        //        var queryString = $"SELECT * FROM f WHERE f.type='post' ORDER BY f.dateCreated DESC OFFSET {(pageNumber - 1) * pageSize} LIMIT {pageSize}";
        //        Console.WriteLine($"Executing query: {queryString}");
        //        var queryFromPostsContainer = _dbContext.PostsContainer.GetItemQueryIterator<UserPost>(new QueryDefinition(queryString));
        //        while (queryFromPostsContainer.HasMoreResults)
        //        {
        //            var response = await queryFromPostsContainer.ReadNextAsync();
        //            Console.WriteLine($"Fetched {response.Count} posts from Cosmos DB.");
        //            userPosts.AddRange(response.ToList());
        //        }
        //        if (!string.IsNullOrEmpty(userId))
        //        {
        //            Console.WriteLine($"UserId provided: {userId}. Checking user likes...");
        //            var likes = await GetLikesAsync();
        //            var userLikes = new List<UserPost>();
        //            foreach (var item in userPosts)
        //            {
        //                var hasUserLikedPost = likes.FirstOrDefault(x => x.PostId == item.PostId && x.LikeAuthorId == userId);
        //                item.LikeFlag = hasUserLikedPost != null ? 1 : 0;
        //            }

        //            var hasAnyReportedPost = userPosts.Any(x => x.ReportCount > 0);
        //            if (hasAnyReportedPost)
        //            {
        //                var userReportedPostIds = new List<string>();
        //                var query = _dbContext.ReportedPostsContainer.GetItemLinqQueryable<ReportedPost>()
        //                            .Where(p => p.ReportedUserId == userId)
        //                            .Select(p => p.PostId)
        //                            .ToFeedIterator();
        //                while (query.HasMoreResults)
        //                {
        //                    var response = await query.ReadNextAsync();
        //                    userReportedPostIds.AddRange(response.ToList());
        //                }

        //                if (userReportedPostIds.Count > 0) { 
        //                    userPosts = userPosts.Where(x => !userReportedPostIds.Contains(x.Id)).ToList();
        //                }
        //            }
        //        }
        //        Console.WriteLine("Reordering posts by LikeCount, CommentCount, and DateCreated...");

        //        userPosts = userPosts
        //            .OrderByDescending(x => x.DateCreated)
        //            .ThenByDescending(x => x.LikeCount)
        //            .ThenByDescending(x => x.CommentCount)
        //            .ToList();

        //        var userIds = userPosts.Select(x => x.AuthorId).Distinct().ToList();

        //        var usersQuery = _dbContext.UsersContainer.GetItemLinqQueryable<BlogUser>()
        //                                         .Where(x => userIds.Contains(x.Id))
        //                                         .ToFeedIterator();
        //        var users = new List<BlogUser>();
        //        while (usersQuery.HasMoreResults)
        //        {
        //            var response = await usersQuery.ReadNextAsync();
        //            users.AddRange(response.ToList());
        //        }
        //        foreach (var post in userPosts) {
        //            post.Content = post.Content.Replace("https://socialnotebooksstorage.blob.core.windows.net/", cdnBaseUrl);
        //            var user = users.FirstOrDefault(x => x.Id == post.AuthorId);
        //            post.IsVerified = user != null ? user.IsVerified : false;
        //        }
        //        Console.WriteLine("Reordering complete.");
        //        Console.WriteLine("Returning final ordered list of posts.");
        //        return Ok(new { BlogPostsMostRecent = userPosts });
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"Error retrieving feeds: {ex.Message}");
        //        return StatusCode(500, $"Error retrieving feeds: {ex.Message}");
        //    }
        //}

        private async Task<List<UserPostLike>> GetLikesAsync()
        {
            var likes = new List<UserPostLike>();
            var query = _dbContext.LikesContainer.GetItemLinqQueryable<UserPostLike>()
                        .ToFeedIterator();
            while (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                likes.AddRange(response.ToList());
            }
            return likes;
        }

        [HttpGet("download")]
        public async Task<IActionResult> DownloadFile([FromQuery] string fileName)
        {
            try
            {
                if (string.IsNullOrEmpty(fileName))
                {
                    return BadRequest("File name is required.");
                }
                var containerClient = _blobServiceClient.GetBlobContainerClient(_feedContainer);
                var blobClient = containerClient.GetBlobClient(fileName);
                if (!await blobClient.ExistsAsync())
                {
                    return NotFound("File not found.");
                }
                var downloadInfo = await blobClient.DownloadAsync();
                return File(downloadInfo.Value.Content, downloadInfo.Value.ContentType, fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error downloading file: {ex.Message}");
                return StatusCode(500, "Error downloading file.");
            }
        }

        private string GetMimeType(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLower();

            var mimeTypes = new Dictionary<string, string>
            {
                // Image formats
                { ".jpg", "image/jpeg" },
                { ".jpeg", "image/jpeg" },
                { ".png", "image/png" },
                { ".gif", "image/gif" },
                { ".bmp", "image/bmp" },
                { ".svg", "image/svg+xml" },
                { ".webp", "image/webp" },

                // Video formats
                { ".mp4", "video/mp4" },
                { ".mov", "video/quicktime" },
                { ".avi", "video/x-msvideo" },
                { ".wmv", "video/x-ms-wmv" },
                { ".flv", "video/x-flv" },
                { ".mkv", "video/x-matroska" },
                { ".webm", "video/webm" }
            };

            return mimeTypes.TryGetValue(extension, out var mimeType) ? mimeType : "application/octet-stream";
        }

        public class Crc32 : HashAlgorithm
        {
            private const uint Polynomial = 0xedb88320;
            private readonly uint[] table = new uint[256];
            private uint crc = 0xffffffff;
            public Crc32()
            {
                InitializeTable();
                HashSizeValue = 32;
            }
            private void InitializeTable()
            {
                for (uint i = 0; i < 256; i++)
                {
                    uint entry = i;
                    for (int j = 0; j < 8; j++)
                    {
                        if ((entry & 1) == 1)
                            entry = (entry >> 1) ^ Polynomial;
                        else
                            entry >>= 1;
                    }
                    table[i] = entry;
                }
            }
            public override void Initialize()
            {
                crc = 0xffffffff;
            }
            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                for (int i = ibStart; i < ibStart + cbSize; i++)
                {
                    byte index = (byte)(crc ^ array[i]);
                    crc = (crc >> 8) ^ table[index];
                }
            }
            protected override byte[] HashFinal()
            {
                crc ^= 0xffffffff;
                return BitConverter.GetBytes(crc);
            }
        }
    }
}
