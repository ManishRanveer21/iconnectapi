using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using BackEnd.ViewModels;
using BackEnd.Entities;
using Azure.Storage.Blobs;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserPostController : ControllerBase
    {
        private readonly CosmosDbContext _dbContext;
        private readonly BlobServiceClient _blobServiceClient;
        private readonly string _feedContainer = "media";

        public UserPostController(CosmosDbContext dbContext, BlobServiceClient blobServiceClient)
        {
            _dbContext = dbContext;
            _blobServiceClient = blobServiceClient;
        }


        [Route("post/{postId}")]
        [HttpGet]
        public async Task<IActionResult> PostView(string postId, string userId)
        {

            //When getting the blogpost from the Posts container, the id is postId and the partitionKey is also postId.
            //  This will automatically return only the type="post" for this postId (and not the type=comment or any other types in the same partition postId)
            ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var bp = response.Resource;



            var queryString1 = $"SELECT * FROM p WHERE p.type='comment' AND p.postId = @PostId ORDER BY p.dateCreated DESC";
            var queryDef1 = new QueryDefinition(queryString1);
            queryDef1.WithParameter("@PostId", postId);
            var query1 = _dbContext.PostsContainer.GetItemQueryIterator<UserPostComment>(queryDef1);

            List<UserPostComment> comments = new List<UserPostComment>();
            while (query1.HasMoreResults)
            {
                var resp1 = await query1.ReadNextAsync();
                var ru = resp1.RequestCharge;
                comments.AddRange(resp1.ToList());
            }
            var userLikedPost = false;




            var queryString2 = $"SELECT TOP 1 * FROM p WHERE p.type='like' AND p.postId = @PostId AND p.userId = @UserId ORDER BY p.dateCreated DESC";

            var queryDef2 = new QueryDefinition(queryString2);
            queryDef2.WithParameter("@PostId", postId);
            queryDef2.WithParameter("@UserId", userId);
            var query2 = _dbContext.PostsContainer.GetItemQueryIterator<UserPostLike>(queryDef2);

            UserPostLike like = null;
            if (query2.HasMoreResults)
            {
                var resp2 = await query2.ReadNextAsync();
                var ru = resp2.RequestCharge;
                like = resp2.FirstOrDefault();
            }
            userLikedPost = like != null;

            var m = new BlogPostViewViewModel
            {
                PostId = bp.PostId,
                Title = bp.Title,
                Content = bp.Content,
                CommentCount = bp.CommentCount,
                Comments = comments,
                UserLikedPost = userLikedPost,
                LikeCount = bp.LikeCount,
                AuthorId = bp.AuthorId,
                AuthorUsername = bp.AuthorUsername
            };
            return Ok(m);
        }


        [Route("post/edit/{postId}")]
        [HttpGet]
        public async Task<IActionResult> PostEdit(string postId)
        {
            //When getting the blogpost from the Posts container, the id is postId and the partitionKey is also postId.
            //  This will automatically return only the type="post" for this postId (and not the type=comment or any other types in the same partition postId)
            ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var ru = response.RequestCharge;
            var bp = response.Resource;

            var m = new BlogPostEditViewModel
            {
                Title = bp.Title,
                Content = bp.Content
            };
            return Ok(m);
        }


        [Route("post/new")]
        [HttpPost]
        public async Task<IActionResult> PostNew(BlogPostEditViewModel blogPostChanges)
        {
            blogPostChanges.Content = "Testing Text";

            var blogPost = new UserPost
            {
                PostId = Guid.NewGuid().ToString(),
                Title = blogPostChanges.Title,
                Content = blogPostChanges.Content,
                AuthorId = User.Claims.FirstOrDefault(p => p.Type == ClaimTypes.NameIdentifier).Value,
                AuthorUsername = User.Identity.Name,
                DateCreated = DateTime.UtcNow,
            };

            //Insert the new blog post into the database.
            await _dbContext.PostsContainer.UpsertItemAsync<UserPost>(blogPost, new PartitionKey(blogPost.PostId));


            //Show the view with a message that the blog post has been created.

            return Ok(blogPostChanges);
        }


        [Route("post/edit/{postId}")]
        [HttpPost]
        public async Task<IActionResult> PostEdit(string postId, BlogPostEditViewModel blogPostChanges)
        {
            ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var ru = response.RequestCharge;
            var bp = response.Resource;

            bp.Title = blogPostChanges.Title;
            bp.Content = blogPostChanges.Content;

            //Update the database with these changes.
            await _dbContext.PostsContainer.UpsertItemAsync<UserPost>(bp, new PartitionKey(bp.PostId));

            //Show the view with a message that the blog post has been updated.
            return Ok(blogPostChanges);
        }

        // Remove once new apis integrated
        [Route("PostCommentNew")]
        [HttpPost]
        public async Task<IActionResult> PostCommentNew([FromForm] CommentPost model)
        {

            if (!string.IsNullOrWhiteSpace(model.CommentContent))
            {
                ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(model.PostId, new PartitionKey(model.PostId));
                var ru = response.RequestCharge;
                var bp = response.Resource;

                if (bp != null)
                {
                    var blogPostComment = new UserPostComment
                    {
                        CommentId = Guid.NewGuid().ToString(),
                        PostId = Guid.NewGuid().ToString(),
                        CommentContent = model.CommentContent,
                        CommentAuthorId = model.CommentAuthorId,
                        CommentAuthorUsername = model.CommentAuthorUsername,
                        CommentDateCreated = DateTime.UtcNow,
                        UserProfileUrl = model.UserProfileUrl,
                    };


                    var obj = new dynamic[] { blogPostComment.PostId, blogPostComment };

                    try
                    {
                        var result = await _dbContext.PostsContainer.Scripts.ExecuteStoredProcedureAsync<string>("createComment", new PartitionKey(blogPostComment.PostId), obj);
                    }
                    catch (Exception ex)
                    {
                        var e = ex.Message;
                    }


                }
            }

            return Ok(new { postId = model.PostId });
        }

        // Remove once new apis integrated
        [Route("postLike")]
        [HttpPost]
        public async Task<IActionResult> PostLike([FromForm] LikePost model)
        {
            try
            {
                var response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(model.PostId, new PartitionKey(model.PostId));
                var post = response.Resource;

                if (post != null)
                {
                    var queryString = "SELECT TOP 1 * FROM p WHERE p.type='like' AND p.postId = @PostId AND p.userId = @UserId";
                    var queryDef = new QueryDefinition(queryString)
                        .WithParameter("@PostId", model.PostId)
                        .WithParameter("@UserId", model.LikeAuthorId);

                    var query = _dbContext.PostsContainer.GetItemQueryIterator<UserPostLike>(queryDef);
                    var existingLike = (await query.ReadNextAsync()).FirstOrDefault();

                    if (existingLike == null)
                    {
                        var like = new UserPostLike
                        {
                            LikeId = Guid.NewGuid().ToString(),
                            PostId = model.PostId,
                            LikeAuthorId = model.LikeAuthorId,
                            LikeAuthorUsername = model.LikeAuthorUsername,
                            LikeDateCreated = DateTime.UtcNow,
                            UserProfileUrl = model.UserProfileUrl
                        };

                        await _dbContext.PostsContainer.UpsertItemAsync(like, new PartitionKey(model.PostId));
                        post.LikeCount++;
                    }
                    else
                    {
                        await _dbContext.PostsContainer.DeleteItemAsync<UserPostLike>(existingLike.LikeId, new PartitionKey(model.PostId));
                        post.LikeCount--;
                    }

                    await _dbContext.PostsContainer.UpsertItemAsync(post, new PartitionKey(post.PostId));
                    return Ok(new { likeCount = post.LikeCount });
                }

                return NotFound("Post not found.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error toggling like: {ex.Message}");
                return StatusCode(500, "An error occurred while processing the like request.");
            }
        }

        // Remove once new apis integrated
        [Route("post/{postId}/unlike")]
        [HttpPost]
        public async Task<IActionResult> PostUnlike(string postId)
        {
            ItemResponse<UserPost> response = await this._dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var ru = response.RequestCharge;
            var bp = response.Resource;

            if (bp != null)
            {
                var userId = User.Claims.FirstOrDefault(p => p.Type == ClaimTypes.NameIdentifier).Value;
                var obj = new dynamic[] { postId, userId };
                var result = await _dbContext.PostsContainer.Scripts.ExecuteStoredProcedureAsync<string>("deleteLike", new PartitionKey(postId), obj);
            }

            return Ok(new { postId = postId });
        }

        // Remove once new apis integrated
        [Route("PostLikes")]
        [HttpGet]
        public async Task<IActionResult> PostLikes(string postId)
        {

            ItemResponse<UserPost> response_ = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var bp = response_.Resource;

            var postLikes = new List<UserPostLike>();
            if (bp != null)
            {
                //Check that this user has not already liked this post
                var queryString = $"SELECT * FROM p WHERE p.type='like' AND p.postId = @PostId  ORDER BY p.dateCreated DESC";

                var queryDef = new QueryDefinition(queryString);
                queryDef.WithParameter("@PostId", postId);
                var query = _dbContext.PostsContainer.GetItemQueryIterator<UserPostLike>(queryDef);

                if (query.HasMoreResults)
                {
                    var response = await query.ReadNextAsync();
                    var ru = response.RequestCharge;
                    postLikes.AddRange(response.ToList());
                }
            }

            return Ok(postLikes);
        }

        // Remove once new apis integrated
        [Route("PostComments")]
        [HttpGet]
        public async Task<IActionResult> PostComments(string postId)
        {

            ItemResponse<UserPost> response_ = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(postId, new PartitionKey(postId));
            var bp = response_.Resource;

            var postComments = new List<UserPostComment>();
            if (bp != null)
            {
                //Check that this user has not already liked this post
                var queryString = $"SELECT * FROM p WHERE p.type='comment' AND p.postId = @PostId  ORDER BY p.dateCreated DESC";

                var queryDef = new QueryDefinition(queryString);
                queryDef.WithParameter("@PostId", postId);
                var query = _dbContext.PostsContainer.GetItemQueryIterator<UserPostComment>(queryDef);

                if (query.HasMoreResults)
                {
                    var response = await query.ReadNextAsync();
                    var ru = response.RequestCharge;
                    postComments.AddRange(response.ToList());
                }
            }

            return Ok(postComments);
        }


        [Route("like-unlike-post")]
        [HttpPost]
        public async Task<IActionResult> LikeUnlikePost([FromForm] LikePost model)
        {
            try
            {
                var response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(model.PostId, new PartitionKey(model.PostId));
                var post = response.Resource;

                if (post != null)
                {
                    var queryString = "SELECT TOP 1 * FROM p WHERE p.type='like' AND p.postId = @PostId AND p.userId = @UserId";
                    var queryDef = new QueryDefinition(queryString)
                        .WithParameter("@PostId", model.PostId)
                        .WithParameter("@UserId", model.LikeAuthorId);

                    var query = _dbContext.LikesContainer.GetItemQueryIterator<UserPostLike>(queryDef);
                    var existingLike = (await query.ReadNextAsync()).FirstOrDefault();

                    if (existingLike == null)
                    {
                        var like = new UserPostLike
                        {
                            LikeId = ShortGuidGenerator.Generate(),
                            PostId = model.PostId,
                            LikeAuthorId = model.LikeAuthorId,
                            LikeAuthorUsername = model.LikeAuthorUsername,
                            LikeDateCreated = DateTime.UtcNow,
                            UserProfileUrl = model.UserProfileUrl
                        };

                        await _dbContext.LikesContainer.UpsertItemAsync(like, new PartitionKey(like.LikeId));
                        post.LikeCount++;
                    }
                    else
                    {
                        await _dbContext.LikesContainer.DeleteItemAsync<UserPostLike>(existingLike.LikeId, new PartitionKey(existingLike.LikeId));
                        if(post.LikeCount > 0)
                        {
                            post.LikeCount--;
                        }
                    }
                    await _dbContext.PostsContainer.UpsertItemAsync(post, new PartitionKey(model.PostId));
                    return Ok(new { likeCount = post.LikeCount });
                }

                return BadRequest("Post not found.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error toggling like: {ex.Message}");
                return StatusCode(500, "An error occurred while processing the like request.");
            }
        }

        [Route("post-likes")]
        [HttpGet]
        public async Task<IActionResult> GetPostLikes(string postId)
        {
            var postLikes = new List<UserPostLike>();
            var query = _dbContext.LikesContainer.GetItemLinqQueryable<UserPostLike>()
                        .Where(p => p.PostId == postId)
                        .ToFeedIterator();
            while (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                postLikes.AddRange(response.ToList());
            }

            return Ok(postLikes);
        }

        [Route("create-post-comment")]
        [HttpPost]
        public async Task<IActionResult> CreatePostComment([FromBody] CommentPost model)
        {

            if (!string.IsNullOrWhiteSpace(model.CommentContent))
            {
                ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(model.PostId, new PartitionKey(model.PostId));
                var post = response.Resource;

                if (post != null)
                {
                    var blogPostComment = new UserPostComment
                    {
                        CommentId = ShortGuidGenerator.Generate(),
                        PostId = model.PostId,
                        CommentContent = model.CommentContent,
                        CommentAuthorId = model.CommentAuthorId,
                        CommentAuthorUsername = model.CommentAuthorUsername,
                        CommentDateCreated = DateTime.UtcNow,
                        UserProfileUrl = model.UserProfileUrl,
                    };

                    await _dbContext.CommentsContainer.UpsertItemAsync(blogPostComment, new PartitionKey(blogPostComment.CommentId));
                    post.CommentCount++;

                    await _dbContext.PostsContainer.UpsertItemAsync(post, new PartitionKey(model.PostId));
                    return Ok(new { commentCount = post.CommentCount });
                }

                return BadRequest("Post not found.");
            }

            return BadRequest("Invalid Data.");
        }

        [Route("update-post-comment/{commentId}")]
        [HttpPut]
        public async Task<IActionResult> UpdatePostComment(string commentId, [FromBody] UpdateCommentPost model)
        {

            if (!string.IsNullOrWhiteSpace(commentId) && !string.IsNullOrWhiteSpace(model.CommentContent))
            {
                var query = _dbContext.CommentsContainer.GetItemLinqQueryable<UserPostComment>()
                        .Where(p => p.CommentId == commentId)
                        .ToFeedIterator();
                var postComment = (await query.ReadNextAsync()).FirstOrDefault();

                if (postComment != null)
                {
                    postComment.CommentContent = model.CommentContent;

                    await _dbContext.CommentsContainer.UpsertItemAsync(postComment, new PartitionKey(commentId));
                    return Ok();
                }

                return BadRequest("Post Comment not found.");
            }

            return BadRequest("Invalid Data");
        }

        [Route("delete-post-comment/{commentId}")]
        [HttpDelete]
        public async Task<IActionResult> DeletePostComment(string commentId)
        {
            if (!string.IsNullOrWhiteSpace(commentId))
            {
                var query = _dbContext.CommentsContainer.GetItemLinqQueryable<UserPostComment>()
                        .Where(p => p.CommentId == commentId)
                        .ToFeedIterator();
                var postComment = (await query.ReadNextAsync()).FirstOrDefault();
                if (postComment != null)
                {
                    await _dbContext.CommentsContainer.DeleteItemAsync<UserPostComment>(commentId, new PartitionKey(commentId));
                    return Ok();
                }
                return BadRequest("Post Comment not found.");
            }
            return BadRequest("Invalid CommentId");
        }

        [Route("post-comments")]
        [HttpGet]
        public async Task<IActionResult> GetPostComments(string postId)
        {
            var postComments = new List<UserPostComment>();
            var query = _dbContext.CommentsContainer.GetItemLinqQueryable<UserPostComment>()
                        .Where(p => p.PostId == postId)
                        .ToFeedIterator();
            while (query.HasMoreResults)
            {
                var response = await query.ReadNextAsync();
                postComments.AddRange(response.ToList());
            }

            return Ok(postComments);
        }

        [Route("report-post")]
        [HttpPost]
        public async Task<IActionResult> ReportPost([FromBody] ReportPost model)
        {

            if (!string.IsNullOrWhiteSpace(model.PostId) && !string.IsNullOrWhiteSpace(model.ReportedUserId) && !string.IsNullOrWhiteSpace(model.Reason))
            {
                ItemResponse<UserPost> response = await _dbContext.PostsContainer.ReadItemAsync<UserPost>(model.PostId, new PartitionKey(model.PostId));
                var post = response.Resource;

                if (post != null)
                {
                    post.ReportCount++;
                    if (post.ReportCount == 3)
                    {
                        await DeleteBlobFromAzureStorageAsync(post.Content);
                        await _dbContext.PostsContainer.DeleteItemAsync<UserPost>(post.Id, new PartitionKey(post.PostId));

                        // Remove entries from ReportedPosts Container as Post has been deleted.
                        var reportIds = new List<string>();
                        var query = _dbContext.ReportedPostsContainer.GetItemLinqQueryable<ReportedPost>()
                                    .Where(p => p.PostId == post.Id)
                                    .Select(p => p.Id)
                                    .ToFeedIterator();
                        while (query.HasMoreResults)
                        {
                            var res = await query.ReadNextAsync();
                            reportIds.AddRange(res.ToList());
                        }

                        foreach (var id in reportIds)
                        {
                            await _dbContext.ReportedPostsContainer.DeleteItemAsync<ReportedPost>(id, new PartitionKey(id));
                        }
                    }
                    else
                    {
                        await _dbContext.PostsContainer.UpsertItemAsync(post, new PartitionKey(post.Id));

                        var reportedPost = new ReportedPost
                        {
                            Id = ShortGuidGenerator.Generate(),
                            PostId = model.PostId,
                            ReportedUserId = model.ReportedUserId,
                            Reason = model.Reason,
                            ReportedOn = DateTime.UtcNow
                        };
                        await _dbContext.ReportedPostsContainer.UpsertItemAsync(reportedPost, new PartitionKey(reportedPost.Id));
                    }

                    return Ok(new { postReportCount = post.ReportCount });
                }

                return BadRequest("Post not found.");
            }

            return BadRequest("Invalid Data.");
        }

        private async Task DeleteBlobFromAzureStorageAsync(string blobUrl)
        {
            try
            {
                Uri blobUri = new Uri(blobUrl);
                string blobName = blobUri.Segments[2];

                var containerClient = _blobServiceClient.GetBlobContainerClient(_feedContainer);
                Console.WriteLine($"Connecting to Blob Container: {_feedContainer}");
                var blobClient = containerClient.GetBlobClient(blobName);
                await blobClient.DeleteIfExistsAsync();

                Console.WriteLine($"Blob '{blobName}' has been deleted successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting blob: {ex.Message}");
            }

        }
    }
}