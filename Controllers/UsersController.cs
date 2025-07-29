using Microsoft.AspNetCore.Mvc;
using BackEnd.Entities;
using Microsoft.Azure.Cosmos;
using Azure.Storage.Blobs;
using BackEnd.Models;
using System.Collections;
using System.Net;
using System.Resources;
using System.Reflection;
using BackEnd.Shared;
using System.ComponentModel.Design;
using System.Collections.Generic;
using Microsoft.Azure.Cosmos.Linq;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly CosmosDbContext _dbContext;
        private readonly BlobServiceClient _blobServiceClient;
        private static readonly Random _random = new Random();
        private readonly string _profileContainer = "profilepics";  // Blob container for storing profile pictures

        public UsersController(CosmosDbContext dbContext, BlobServiceClient blobServiceClient)
        {
            _dbContext = dbContext;
            _blobServiceClient = blobServiceClient;
        }

        [HttpPost("updateUser")]
        public async Task<IActionResult> UpdateUser([FromForm] FeedUploadModel model)
        {
            try
            {
                string updatedPicURL = string.Empty;

                if (model.File != null && !string.IsNullOrEmpty(model.UserId) && !string.IsNullOrEmpty(model.FileName) && !string.IsNullOrEmpty(model.ProfilePic))
                {
                    var containerClient = _blobServiceClient.GetBlobContainerClient(_profileContainer);
                    var blobName = Utility.GetFileNameFromUrl(model.ProfilePic);
                    var blobClient = containerClient.GetBlobClient(blobName);

                    using (var stream = model.File.OpenReadStream())
                    {
                        await blobClient.UploadAsync(stream, overwrite: true);
                    }

                    updatedPicURL = blobClient.Uri.ToString(); // Direct Blob Storage URL
                }

                var itemToUpdate = new BlogUser
                {
                    UserId = model.UserId,
                    Username = model.UserName,
                    ProfilePicUrl = updatedPicURL
                };

                var updatedItem = await _dbContext.UsersContainer.UpsertItemAsync(itemToUpdate);
                Console.WriteLine("Item updated successfully: " + updatedItem);

                return Ok(new { Message = "Profile updated successfully.", UserId = model.UserId });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error updating profile picture: {ex.Message}");
            }
        }

        [HttpGet("getUser")]
        public async Task<IActionResult> GetUser(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid User Id.");
            }
            try
            {
                var query = _dbContext.UsersContainer.GetItemLinqQueryable<BlogUser>()
                        .Where(x => x.UserId == userId)
                        .ToFeedIterator();
                var user = (await query.ReadNextAsync()).FirstOrDefault();

                if (user != null) 
                {
                    return Ok(new
                    {
                        userId = user.Id,
                        email = user.Email,
                        username = user.Username,
                        firstname = user.FirstName,
                        lastname = user.LastName,
                        profilePic = user.ProfilePicUrl,
                        isVerified = user.IsVerified
                    });
                }

                return BadRequest("User not found.");
            }
            catch (CosmosException ex)
            {
                return StatusCode(500, $"Cosmos DB Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        [HttpGet("create")]
        public async Task<IActionResult> CreateUser()
        {
            try
            {
                var user = new BlogUser
                {
                    UserId = ShortGuidGenerator.Generate(),
                    Username = GenerateRandomName(),
                    ProfilePicUrl = GetRandomProfilePic() // Updated for Blob Storage URLs
                };

                try
                {
                    user.Action = "Create";
                    await _dbContext.UsersContainer.CreateItemAsync(user, new PartitionKey(user.UserId));

                    return Ok(new
                    {
                        userId = user.UserId,
                        username = user.Username,
                        profilePic = user.ProfilePicUrl
                    });
                }
                catch (CosmosException ex) when (ex.StatusCode == HttpStatusCode.Conflict)
                {
                    throw ex;
                }
            }
            catch (CosmosException ex)
            {
                return StatusCode(500, $"Cosmos DB Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        private string GenerateRandomName()
        {
            string adjective = GetRandomResource("Adj_");
            string noun = GetRandomResource("Noun_");

            bool isAdjectiveFrench = _random.Next(2) == 0;

            string finalAdjective = isAdjectiveFrench ? GetFrenchPart(adjective) : GetEnglishPart(adjective);
            string finalNoun = isAdjectiveFrench ? GetEnglishPart(noun) : GetFrenchPart(noun);

            return $"{finalAdjective}_{finalNoun}";
        }

        private string GetRandomProfilePic()
        {
            int randomNumber = _random.Next(1, 5); // Generate a random number between 1 and 25
            var containerClient = _blobServiceClient.GetBlobContainerClient(_profileContainer);
            return $"{containerClient.Uri}/pp{randomNumber}.jpg"; // Blob Storage URL
        }

        private string GetRandomResource(string resourceType)
        {
            ResourceManager resourceManager = new ResourceManager("BackEnd.Resources.AdjectivesNouns", Assembly.GetExecutingAssembly());
            var resourceSet = resourceManager.GetResourceSet(System.Globalization.CultureInfo.CurrentUICulture, true, true);

            if (resourceSet == null)
            {
                throw new Exception("ResourceSet is null. Resource file might not be found.");
            }

            var matchingEntries = new List<DictionaryEntry>();
            foreach (DictionaryEntry entry in resourceSet)
            {
                if (entry.Key.ToString().StartsWith(resourceType))
                {
                    matchingEntries.Add(entry);
                }
            }

            if (matchingEntries.Count == 0)
            {
                throw new Exception($"No matching {resourceType} resources found.");
            }

            DictionaryEntry selectedEntry = matchingEntries[_random.Next(matchingEntries.Count)];
            return $"{selectedEntry.Key}-{selectedEntry.Value}";
        }

        private string GetFrenchPart(string entry)
        {
            var parts = entry?.Split('-');
            return parts?[0].Split('_')[1];
        }

        private string GetEnglishPart(string entry)
        {
            var parts = entry?.Split('-');
            return parts?[1];
        }
    }
}
