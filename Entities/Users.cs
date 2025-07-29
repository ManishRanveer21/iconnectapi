using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class User
    {
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; } = Guid.NewGuid().ToString(); // Required 'id' field for CosmosDB

        [JsonProperty(PropertyName = "username")]
        public string Username { get; set; } = "Anonymous"; // Default value
        public string ProfilePicUrl { get; internal set; }
    }
}
