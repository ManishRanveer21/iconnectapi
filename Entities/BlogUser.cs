using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class BlogUser
    {

        [JsonProperty(PropertyName = "id")]
        public string Id
        {
            get
            {
                return UserId;
            }
        }

        [JsonProperty(PropertyName = "userId")]
        public string UserId { get; set; }

        [JsonProperty(PropertyName = "email")]
        public string Email { get; set; }

        [JsonProperty(PropertyName = "profilePicUrl")]
        public string ProfilePicUrl { get; set; }


        [JsonProperty(PropertyName = "type")]
        public string Type
        {
            get
            {
                return "user";
            }
        }


        [JsonProperty(PropertyName = "username")]
        public string Username { get; set; }

        [JsonProperty(PropertyName = "firstname")]
        public string? FirstName { get; set; }

        [JsonProperty(PropertyName = "lastname")]
        public string? LastName { get; set; }


        [JsonProperty(PropertyName = "action")]
        public string Action { get; set; }


        [JsonProperty(PropertyName = "connectionId")]
        public string ConnectionId { get; set; }

        [JsonProperty(PropertyName = "isVerified")]
        public bool IsVerified { get; set; } = false;


        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }


    }
}
