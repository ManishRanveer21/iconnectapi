using Microsoft.AspNetCore.Mvc;
using BackEnd.Entities;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;
using Newtonsoft.Json;
using Azure.Messaging.ServiceBus;

namespace BackEnd.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MessagesController : ControllerBase
    {
        private readonly CosmosDbContext _dbContext;
        private readonly ServiceBusSender _serviceBusSender;
        private readonly ServiceBusClient _serviceBusClient;
        private readonly IConfiguration _configuration;

        public MessagesController(
            CosmosDbContext dbContext, 
            ServiceBusSender serviceBusSender, 
            ServiceBusClient serviceBusClient,
            IConfiguration configuration
            )
        {
            _dbContext = dbContext;
            _serviceBusSender = serviceBusSender;
            _serviceBusClient = serviceBusClient;
            _configuration = configuration;
        }


        [Route("chat-users/{userId}")]
        [HttpGet]
        public async Task<IActionResult> GetUsersChattedWith(string userId)
        {
            var chatQuery = _dbContext.ChatsContainer.GetItemLinqQueryable<Chat>()
                                                 .Where(m => m.SenderId == userId || m.RecipientId == userId)
                                                 .OrderByDescending(m => m.Timestamp)
                                                 .ToFeedIterator();

            var chats = new List<Chat>();
            while (chatQuery.HasMoreResults)
            {
                var response = await chatQuery.ReadNextAsync();
                chats.AddRange(response.ToList());
            }

            var userIds = chats
                .Select(m => m.SenderId == userId ? m.RecipientId : m.SenderId)
                .Distinct()
                .ToList();

            var userQuery = _dbContext.UsersContainer.GetItemLinqQueryable<BlogUser>()
                                          .Where(u => userIds.Contains(u.Id))
                                          .ToFeedIterator();

            var users = new List<BlogUser>();
            while (userQuery.HasMoreResults)
            {
                var response = await userQuery.ReadNextAsync();
                users.AddRange(response.ToList());
            }

            var chatUsers = new List<ChatUser>();
            foreach (var user in users) 
            {
                var chat = chats.First(x => x.SenderId == user.Id || x.RecipientId == user.Id);
                chatUsers.Add(new ChatUser()
                {
                    UserId = user.Id,
                    Email = user.Email,
                    ProfilePicUrl = user.ProfilePicUrl,
                    Username = user.Username,
                    ChatId = chat.Id,
                    TimeStamp = chat.Timestamp
                });
            }

            return Ok(chatUsers.OrderByDescending(x => x.TimeStamp));
        }

        [Route("chat-history/{chatId}")]
        [HttpGet]
        public async Task<IActionResult> GetChatHistory(string chatId)
        {
            var messageQuery = _dbContext.MessagesContainer.GetItemLinqQueryable<Message>()
                                                 .Where(m => m.ChatId == chatId)
                                                 .OrderBy(m => m.Timestamp)
                                                 .ToFeedIterator();

            var messages = new List<Message>();
            while (messageQuery.HasMoreResults)
            {
                var response = await messageQuery.ReadNextAsync();
                messages.AddRange(response.ToList());
            }

            return Ok(messages);
        }

        [Route("send-message")]
        [HttpPost]
        public async Task<IActionResult> SendMessage([FromBody] SendMessage request)
        {
            if (request != null && request.SenderId != null && request.RecipientId != null && request.Content != null)
            {
                var existingChat = new Chat();
                if(request.ChatId == null)
                {
                    existingChat = _dbContext.ChatsContainer.GetItemLinqQueryable<Chat>()
                        .Where(c => (c.SenderId == request.SenderId && c.RecipientId == request.RecipientId) || (c.RecipientId == request.SenderId && c.SenderId == request.RecipientId))
                        .FirstOrDefault();
                    if(existingChat == null)
                    {
                        request.ChatId = ShortGuidGenerator.Generate();
                        var chat = new Chat
                        {
                            Id = request.ChatId,
                            SenderId = request.SenderId,
                            RecipientId = request.RecipientId,
                            Timestamp = DateTime.UtcNow
                        };
                        await _dbContext.ChatsContainer.CreateItemAsync(chat, new PartitionKey(chat.Id));
                    }
                    else
                    {
                        request.ChatId = existingChat.Id;
                    }
                }
                else
                {
                    existingChat = _dbContext.ChatsContainer.GetItemLinqQueryable<Chat>()
                        .Where(c => (c.Id == request.ChatId))
                        .FirstOrDefault();
                    if(existingChat == null)
                    {
                        return BadRequest("Incorrect ChatId. Chat not found.");
                    }
                    existingChat.Timestamp = DateTime.UtcNow;
                    await _dbContext.ChatsContainer.UpsertItemAsync(existingChat, new PartitionKey(existingChat.Id));
                }

                var message = new Message
                {
                    Id = ShortGuidGenerator.Generate(),
                    ChatId = request.ChatId,
                    SenderId = request.SenderId,
                    RecipientId = request.RecipientId,
                    Content = request.Content,
                    Timestamp = DateTime.UtcNow
                };

                await _dbContext.MessagesContainer.CreateItemAsync(message, new PartitionKey(message.Id));

                // Publish message to Service Bus
                await PublishMessageToServiceBus(message);

                return Ok(new { request.ChatId });
            }
            return BadRequest("Invalid Request Data");
        }

        [HttpGet("get-new-messages")]
        public async Task<IActionResult> GetNewMessages()
        {
            var messages = new List<Message>();
            var queueName = _configuration["ServiceBus:QueueName"];
            var receiver = _serviceBusClient.CreateReceiver(queueName);

            try
            {
                // Receive up to 10 messages or wait for 5 seconds
                var receivedMessages = await receiver.ReceiveMessagesAsync(maxMessages: 1, maxWaitTime: TimeSpan.FromSeconds(5));

                foreach (var message in receivedMessages)
                {
                    messages.Add(JsonConvert.DeserializeObject<Message>(message.Body.ToString()));

                    // Complete the message to remove it from the queue
                    await receiver.CompleteMessageAsync(message);
                }

                return Ok(messages);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error receiving messages: {ex.Message}");
                return StatusCode(500, "Error receiving messages from the Service Bus queue.");
            }
        }

        private async Task PublishMessageToServiceBus(Message message)
        {
            var messageBody = JsonConvert.SerializeObject(message);
            var serviceBusMessage = new ServiceBusMessage(messageBody);

            await _serviceBusSender.SendMessageAsync(serviceBusMessage);

        }
    }
}