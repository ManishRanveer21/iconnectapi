using Azure.Storage.Blobs;
using BackEnd.Entities;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Serialization.HybridRow.Schemas;
using System.Reflection;
using static System.Net.Mime.MediaTypeNames;

namespace BackEnd
{
    public class ChatHub : Hub
    {
        private readonly CosmosDbContext _dbContext;
        public ChatHub(CosmosDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        //public async Task SendMessage(string user,string message)
        //{
        //    string cid = Context.ConnectionId;
        //    await Clients.All.SendAsync("ReceiveMessage",user, message);
        //}

        public async Task SendMessage(string fromUser, string toUser,string message, string connectionId) {

            //await AddToGroup(user, connectionId);
            //var savedGroups = Groups;

            IQueryable<BlogUser> query = _dbContext.UsersContainer.GetItemLinqQueryable<BlogUser>();

            // Apply the userId filter if provided
            if (!string.IsNullOrEmpty(toUser))
            {
                query = query.Where(x => x.UserId == toUser);
            }

            // Apply ordering after filtering
            var result = query.Select(item => new
            {
                item.Id,
                item.ConnectionId,
            }).FirstOrDefault();

            if (result != null)
            {
                connectionId = result.ConnectionId;
            }


            IQueryable<Chats> queryChats = _dbContext.ChatsContainer.GetItemLinqQueryable<Chats>();

            if (!string.IsNullOrEmpty(fromUser) && !string.IsNullOrEmpty(toUser))
            {
                queryChats = queryChats.Where(x => x.chatId == fromUser+"|"+toUser || x.chatId == toUser + "|" + fromUser);
            }

            var resultChats = queryChats.Select(item => new
            {
                item.Id,
                item.chatMessage
            }).FirstOrDefault();

            if (resultChats!=null)
            {
                ChatMessage chatMessage = new ChatMessage
                {
                    messageId = Guid.NewGuid().ToString(),
                    fromuserId = fromUser,
                    touserId = toUser,
                    message = message
                };

                string partitionKey = resultChats.Id;
                var response1 = _dbContext.ChatsContainer.PatchItemAsync<Chats>(
                                      id: partitionKey,
                                      partitionKey: new Microsoft.Azure.Cosmos.PartitionKey(partitionKey),
                                      patchOperations: new[] {
                                            PatchOperation.Add($"/chatMessage/0", chatMessage)
                                      });
            }
            else
            {
                Chats chats = new Chats
                {
                    chatId = fromUser + "|" + toUser,
                    chatMessage = new ChatMessage[] { new ChatMessage {
                        messageId = Guid.NewGuid().ToString(),
                        fromuserId = fromUser,
                        touserId = toUser,
                        message = message
                        }
                    },
                };

                _dbContext.ChatsContainer.CreateItemAsync<Chats>(chats, new Microsoft.Azure.Cosmos.PartitionKey(chats.chatId));
            }

            await Clients.Client(connectionId).SendAsync("ReceiveMessage", message);
        }

        public async Task SendBellCount(string toUser,string count)
        {
            string connectionId = null;

            IQueryable<BlogUser> query = _dbContext.UsersContainer.GetItemLinqQueryable<BlogUser>();

            // Apply the userId filter if provided
            if (!string.IsNullOrEmpty(toUser))
            {
                query = query.Where(x => x.UserId == toUser);
            }

            // Apply ordering after filtering
            var result = query.Select(item => new
            {
                item.Id,
                item.ConnectionId,
            }).FirstOrDefault();

            if (result != null)
            {
                connectionId = result.ConnectionId;
            }

            await Clients.Client(connectionId).SendAsync("ReceiveBellCount", count);
        }

        public async Task AddToGroup(string groupName,string connectionId)
        {
             await Groups.AddToGroupAsync(connectionId, groupName);
        }
   

        public string GetConnectionId(string userId)
        {
            string connectionId= Context.ConnectionId;

            //set the connectionId for each user when they open site
            if (!string.IsNullOrEmpty(userId))
            {
                var pKey = userId;
                var resp = _dbContext.UsersContainer.PatchItemAsync<SignalUser>(
                                       id: pKey,
                                       partitionKey: new Microsoft.Azure.Cosmos.PartitionKey(pKey),
                                       patchOperations: new[] {
                                        PatchOperation.Add($"/connectionId", connectionId)
                                       });
            }



            //var itemToUpdate = new SignalUser
            //{
            //    UserId = userId,
            //    Action = connectionId
            //};
            //userId = "39b4f090-6e61-4464-852a-359b71db3bbf";

            //IQueryable<Chats> query = _dbContext.ChatsContainer.GetItemLinqQueryable<Chats>();

            //// Apply the userId filter if provided
            //if (!string.IsNullOrEmpty(userId))
            //{
            //    query = query.Where(x => x.userId1 == userId || x.userId2==userId);
            //}

            //var result = query.Select(item => new
            //{
            //    item.Id,
            //    item.chatMessages
            //}).FirstOrDefault();

            //var updatedItem =  _dbContext.UsersContainer.UpsertItemAsync(itemToUpdate, new Microsoft.Azure.Cosmos.PartitionKey(userId));

            //var partitionKey = "d570a5ba-de59-43e6-9655-67cbb8b8dd03";
            //var response =   _dbContext.PostsContainer.PatchItemAsync<SignalUser>(
            //                       id: partitionKey,
            //                       partitionKey: new Microsoft.Azure.Cosmos.PartitionKey(partitionKey),
            //                       patchOperations: new[] {
            //                            PatchOperation.Add($"/ConnectionId", "London")
            //                       });

            //Chats chats = new Chats
            //{
            //     chatId = Guid.NewGuid().ToString(),
            //    //chatMessage = new ChatMessage
            //    //{
            //    //    messageId = Guid.NewGuid().ToString(),
            //    //    userId = "don",
            //    //    message = "Hello Sir"
            //    //},
            //    chatMessages = new ChatMessage[] { new ChatMessage {  

            //        messageId = Guid.NewGuid().ToString(),
            //        userId = "don",
            //        message = "Hello Sir"} },
            //    userId1 = userId,
            //     userId2 = userId,
            //};

            //_dbContext.ChatsContainer.CreateItemAsync<Chats>(chats, new Microsoft.Azure.Cosmos.PartitionKey(chats.chatId));


            //ChatMessage chatMessage = new ChatMessage
            //{
            //    messageId = Guid.NewGuid().ToString(),
            //    userId = userId,
            //    message = "Hello Maam"
            //};

            //partitionKey = "3be962f9-1455-4130-a99f-94675d2efb50";
            //var response1 = _dbContext.ChatsContainer.PatchItemAsync<Chats>(
            //                      id: partitionKey,
            //                      partitionKey: new Microsoft.Azure.Cosmos.PartitionKey(partitionKey),
            //                      patchOperations: new[] {
            //                            PatchOperation.Add($"/chatMessage/0", chatMessage)
            //                      });
           
            return connectionId;
        }
    }
}
