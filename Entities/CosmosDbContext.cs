using Microsoft.Azure.Cosmos;

namespace BackEnd.Entities
{
    public class CosmosDbContext
    {
        public Container UsersContainer { get; }
        public Container PostsContainer { get; }
        public Container FeedsContainer { get; }
        public Container LikesContainer { get; }
        public Container CommentsContainer { get; }
        public Container ChatsContainer { get; }
        public Container MessagesContainer { get; }
        public Container ReportedPostsContainer { get; }

        public CosmosDbContext(CosmosClient cosmosClient, IConfiguration configuration)
        {
            var databaseName = configuration["CosmosDbSettings:DatabaseName"];
            var usersContainerName = configuration["CosmosDbSettings:UsersContainerName"];
            var postsContainerName = configuration["CosmosDbSettings:PostsContainerName"];
            var feedsContainerName = configuration["CosmosDbSettings:FeedsContainerName"];
            var likesContainerName = configuration["CosmosDbSettings:LikesContainerName"];
            var commentsContainerName = configuration["CosmosDbSettings:CommentsContainerName"];
            var chatsContainerName = configuration["CosmosDbSettings:ChatsContainerName"];
            var messagesContainerName = configuration["CosmosDbSettings:MessagesContainerName"];
            var reportedPostsContainerName = configuration["CosmosDbSettings:ReportedPostsContainerName"];

            UsersContainer = cosmosClient.GetContainer(databaseName, usersContainerName);
            PostsContainer = cosmosClient.GetContainer(databaseName, postsContainerName);
            FeedsContainer = cosmosClient.GetContainer(databaseName, feedsContainerName);
            LikesContainer = cosmosClient.GetContainer(databaseName, likesContainerName);
            CommentsContainer = cosmosClient.GetContainer(databaseName, commentsContainerName);
            ChatsContainer = cosmosClient.GetContainer(databaseName, chatsContainerName);
            MessagesContainer = cosmosClient.GetContainer(databaseName, messagesContainerName);
            ReportedPostsContainer = cosmosClient.GetContainer(databaseName, reportedPostsContainerName);
        }
    }
}
