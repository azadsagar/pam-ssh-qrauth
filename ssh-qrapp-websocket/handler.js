const {ApiGatewayManagementApi,DynamoDB} = require("aws-sdk");

const wsNotify = async (connectionId, data) => {
  
  const apigw = new ApiGatewayManagementApi({
    region : process.env.REGION,
    endpoint: process.env.WEBSOCKET_ENDPOINT
  });

  return new Promise((resolve,reject)=> {
    try {

      apigw.postToConnection({
        ConnectionId: connectionId,
        Data: typeof(data) === 'object' ? JSON.stringify(data) : data
      },(error,data)=> {
        if(error){
          console.log(error);
        }

        resolve(true);
      });

      
    } catch (error) {
      console.log(error);
      resolve(true);
    }
  });

};


module.exports = {
  connectHandler : async (event,context) => {

    console.log(`New connection from ${event.requestContext.connectionId}`)
    
    return {
      statusCode: 200,
      body: `connectionid:${event.requestContext.connectionId}`
    };
  },

  disconnectHandler : async (event,context) => {
    console.log(`Disconnect event received from ${event.requestContext.connectionId}`);
    return Promise.resolve({
      statusCode: 200,
      body: "OK"
    });
  },

  defaultHandler : async (event,context) => {
    console.log(`Unhandled event received from ${event.requestContext.connectionId}`);
    return Promise.resolve({
      statusCode: 200,
      body: "OK"
    });
  },

  queryHandler: async (event,context) => {

    const payload = JSON.parse(event.body);
    const documentClient = new DynamoDB.DocumentClient({
      region : process.env.REGION
    });

    try {

      switch(payload.action){
        case 'expectauth':
          
          const expires_at = parseInt(new Date().getTime() / 1000) + 300;
    
          await documentClient.put({
            TableName : process.env.DYNAMODB_TABLE,
            Item: {
              authkey : payload.authkey,
              connectionId : event.requestContext.connectionId,
              username : payload.username,
              expires_at : expires_at,
              authVerified: false
            }
          }).promise();

          return {
            statusCode: 200,
            body : "OK"
          };

        case 'getconid':
          return {
            statusCode: 200,
            body: `connectionid:${event.requestContext.connectionId}`
          };

        case 'verifyauth':

          const data = await documentClient.get({
            TableName : process.env.DYNAMODB_TABLE,
            Key : {
              authkey : payload.authkey
            }
          }).promise();

          if(!("Item" in data)){
            throw "Failed to query data";
          }

          if(data.Item.authVerified === true){
            return {
              statusCode: 200,
              body: `authverified:${payload.challengeText}`
            }
          }

          throw "auth verification failed";

      }

    } catch (error) {
      console.log(error);
    }

    return {
      statusCode:  200,
      body : "ok"
     };
    
  }

};