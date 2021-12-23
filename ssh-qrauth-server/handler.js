const serverless = require("serverless-http");
const express = require("express");
const bodyParser = require('body-parser');
const { DynamoDB, ApiGatewayManagementApi } = require("aws-sdk");
const crypto = require("crypto");

const app = express();

app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(bodyParser.json({ limit: '50mb', extended: true }));
app.set('trust proxy', true);
app.disable('etag');


const badQuery = {
    status: 401,
    success: false,
    msg : "Invalid Auth Query"
};

const logger = async (data) => {
    if(typeof(data) === 'object'){
        console.log(new Date(),JSON.stringify(data,null,2));
    }
    else{
        console.log(new Date(),data);
    }
};

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

app.post("/v1/app/sshqrauth/qrauth",async (req,res)=>{

    try {
        const {authcode,shacode} = req.body;

        if(typeof(authcode) === 'undefined' || typeof(shacode) === 'undefined') {
            throw {
                status: 400,
                success: false,
                msg : "Bad request !"
            };
        }

        console.log(`auth code is ${authcode} and shacode is ${shacode}`);

        const documentClient = new DynamoDB.DocumentClient({
            region : process.env.REGION
        });

        const data = await documentClient.get({
            TableName : process.env.DYNAMODB_TABLE,
            Key : {
                authkey : authcode
            }
        }).promise();

        //To Do : send response to websocket
        logger(data);

        if(!("Item" in data)){
            console.log("auth code not found !");
            throw badQuery;
        }

        const sha1 = crypto.createHash('sha1');
        
        sha1.update(data.Item.connectionId);
        const shasum = sha1.digest('hex').toString();
        
        if(shasum !== shacode){
            console.log("sha code didn't match");
            throw badQuery;
        }

        let Item = {...data.Item};
        Item.authVerified = true;

        await documentClient.put({
            TableName: process.env.DYNAMODB_TABLE,
            Item : Item
        }).promise();

        await wsNotify(data.Item.connectionId,"authVerified:true");

        return res.status(200).json({
            status: 200,
            success: true,
            msg : "Done"
        });


    } catch (error) {
        logger(error);
        if(typeof(error) === 'object' && "status" in error) {
            return res.status(error.status).json(error);
        }
        else {
            return res.status(500).json({
                status: 500,
                success: false,
                msg: "Something went wrong while processing this request !"
            });
        }
    }
    
});

module.exports.authqrcode = serverless(app);