import React, { Component } from "react";
import {View,Text,StyleSheet,Button, ToastAndroid} from 'react-native';
import Amplify,{Auth} from 'aws-amplify';
import {withAuthenticator} from 'aws-amplify-react-native';
import AuthQRCode from "./Components/AuthQRCode";
import axios from "axios";

import awsconfig from "./aws-exports";

const API_URL="";

Amplify.configure({
  ...awsconfig, Analytics: {
    disabled: true,
  }
});

const styles= StyleSheet.create({
  container: {
    flex : 1,
    backgroundColor : "aliceblue",
    flexDirection : 'row',
    alignItems: 'center',
    justifyContent: 'center',
    
  }
});

class App extends Component {

  state = {
    authQRCode : false
  };

  showAuthQRCode = () => {
    this.setState({
      authQRCode : true
    });
  };

  hideAuthQRCode = () => {
    this.setState({
      authQRCode : false
    });
  };

  signout = async () => {
    Auth.signOut();
  }

  qrScanData = async (e) => {

    let rescanQRCode = true;
    
    try {
      console.log(e.data);
      ToastAndroid.showWithGravity(e.data,ToastAndroid.LONG,ToastAndroid.CENTER);

      const scanCode = e.data.split(':');

      if(scanCode.length <3){
        throw "invalid qr code";
      }

      const [appstring,authcode,shacode] = scanCode;

      if(appstring !== "qrauth"){
        throw "Not a valid app qr code";
      }

      const authsession = await Auth.currentSession();
      const jwtToken = authsession.getIdToken().jwtToken;

      const response = await axios({
        url : `${API_URL}/v1/app/sshqrauth/qrauth`,
        method : "post",
        headers : {
          Authorization : jwtToken,
          'Content-Type' : 'application/json'
        },
        responseType: "json",
        data : {
          authcode,
          shacode
        }
      });

      if(response.data.status === 200){
        rescanQRCode=false;
        setTimeout(this.hideAuthQRCode, 1000);
      }
      
    } catch (error) {

      console.log(error);
      //ToastAndroid.showWithGravity(error,ToastAndroid.LONG,ToastAndroid.CENTER);
      
    }

    Promise.resolve(rescanQRCode);
  }

  render(){
    return (
      <View style={styles.container}>
        {this.state.authQRCode ? 
        <AuthQRCode 
         hideAuthQRCode = {this.hideAuthQRCode}
         qrScanData = {this.qrScanData}
        /> 
        :
        <View style={{marginVertical: 10}}> 
        <Button title="Auth SSH Login" onPress={this.showAuthQRCode} />
        <View style={{margin:10}} />
        <Button title="Sign Out" onPress={this.signout} />
        </View>
        
        }
      </View>
    );
  }
}

export default withAuthenticator(App);