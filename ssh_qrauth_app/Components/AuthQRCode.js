import React,{ Component } from "react";
import { Button, StyleSheet, Text } from "react-native";
import {RNCamera} from 'react-native-camera';
import QRCodeScanner from 'react-native-qrcode-scanner';


class AuthQRCode extends Component {

    state = {
        rescan : false
    };


    qrReadCallback = async (e) => {
        const rescan = await this.props.qrScanData(e);

        this.setState({
            rescan: rescan
        })

    };


    render(){

        return (
          <QRCodeScanner
            onRead = {this.props.qrScanData}
            reactivate = {this.state.rescan}
            reactivateTimeout ={2000}
            topContent = {
                <Text>
                    Scan SSH Auth QR Code on your computer to Authentication Login
                </Text>
            }

            bottomContent = {
                <Button onPress={this.props.hideAuthQRCode} title="Go Back" />
            }

            vibrate = {false}

          />  
        );
    }
}

const styles = StyleSheet.create({
    centerText: {
        flex: 1,
        fontSize: 18,
        padding: 32,
        color: '#777'
    },
    textBold: {
        fontWeight: '500',
        color: '#000'
    },
    buttonText: {
        fontSize: 21,
        color: 'rgb(0,122,255)'
    },
    buttonTouchable: {
        padding: 16
    }
});

export default AuthQRCode;