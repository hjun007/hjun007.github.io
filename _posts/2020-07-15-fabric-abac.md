---
layout: post
title: "Fabric链码中基于属性的访问控制"
date: 2020-07-15
description: "2020-07-15-Fabric链码中基于属性的访问控制"
categories: 区块链

tag: [区块链,Fabric,链码,访问控制]

---

# 在用户证书中加入自定义属性

可以使用fabric-ca-client在证书中加入自定义属性
```
# 管理员register用户id的时候，加上自定义属性
$ fabric-ca-client register --id.name user1 --id.secret user1pw --id.type user --id.affiliation org1 --id.attrs 'attr1=value1'
# 管理员enroll用户的时候，指定之前注册的id中的哪些属性要加入到证书中
fabric-ca-client enroll -u http://user1:user1pw@localhost:7054 --enrollment.attrs "attr1,attr2:opt"
# enroll的时候，属性后面加opt，说明该属性是可选的，不带opt的属性，是在register用户id的时候必须指定该属性，否则enroll失败
```

也可以使用fabric-ca-sdk在证书中加入自定义属性
以fabric-samples/fabcar/java/src/main/java/org/example/RegisterUser.java为例

```
/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Properties;
import java.util.Set;

import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallet.Identity;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.Attribute;

public class RegisterUser {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}

	public static void main(String[] args) throws Exception {

		// Create a CA client for interacting with the CA.
		Properties props = new Properties();
		props.put("pemFile",
			"../../first-network/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem");
		props.put("allowAllHostNames", "true");
		HFCAClient caClient = HFCAClient.createNewInstance("https://localhost:7054", props);
		CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
		caClient.setCryptoSuite(cryptoSuite);

		// Create a wallet for managing identities
		Wallet wallet = Wallet.createFileSystemWallet(Paths.get("wallet"));

		// Check to see if we've already enrolled the user.
		boolean userExists = wallet.exists(newUser);
		if (userExists) {
			System.out.println("An identity for the user \"user1\" already exists in the wallet");
			return;
		}

		userExists = wallet.exists("admin");
		if (!userExists) {
			System.out.println("\"admin\" needs to be enrolled and added to the wallet first");
			return;
		}

		Identity adminIdentity = wallet.get("admin");
		User admin = new User() {

			@Override
			public String getName() {
				return "admin";
			}

			@Override
			public Set<String> getRoles() {
				return null;
			}

			@Override
			public String getAccount() {
				return null;
			}

			@Override
			public String getAffiliation() {
				return "org1.department1";
			}

			@Override
			public Enrollment getEnrollment() {
				return new Enrollment() {

					@Override
					public PrivateKey getKey() {
						return adminIdentity.getPrivateKey();
					}

					@Override
					public String getCert() {
						return adminIdentity.getCertificate();
					}
				};
			}

			@Override
			public String getMspId() {
				return "Org1MSP";
			}

		};

		// Register the user, enroll the user, and import the new identity into the wallet.
		RegistrationRequest registrationRequest = new RegistrationRequest(newUser);
		registrationRequest.setAffiliation("org1.department1");
		registrationRequest.setEnrollmentID("user1");
		// register的时候在registrationRequest中增加自定义属性
		registrationRequest.addAttribute(new Attribute("attr1", "value1"));	//user-defined attributes
		String enrollmentSecret = caClient.register(registrationRequest, admin);
		//定义一个enrollmentRequest，在里面设置需要加入到证书中的属性
		//不设置的话，只把默认的hf.Affiliation, hf.EnrollmentID, hf.Type加入到证书中
		EnrollmentRequest enrollmentRequest = new EnrollmentRequest();
		enrollmentRequest.addAttrReq("hf.Affiliation");		//default attribute
		enrollmentRequest.addAttrReq("hf.EnrollmentID");	//default attribute
		enrollmentRequest.addAttrReq("hf.Type");			//default attribute
		enrollmentRequest.addAttrReq("attr1");				//user-defined attribute
		//把enrollmentRequest放在在caClient.enroll()的第三个参数
		Enrollment enrollment = caClient.enroll("user1", enrollmentSecret, enrollmentRequest);
		Identity user = Identity.createIdentity("Org1MSP", enrollment.getCert(), enrollment.getKey());
		wallet.put("user1", user);
		System.out.println("Successfully enrolled user \"user1\" and imported it into the wallet");
	}

}
```
用openssl查看enroll获得的证书
```
openssl x509 -in user1.crt.pem -text -noout
```
可以看到证书里面已经包含了指定的属性了
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            56:01:fb:3e:31:4b:79:0d:32:af:be:62:44:69:25:ba:47:5b:c2:b9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, ST = California, L = San Francisco, O = org1.example.com, CN = ca.org1.example.com
        Validity
            Not Before: Jul 14 16:42:00 2020 GMT
            Not After : Jul 14 16:47:00 2021 GMT
        Subject: OU = client + OU = org1 + OU = department1, CN = user1
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:6b:b1:f1:b2:35:fd:ed:9f:5f:64:0e:a1:e3:a5:
                    ca:ad:c0:51:3a:12:b8:75:b6:e8:2a:9f:8c:3b:c4:
                    ad:7c:c3:dd:7a:5a:03:ab:f8:e4:dd:5a:61:71:12:
                    ee:34:6f:7d:ae:78:2d:c1:df:a9:cd:23:6e:e8:ce:
                    6a:20:0a:39:dd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                AC:72:C3:6A:96:60:E5:FB:76:2C:36:A7:8A:82:BA:D9:A5:DE:74:5F
            X509v3 Authority Key Identifier: 
                keyid:04:A3:8D:BE:E5:50:3E:7A:3D:29:FC:49:A4:8D:2B:25:F5:7D:81:1E:4D:C8:08:C6:BE:96:85:48:CA:10:CE:AA

            1.2.3.4.5.6.7.8.1: 
                {"attrs":{"attr1":"value1","hf.Affiliation":"org1.department1","hf.EnrollmentID":"user1","hf.Type":"client"}}
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:0c:ab:c1:ee:20:f8:a0:52:0e:6f:d1:16:38:81:
         2f:b4:0e:6a:cc:6a:d4:45:2f:0b:f8:b3:d2:78:14:8e:7a:92:
         02:20:54:4e:a7:47:02:2b:ef:d8:9e:25:bf:4b:d3:60:db:51:
         b2:ee:bc:40:a9:00:4b:af:05:70:13:a1:43:c2:ef:8b
```
# 在链码中使用自定义属性
在链码中引入cid包
```
"github.com/hyperledger/fabric/core/chaincode/shim/ext/cid"
```
在链码中使用cid包，以fabcar中的createCar为例
```
func (s *SmartContract) createCar(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {

	if len(args) != 5 {
		return shim.Error("Incorrect number of arguments. Expecting 5")
	}

	//读取自定义的属性
	retVal := "default retVal"
	attr1, isFound, err := cid.GetAttributeValue(APIstub, "attr1")
	if err != nil {
		retVal = "get attribute value err"
	}
	if !isFound {
		retVal = "attr1 not found"
	}
	retVal = attr1

	var car = Car{Make: args[1], Model: args[2], Colour: args[3], Owner: args[4]}

	carAsBytes, _ := json.Marshal(car)
	APIstub.PutState(args[0], carAsBytes)
	
	//返回获取到的值
	return shim.Success([]byte(retVal))
}
```
# 用前面注册得到的用户去调用链码
修改一下fabcar的ClientApp.java
```
/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;

public class ClientApp {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
	}

	public static void main(String[] args) throws Exception {
		// Load a file system based wallet for managing identities.
		Path walletPath = Paths.get("wallet");
		Wallet wallet = Wallet.createFileSystemWallet(walletPath);

		// load a CCP
		Path networkConfigPath = Paths.get("..", "..", "first-network", "connection-org1.yaml");

		Gateway.Builder builder = Gateway.createBuilder();
		//这里指定使用前面注册好的user1
		builder.identity(wallet, "user1").networkConfig(networkConfigPath).discovery(true);

		// create a gateway connection
		try (Gateway gateway = builder.connect()) {

			// get the network and contract
			Network network = gateway.getNetwork("mychannel");
			Contract contract = network.getContract("fabcar");

			byte[] result;

			result = contract.evaluateTransaction("queryAllCars");
			System.out.println(new String(result));

			// 把createCar的执行结果输出
			result = contract.submitTransaction("createCar", "CAR10", "VW", "Polo", "Grey", "Mary");
			System.out.println(new String(result));

			result = contract.evaluateTransaction("queryCar", "CAR10");
			System.out.println(new String(result));

			contract.submitTransaction("changeCarOwner", "CAR10", "Archie");

			result = contract.evaluateTransaction("queryCar", "CAR10");
			System.out.println(new String(result));
		}
	}
}
```
执行SDK
```
fabcar/java$ mvn test
```
输出结果如下：
```
-------------------------------------------------------
 T E S T S
-------------------------------------------------------
Running org.example.ClientTest
Successfully enrolled user "admin" and imported it into the wallet
Successfully enrolled user "user1" and imported it into the wallet
[{"Key":"CAR0", "Record":{"colour":"blue","make":"Toyota","model":"Prius","owner":"Tomoko"}},{"Key":"CAR1", "Record":{"colour":"red","make":"Ford","model":"Mustang","owner":"Brad"}},{"Key":"CAR2", "Record":{"colour":"green","make":"Hyundai","model":"Tucson","owner":"Jin Soo"}},{"Key":"CAR3", "Record":{"colour":"yellow","make":"Volkswagen","model":"Passat","owner":"Max"}},{"Key":"CAR4", "Record":{"colour":"black","make":"Tesla","model":"S","owner":"Adriana"}},{"Key":"CAR5", "Record":{"colour":"purple","make":"Peugeot","model":"205","owner":"Michel"}},{"Key":"CAR6", "Record":{"colour":"white","make":"Chery","model":"S22L","owner":"Aarav"}},{"Key":"CAR7", "Record":{"colour":"violet","make":"Fiat","model":"Punto","owner":"Pari"}},{"Key":"CAR8", "Record":{"colour":"indigo","make":"Tata","model":"Nano","owner":"Valeria"}},{"Key":"CAR9", "Record":{"colour":"brown","make":"Holden","model":"Barina","owner":"Shotaro"}}]
value1
{"colour":"Grey","make":"VW","model":"Polo","owner":"Mary"}
{"colour":"Grey","make":"VW","model":"Polo","owner":"Archie"}
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 25.977 sec

Results :

Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
```
可以看到，能够正常读取到自定义的attr1的值
