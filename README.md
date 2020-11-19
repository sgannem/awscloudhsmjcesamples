# awscloudhsmjcesamples

These sample applications demonstrate how to use the JCE with CloudHSM.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Building the examples

### Dependencies

The CloudHSM Client and JCE dependencies are required. They should be installed using the official
procedures documented here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library-install.html

The examples are tested on a fresh Amazon Linux 2 AMI. You will need to have the following packages 
installed:

* OpenJDK 8
* Apache Maven 3.0.5

You can install these packages on Amazon Linux 2 by running

```
sudo yum install -y java maven
```

If you are running on Amazon Linux 1, you will need to install extra packages to get Maven.
You can follow these instructions to build the samples on Amazon Linux 1:

```
# Maven is only available through extra packages
sudo wget http://repos.fedorapeople.org/repos/dchen/apache-maven/epel-apache-maven.repo -O /etc/yum.repos.d/epel-apache-maven.repo
sudo sed -i s/\$releasever/6/g /etc/yum.repos.d/epel-apache-maven.repo

# You will need Java 1.8 to build the samples
sudo yum install -y java-1.8.0-openjdk-devel
sudo yum install -y apache-maven

# When updating alternatives, choose the 1.8 path: /usr/lib/jvm/jre-1.8.0-openjdk.x86_64/bin/java
sudo update-alternatives --config java
```


### Building

You can build the project using Maven. Maven will copy the required CloudHSM jars into a local repository
and build fat jars which can be executed from the command line. These fat jars will be placed in the
`target/assembly/` directory. To build the project, use the following command:

```
mvn validate
mvn clean package
```

## Running the samples

You will need to have a CloudHSM Client connected to an ACTIVE cluster. For more details, please follow
the official instructions here:

* https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html

All Java dependencies should be bundled in the fat jars. You will only need to specify the location of the
native library in `/opt/cloudhsm/lib`. Jars can be run using the following command line (as an example): 

```
java -ea -Djava.library.path=/opt/cloudhsm/lib/ -jar nxpkeydiversification.jar --nxp-div --masterKeyHandle 3932766 --divInput 010490000000013500010000005E88715B --kekHandle 3932766 --threadPoolSize 10 --totalRequestSize 10 --user username --password password --partition hsm-xiasgciswmb
```
## Output would look like as below.
```
#Logging into HSM with user:xxxxxx

Login successful!

#Logged into HSM with user:xxxxx successful...
# Operating key import operations ...
#calling getKey({})3932766
Key handle 3932766 with label nxpsp-test-ck
Is Key Extractable? : false
Is Key Persistent? : true
Key Algo : AES
Key Size : 128
#calling getKey({})3932766
Key handle 3932766 with label nxpsp-test-ck
Is Key Extractable? : false
Is Key Persistent? : true
Key Algo : AES
Key Size : 128
TRACE [main] | 2020-11-12 17:44:00.107 | CaviumCipher.java | 536 |   | Enter algorithm AES mode ECB blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.108 | CaviumCipher.java | 250 |   | Enter LogId 1 opmode 1
TRACE [main] | 2020-11-12 17:44:00.108 | CaviumCipher.java | 386 |   | Enter LogId 1
TRACE [main] | 2020-11-12 17:44:00.108 | CaviumCipher.java | 613 |   | Enter LogId 1 blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.109 | CaviumCipher.java | 105 |   | Enter LogId 1 inputOffset 0 inputLen 16
TRACE [main] | 2020-11-12 17:44:00.110 | CaviumCipher.java | 140 |   | LogId 1 Mode Encrypt doFinal processing 16 bytes, buffer remaining 0
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 536 |   | Enter algorithm AES mode CBC blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 301 |   | Enter LogId 2 opmode 1
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 386 |   | Enter LogId 2
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 613 |   | Enter LogId 2 blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 621 |   | LogId 2
TRACE [main] | 2020-11-12 17:44:00.113 | CaviumCipher.java | 105 |   | Enter LogId 2 inputOffset 0 inputLen 32
TRACE [main] | 2020-11-12 17:44:00.114 | Paddings.java | 58 |   | Padded input of 32 bytes to 48 bytes
TRACE [main] | 2020-11-12 17:44:00.114 | CaviumCipher.java | 140 |   | LogId 2 Mode Encrypt doFinal processing 48 bytes, buffer remaining 0
Entering encryptKey...
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 536 |   | Enter algorithm AES mode CBC blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 301 |   | Enter LogId 3 opmode 1
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 386 |   | Enter LogId 3
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 613 |   | Enter LogId 3 blockSize 16 maxBlocks 1000 aadBlockSize 0 aadMaxBlocks 0
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 621 |   | LogId 3
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 105 |   | Enter LogId 3 inputOffset 0 inputLen 16
TRACE [main] | 2020-11-12 17:44:00.116 | CaviumCipher.java | 140 |   | LogId 3 Mode Encrypt doFinal processing 16 bytes, buffer remaining 0
Exiting encryptKey...
#Execution Id:9, Total time taken(ms):76 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:1, Total time taken(ms):68 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:2, Total time taken(ms):63 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:3, Total time taken(ms):69 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:4, Total time taken(ms):72 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:5, Total time taken(ms):50 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:6, Total time taken(ms):70 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:7, Total time taken(ms):69 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:8, Total time taken(ms):58 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:9, Total time taken(ms):76 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Execution Id:10, Total time taken(ms):58 Got encryptedDivKey:9E226FB250C504021D80F5BC19B24E34
#Now it is logging out ...
#Logged out from hsm successful...
```

## Running and verifying all the samples

To run and verify all the samples together, run the command ```mvn verify```
