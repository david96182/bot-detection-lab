## Bot-Detection-Lab
![Py versions](https://img.shields.io/pypi/pyversions/Django)  ![Repo Size](https://img.shields.io/github/repo-size/david96182/bot-detection-lab)  ![License](https://img.shields.io/github/license/david96182/bot-detection-lab)

### Description

This repository contains a tool for accurately capture information in real time for bot detection on the web. The repository consists of two components: a test environment for bot detection and a features capture tool.

The features capture tool is a tool that allows capturing information at the network level about the users of a web service. The Wireshark software and the pyshark library are used to capture information. In the repository there are 3 versions of the tool, one that runs sequentially, one that uses the threading library and one that uses the multiprocessing library. The characteristics obtained coincide with the characteristics used in a database used in the state of the art of bot detection, it was decided to use these characteristics after much research having as results that these characteristics at the network level are used in many works where algorithms are created for bot detection. 

The test environment contains a web service and a bot that can be used for testing and further development of bot detection solutions. The web service is a e-commerce app created using prestashop, and the bot is created to scrap this website and obtain data about the prices of the products. This is a simulated environment very similar to a real one. The test environment allows users to simulate real world bot behavior by setting up a bot for scanning web services. The user can also use it as a virtual testing harness to assess whether the bot is successfully detecting bots on the network or not. 

This project is created with the goal of helping to detect, identify, mitigate and protect against automated bots which can cause malicious activities on websites. Also this project can be very usefull for developers to test their bot detection algorithms. The tool will provide an efficient way to capture information about bad bots while ensuring minimal disruption, as well as providing opportunities to learn more about their presence. 

---

### Features

Captures Information from User Interactions in Real-Time: The tool captures information from user interaction with a website at network level. This information can be used with artificial intelligence algorithms for bot detection. This enables an accurate analysis of suspicious actions from both users and bots. 

Test Environment with Bot and Web Service: Includes a test environment composed of a bot and a web service which can be used for development and evaluation purposes. This environment simulates a real environment that can be used to test classification algorithms. A self-contained test environment provides insight into how bots might interact with a web service. 

---

### Project Structure

[features-capture](https://github.com/david96182/SniffPyBot/tree/main/features-capture-mp): Contains a tool that captures information for bot detection using threading library. 

[features-capture-mp](https://github.com/david96182/SniffPyBot/tree/main/features-capture): Contains a tool that captures information for bot detection using python multiprocessing library. 

[moderate-bot](https://github.com/david96182/SniffPyBot/tree/main/moderate-bot): Contains a created bot that consumes the web service of the test environment. 

[sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website): Includes a simple e-commerce website created using docker as part of the test environment. 

[sequential-features-capture](https://github.com/david96182/SniffPyBot/tree/main/sequential-features-capture): Includes a tool that captures information for bot detection in sequential order. 

*features-capture, features-capture-mp and sequential-features-capture have the same functionality, the difference is that sequential-features-capture is executed sequentially while features-capture and features-capture-mp use the threading and multiprocessing libraries respectively.*

---

### Description of the features captured by the tool

The characteristics obtained by the tool are captured at the network level. These characteristics match those of a database used in state-of-the-art bot detection called CTU-13.

| **No.** | **Feature** | **Full name**                            | **Type** |
| ------- | ----------- | ---------------------------------------- | -------- |
| 1       | StartTime   | Start time                               | *date*   |
| 2       | Dur         | Duration                                 | *double* |
| 3       | Proto       | Protocol                                 | *string* |
| 4       | ScrAddr     | Address of origin                        | *string* |
| 5       | Sport       | Port of origin                           | *int*    |
| 6       | DstAddr     | Destination address                      | *string* |
| 7       | Dport       | Port of destination                      | *int*    |
| 8       | State       | State                                    | *string* |
| 9       | sTos        | Type of service of origin                | *string* |
| 10      | dTos        | Type of destination service              | *string* |
| 11      | TotPkts     | Total packages                           | *int*    |
| 12      | TotBytes    | Total bytes                              | *double* |
| 13      | SrcBytes    | Total bytes sent by source               | *double* |
| 14      | Label       | Label for network traffic classification | *string* |

1. StartTime: Date and time when a communication between two machines starts.
2. Dur: Total duration in seconds of the transfer, from when the first packet is sent until the last packet is received.
3. Proto: Protocol used to perform the communication between the destination and the source.
4. ScrAddr: IP address of the source machine.
5. Sport: Port of the source machine to be used.
6. DstAddr: IP address of the destination machine.
7. Dport: Port of the destination machine used.
8. State: Represents the state of the transactions in dependence of the protocol.
9. sTos: Type of service used at the source to perform the communication, the type of service may vary depending on the protocol.
10. dTos: Type of service used at the destination to perform the communication, the type of service may vary depending on the protocol.
11. TotPkts: Total number of packets that were sent between the destination and the source to complete the communication.
12. TotBytes: Total number of bytes sent by the source and destination in the communication.
13. SrcBytes: Total amount of bytes sent only by the source in the communication.
14. Label: Label used to classify the type of traffic processed, **used only for testing purposes**.

---

### Requirements

- Python
- Wireshark
- Docker (Optional if you are only going to use the tool for data capture or if you are going to use your own web service)

---

### Getting Started

***Each folder associated with the repository contains its own steps and description.*** 

1. First step is to clone this repository:

   ```bash
   git clone https://github.com/david96182/SniffPyBot.git && cd SniffPyBot/
   ```

2. Install [Wireshark](https://www.wireshark.org/download.html)

2. Install python requirements:

   ```bash
   pip install -r requirements.txt
   ```

3. Set up web service:

   - Go to [sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website)

4. Set up bot:

   - Go to [moderate-bot](https://github.com/david96182/SniffPyBot/tree/main/moderate-bot)

5. Set up feature capture tool:

   ***In this step you have to choose one of the 3 available variants***

   - Go to [features-capture](https://github.com/david96182/SniffPyBot/tree/main/features-capture-mp) or
   - [features-capture-mp](https://github.com/david96182/SniffPyBot/tree/main/features-capture) or
   - [sequential-features-capture](https://github.com/david96182/SniffPyBot/tree/main/sequential-features-capture)

---

### Future Work

The characteristics obtained are not limited to those, in the future they can be extended, or they can be extended depending on the algorithms with which the tool will be mixed to capture information. Other more sophisticated types of bots could also be added to have more variety of data and detection complexity.
Artificial intelligence algorithms for bot detection could be added. And even a complete bot detection system can be created (why not?).

---

### License
This project is [GNU GPLv3](LICENSE) License.

---

### Contributing

I'd love to have your help in making this project better! If you have any questions or ideas, feel free to open an issue or submit a pull request. All kinds of contributions are welcome, including bug reports, feature requests, documentation improvements, and code changes. 

Thank you for taking the time and effort to help!
