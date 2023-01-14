## Moderate-bot

### Description

The developed bot is a very simple bot, for its creation the selenium library was used. The bot connects to the web site created in [sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website) and navigates through the different pages of product categories and obtains the prices of the products and saves them in a json file, the bot is designed so that its execution does not end, so it keeps consuming the web service all the time. To perform these tasks were set random waiting time between one and another.

In addition the bot was developed to connect to a webdriver that is inside a Docker container. This container is connected to the same network as [sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website).

---

### File Descriptions

There are three files:

- **main.py**: File containing the bot implementation, mainly used for development and testing. When running the bot through this file the bot IP would be the same as localhost. 
- **remote-driver.py**: File containing the bot implementation to make use of remote web drivers. This way the bots are executed with different IP. 
- **docker-compose.yml**: File containing the details for mounting the webdriver containers for the bots.

---

### Installation

1. Install Firefox. 

2. Install webdriver:

   The first step is to install the webdriver, in this case GeckoDriver is being used.

   If you are using Linux you can install it directly (at least in my case, Arch Linux) using the package manager:

   ```bash
   sudo pacman -S geckodriver
   ```

   If you don't use Linux or your package manager doesn't have the driver, then download the driver from [this page](https://github.com/mozilla/geckodriver/releases).

   Extract the webdriver in the moderate-bot folder.

   Modify the code (main.py and remote-driver.py):

   ```python
   if __name__ == '__main__':
       service = FirefoxService(executable_path='./geckodriver') # set webdriver path 
       firefox_options = webdriver.FirefoxOptions()
   ```

3. Update the IP address of the web server([sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website)) at main.py and remote-driver.py in **browser.get()** line.

4. Create an account in the web service([sample-website](https://github.com/david96182/SniffPyBot/tree/main/sample-website)) and update the credentials in the **login()** function at main.py and remote-driver.py.

5. Run main.py:

   ```bash
   python main.py
   ```

   When the command is executed, the browser should open where you can see the bot running. If you do not want to see the browser while the bot is running you can uncomment the following line to run it in headless mode:

   ```python
   # firefox_options.headless = True
   ```

6. Download **selenium/standalone-firefox** Docker image:

   ```bash
   docker pull selenium/standalone-firefox
   ```

7. Now it is necessary to create the containers for the bots to be executed:

   * First edit the docker-compose.yml file if you want to add more containers for webdriver, each container is used by only one bot.

   * Edit the network name at docker-compose.yml in case it is different from the set one.

   * Run the containers:

     ```bash
     docker-compose up -d
     ```

8. Update **remote_url** at remote-driver.py with container IP domains.

9. Execute for each bot that you want to have running depending on the webdriver containers that were enabled:

   ```bash
   python remote-driver.py N
   ```

   Where **N** is the number of the webdriver container. If everything works correctly you will have an output like the following:

   ```bash
   http://172.18.0.6:4444/wd/hub
   Current page: http://172.18.0.3/
   READY
   LOGIN..
   GET CLOTHES
   ```

   Where you can see the steps that the bot is executing.

   To execute each bot it is necessary to execute the command shown for each one, it is **recommended** to create a bash script that executes all of them.

10. Now you have bots running that consume the web service already created.
