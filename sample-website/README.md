## Sample-Website

### Description

The website is an e-commerce site created using the Docker Prestashop image. Prestashop is a CMS that allows you to create an e-commerce site in a very simple and fast way, and using docker is even faster. The goal of this site is to have a web service that when created with docker creates a network, from which network traffic can be captured using the developed tool.

---

### Installation

It is not mandatory to install the web service, you can use your own, but if you plan to use the test environment you will have to create a bot. It is also recommended to use Docker because it creates a network that to some extent simulates a real network.

1. Install **Docker** and **docker-compose** if not already installed.

2. Go to sample-website folder:

   ```bash
   cd sample-website/
   ```

3. Modify the settings **if necessary**. It is configured to install the store automatically.

4. Start the docker container:

   ```bash
   docker-compose up -d
   ```

5. Wait for the store to be installed. You can check the logs of the container: 

   ```bash
   docker logs -f psweb
   ```

   Wait till see this:

   *\* Almost ! Starting web server now*

6. Once the installation is done, it is necessary to access the page to verify that it loads.

   As in the docker-compose.yml the port 9000 for prestashop(**psweb**) is exposed and not mapped then you can access directly with the ip of the container.

   Get IP of the container by scanning the container network:

   ```bash
   docker network inspect sample-website-default
   ```

   Search for the IP of **psweb**.

7. Put the IP obtained in the last step on your web browser.

8. Now you have the web service up and running.

If you have problems with the installation you can check [the documentation of the prestashop docker image](https://hub.docker.com/r/prestashop/prestashop/).