## create a selenium container

`docker run -it -w /usr/workspace --name selenium-1 --network=prestashop_default -v $(pwd):/usr/workspace joyzoursky/python-chromedriver:3.9-selenium bash`
docker run -it -w /usr/workspace --name selenium-1 --net selelenium -v $(pwd):/usr/workspace joyzoursky/python-chromedriver:3.9-selenium bash
docker run -it -w /usr/workspace --name selenium-1 --network=prestashop_default --link=ps-web -v $(pwd):/usr/workspace joyzoursky/python-chromedriver:3.9-selenium bash