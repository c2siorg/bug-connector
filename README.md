# bug-connector
The idea of this project is to create a public dataset based on openly available CVE information, the key goal is to create fully functional scapers set to gather CVE information from different sources augment comprehensive data points, and make it public

# Installation
Install python 

Install pip

# Commands

pip install virtualenv

python -m venv venv (venv — Creation of virtual environments)

venv\Scripts\Activate.ps1  (Command to activate virtual environment)

pip install scrapy



scrapy startproject scraperr

cd scraperr



cd scraperr/spider

scrapy genspider spider https://services.nvd.nist.gov



scrapy crawl spider

scrapy crawl spider -o data.csv #