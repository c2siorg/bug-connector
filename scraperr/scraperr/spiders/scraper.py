import scrapy
import json


class SpiderSpider(scrapy.Spider):
    name = "spider"
    allowed_domains = ["services.nvd.nist.gov"]
    start_urls = ["https://services.nvd.nist.gov/rest/json/cves/2.0"]

    def parse(self, response):
       #print(response.body)
       # pass
        data=json.loads(response.body) 
        #print(data) 

        for vulnerabilities1 in data['vulnerabilities']:
             data1=(vulnerabilities1['cve'])
             data2=(data1['id'])
             print(data1['id'])
             

             for data2 in data1['descriptions']:
                 print(data2['value'])

            # print(data1['published'])
            # print(data1['lastModified'])
            # print(data1['vulnStatus'])

             yield {
            'url' : (data1['id']),
            'value':  (data2['value'])
            }
             
             
             
           
    
      