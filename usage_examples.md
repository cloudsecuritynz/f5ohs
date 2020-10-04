#### Python usage examples:

#### NOTE - if writing to a file on a Windows system, either use double backslash or prefix the quoted filename with r to denote a raw string in python:
* filePath="C:\\f5snapshot\\F5devicename_date.txt" 
* filePath=**r**"C:\f5snapshot\F5devicename_date.txt"


* Return summary and detailed output strings using admin username and password:
> import f5osh   
>      
> summaryString, detailedString = f5osh.f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd")    
> print(summaryString, detailedString)

* Return summary and detailed strings using API token:
> import f5osh    
>   
> summaryString, detailedString = f5osh.f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere")    
> print(summaryString, detailedString)

* Output both summary and detailed strings to a text file with admin username and password:
> import f5osh   
>  
> f5osh.f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", filePath=r"C:\f5snapshot\F5devicename_date.txt")


* Return only summary string using admin username and password:
> import f5osh  
>   
> summaryString = f5osh.f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", summary_only=True)
> print(summaryString, detailedString)

* Return only detailed string using admin username and password:
> import f5osh 
>   
> summaryString = f5osh.f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", detailed_only=True)
> print(summaryString, detailedString)

* Return only detailed string using admin username and password and output to file. 
> import f5osh  
>   
> f5osh.f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", detailed_only=True, filePath=r"C:\f5snapshot\F5devicename_date.txt")

* Return summary and detailed strings using API token and non-default alert message:
> import f5osh  
>   
> summaryString, detailedString = f5osh.f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", alert_message="*ALARM*")
> print(summaryString, detailedString)

* Return summary and detailed strings using API token WITHOUT including the F5 device serial number:
> import f5osh  
>   
> summaryString, detailedString = f5osh.f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", serial=False)
> print(summaryString, detailedString)

* Return only summary string using admin username and password and non-default memory and disk alert thresholds:
> import f5osh  
>   
> summaryString = f5osh.f5snapshot("10.10.10.10", username="admin",password="aP@ssw0rd", memory_alert=70, disk_usage=80)
> print(summaryString, detailedString)


* Return only detailed string using admin username and password and non-default SSL/TLS expiry thresholds:
> import f5osh  
>   
> detailedString = f5osh.f5snapshot("10.10.10.10", username="admin",password="aP@ssw0rd", ssl_expire_days=62)
> print(summaryString, detailedString)

* Return summary and detailed output strings using admin username and password and non-default fqdns:
> import f5osh  
>   
> summaryString, detailedString = f5osh.f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", fqdns=['example1.com','example2.com'])
> print(summaryString, detailedString)
