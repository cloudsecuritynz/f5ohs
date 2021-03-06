

#### NOTE - if writing to a file on a Windows system, either use double backslash (escape the backslash) or prefix the quoted filename with r to denote a raw string in Python:
* filePath="C:\\\f5snapshots\\\F5devicename_101020.txt" 
* filePath=**r**"C:\f5snapshots\F5devicename_101020.txt"

#### Python usage examples:

* Return summary and detailed output strings using admin username and password:
> from f5ohs import f5snapshot       
>      
> summaryString, detailedString = f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd")    
> print(summaryString, detailedString)

* Return summary and detailed strings using API token:
> from f5ohs import f5snapshot        
>   
> summaryString, detailedString = f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere")    
> print(summaryString, detailedString)

* Output both summary and detailed strings to a text file with admin username and password:
> from f5ohs import f5snapshot      
>  
> f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", filePath=r"C:\f5snapshot\F5devicename_date.txt")


* Return only summary string using admin username and password:
> from f5ohs import f5snapshot      
>   
> summaryString = f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", summary_only=True)  
> print(summaryString, detailedString)

* Return only detailed string using admin username and password:
> from f5ohs import f5snapshot   
>   
> summaryString = f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", detailed_only=True)  
> print(summaryString, detailedString)

* Return only detailed string using admin username and password and output to file. 
> from f5ohs import f5snapshot    
>   
> f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", detailed_only=True, filePath=r"C:\f5snapshot\F5devicename_date.txt")

* Return summary and detailed strings using API token and non-default alert message:
> from f5ohs import f5snapshot  
>   
> summaryString, detailedString = f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", alert_message="*ALARM*")  
> print(summaryString, detailedString)

* Return summary and detailed strings using API token WITHOUT including the F5 device serial number:
> from f5ohs import f5snapshot    
>   
> summaryString, detailedString = f5snapshot("10.10.10.10", token="alphanumericAPITokengoeshere", serial=False)  
> print(summaryString, detailedString)

* Return only summary string using admin username and password and non-default memory and disk alert thresholds:
> from f5ohs import f5snapshot    
>   
> summaryString = f5snapshot("10.10.10.10", username="admin",password="aP@ssw0rd", memory_alert=70, disk_usage=80)  
> print(summaryString, detailedString)


* Return only detailed string using admin username and password and non-default SSL/TLS expiry thresholds:
> from f5ohs import f5snapshot    
>   
> detailedString = f5snapshot("10.10.10.10", username="admin",password="aP@ssw0rd", ssl_expire_days=62)  
> print(summaryString, detailedString)

* Return summary and detailed output strings using admin username and password and non-default fqdns:
> from f5ohs import f5snapshot  
>   
> summaryString, detailedString = f5snapshot("10.10.10.10", username="admin", password="aP@ssw0rd", fqdns=['example1.com','example2.com'])  
> print(summaryString, detailedString)
