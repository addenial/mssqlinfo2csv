# mssql-info-parser.py
Script to convert nmap ms-sql-info XML output to a CSV file

Currently the script pulls and parses the following fields of interest:

`IP,TCPport,Winservername,Instance,ProductVersionName,Named Pipe`

Fields details~
IP Address,
Instance TCP Port,
Windows Server Name,
SQL Server Instance,
SQL Version Product Name Number Service Pack,
Instance Named Pipe

## Usage
`python ./mssql-info-parser.py <results-ms-sql-info.xml> `

## Examples
Parse and output to file:

`python ./mssql-info-parser.py results-ms-sql-info.xml `


#ip,port - use for pw guessing

`python3 mssql-info-parser.py results-ms-sql-info.xml | cut -d, -f1,2`
#
#ip,port,winhostname,instancename,namedpipe

`python3 mssql-info-parser.py results-ms-sql-info.xml | cut -d, -f1,2,3,4,10`
#






